//! The derived, rebuildable namespace index (research §6, §23.2, §24, §25).
//!
//! The index is **not** authoritative. It is a deterministic projection of the
//! authoritative log and can always be rebuilt from scratch by replaying
//! committed records. If an index (or a persisted snapshot of one) disagrees
//! with replay, the **log wins** and the index is discarded (research §23.2).
//!
//! The index maps:
//!
//! ```text
//!   inode_id            -> current inode version (+ its historical versions)
//!   (parent_inode,name) -> child inode_id
//!   inode_id            -> extent map
//!   inode_id            -> xattr map
//!   root                -> named committed snapshots / checkpoints
//! ```
//!
//! Everything is native Rust (`std::collections` maps); there is no external
//! database and no correctness property depends on a persisted snapshot. A
//! snapshot under `index/` is written purely as an accelerator and validated
//! against its own digest on load.

use std::path::Path;
use std::sync::Arc;

use crate::persistent::PMap;

use crate::directory::{DentryAddPayload, DentryRemovePayload, DentryRenamePayload, RenameFlags};
use crate::error::{OrfsError, Result};
use crate::extent::{
    DataExtentPayload, DataZeroRangePayload, ExtentKind, FileResizePayload, DATA_EXTENT_DATA_OFFSET,
};
use crate::inode::{
    Inode, InodeCreatePayload, InodeMetadataPayload, InodeSetattrPayload, InodeType,
    PermissionChangePayload, SymlinkCreatePayload, Timespec, XattrRemovePayload, XattrSetPayload,
};
use crate::log::Log;
use crate::record::{Record, RecordType};

/// The reserved inode id of the volume root (matches FUSE's `FUSE_ROOT_ID`).
pub const ROOT_INODE: u64 = 1;

/// A recorded index checkpoint (research §24) — an accelerator/verification aid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub root: u64,
    pub inode_count: u64,
    pub dentry_count: u64,
    pub digest: [u8; 32],
}

/// The work performed by an [`Index::apply_range`] call (Phase 20).
///
/// `bytes` is the canonical byte span actually decoded from the log: because
/// committed records are contiguous, a suffix replay over `[start, end)` decodes
/// exactly `end - start` bytes, independent of how much history precedes
/// `start`. This is the measurable statement of the suffix-replay fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct RangeApplyStats {
    /// The committed boundary the replay began at.
    pub start: u64,
    /// The committed boundary the replay ended at.
    pub end: u64,
    /// Number of records decoded.
    pub records: u64,
    /// Canonical bytes decoded (equal to `end - start` for a contiguous replay).
    pub bytes: u64,
}

/// The derived namespace index.
///
/// # Structural sharing (Phase 19)
///
/// The index is published to readers as an immutable snapshot
/// ([`crate::namespace::ReadState`]). To keep publication cheap it is stored so
/// that a snapshot can share almost all of its memory with the live writer:
///
/// * `inodes` is a [`PMap`] from id to `Arc<Inode>`, so a commit copies only the
///   `O(log n)` spine nodes on the root-to-key path; every other inode (and the
///   inode *nodes* themselves — their extent maps, version history and xattrs)
///   is shared with the prior snapshot.
/// * `children` is a [`PMap`] from a directory id to that directory's own
///   `PMap<name, child>`, so an untouched directory's listing is shared wholesale
///   and only the affected directory's entry is path-copied.
/// * `snapshots` is a [`PMap`] keyed by name, and `checkpoints` is an `Arc<Vec>`
///   appended copy-on-write (checkpoint records are rare), so neither spine grows
///   the per-commit copy cost.
///
/// Cloning an `Index` is therefore a handful of `Arc` pointer copies — never a
/// copy of the inode/directory spines and never a deep copy of any inode payload.
/// The per-commit cost is `O(log n)` path copies for the maps a commit touches
/// plus `O(affected)` node clones, independent of total retained history. The
/// earlier `O(n)`-spine representation documented as deferred in
/// `docs/CONCURRENCY.md` §4.1 is now replaced by this persistent map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    root: u64,
    inodes: PMap<u64, Arc<Inode>>,
    children: PMap<u64, PMap<Vec<u8>, u64>>,
    next_inode_id: u64,
    snapshots: PMap<Vec<u8>, u64>,
    checkpoints: Arc<Vec<Checkpoint>>,
}

impl Default for Index {
    fn default() -> Self {
        Index {
            root: 0,
            inodes: PMap::new(),
            children: PMap::new(),
            next_inode_id: ROOT_INODE,
            snapshots: PMap::new(),
            checkpoints: Arc::new(Vec::new()),
        }
    }
}

impl Index {
    /// An empty index (no root inode yet; genesis creates it).
    pub fn empty() -> Index {
        Index::default()
    }

    /// Build the index by replaying the committed log up to `root`.
    ///
    /// `root` must be a committed transaction boundary; the log's own
    /// [`Log::is_boundary`] is the authority.
    pub fn from_log(log: &Log, root: u64) -> Result<Index> {
        if root > log.committed_end_offset() {
            return Err(OrfsError::InvalidArgument(format!(
                "index root {root} exceeds the committed root {}",
                log.committed_end_offset()
            )));
        }
        if root != 0 && !log.is_boundary(root) {
            return Err(OrfsError::InvalidArgument(format!(
                "index root {root} is not a committed transaction boundary"
            )));
        }
        let mut index = Index::default();
        index.apply_range(log, 0, root)?;
        Ok(index)
    }

    /// Apply the committed records in `[start, end)` to the index.
    ///
    /// Used both to build an index from scratch (`start = 0`) and to extend a
    /// live index after a commit (`start = previous root`). Because both paths
    /// call the identical [`Index::apply_record`], a live index is always equal
    /// to a rebuild over the same records.
    ///
    /// # Suffix replay (Phase 20)
    ///
    /// The suffix is iterated **directly** with [`Log::records_from`], which seeks
    /// to `start` and decodes no bytes before it. Iterating `records_upto(end)`
    /// while skipping records with `offset < start` would decode the entire
    /// preceding stream on every call — so a live index extended by one small
    /// commit would `O(|L|)`-decode the whole history each time. Here the work is
    /// proportional to `end - start`, not to `end`.
    ///
    /// `start` must be a committed transaction boundary so iteration begins
    /// exactly at a framed record; a non-boundary start would apply a garbled
    /// record and is rejected.
    pub fn apply_range(&mut self, log: &Log, start: u64, end: u64) -> Result<()> {
        self.apply_range_traced(log, start, end).map(|_| ())
    }

    /// [`Index::apply_range`] with the records and canonical bytes it actually
    /// decoded. The log-wins invariant (equal to full replay over the same
    /// records) is unchanged; the statistics exist so tests/evidence can prove
    /// that a suffix replay is proportional to the suffix, not to total history.
    pub fn apply_range_traced(
        &mut self,
        log: &Log,
        start: u64,
        end: u64,
    ) -> Result<RangeApplyStats> {
        if end > log.committed_end_offset() {
            return Err(OrfsError::InvalidArgument(format!(
                "apply end {end} exceeds the committed root {}",
                log.committed_end_offset()
            )));
        }
        if start > end {
            return Err(OrfsError::InvalidArgument(format!(
                "apply start {start} is beyond end {end}"
            )));
        }
        if start != 0 && !log.is_boundary(start) {
            return Err(OrfsError::InvalidArgument(format!(
                "apply start {start} is not a committed transaction boundary"
            )));
        }
        let mut offset = start;
        let mut records = 0u64;
        let mut bytes = 0u64;
        for record in log.records_from(start, end) {
            let record = record?;
            let total = record.header.total_len().map_err(OrfsError::from)?;
            self.apply_record(&record, offset)?;
            records += 1;
            bytes = bytes.checked_add(total).ok_or(OrfsError::Overflow {
                what: "index replay bytes",
            })?;
            offset = offset.checked_add(total).ok_or(OrfsError::Overflow {
                what: "index offset",
            })?;
        }
        Ok(RangeApplyStats {
            start,
            end,
            records,
            bytes,
        })
    }

    /// Apply a single authoritative record at the given logical `offset`.
    ///
    /// This is the *only* function that mutates the index, so the live index and
    /// a from-scratch rebuild are provably identical over the same record
    /// sequence.
    pub fn apply_record(&mut self, record: &Record, offset: u64) -> Result<()> {
        let ty = record.known_type().map_err(OrfsError::from)?;
        match ty {
            RecordType::VolumeGenesis => {
                if !self.inodes.is_empty() {
                    return Err(OrfsError::Corrupt("duplicate VOLUME_GENESIS".into()));
                }
                let root = Inode::new(
                    ROOT_INODE,
                    1,
                    InodeType::Directory,
                    0o755,
                    0,
                    0,
                    2,
                    0,
                    Timespec::ZERO,
                    Timespec::ZERO,
                    Timespec::ZERO,
                    offset,
                );
                self.inodes = self.inodes.insert(ROOT_INODE, Arc::new(root));
                self.children = self.children.insert(ROOT_INODE, PMap::new());
                self.next_inode_id = ROOT_INODE + 1;
                self.root = offset + record.header.total_len().map_err(OrfsError::from)?;
            }
            RecordType::TxBegin | RecordType::TxAbort => {}
            RecordType::TxCommit => {
                if record.header.transaction_id == 0 {
                    return Err(OrfsError::Corrupt(
                        "TX_COMMIT with zero transaction id".into(),
                    ));
                }
                self.root = offset + record.header.total_len().map_err(OrfsError::from)?;
            }
            RecordType::InodeCreate => {
                let p = InodeCreatePayload::decode(&record.payload)?;
                self.create_inode(
                    p.inode_id,
                    p.generation,
                    p.kind,
                    p.mode,
                    p.uid,
                    p.gid,
                    p.nlink,
                    p.size,
                    None,
                    p.atime,
                    p.mtime,
                    p.ctime,
                    offset,
                )?;
            }
            RecordType::SymlinkCreate => {
                let p = SymlinkCreatePayload::decode(&record.payload)?;
                let size = p.target.len() as u64;
                self.create_inode(
                    p.inode_id,
                    p.generation,
                    InodeType::Symlink,
                    p.mode,
                    p.uid,
                    p.gid,
                    1,
                    size,
                    Some(p.target.clone()),
                    Timespec::ZERO,
                    p.mtime,
                    p.mtime,
                    offset,
                )?;
            }
            RecordType::InodeMetadata => {
                let p = InodeMetadataPayload::decode(&record.payload)?;
                let id = subject(record, p.inode_id)?;
                let mut inode = self.take_inode(id)?;
                inode.nlink = p.nlink;
                inode.bump_version(offset);
                self.put_inode(id, inode);
            }
            RecordType::PermissionChange => {
                let p = PermissionChangePayload::decode(&record.payload)?;
                let id = subject(record, p.inode_id)?;
                let mut inode = self.take_inode(id)?;
                if let Some(m) = p.mode {
                    inode.mode = m;
                }
                if let Some(u) = p.uid {
                    inode.uid = u;
                }
                if let Some(g) = p.gid {
                    inode.gid = g;
                }
                inode.bump_version(offset);
                self.put_inode(id, inode);
            }
            RecordType::InodeSetattr => {
                let p = InodeSetattrPayload::decode(&record.payload)?;
                let id = subject(record, p.inode_id)?;
                let mut inode = self.take_inode(id)?;
                if let Some(t) = p.atime {
                    inode.atime = t;
                }
                if let Some(t) = p.mtime {
                    inode.mtime = t;
                }
                inode.ctime = inode.mtime;
                inode.bump_version(offset);
                self.put_inode(id, inode);
            }
            RecordType::XattrSet => {
                let p = XattrSetPayload::decode(&record.payload)?;
                let id = subject(record, p.inode_id)?;
                let mut inode = self.take_inode(id)?;
                inode.xattrs.insert(p.name, p.value);
                inode.bump_version(offset);
                self.put_inode(id, inode);
            }
            RecordType::XattrRemove => {
                let p = XattrRemovePayload::decode(&record.payload)?;
                let id = subject(record, p.inode_id)?;
                let mut inode = self.take_inode(id)?;
                inode.xattrs.remove(&p.name);
                inode.bump_version(offset);
                self.put_inode(id, inode);
            }
            RecordType::DentryAdd => {
                let p = DentryAddPayload::decode(
                    &record.payload,
                    crate::directory::DENTRY_ADD_MAGIC,
                    "DENTRY_ADD",
                )?;
                self.add_dentry(p.parent, p.name, p.child, offset)?;
            }
            RecordType::HardlinkAdd => {
                let p = DentryAddPayload::decode(
                    &record.payload,
                    crate::directory::HARDLINK_ADD_MAGIC,
                    "HARDLINK_ADD",
                )?;
                self.add_dentry(p.parent, p.name, p.child, offset)?;
            }
            RecordType::DentryRemove => {
                let p = DentryRemovePayload::decode(
                    &record.payload,
                    crate::directory::DENTRY_REMOVE_MAGIC,
                    "DENTRY_REMOVE",
                )?;
                self.remove_dentry(p.parent, &p.name, offset)?;
            }
            RecordType::HardlinkRemove => {
                let p = DentryRemovePayload::decode(
                    &record.payload,
                    crate::directory::HARDLINK_REMOVE_MAGIC,
                    "HARDLINK_REMOVE",
                )?;
                self.remove_dentry(p.parent, &p.name, offset)?;
            }
            RecordType::DentryRename => {
                let p = DentryRenamePayload::decode(&record.payload)?;
                self.rename_dentry(&p, offset)?;
            }
            RecordType::DataExtent => {
                let p = DataExtentPayload::decode(&record.payload)?;
                let id = subject(record, 0)?;
                let data_offset = offset
                    .checked_add(crate::record::HEADER_LEN as u64)
                    .and_then(|v| v.checked_add(DATA_EXTENT_DATA_OFFSET as u64))
                    .ok_or(OrfsError::Overflow {
                        what: "DATA_EXTENT data offset",
                    })?;
                let mut inode = self.take_inode(id)?;
                inode
                    .extents
                    .write(p.offset, p.data.len() as u64, data_offset);
                inode.size = inode.extents.size();
                inode.bump_version(offset);
                self.put_inode(id, inode);
            }
            RecordType::DataZeroRange => {
                let p = DataZeroRangePayload::decode(&record.payload)?;
                let id = subject(record, 0)?;
                let mut inode = self.take_inode(id)?;
                inode.extents.zero(p.offset, p.len);
                inode.size = inode.extents.size();
                inode.bump_version(offset);
                self.put_inode(id, inode);
            }
            RecordType::FileResize => {
                let p = FileResizePayload::decode(&record.payload)?;
                let id = subject(record, 0)?;
                let mut inode = self.take_inode(id)?;
                inode.extents.resize(p.new_size);
                inode.size = inode.extents.size();
                inode.bump_version(offset);
                self.put_inode(id, inode);
            }
            RecordType::SnapshotRoot => {
                let p = crate::namespace::SnapshotRootPayload::decode(&record.payload)?;
                self.snapshots = self.snapshots.insert(p.name, p.root);
            }
            RecordType::IndexCheckpoint => {
                let p = crate::namespace::IndexCheckpointPayload::decode(&record.payload)?;
                Arc::make_mut(&mut self.checkpoints).push(Checkpoint {
                    root: p.root,
                    inode_count: p.inode_count,
                    dentry_count: p.dentry_count,
                    digest: p.digest,
                });
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn create_inode(
        &mut self,
        id: u64,
        generation: u64,
        kind: InodeType,
        mode: u32,
        uid: u32,
        gid: u32,
        nlink: u32,
        size: u64,
        target: Option<Vec<u8>>,
        atime: Timespec,
        mtime: Timespec,
        ctime: Timespec,
        offset: u64,
    ) -> Result<()> {
        if id == 0 || id == ROOT_INODE {
            return Err(OrfsError::Corrupt(format!(
                "INODE_CREATE with reserved inode id {id}"
            )));
        }
        if self.inodes.contains_key(&id) {
            return Err(OrfsError::Corrupt(format!("duplicate inode id {id}")));
        }
        let mut inode = Inode::new(
            id, generation, kind, mode, uid, gid, nlink, size, atime, mtime, ctime, offset,
        );
        inode.symlink_target = target;
        self.inodes = self.inodes.insert(id, Arc::new(inode));
        self.next_inode_id = self.next_inode_id.max(id + 1);
        Ok(())
    }

    fn add_dentry(&mut self, parent: u64, name: Vec<u8>, child: u64, offset: u64) -> Result<()> {
        {
            let p = self.inodes.get(&parent).ok_or_else(|| {
                OrfsError::Corrupt(format!("dentry parent {parent} does not exist"))
            })?;
            if !p.is_dir() {
                return Err(OrfsError::Corrupt(format!(
                    "dentry parent {parent} is not a directory"
                )));
            }
            if !self.inodes.contains_key(&child) {
                return Err(OrfsError::Corrupt(format!(
                    "dentry child {child} does not exist"
                )));
            }
        }
        if self.lookup(parent, &name).is_some() {
            return Err(OrfsError::Corrupt(format!(
                "duplicate dentry under {parent}"
            )));
        }
        self.set_child(parent, &name, Some(child));
        let mut c = self.take_inode(child)?;
        c.bump_version(offset);
        self.put_inode(child, c);
        Ok(())
    }

    fn remove_dentry(&mut self, parent: u64, name: &[u8], offset: u64) -> Result<()> {
        let child = self
            .lookup(parent, name)
            .ok_or_else(|| OrfsError::Corrupt(format!("remove of absent dentry under {parent}")))?;
        self.set_child(parent, name, None);
        let mut c = self.take_inode(child)?;
        c.bump_version(offset);
        self.put_inode(child, c);
        Ok(())
    }

    fn rename_dentry(&mut self, p: &DentryRenamePayload, offset: u64) -> Result<()> {
        match p.flags {
            RenameFlags::Move => {
                if p.old_parent == p.new_parent && p.old_name == p.new_name {
                    return Ok(());
                }
                let child = self.lookup(p.old_parent, &p.old_name).ok_or_else(|| {
                    OrfsError::Corrupt("rename source does not exist".to_string())
                })?;
                if self.lookup(p.new_parent, &p.new_name).is_some() {
                    return Err(OrfsError::Corrupt(
                        "rename destination already exists".to_string(),
                    ));
                }
                self.set_child(p.old_parent, &p.old_name, None);
                self.set_child(p.new_parent, &p.new_name, Some(child));
                let mut c = self.take_inode(child)?;
                c.bump_version(offset);
                self.put_inode(child, c);
            }
            RenameFlags::Exchange => {
                let c1 = self
                    .lookup(p.old_parent, &p.old_name)
                    .ok_or_else(|| OrfsError::Corrupt("exchange source does not exist".into()))?;
                let c2 = self.lookup(p.new_parent, &p.new_name).ok_or_else(|| {
                    OrfsError::Corrupt("exchange destination does not exist".into())
                })?;
                self.set_child(p.old_parent, &p.old_name, Some(c2));
                self.set_child(p.new_parent, &p.new_name, Some(c1));
                let mut i1 = self.take_inode(c1)?;
                i1.bump_version(offset);
                self.put_inode(c1, i1);
                let mut i2 = self.take_inode(c2)?;
                i2.bump_version(offset);
                self.put_inode(c2, i2);
            }
        }
        Ok(())
    }

    fn set_child(&mut self, parent: u64, name: &[u8], child: Option<u64>) {
        let existing = self.children.get(&parent).cloned();
        match child {
            Some(c) => {
                let map = existing.unwrap_or_default().insert(name.to_vec(), c);
                self.children = self.children.insert(parent, map);
            }
            None => {
                if let Some(map) = existing {
                    self.children = self.children.insert(parent, map.remove(name));
                }
            }
        }
    }

    /// Take an owned, mutable copy of inode `id`. When the `Arc<Inode>` is
    /// shared with a published read view (the common case after a commit) the
    /// inode node is cloned once; because its version history and extent map are
    /// themselves structurally shared, that clone is `O(1)` in retained history.
    fn take_inode(&self, id: u64) -> Result<Inode> {
        let arc = self
            .inodes
            .get(&id)
            .ok_or_else(|| OrfsError::Corrupt(format!("record references missing inode {id}")))?
            .clone();
        Ok(Arc::try_unwrap(arc).unwrap_or_else(|shared| (*shared).clone()))
    }

    /// Store a mutated inode back, path-copying the `inodes` spine.
    fn put_inode(&mut self, id: u64, inode: Inode) {
        self.inodes = self.inodes.insert(id, Arc::new(inode));
    }

    // -- read accessors ----------------------------------------------------

    /// The committed root this index reflects.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// The next inode id to allocate (strictly greater than every id seen).
    pub fn next_inode_id(&self) -> u64 {
        self.next_inode_id
    }

    /// The number of live inodes (including unlinked-but-retained ones).
    pub fn inode_count(&self) -> usize {
        self.inodes.len()
    }

    /// The number of live directory entries.
    pub fn dentry_count(&self) -> usize {
        self.children.values().map(|m| m.len()).sum()
    }

    /// Named committed snapshots (`SNAPSHOT_ROOT`).
    pub fn snapshot_roots(&self) -> &PMap<Vec<u8>, u64> {
        &self.snapshots
    }

    /// Recorded index checkpoints (`INDEX_CHECKPOINT`).
    pub fn checkpoints(&self) -> &[Checkpoint] {
        self.checkpoints.as_slice()
    }

    /// A reference to an inode by id.
    pub fn inode(&self, id: u64) -> Option<&Inode> {
        self.inodes.get(&id).map(|a| &**a)
    }

    /// Every live inode id (used by physical accounting and manifestation).
    pub fn inode_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.inodes.keys().copied()
    }

    /// The latest authoritative record offset for an inode (0 if unknown).
    pub fn latest_offset(&self, id: u64) -> u64 {
        self.inodes
            .get(&id)
            .map(|i| i.latest_record_offset)
            .unwrap_or(0)
    }

    /// Resolve `(parent, name)` to a child inode id.
    pub fn lookup(&self, parent: u64, name: &[u8]) -> Option<u64> {
        self.children
            .get(&parent)
            .and_then(|m| m.get(name))
            .copied()
    }

    /// The visible children of a directory, sorted by name. `None` if `parent`
    /// is not a directory.
    pub fn readdir(&self, parent: u64) -> Option<Vec<(Vec<u8>, u64)>> {
        let inode = self.inodes.get(&parent)?;
        if !inode.is_dir() {
            return None;
        }
        Some(
            self.children
                .get(&parent)
                .map(|m| m.iter().map(|(k, v)| (k.clone(), *v)).collect())
                .unwrap_or_default(),
        )
    }

    /// Whether `ancestor` is `node` or an ancestor of `node` (used to reject
    /// directory cycles on rename).
    pub fn is_ancestor(&self, ancestor: u64, node: u64) -> bool {
        if ancestor == node {
            return true;
        }
        let mut cur = node;
        loop {
            let Some(parent) = self.parent_of(cur) else {
                return false;
            };
            if parent == ancestor {
                return true;
            }
            if parent == cur || parent == ROOT_INODE {
                return false;
            }
            cur = parent;
        }
    }

    /// The parent directory of an inode (the sole parent for directories).
    pub fn parent_of(&self, child: u64) -> Option<u64> {
        let inode = self.inodes.get(&child)?;
        if inode.is_dir() {
            // Directories have exactly one parent: search the children graph.
            for (parent, map) in self.children.iter() {
                if map.values().any(|c| *c == child) {
                    return Some(*parent);
                }
            }
            None
        } else {
            None
        }
    }

    /// The number of visible directory entries that reference `inode`.
    pub fn link_count_from_dentries(&self, inode: u64) -> u32 {
        self.children
            .values()
            .flat_map(|m| m.values())
            .filter(|c| **c == inode)
            .count() as u32
    }

    /// Whether `inode` is a directory that is still part of the live namespace:
    /// the root, or a directory named by at least one directory entry.
    ///
    /// A directory that has been removed (`rmdir`) keeps its inode (every inode
    /// is retained immutably in history and stays readable by id), but it has no
    /// remaining names, so it is no longer *live*. Such a directory must not
    /// accept new namespace mutations: doing so would resurrect a deleted
    /// subtree and make its link count inconsistent with the documented
    /// derivation ("`0` once removed", `docs/NAMESPACE.md` §4.1).
    pub fn is_live_dir(&self, inode: u64) -> bool {
        match self.inodes.get(&inode) {
            Some(i) if i.is_dir() => {
                inode == ROOT_INODE || self.link_count_from_dentries(inode) > 0
            }
            _ => false,
        }
    }

    // -- snapshot / digest -------------------------------------------------

    /// A deterministic BLAKE3 digest of the canonical index content.
    pub fn canonical_digest(&self) -> [u8; 32] {
        let snap = Snapshot::from_index(self);
        let bytes = serde_json::to_vec(&snap).unwrap_or_default();
        *blake3::hash(&bytes).as_bytes()
    }

    /// Serialise the index to a canonical, self-describing snapshot document.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>> {
        let snap = Snapshot::from_index(self);
        let file = SnapshotFile {
            schema: SNAPSHOT_SCHEMA.to_string(),
            digest: hex32(&snap.digest()),
            snapshot: snap,
        };
        let mut out = serde_json::to_vec_pretty(&file)
            .map_err(|e| OrfsError::Corrupt(format!("snapshot encode: {e}")))?;
        out.push(b'\n');
        Ok(out)
    }

    /// Parse a snapshot document, rejecting it if its self-digest does not
    /// validate. The returned index is valid only for a matching committed root;
    /// callers must confirm that against the log.
    pub fn decode_snapshot(bytes: &[u8]) -> Result<Index> {
        let file: SnapshotFile = serde_json::from_slice(bytes)
            .map_err(|e| OrfsError::Corrupt(format!("snapshot decode: {e}")))?;
        if file.schema != SNAPSHOT_SCHEMA {
            return Err(OrfsError::Compatibility(format!(
                "index snapshot schema {}",
                file.schema
            )));
        }
        if file.digest != hex32(&file.snapshot.digest()) {
            return Err(OrfsError::Corrupt(
                "index snapshot digest mismatch (tampered or torn)".into(),
            ));
        }
        Ok(file.snapshot.into_index())
    }

    /// Persist the index as an accelerator snapshot under `path`.
    pub fn save_snapshot(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = self.encode_snapshot()?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Load a persisted accelerator snapshot, if present and valid.
    ///
    /// Returns `Ok(None)` when the file is absent, or when it fails to validate
    /// (torn/tampered/foreign root). A derived snapshot never overrides the log.
    pub fn load_snapshot(path: &Path, expected_root: u64) -> Result<Option<Index>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        match Index::decode_snapshot(&bytes) {
            Ok(index) if index.root == expected_root => Ok(Some(index)),
            _ => Ok(None),
        }
    }
}

/// Resolve a record's subject inode: prefer the payload's explicit id, falling
/// back to the record header, and reject disagreements.
fn subject(record: &Record, payload_id: u64) -> Result<u64> {
    let header_id = record.header.inode_id;
    let id = if payload_id != 0 {
        payload_id
    } else {
        header_id
    };
    if id == 0 {
        return Err(OrfsError::Corrupt("record has no subject inode".into()));
    }
    if payload_id != 0 && header_id != 0 && payload_id != header_id {
        return Err(OrfsError::Corrupt(
            "payload inode id disagrees with record header".into(),
        ));
    }
    Ok(id)
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

const SNAPSHOT_SCHEMA: &str = "orfs.index.snapshot.v1";

// ---------------------------------------------------------------------------
// Snapshot serialisation (deterministic; used for the digest and the file)
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SnapshotFile {
    schema: String,
    digest: String,
    snapshot: Snapshot,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Snapshot {
    root: u64,
    next_inode_id: u64,
    inodes: Vec<SnapshotInode>,
    dentries: Vec<SnapshotDentry>,
    snapshots: Vec<SnapshotRoot>,
    checkpoints: Vec<SnapshotCheckpoint>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SnapshotInode {
    id: u64,
    generation: u64,
    kind: u8,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
    atime_secs: i64,
    atime_nanos: u32,
    mtime_secs: i64,
    mtime_nanos: u32,
    ctime_secs: i64,
    ctime_nanos: u32,
    symlink_target: Option<Vec<u8>>,
    latest_record_offset: u64,
    versions: Vec<SnapshotVersion>,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    extents: Vec<SnapshotExtent>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SnapshotVersion {
    version: u64,
    record_offset: u64,
    kind: u8,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SnapshotExtent {
    start: u64,
    len: u64,
    /// `None` is a zero extent; `Some` is immutable data at this log offset.
    data_offset: Option<u64>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SnapshotDentry {
    parent: u64,
    name: Vec<u8>,
    child: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SnapshotRoot {
    name: Vec<u8>,
    root: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SnapshotCheckpoint {
    root: u64,
    inode_count: u64,
    dentry_count: u64,
    digest: Vec<u8>,
}

impl Snapshot {
    fn from_index(index: &Index) -> Snapshot {
        let mut inode_ids: Vec<u64> = index.inodes.keys().copied().collect();
        inode_ids.sort_unstable();
        let inodes = inode_ids
            .into_iter()
            .map(|id| {
                let i = index.inodes.get(&id).expect("id from the inode map");
                SnapshotInode {
                    id: i.id,
                    generation: i.generation,
                    kind: i.kind.code(),
                    mode: i.mode,
                    uid: i.uid,
                    gid: i.gid,
                    nlink: i.nlink,
                    size: i.size,
                    atime_secs: i.atime.secs,
                    atime_nanos: i.atime.nanos,
                    mtime_secs: i.mtime.secs,
                    mtime_nanos: i.mtime.nanos,
                    ctime_secs: i.ctime.secs,
                    ctime_nanos: i.ctime.nanos,
                    symlink_target: i.symlink_target.clone(),
                    latest_record_offset: i.latest_record_offset,
                    versions: i
                        .versions
                        .iter()
                        .map(|v| SnapshotVersion {
                            version: v.version,
                            record_offset: v.record_offset,
                            kind: v.kind.code(),
                            mode: v.mode,
                            uid: v.uid,
                            gid: v.gid,
                            nlink: v.nlink,
                            size: v.size,
                        })
                        .collect(),
                    xattrs: i
                        .xattrs
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                    extents: i
                        .extents
                        .extents()
                        .iter()
                        .map(|e| SnapshotExtent {
                            start: e.start,
                            len: e.len,
                            data_offset: match e.kind {
                                ExtentKind::Data { data_offset } => Some(data_offset),
                                ExtentKind::Zero => None,
                            },
                        })
                        .collect(),
                }
            })
            .collect();
        let mut dentries: Vec<SnapshotDentry> = Vec::new();
        for (parent, map) in index.children.iter() {
            for (name, child) in map.iter() {
                dentries.push(SnapshotDentry {
                    parent: *parent,
                    name: name.clone(),
                    child: *child,
                });
            }
        }
        dentries.sort_by(|a, b| (a.parent, &a.name).cmp(&(b.parent, &b.name)));
        let mut snaps: Vec<SnapshotRoot> = index
            .snapshots
            .iter()
            .map(|(name, root)| SnapshotRoot {
                name: name.clone(),
                root: *root,
            })
            .collect();
        snaps.sort_by(|a, b| a.name.cmp(&b.name));
        let checkpoints = index
            .checkpoints
            .iter()
            .map(|c| SnapshotCheckpoint {
                root: c.root,
                inode_count: c.inode_count,
                dentry_count: c.dentry_count,
                digest: c.digest.to_vec(),
            })
            .collect();
        Snapshot {
            root: index.root,
            next_inode_id: index.next_inode_id,
            inodes,
            dentries,
            snapshots: snaps,
            checkpoints,
        }
    }

    fn digest(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        *blake3::hash(&bytes).as_bytes()
    }

    fn into_index(self) -> Index {
        let mut index = Index {
            root: self.root,
            next_inode_id: self.next_inode_id,
            ..Index::default()
        };
        for si in self.inodes {
            let kind = InodeType::from_code(si.kind).unwrap_or(InodeType::File);
            let mut inode = Inode::new(
                si.id,
                si.generation,
                kind,
                si.mode,
                si.uid,
                si.gid,
                si.nlink,
                si.size,
                Timespec::new(si.atime_secs, si.atime_nanos),
                Timespec::new(si.mtime_secs, si.mtime_nanos),
                Timespec::new(si.ctime_secs, si.ctime_nanos),
                si.latest_record_offset,
            );
            inode.latest_record_offset = si.latest_record_offset;
            inode.symlink_target = si.symlink_target;
            inode.xattrs = si.xattrs.into_iter().collect();
            inode.versions = crate::inode::VersionHistory::from_vec(
                si.versions
                    .into_iter()
                    .map(|v| crate::inode::InodeVersion {
                        version: v.version,
                        record_offset: v.record_offset,
                        kind: InodeType::from_code(v.kind).unwrap_or(InodeType::File),
                        mode: v.mode,
                        uid: v.uid,
                        gid: v.gid,
                        nlink: v.nlink,
                        size: v.size,
                    })
                    .collect(),
            );
            let mut extents = crate::extent::ExtentMap::default();
            for e in si.extents {
                match e.data_offset {
                    Some(data_offset) => extents.write(e.start, e.len, data_offset),
                    None => extents.zero(e.start, e.len),
                }
            }
            inode.extents = extents;
            index.inodes = index.inodes.insert(si.id, Arc::new(inode));
            if kind == InodeType::Directory {
                index.children = index.children.insert(si.id, PMap::new());
            }
        }
        for d in self.dentries {
            let map = index
                .children
                .get(&d.parent)
                .cloned()
                .unwrap_or_default()
                .insert(d.name, d.child);
            index.children = index.children.insert(d.parent, map);
        }
        index.snapshots = PMap::from_pairs(self.snapshots.into_iter().map(|s| (s.name, s.root)));
        index.checkpoints = Arc::new(
            self.checkpoints
                .into_iter()
                .map(|c| {
                    let mut digest = [0u8; 32];
                    let n = c.digest.len().min(32);
                    digest[..n].copy_from_slice(&c.digest[..n]);
                    Checkpoint {
                        root: c.root,
                        inode_count: c.inode_count,
                        dentry_count: c.dentry_count,
                        digest,
                    }
                })
                .collect(),
        );
        index
    }
}
