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

/// The physical layout of the inode-id spine (Phase 58).
///
/// The live, publication-sensitive writer spine is **always**
/// [`InodeStore::Persistent`] (the Phase-27 path-copying treap). A **sealed
/// historical** index — a committed root that will never be mutated and is only
/// ever read — may instead use [`InodeStore::Sealed`], a direct-ordinal array
/// keyed by inode id. Inode ids are allocated densely and monotonically, so
/// `slots[id]` is a near-`O(1)` lookup that is far more compact than one treap
/// node per inode — and it is legal precisely because the role is immutable.
///
/// The two forms answer identical `get`/`ids`/`readdir` and compare **equal by
/// content** ([`PartialEq`] is structural, not representational), so nothing
/// downstream can observe the difference except memory and speed. A sealed store
/// that is ever mutated (it never is on the writer spine) **thaws** to the
/// persistent spine rather than misbehaving.
#[derive(Clone)]
enum InodeStore {
    /// The live writer spine: an immutable, path-copying treap.
    Persistent(PMap<u64, Arc<Inode>>),
    /// The sealed historical spine: a direct-ordinal array indexed by inode id.
    Sealed(Arc<SealedInodes>),
}

/// A direct-ordinal array of inodes: `slots[id]` is the inode with that id, or
/// `None` for an absent id. `slots.len()` is `max_id + 1`; because ids start at
/// [`ROOT_INODE`] and increase by one per allocation, the array has at most a
/// handful of holes even in a long history (and none in practice).
struct SealedInodes {
    slots: Box<[Option<Arc<Inode>>]>,
    len: usize,
}

impl InodeStore {
    fn new() -> InodeStore {
        InodeStore::Persistent(PMap::new())
    }

    #[inline]
    fn get(&self, id: &u64) -> Option<&Arc<Inode>> {
        match self {
            InodeStore::Persistent(m) => m.get(id),
            InodeStore::Sealed(s) => {
                let i = usize::try_from(*id).ok()?;
                s.slots.get(i).and_then(|slot| slot.as_ref())
            }
        }
    }

    #[inline]
    fn contains_key(&self, id: &u64) -> bool {
        self.get(id).is_some()
    }

    #[inline]
    fn len(&self) -> usize {
        match self {
            InodeStore::Persistent(m) => m.len(),
            InodeStore::Sealed(s) => s.len,
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every present id, ascending.
    fn ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.iter().map(|(id, _)| id)
    }

    /// Every `(id, inode)` pair, ascending by id.
    fn iter(&self) -> Box<dyn Iterator<Item = (u64, &Arc<Inode>)> + '_> {
        match self {
            InodeStore::Persistent(m) => Box::new(m.iter().map(|(k, v)| (*k, v))),
            InodeStore::Sealed(s) => Box::new(
                s.slots
                    .iter()
                    .enumerate()
                    .filter_map(|(i, slot)| slot.as_ref().map(|v| (i as u64, v))),
            ),
        }
    }

    /// Return a new store with `id` bound to `value`.
    ///
    /// On the persistent spine this is a path copy (`O(log n)`). A sealed store
    /// is produced only for an immutable historical root and is never mutated on
    /// the writer spine; if it ever is, it **thaws** to the persistent spine
    /// (correct, if not compact) rather than silently misbehaving.
    fn insert(&self, id: u64, value: Arc<Inode>) -> InodeStore {
        match self {
            InodeStore::Persistent(m) => InodeStore::Persistent(m.insert(id, value)),
            InodeStore::Sealed(s) => {
                let m = PMap::from_pairs(
                    s.slots
                        .iter()
                        .enumerate()
                        .filter_map(|(i, v)| v.as_ref().map(|v| (i as u64, v.clone()))),
                );
                InodeStore::Persistent(m.insert(id, value))
            }
        }
    }

    /// Estimated structural bytes of the spine alone (no inode payloads, no
    /// allocator slop), matching the [`PMap::mem_bytes`] convention.
    fn mem_bytes(&self) -> usize {
        match self {
            InodeStore::Persistent(m) => m.mem_bytes(),
            InodeStore::Sealed(s) => {
                std::mem::size_of::<Arc<SealedInodes>>()
                    + std::mem::size_of::<SealedInodes>()
                    + s.slots.len() * std::mem::size_of::<Option<Arc<Inode>>>()
            }
        }
    }

    fn layout_name(&self) -> &'static str {
        match self {
            InodeStore::Persistent(_) => "persistent-treap",
            InodeStore::Sealed(_) => "sealed-dense-ordinal",
        }
    }
}

/// Structural (content) equality: a sealed dense-ordinal spine equals a
/// persistent treap spine with the same entries, so the representation is never
/// observable through `==`.
impl PartialEq for InodeStore {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        self.iter().eq(other.iter())
    }
}

impl Eq for InodeStore {}

impl std::fmt::Debug for InodeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately non-recursive: a sealed store may hold millions of ids.
        f.debug_struct("InodeStore")
            .field("layout", &self.layout_name())
            .field("len", &self.len())
            .finish()
    }
}

/// The derived namespace index.
///
/// # Structural sharing (Phase 19)
///
/// The index is published to readers as an immutable snapshot
/// ([`crate::namespace::ReadState`]). To keep publication cheap it is stored so
/// that a snapshot can share almost all of its memory with the live writer:
///
/// * `inodes` is an [`InodeStore`] — a [`PMap`] from id to `Arc<Inode>` on the
///   live writer spine (so a commit copies only the `O(log n)` spine nodes on the
///   root-to-key path) or, for a **sealed historical** index, a dense
///   direct-ordinal array (Phase 58). Every other inode (and the inode *nodes*
///   themselves — their extent maps, version history and xattrs) is shared with
///   the prior snapshot in both forms.
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
    inodes: InodeStore,
    children: PMap<u64, PMap<Vec<u8>, u64>>,
    next_inode_id: u64,
    snapshots: PMap<Vec<u8>, u64>,
    checkpoints: Arc<Vec<Checkpoint>>,
}

impl Default for Index {
    fn default() -> Self {
        Index {
            root: 0,
            inodes: InodeStore::new(),
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

    /// Every live inode id, ascending (used by physical accounting and
    /// manifestation).
    pub fn inode_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.inodes.ids()
    }

    /// The physical layout of the inode-id spine (Phase 58):
    /// `"persistent-treap"` for the live/current index, `"sealed-dense-ordinal"`
    /// for a sealed historical index decoded from an accelerator. Purely
    /// observational; the two answer identical reads.
    pub fn inode_layout(&self) -> &'static str {
        self.inodes.layout_name()
    }

    /// Estimated structural bytes of the inode-id spine alone (the treap's nodes
    /// or the sealed array's slots; no inode payloads, no allocator slop). A
    /// sealed historical spine is far smaller; the live spine is never sealed.
    pub fn inode_spine_bytes(&self) -> usize {
        self.inodes.mem_bytes()
    }

    /// Return a copy of this index with the inode-id spine **sealed** as a dense
    /// direct-ordinal array (Phase 58).
    ///
    /// Intended for an immutable historical root: the result answers identical
    /// reads and is more compact. It is never used on the live writer spine — a
    /// sealed spine that is later mutated thaws back to the persistent treap. A
    /// sparse id domain (which a well-formed history never has) is left as the
    /// treap.
    pub fn to_sealed(&self) -> Index {
        let mut out = self.clone();
        out.seal_inodes();
        out
    }

    /// Re-seal the inode-id spine as a direct-ordinal array (Phase 58).
    ///
    /// Called only on a **decoded, immutable historical** index (the `.v2.bin`
    /// accelerator, the legacy JSON accelerator), never on the live writer spine.
    /// If the id domain is not dense — which cannot happen for a well-formed
    /// history but could for a corrupt (yet internally consistent) payload — the
    /// spine is left as the persistent treap, so a declared sparse domain can
    /// neither waste memory nor misparse. The public read surface is unchanged.
    pub(crate) fn seal_inodes(&mut self) {
        let count = self.inodes.len();
        if count == 0 {
            return;
        }
        let max_id = self.inodes.ids().max().unwrap_or(0);
        // Dense iff the id span is close to the live count. A sparse span would
        // make the array mostly holes (and could be large), so keep the treap.
        if max_id > (count as u64).saturating_mul(2) + 64 {
            return;
        }
        let n = (max_id + 1) as usize;
        let mut slots: Vec<Option<Arc<Inode>>> = vec![None; n];
        for (id, inode) in self.inodes.iter() {
            slots[id as usize] = Some(inode.clone());
        }
        self.inodes = InodeStore::Sealed(Arc::new(SealedInodes {
            slots: slots.into_boxed_slice(),
            len: count,
        }));
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

    // -- packed binary accelerator payload (Phase 43) ----------------------

    /// Encode the index to the immutable, **packed binary** accelerator payload.
    ///
    /// This is the JSON-free counterpart of [`Index::encode_snapshot`]. It packs
    /// the identical logical content — the inode, dentry, named-snapshot, and
    /// checkpoint tables — into one little-endian document with an explicit table
    /// of contents (offset/length per table), so a persisted historical
    /// accelerator can be decoded without parsing a JSON envelope or materialising
    /// an intermediate tree of `serde` values.
    ///
    /// The representation is **derived**: the authoritative log remains the only
    /// source of truth. A consumer must still bind the payload to `(uuid, root)`
    /// and verify a digest over the whole container; [`Index::decode_packed`] only
    /// checks the payload's own internal consistency.
    pub fn encode_packed(&self) -> Vec<u8> {
        packed::encode(self)
    }

    /// Decode a packed binary accelerator payload produced by
    /// [`Index::encode_packed`].
    ///
    /// Every offset, length, and count is validated with checked arithmetic before
    /// any byte is trusted, and a payload that is torn, truncated, or internally
    /// inconsistent is rejected with [`OrfsError::Corrupt`] / [`OrfsError::Overflow`]
    /// rather than partially applied. The returned index is still only valid for a
    /// matching committed root; callers confirm that against the log.
    ///
    /// The decoded index is a **sealed** one ([`Index::inode_layout`] returns
    /// `"sealed-dense-ordinal"`): the payload names an immutable historical root,
    /// so its inode-id spine is stored as a direct-ordinal array rather than a
    /// treap. That is purely a representation choice — lookups, ranges, readdir,
    /// the canonical digest, and structural equality are unchanged.
    pub fn decode_packed(bytes: &[u8]) -> Result<Index> {
        packed::decode(bytes)
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
        let mut inode_ids: Vec<u64> = index.inodes.ids().collect();
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

// ---------------------------------------------------------------------------
// Packed binary accelerator payload (Phase 43)
//
// A compact, JSON-free encoding of an [`Index`]. Layout:
//
// ```text
//   magic          u32    "ORIX"
//   version        u32    1
//   root           u64
//   next_inode_id  u64
//   inode_count    u32    records in table 0
//   dentry_count   u32    records in table 1
//   snapshot_count u32    records in table 2
//   checkpoint_count u32  records in table 3
//   parent_count   u32    records in table 4
//   toc            [5]    (offset:u64, len:u64) per table, offsets relative to the
//                         payload start; tables are contiguous and cover the tail
//   tables         ...    inode, dentry, named-snapshot, checkpoint, directory-key
// ```
//
// The table of contents makes each table **directly addressable**: a reader can
// locate the dentry table without decoding the inode table. All little-endian.
//
// Table 4 lists every key of the index's directory map, *including directories
// with no visible children*. Without it the decode would invent an empty entry
// for every directory inode, which is not the exact structure a log replay
// builds; with it, `decode_packed(encode_packed(i)) == i` exactly.
mod packed {
    use super::*;

    const MAGIC: u32 = 0x4F52_4958; // "ORIX"
    const VERSION: u32 = 1;
    const N_TABLES: usize = 5;
    /// Fixed prefix: magic/version/root/next_inode_id/5 counts/5 toc entries.
    const PREFIX: usize = 4 + 4 + 8 + 8 + 4 * 5 + N_TABLES * 16;

    fn corrupt(what: &str) -> OrfsError {
        OrfsError::Corrupt(format!("packed index: {what}"))
    }

    fn rd_u32(b: &[u8], off: usize) -> Result<u32> {
        let end = off.checked_add(4).ok_or(OrfsError::Overflow {
            what: "packed index offset",
        })?;
        let s = b.get(off..end).ok_or_else(|| corrupt("truncated u32"))?;
        Ok(u32::from_le_bytes(s.try_into().expect("4 bytes")))
    }

    fn rd_u64(b: &[u8], off: usize) -> Result<u64> {
        let end = off.checked_add(8).ok_or(OrfsError::Overflow {
            what: "packed index offset",
        })?;
        let s = b.get(off..end).ok_or_else(|| corrupt("truncated u64"))?;
        Ok(u64::from_le_bytes(s.try_into().expect("8 bytes")))
    }

    /// A bounded, checked little-endian cursor over one table slice.
    struct Reader<'a> {
        b: &'a [u8],
        pos: usize,
    }

    impl<'a> Reader<'a> {
        fn new(b: &'a [u8]) -> Reader<'a> {
            Reader { b, pos: 0 }
        }

        fn remaining(&self) -> usize {
            self.b.len() - self.pos
        }

        fn take(&mut self, n: usize) -> Result<&'a [u8]> {
            let end = self.pos.checked_add(n).ok_or(OrfsError::Overflow {
                what: "packed index length",
            })?;
            let s = self
                .b
                .get(self.pos..end)
                .ok_or_else(|| corrupt("table runs past its end"))?;
            self.pos = end;
            Ok(s)
        }

        fn u8(&mut self) -> Result<u8> {
            Ok(self.take(1)?[0])
        }

        fn u32(&mut self) -> Result<u32> {
            Ok(u32::from_le_bytes(
                self.take(4)?.try_into().expect("4 bytes"),
            ))
        }

        fn u64(&mut self) -> Result<u64> {
            Ok(u64::from_le_bytes(
                self.take(8)?.try_into().expect("8 bytes"),
            ))
        }

        fn i64(&mut self) -> Result<i64> {
            Ok(i64::from_le_bytes(
                self.take(8)?.try_into().expect("8 bytes"),
            ))
        }

        /// A length-prefixed byte string. The length is bounded by the bytes
        /// that physically remain, so a hostile length can never over-read or
        /// trigger a large speculative allocation here.
        fn bytes(&mut self) -> Result<Vec<u8>> {
            let n = self.u32()? as usize;
            if n > self.remaining() {
                return Err(corrupt("declared byte-string length exceeds the table"));
            }
            Ok(self.take(n)?.to_vec())
        }

        fn done(&self) -> Result<()> {
            if self.remaining() != 0 {
                return Err(corrupt("table has trailing bytes"));
            }
            Ok(())
        }
    }

    fn p_u32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn p_u64(v: &mut Vec<u8>, x: u64) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn p_i64(v: &mut Vec<u8>, x: i64) {
        v.extend_from_slice(&x.to_le_bytes());
    }
    fn p_bytes(v: &mut Vec<u8>, b: &[u8]) {
        p_u32(v, b.len() as u32);
        v.extend_from_slice(b);
    }

    fn encode_inodes(inodes: &[SnapshotInode]) -> Vec<u8> {
        let mut v = Vec::new();
        for i in inodes {
            p_u64(&mut v, i.id);
            p_u64(&mut v, i.generation);
            v.push(i.kind);
            p_u32(&mut v, i.mode);
            p_u32(&mut v, i.uid);
            p_u32(&mut v, i.gid);
            p_u32(&mut v, i.nlink);
            p_u64(&mut v, i.size);
            p_i64(&mut v, i.atime_secs);
            p_u32(&mut v, i.atime_nanos);
            p_i64(&mut v, i.mtime_secs);
            p_u32(&mut v, i.mtime_nanos);
            p_i64(&mut v, i.ctime_secs);
            p_u32(&mut v, i.ctime_nanos);
            p_u64(&mut v, i.latest_record_offset);
            match &i.symlink_target {
                Some(t) => {
                    v.push(1);
                    p_bytes(&mut v, t);
                }
                None => v.push(0),
            }
            p_u32(&mut v, i.versions.len() as u32);
            for ver in &i.versions {
                p_u64(&mut v, ver.version);
                p_u64(&mut v, ver.record_offset);
                v.push(ver.kind);
                p_u32(&mut v, ver.mode);
                p_u32(&mut v, ver.uid);
                p_u32(&mut v, ver.gid);
                p_u32(&mut v, ver.nlink);
                p_u64(&mut v, ver.size);
            }
            p_u32(&mut v, i.xattrs.len() as u32);
            for (k, val) in &i.xattrs {
                p_bytes(&mut v, k);
                p_bytes(&mut v, val);
            }
            p_u32(&mut v, i.extents.len() as u32);
            for e in &i.extents {
                p_u64(&mut v, e.start);
                p_u64(&mut v, e.len);
                match e.data_offset {
                    Some(off) => {
                        v.push(1);
                        p_u64(&mut v, off);
                    }
                    None => v.push(0),
                }
            }
        }
        v
    }

    fn decode_inodes(table: &[u8], count: usize) -> Result<Vec<SnapshotInode>> {
        let mut r = Reader::new(table);
        let mut out = Vec::new();
        for _ in 0..count {
            let id = r.u64()?;
            let generation = r.u64()?;
            let kind = r.u8()?;
            let mode = r.u32()?;
            let uid = r.u32()?;
            let gid = r.u32()?;
            let nlink = r.u32()?;
            let size = r.u64()?;
            let atime_secs = r.i64()?;
            let atime_nanos = r.u32()?;
            let mtime_secs = r.i64()?;
            let mtime_nanos = r.u32()?;
            let ctime_secs = r.i64()?;
            let ctime_nanos = r.u32()?;
            let latest_record_offset = r.u64()?;
            let symlink_target = match r.u8()? {
                0 => None,
                1 => Some(r.bytes()?),
                _ => return Err(corrupt("invalid symlink presence flag")),
            };
            let n_versions = r.u32()? as usize;
            if n_versions > r.remaining() / 41 {
                return Err(corrupt("version count exceeds the table"));
            }
            let mut versions = Vec::with_capacity(n_versions);
            for _ in 0..n_versions {
                versions.push(SnapshotVersion {
                    version: r.u64()?,
                    record_offset: r.u64()?,
                    kind: r.u8()?,
                    mode: r.u32()?,
                    uid: r.u32()?,
                    gid: r.u32()?,
                    nlink: r.u32()?,
                    size: r.u64()?,
                });
            }
            let n_xattrs = r.u32()? as usize;
            if n_xattrs > r.remaining() / 8 {
                return Err(corrupt("xattr count exceeds the table"));
            }
            let mut xattrs = Vec::with_capacity(n_xattrs);
            for _ in 0..n_xattrs {
                let k = r.bytes()?;
                let val = r.bytes()?;
                xattrs.push((k, val));
            }
            let n_extents = r.u32()? as usize;
            if n_extents > r.remaining() / 17 {
                return Err(corrupt("extent count exceeds the table"));
            }
            let mut extents = Vec::with_capacity(n_extents);
            for _ in 0..n_extents {
                let start = r.u64()?;
                let len = r.u64()?;
                let data_offset = match r.u8()? {
                    0 => None,
                    1 => Some(r.u64()?),
                    _ => return Err(corrupt("invalid extent kind flag")),
                };
                extents.push(SnapshotExtent {
                    start,
                    len,
                    data_offset,
                });
            }
            out.push(SnapshotInode {
                id,
                generation,
                kind,
                mode,
                uid,
                gid,
                nlink,
                size,
                atime_secs,
                atime_nanos,
                mtime_secs,
                mtime_nanos,
                ctime_secs,
                ctime_nanos,
                symlink_target,
                latest_record_offset,
                versions,
                xattrs,
                extents,
            });
        }
        r.done()?;
        Ok(out)
    }

    fn encode_dentries(dentries: &[SnapshotDentry]) -> Vec<u8> {
        let mut v = Vec::new();
        for d in dentries {
            p_u64(&mut v, d.parent);
            p_bytes(&mut v, &d.name);
            p_u64(&mut v, d.child);
        }
        v
    }

    fn decode_dentries(table: &[u8], count: usize) -> Result<Vec<SnapshotDentry>> {
        let mut r = Reader::new(table);
        let mut out = Vec::new();
        for _ in 0..count {
            let parent = r.u64()?;
            let name = r.bytes()?;
            let child = r.u64()?;
            out.push(SnapshotDentry {
                parent,
                name,
                child,
            });
        }
        r.done()?;
        Ok(out)
    }

    fn encode_snapshots(snaps: &[SnapshotRoot]) -> Vec<u8> {
        let mut v = Vec::new();
        for s in snaps {
            p_bytes(&mut v, &s.name);
            p_u64(&mut v, s.root);
        }
        v
    }

    fn decode_snapshots(table: &[u8], count: usize) -> Result<Vec<SnapshotRoot>> {
        let mut r = Reader::new(table);
        let mut out = Vec::new();
        for _ in 0..count {
            let name = r.bytes()?;
            let root = r.u64()?;
            out.push(SnapshotRoot { name, root });
        }
        r.done()?;
        Ok(out)
    }

    fn encode_checkpoints(checkpoints: &[SnapshotCheckpoint]) -> Vec<u8> {
        let mut v = Vec::new();
        for c in checkpoints {
            p_u64(&mut v, c.root);
            p_u64(&mut v, c.inode_count);
            p_u64(&mut v, c.dentry_count);
            p_bytes(&mut v, &c.digest);
        }
        v
    }

    fn decode_checkpoints(table: &[u8], count: usize) -> Result<Vec<SnapshotCheckpoint>> {
        let mut r = Reader::new(table);
        let mut out = Vec::new();
        for _ in 0..count {
            let root = r.u64()?;
            let inode_count = r.u64()?;
            let dentry_count = r.u64()?;
            let digest = r.bytes()?;
            out.push(SnapshotCheckpoint {
                root,
                inode_count,
                dentry_count,
                digest,
            });
        }
        r.done()?;
        Ok(out)
    }

    /// Encode every key of the index's directory map (sorted ascending), so the
    /// exact set of directory entries survives a round trip.
    fn encode_parents(index: &Index) -> Vec<u8> {
        let mut parents: Vec<u64> = index.children.iter().map(|(p, _)| *p).collect();
        parents.sort_unstable();
        let mut v = Vec::with_capacity(parents.len() * 8);
        for p in parents {
            p_u64(&mut v, p);
        }
        v
    }

    fn decode_parents(table: &[u8], count: usize) -> Result<Vec<u64>> {
        let mut r = Reader::new(table);
        let mut out = Vec::with_capacity(count);
        let mut last = None;
        for _ in 0..count {
            let p = r.u64()?;
            if let Some(prev) = last {
                if p <= prev {
                    return Err(corrupt("directory keys are not strictly ascending"));
                }
            }
            last = Some(p);
            out.push(p);
        }
        r.done()?;
        Ok(out)
    }

    pub(super) fn encode(index: &Index) -> Vec<u8> {
        let snap = Snapshot::from_index(index);
        let tables: [Vec<u8>; N_TABLES] = [
            encode_inodes(&snap.inodes),
            encode_dentries(&snap.dentries),
            encode_snapshots(&snap.snapshots),
            encode_checkpoints(&snap.checkpoints),
            encode_parents(index),
        ];
        let total: usize = tables.iter().map(|t| t.len()).sum();
        let mut out = Vec::with_capacity(PREFIX + total);
        p_u32(&mut out, MAGIC);
        p_u32(&mut out, VERSION);
        p_u64(&mut out, index.root());
        p_u64(&mut out, index.next_inode_id());
        p_u32(&mut out, snap.inodes.len() as u32);
        p_u32(&mut out, snap.dentries.len() as u32);
        p_u32(&mut out, snap.snapshots.len() as u32);
        p_u32(&mut out, snap.checkpoints.len() as u32);
        p_u32(&mut out, tables[4].len() as u32 / 8);
        let mut off = PREFIX as u64;
        for t in &tables {
            p_u64(&mut out, off);
            p_u64(&mut out, t.len() as u64);
            off += t.len() as u64;
        }
        debug_assert_eq!(out.len(), PREFIX);
        for t in &tables {
            out.extend_from_slice(t);
        }
        out
    }

    pub(super) fn decode(b: &[u8]) -> Result<Index> {
        if b.len() < PREFIX {
            return Err(corrupt("payload is shorter than the fixed prefix"));
        }
        if rd_u32(b, 0)? != MAGIC {
            return Err(corrupt("bad magic"));
        }
        let version = rd_u32(b, 4)?;
        if version != VERSION {
            return Err(OrfsError::Compatibility(format!(
                "packed index version {version}"
            )));
        }
        let root = rd_u64(b, 8)?;
        let next_inode_id = rd_u64(b, 16)?;
        let counts = [
            rd_u32(b, 24)? as usize,
            rd_u32(b, 28)? as usize,
            rd_u32(b, 32)? as usize,
            rd_u32(b, 36)? as usize,
            rd_u32(b, 40)? as usize,
        ];
        // Validate the table of contents: contiguity and coverage of the tail.
        let mut spans = [(0usize, 0usize); N_TABLES];
        let mut expected = PREFIX;
        for (i, span) in spans.iter_mut().enumerate() {
            let off = rd_u64(b, 44 + i * 16)?;
            let len = rd_u64(b, 52 + i * 16)?;
            let off = usize::try_from(off).map_err(|_| OrfsError::Overflow {
                what: "packed index offset",
            })?;
            let len = usize::try_from(len).map_err(|_| OrfsError::Overflow {
                what: "packed index length",
            })?;
            if off != expected {
                return Err(corrupt("table of contents is not contiguous"));
            }
            let end = off.checked_add(len).ok_or(OrfsError::Overflow {
                what: "packed index table end",
            })?;
            if end > b.len() {
                return Err(corrupt("table runs past the payload end"));
            }
            *span = (off, len);
            expected = end;
        }
        if expected != b.len() {
            return Err(corrupt("payload has trailing bytes after the tables"));
        }
        let table = |i: usize| -> &[u8] { &b[spans[i].0..spans[i].0 + spans[i].1] };
        let inodes = decode_inodes(table(0), counts[0])?;
        let dentries = decode_dentries(table(1), counts[1])?;
        let snapshots = decode_snapshots(table(2), counts[2])?;
        let checkpoints = decode_checkpoints(table(3), counts[3])?;
        if counts[4] > table(4).len() / 8 {
            return Err(corrupt("directory-key count exceeds the table"));
        }
        let parents = decode_parents(table(4), counts[4])?;
        let snap = Snapshot {
            root,
            next_inode_id,
            inodes,
            dentries,
            snapshots,
            checkpoints,
        };
        let mut index = snap.into_index();
        // Rebuild the directory map with exactly the encoded key set (so an
        // unlisted directory carries no entry, matching a log replay exactly).
        index.children = PMap::from_pairs(parents.iter().map(|p| {
            let map = index.children.get(p).cloned().unwrap_or_default();
            (*p, map)
        }));
        // A packed payload names an immutable historical root, so seal the
        // inode-id spine as a dense direct-ordinal array (Phase 58).
        index.seal_inodes();
        Ok(index)
    }
}
