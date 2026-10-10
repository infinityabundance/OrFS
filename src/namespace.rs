//! The transport-neutral namespace engine (research §6, §7, §13, §14).
//!
//! [`Namespace`] is the filesystem core: it turns POSIX-like operations into
//! authoritative transactions (appended through the single commit sequencer) and
//! answers reads from the derived [`Index`]. It is deliberately independent of
//! any transport: the FUSE layer (Phase 4) calls it through the [`OrfsCore`]
//! trait.
//!
//! Every mutation is a new transaction — an ordered list of immutable records
//! bracketed by `TX_BEGIN … TX_COMMIT`. Nothing is ever edited in place (Law I):
//!
//! * a write appends a `DATA_EXTENT` whose bytes are immutable;
//! * an unlink appends a `DENTRY_REMOVE` tombstone;
//! * a truncate appends `FILE_RESIZE`;
//! * a rename appends `DENTRY_RENAME` (identity preserved).
//!
//! After a commit, the engine extends its live index by replaying exactly the
//! records it just committed ([`Index::apply_range`]). Because the same
//! [`Index::apply_record`] function is used for the live extension and for a
//! from-scratch rebuild, the live index is always equal to a rebuild over the
//! log — and the log always wins.

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::commit::{CommitOutcome, CommitSequencer, DurabilityMode};
use crate::directory::{
    validate_name, DentryAddPayload, DentryRemovePayload, DentryRenamePayload, RenameFlags,
    DENTRY_ADD_MAGIC, DENTRY_REMOVE_MAGIC, HARDLINK_ADD_MAGIC, HARDLINK_REMOVE_MAGIC,
};
use crate::error::{OrfsError, Result};
use crate::extent::{
    DataExtentPayload, DataZeroRangePayload, ExtentKind, FileResizePayload, ReadPiece,
};
use crate::index::{Index, ROOT_INODE};
use crate::inode::{
    validate_xattr_name, Inode, InodeCreatePayload, InodeMetadataPayload, InodeSetattrPayload,
    InodeStat, InodeType, PermissionChangePayload, SymlinkCreatePayload, Timespec,
    XattrRemovePayload, XattrSetPayload,
};
use crate::log::OpenMode;
use crate::record::{RecordType, FOOTER_LEN, HEADER_LEN};
use crate::transaction::{Transaction, TransactionBuilder, TX_BEGIN_PAYLOAD_LEN};
use crate::volume::Volume;

/// Encoded length of a `TX_BEGIN` record (`header + payload + footer`).
pub const TX_BEGIN_RECORD_LEN: u64 = (HEADER_LEN + TX_BEGIN_PAYLOAD_LEN + FOOTER_LEN) as u64;

// ---------------------------------------------------------------------------
// SNAPSHOT_ROOT / INDEX_CHECKPOINT payloads
// ---------------------------------------------------------------------------

/// `SNAPSHOT_ROOT` magic; LE bytes spell `SNR1`.
pub const SNAPSHOT_ROOT_MAGIC: u32 = 0x3152_4E53;
/// `INDEX_CHECKPOINT` magic; LE bytes spell `ICP1`.
pub const INDEX_CHECKPOINT_MAGIC: u32 = 0x3150_4349;
/// Fixed length of an `INDEX_CHECKPOINT` payload.
pub const INDEX_CHECKPOINT_PAYLOAD_LEN: usize = 64;

/// Payload of `SNAPSHOT_ROOT`: publish a named committed root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRootPayload {
    pub root: u64,
    pub name: Vec<u8>,
}

impl SnapshotRootPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(16 + self.name.len() + 4);
        b.extend_from_slice(&SNAPSHOT_ROOT_MAGIC.to_le_bytes());
        b.extend_from_slice(&self.root.to_le_bytes());
        b.extend_from_slice(&(self.name.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.name);
        let check = crc32c::crc32c(&b);
        b.extend_from_slice(&check.to_le_bytes());
        b
    }

    pub fn decode(buf: &[u8]) -> Result<SnapshotRootPayload> {
        if buf.len() < 20 || crate::record::get_u32(buf, 0) != SNAPSHOT_ROOT_MAGIC {
            return Err(OrfsError::Corrupt("SNAPSHOT_ROOT payload bad magic".into()));
        }
        let n = buf.len();
        if crate::record::get_u32(buf, n - 4) != crc32c::crc32c(&buf[..n - 4]) {
            return Err(OrfsError::Corrupt(
                "SNAPSHOT_ROOT payload checksum mismatch".into(),
            ));
        }
        let name_len = crate::record::get_u32(buf, 12) as usize;
        let start: usize = 16;
        let end = start.checked_add(name_len).ok_or(OrfsError::Overflow {
            what: "snapshot name",
        })?;
        if end + 4 != n {
            return Err(OrfsError::Corrupt(
                "SNAPSHOT_ROOT payload length disagreement".into(),
            ));
        }
        Ok(SnapshotRootPayload {
            root: crate::record::get_u64(buf, 4),
            name: buf[start..end].to_vec(),
        })
    }
}

/// Payload of `INDEX_CHECKPOINT`: an accelerator/verification checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexCheckpointPayload {
    pub root: u64,
    pub inode_count: u64,
    pub dentry_count: u64,
    pub digest: [u8; 32],
}

impl IndexCheckpointPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; INDEX_CHECKPOINT_PAYLOAD_LEN];
        crate::record::put_u32(&mut b, 0, INDEX_CHECKPOINT_MAGIC);
        crate::record::put_u64(&mut b, 4, self.root);
        crate::record::put_u64(&mut b, 12, self.inode_count);
        crate::record::put_u64(&mut b, 20, self.dentry_count);
        b[28..60].copy_from_slice(&self.digest);
        let check = crc32c::crc32c(&b[..60]);
        crate::record::put_u32(&mut b, 60, check);
        b
    }

    pub fn decode(buf: &[u8]) -> Result<IndexCheckpointPayload> {
        if buf.len() != INDEX_CHECKPOINT_PAYLOAD_LEN
            || crate::record::get_u32(buf, 0) != INDEX_CHECKPOINT_MAGIC
        {
            return Err(OrfsError::Corrupt(
                "INDEX_CHECKPOINT payload bad magic or length".into(),
            ));
        }
        if crate::record::get_u32(buf, 60) != crc32c::crc32c(&buf[..60]) {
            return Err(OrfsError::Corrupt(
                "INDEX_CHECKPOINT payload checksum mismatch".into(),
            ));
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&buf[28..60]);
        Ok(IndexCheckpointPayload {
            root: crate::record::get_u64(buf, 4),
            inode_count: crate::record::get_u64(buf, 12),
            dentry_count: crate::record::get_u64(buf, 20),
            digest,
        })
    }
}

// ---------------------------------------------------------------------------
// Attribute sets and rename modes
// ---------------------------------------------------------------------------

/// A field-masked attribute change for [`Namespace::setattr`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub atime: Option<Timespec>,
    pub mtime: Option<Timespec>,
    pub size: Option<u64>,
}

impl SetAttr {
    /// Whether no field is set.
    pub fn is_empty(&self) -> bool {
        self.mode.is_none()
            && self.uid.is_none()
            && self.gid.is_none()
            && self.atime.is_none()
            && self.mtime.is_none()
            && self.size.is_none()
    }
}

/// The `rename(2)` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameMode {
    /// Ordinary rename; replaces an existing destination.
    Ordinary,
    /// `RENAME_NOREPLACE`: fail if the destination exists.
    NoReplace,
    /// `RENAME_EXCHANGE`: atomically swap the two names (both must exist).
    Exchange,
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// The transport-neutral filesystem core.
pub struct Namespace {
    volume: Volume,
    index: Index,
    durability: DurabilityMode,
}

impl Namespace {
    /// Create a new volume and open it as a namespace.
    pub fn init(dir: &Path, segment_size: u64, durability: DurabilityMode) -> Result<Namespace> {
        let volume = Volume::init(dir, segment_size)?;
        Namespace::from_volume(volume, durability)
    }

    /// Deterministic variant of [`Namespace::init`] for tests and evidence.
    pub fn init_with_uuid(
        dir: &Path,
        segment_size: u64,
        uuid: [u8; 16],
        created_at_unix_secs: u64,
        durability: DurabilityMode,
    ) -> Result<Namespace> {
        let volume = Volume::init_with_uuid(dir, segment_size, uuid, created_at_unix_secs)?;
        Namespace::from_volume(volume, durability)
    }

    /// Open an existing volume as a namespace, rebuilding the index from the log.
    pub fn open(dir: &Path, mode: OpenMode, durability: DurabilityMode) -> Result<Namespace> {
        let volume = Volume::open(dir, mode)?;
        Namespace::from_volume(volume, durability)
    }

    fn from_volume(volume: Volume, durability: DurabilityMode) -> Result<Namespace> {
        let root = volume.log.committed_end_offset();
        let index = Index::from_log(&volume.log, root)?;
        Ok(Namespace {
            volume,
            index,
            durability,
        })
    }

    /// The underlying volume (for inspection/verification).
    pub fn volume(&self) -> &Volume {
        &self.volume
    }

    /// The live derived index.
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// The live committed root.
    pub fn root(&self) -> u64 {
        self.index.root()
    }

    /// The inode id of the volume root (`1`, matching FUSE's `FUSE_ROOT_ID`).
    pub fn root_inode(&self) -> u64 {
        ROOT_INODE
    }

    /// The durability profile used by this namespace's commits.
    pub fn durability(&self) -> DurabilityMode {
        self.durability
    }

    /// Rebuild the index from scratch by replaying the log.
    pub fn rebuild_index(&self) -> Result<Index> {
        Index::from_log(&self.volume.log, self.volume.log.committed_end_offset())
    }

    /// Whether a from-scratch rebuild equals the live index (log-wins check).
    pub fn index_matches_log(&self) -> Result<bool> {
        Ok(self.rebuild_index()? == self.index)
    }

    /// The path of the persisted accelerator snapshot.
    pub fn snapshot_path(&self) -> PathBuf {
        self.volume.root_dir.join("index").join("namespace.v1.json")
    }

    /// Persist the live index as an accelerator snapshot.
    pub fn persist_index_snapshot(&self) -> Result<()> {
        self.index.save_snapshot(&self.snapshot_path())
    }

    /// Load the persisted accelerator snapshot, validated against the current
    /// committed root. An absent, torn, tampered, or foreign snapshot yields
    /// `Ok(None)`; the log is never overridden by a derived file.
    pub fn load_persisted_index(&self) -> Result<Option<Index>> {
        Index::load_snapshot(
            &self.snapshot_path(),
            self.volume.log.committed_end_offset(),
        )
    }

    // -- views -------------------------------------------------------------

    fn view(&self, root: u64) -> Result<Cow<'_, Index>> {
        if root == self.index.root() {
            Ok(Cow::Borrowed(&self.index))
        } else {
            Ok(Cow::Owned(Index::from_log(&self.volume.log, root)?))
        }
    }

    // -- reads -------------------------------------------------------------

    /// Resolve `(parent, name)` in the view at `root`.
    pub fn lookup(&self, parent: u64, name: &[u8], root: u64) -> Result<u64> {
        let view = self.view(root)?;
        view.inode(parent).ok_or(OrfsError::NotFound)?;
        view.lookup(parent, name).ok_or(OrfsError::NotFound)
    }

    /// The stat projection of an inode in the view at `root`.
    pub fn getattr(&self, inode: u64, root: u64) -> Result<InodeStat> {
        let view = self.view(root)?;
        Ok(view.inode(inode).ok_or(OrfsError::NotFound)?.stat())
    }

    /// Read `length` bytes at `offset` from a file, using its extent map.
    pub fn read_at(&self, inode: u64, root: u64, offset: u64, length: u32) -> Result<Vec<u8>> {
        let view = self.view(root)?;
        let ino = view.inode(inode).ok_or(OrfsError::NotFound)?;
        if ino.is_dir() {
            return Err(OrfsError::IsADirectory);
        }
        if !ino.is_file() {
            return Err(OrfsError::InvalidArgument(
                "read_at on a non-file inode".into(),
            ));
        }
        let pieces = ino.extents.plan_read(offset, length as u64);
        let mut out = Vec::new();
        for piece in pieces {
            match piece {
                ReadPiece::Zero { len } => {
                    out.resize(out.len() + len as usize, 0);
                }
                ReadPiece::Data {
                    logical_offset,
                    len,
                } => {
                    let bytes = self.volume.log.read_range(logical_offset, len)?;
                    out.extend_from_slice(&bytes);
                }
            }
        }
        Ok(out)
    }

    /// The visible children of a directory in the view at `root`, sorted by name.
    pub fn readdir(&self, parent: u64, root: u64) -> Result<Vec<(Vec<u8>, u64)>> {
        let view = self.view(root)?;
        let ino = view.inode(parent).ok_or(OrfsError::NotFound)?;
        if !ino.is_dir() {
            return Err(OrfsError::NotADirectory);
        }
        Ok(view.readdir(parent).unwrap_or_default())
    }

    /// The target of a symbolic link.
    pub fn readlink(&self, inode: u64, root: u64) -> Result<Vec<u8>> {
        let view = self.view(root)?;
        let ino = view.inode(inode).ok_or(OrfsError::NotFound)?;
        match &ino.symlink_target {
            Some(t) => Ok(t.clone()),
            None => Err(OrfsError::InvalidArgument(
                "readlink on a non-symlink inode".into(),
            )),
        }
    }

    /// Read an extended attribute (including the derived `user.orfs.*` set).
    pub fn getxattr(&self, inode: u64, name: &[u8], root: u64) -> Result<Vec<u8>> {
        let view = self.view(root)?;
        let ino = view.inode(inode).ok_or(OrfsError::NotFound)?;
        if let Some(v) = derived_xattr(ino, name) {
            return Ok(v);
        }
        ino.xattrs.get(name).cloned().ok_or(OrfsError::NoData)
    }

    /// List extended attribute names (stored plus the derived `user.orfs.*` set).
    pub fn listxattr(&self, inode: u64, root: u64) -> Result<Vec<Vec<u8>>> {
        let view = self.view(root)?;
        let ino = view.inode(inode).ok_or(OrfsError::NotFound)?;
        let mut names: Vec<Vec<u8>> = ino.xattrs.keys().cloned().collect();
        for d in DERIVED_XATTRS {
            names.push(d.as_bytes().to_vec());
        }
        names.sort();
        names.dedup();
        Ok(names)
    }

    // -- mutations ---------------------------------------------------------

    /// Commit a prepared [`Plan`], then extend the live index by replaying
    /// exactly the records just committed.
    fn commit_plan(&mut self, plan: Plan) -> Result<CommitOutcome> {
        let planned_begin = plan.begin;
        let tx = plan.build()?;
        let outcome = {
            let mut seq = CommitSequencer::new(&mut self.volume, self.durability);
            seq.commit(tx)?
        };
        debug_assert_eq!(outcome.begin_offset, planned_begin);
        self.index
            .apply_range(&self.volume.log, outcome.begin_offset, outcome.root)?;
        Ok(outcome)
    }

    /// Begin a plan for the next transaction.
    fn plan(&self) -> Result<Plan> {
        let id = self.volume.log.next_transaction_id()?;
        let begin = self.volume.log.append_end_offset();
        Plan::new(id, begin)
    }

    fn require_dir(&self, inode: u64) -> Result<()> {
        let ino = self.index.inode(inode).ok_or(OrfsError::NotFound)?;
        if ino.is_dir() {
            Ok(())
        } else {
            Err(OrfsError::NotADirectory)
        }
    }

    fn require_file(&self, inode: u64) -> Result<()> {
        let ino = self.index.inode(inode).ok_or(OrfsError::NotFound)?;
        if ino.is_dir() {
            Err(OrfsError::IsADirectory)
        } else if ino.is_file() {
            Ok(())
        } else {
            Err(OrfsError::InvalidArgument("not a regular file".into()))
        }
    }

    /// Create a file, directory, or symlink and link it into `parent`.
    #[allow(clippy::too_many_arguments)]
    fn create_object(
        &mut self,
        parent: u64,
        name: &[u8],
        kind: InodeType,
        mode: u32,
        uid: u32,
        gid: u32,
        target: Option<Vec<u8>>,
    ) -> Result<u64> {
        validate_name(name)?;
        self.require_dir(parent)?;
        if self.index.lookup(parent, name).is_some() {
            return Err(OrfsError::AlreadyExists);
        }
        let id = self.index.next_inode_id();
        let now = now();
        let mut plan = self.plan()?;
        let prev = plan.prev_for(id, &self.index);
        match kind {
            InodeType::Symlink => {
                let payload = SymlinkCreatePayload {
                    inode_id: id,
                    generation: 1,
                    mode,
                    uid,
                    gid,
                    mtime: now,
                    target: target.unwrap_or_default(),
                }
                .encode();
                plan.add(RecordType::SymlinkCreate, id, prev, payload)?;
            }
            _ => {
                let nlink = if kind == InodeType::Directory { 2 } else { 1 };
                let payload = InodeCreatePayload {
                    inode_id: id,
                    generation: 1,
                    kind,
                    mode,
                    uid,
                    gid,
                    nlink,
                    size: 0,
                    atime: now,
                    mtime: now,
                    ctime: now,
                }
                .encode();
                plan.add(RecordType::InodeCreate, id, prev, payload)?;
            }
        }
        let payload = DentryAddPayload {
            parent,
            child: id,
            name: name.to_vec(),
        }
        .encode(DENTRY_ADD_MAGIC)?;
        let prev = plan.prev_for(id, &self.index);
        plan.add(RecordType::DentryAdd, id, prev, payload)?;
        if kind == InodeType::Directory {
            plan.bump_nlink(parent, 1, &self.index)?;
        }
        self.commit_plan(plan)?;
        Ok(id)
    }

    /// Create and open a regular file.
    pub fn create(
        &mut self,
        parent: u64,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<u64> {
        self.create_object(parent, name, InodeType::File, mode, uid, gid, None)
    }

    /// Create a directory.
    pub fn mkdir(
        &mut self,
        parent: u64,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<u64> {
        self.create_object(parent, name, InodeType::Directory, mode, uid, gid, None)
    }

    /// Create a symbolic link whose target is `target`.
    pub fn symlink(
        &mut self,
        parent: u64,
        name: &[u8],
        target: &[u8],
        uid: u32,
        gid: u32,
    ) -> Result<u64> {
        if target.is_empty() {
            return Err(OrfsError::InvalidArgument("empty symlink target".into()));
        }
        self.create_object(
            parent,
            name,
            InodeType::Symlink,
            0o777,
            uid,
            gid,
            Some(target.to_vec()),
        )
    }

    /// Append a new immutable data extent for a write.
    pub fn write_at(&mut self, inode: u64, offset: u64, data: &[u8]) -> Result<u32> {
        self.require_file(inode)?;
        if data.is_empty() {
            return Ok(0);
        }
        let payload = DataExtentPayload {
            offset,
            data: data.to_vec(),
        }
        .encode();
        let mut plan = self.plan()?;
        let prev = plan.prev_for(inode, &self.index);
        plan.add(RecordType::DataExtent, inode, prev, payload)?;
        self.commit_plan(plan)?;
        Ok(data.len() as u32)
    }

    /// Append an explicit zero range (a hole punch or a sparse-region write).
    pub fn zero_range(&mut self, inode: u64, offset: u64, len: u64) -> Result<()> {
        self.require_file(inode)?;
        if len == 0 {
            return Ok(());
        }
        let payload = DataZeroRangePayload { offset, len }.encode();
        let mut plan = self.plan()?;
        let prev = plan.prev_for(inode, &self.index);
        plan.add(RecordType::DataZeroRange, inode, prev, payload)?;
        self.commit_plan(plan)?;
        Ok(())
    }

    /// Truncate or set the logical size by appending a `FILE_RESIZE`.
    pub fn truncate(&mut self, inode: u64, new_size: u64) -> Result<()> {
        self.require_file(inode)?;
        let payload = FileResizePayload { new_size }.encode();
        let mut plan = self.plan()?;
        let prev = plan.prev_for(inode, &self.index);
        plan.add(RecordType::FileResize, inode, prev, payload)?;
        self.commit_plan(plan)?;
        Ok(())
    }

    /// Apply a masked attribute change (chmod/chown/utimes/truncate).
    pub fn setattr(&mut self, inode: u64, attrs: &SetAttr) -> Result<()> {
        let ino = self.index.inode(inode).ok_or(OrfsError::NotFound)?;
        if attrs.size.is_some() && !ino.is_file() {
            return Err(if ino.is_dir() {
                OrfsError::IsADirectory
            } else {
                OrfsError::InvalidArgument("cannot resize a non-file".into())
            });
        }
        if attrs.is_empty() {
            return Ok(());
        }
        let mut plan = self.plan()?;
        if attrs.mode.is_some() || attrs.uid.is_some() || attrs.gid.is_some() {
            let payload = PermissionChangePayload {
                inode_id: inode,
                mode: attrs.mode,
                uid: attrs.uid,
                gid: attrs.gid,
            }
            .encode();
            let prev = plan.prev_for(inode, &self.index);
            plan.add(RecordType::PermissionChange, inode, prev, payload)?;
        }
        if attrs.atime.is_some() || attrs.mtime.is_some() {
            let payload = InodeSetattrPayload {
                inode_id: inode,
                atime: attrs.atime,
                mtime: attrs.mtime,
            }
            .encode();
            let prev = plan.prev_for(inode, &self.index);
            plan.add(RecordType::InodeSetattr, inode, prev, payload)?;
        }
        if let Some(size) = attrs.size {
            let payload = FileResizePayload { new_size: size }.encode();
            let prev = plan.prev_for(inode, &self.index);
            plan.add(RecordType::FileResize, inode, prev, payload)?;
        }
        self.commit_plan(plan)?;
        Ok(())
    }

    /// Remove one name of a file (tombstone: a `DENTRY_REMOVE`/`HARDLINK_REMOVE`).
    pub fn unlink(&mut self, parent: u64, name: &[u8]) -> Result<()> {
        self.require_dir(parent)?;
        let child = self.index.lookup(parent, name).ok_or(OrfsError::NotFound)?;
        let ino = self.index.inode(child).ok_or(OrfsError::NotFound)?;
        if ino.is_dir() {
            return Err(OrfsError::IsADirectory);
        }
        let nlink = ino.nlink;
        let mut plan = self.plan()?;
        let payload = DentryRemovePayload {
            parent,
            name: name.to_vec(),
        };
        if nlink > 1 {
            let bytes = payload.encode(HARDLINK_REMOVE_MAGIC);
            let prev = plan.prev_for(child, &self.index);
            plan.add(RecordType::HardlinkRemove, child, prev, bytes)?;
        } else {
            let bytes = payload.encode(DENTRY_REMOVE_MAGIC);
            let prev = plan.prev_for(child, &self.index);
            plan.add(RecordType::DentryRemove, child, prev, bytes)?;
        }
        plan.bump_nlink(child, -1, &self.index)?;
        self.commit_plan(plan)?;
        Ok(())
    }

    /// Remove an empty directory.
    pub fn rmdir(&mut self, parent: u64, name: &[u8]) -> Result<()> {
        self.require_dir(parent)?;
        let child = self.index.lookup(parent, name).ok_or(OrfsError::NotFound)?;
        let ino = self.index.inode(child).ok_or(OrfsError::NotFound)?;
        if !ino.is_dir() {
            return Err(OrfsError::NotADirectory);
        }
        if child == ROOT_INODE {
            return Err(OrfsError::InvalidArgument("cannot remove the root".into()));
        }
        if self
            .index
            .readdir(child)
            .map(|c| !c.is_empty())
            .unwrap_or(false)
        {
            return Err(OrfsError::DirectoryNotEmpty);
        }
        let mut plan = self.plan()?;
        let payload = DentryRemovePayload {
            parent,
            name: name.to_vec(),
        }
        .encode(DENTRY_REMOVE_MAGIC);
        let prev = plan.prev_for(child, &self.index);
        plan.add(RecordType::DentryRemove, child, prev, payload)?;
        // An rmdir'd directory has no names left: link count goes to zero.
        plan.bump_nlink(child, -2, &self.index)?;
        plan.bump_nlink(parent, -1, &self.index)?;
        self.commit_plan(plan)?;
        Ok(())
    }

    /// Add a hard link to an existing file.
    pub fn link(&mut self, inode: u64, new_parent: u64, new_name: &[u8]) -> Result<()> {
        let ino = self.index.inode(inode).ok_or(OrfsError::NotFound)?;
        if ino.is_dir() {
            return Err(OrfsError::PermissionDenied);
        }
        validate_name(new_name)?;
        self.require_dir(new_parent)?;
        if self.index.lookup(new_parent, new_name).is_some() {
            return Err(OrfsError::AlreadyExists);
        }
        let mut plan = self.plan()?;
        let payload = DentryAddPayload {
            parent: new_parent,
            child: inode,
            name: new_name.to_vec(),
        }
        .encode(HARDLINK_ADD_MAGIC)?;
        let prev = plan.prev_for(inode, &self.index);
        plan.add(RecordType::HardlinkAdd, inode, prev, payload)?;
        plan.bump_nlink(inode, 1, &self.index)?;
        self.commit_plan(plan)?;
        Ok(())
    }

    /// Rename (or exchange) a namespace entry.
    #[allow(clippy::too_many_arguments)]
    pub fn rename(
        &mut self,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        mode: RenameMode,
    ) -> Result<()> {
        self.require_dir(old_parent)?;
        self.require_dir(new_parent)?;
        let src = self
            .index
            .lookup(old_parent, old_name)
            .ok_or(OrfsError::NotFound)?;
        if old_parent == new_parent && old_name == new_name {
            return Ok(());
        }
        validate_name(new_name)?;
        let dest = self.index.lookup(new_parent, new_name);
        let src_inode = self.index.inode(src).ok_or(OrfsError::NotFound)?.clone();
        let mut plan = self.plan()?;

        match mode {
            RenameMode::Exchange => {
                let dest = dest.ok_or(OrfsError::NotFound)?;
                if dest == src {
                    return Ok(());
                }
                let dest_inode = self.index.inode(dest).ok_or(OrfsError::NotFound)?.clone();
                if src_inode.is_dir()
                    && dest_inode.is_dir()
                    && (self.index.is_ancestor(src, dest) || self.index.is_ancestor(dest, src))
                {
                    return Err(OrfsError::DirectoryCycle);
                }
                let payload = DentryRenamePayload {
                    flags: RenameFlags::Exchange,
                    old_parent,
                    new_parent,
                    old_name: old_name.to_vec(),
                    new_name: new_name.to_vec(),
                }
                .encode();
                let prev = plan.prev_for(src, &self.index);
                plan.add(RecordType::DentryRename, src, prev, payload)?;
                // Parent link counts change only if the two entries differ in type.
                adjust_parent_nlink_for_swap(
                    &mut plan,
                    &self.index,
                    old_parent,
                    src_inode.is_dir(),
                    dest_inode.is_dir(),
                )?;
                adjust_parent_nlink_for_swap(
                    &mut plan,
                    &self.index,
                    new_parent,
                    dest_inode.is_dir(),
                    src_inode.is_dir(),
                )?;
            }
            RenameMode::NoReplace => {
                if dest.is_some() {
                    return Err(OrfsError::AlreadyExists);
                }
                self.emit_move(
                    &mut plan, old_parent, old_name, new_parent, new_name, &src_inode,
                )?;
            }
            RenameMode::Ordinary => {
                if let Some(dest) = dest {
                    let dest_inode = self.index.inode(dest).ok_or(OrfsError::NotFound)?.clone();
                    if src_inode.is_dir() && !dest_inode.is_dir() {
                        return Err(OrfsError::NotADirectory);
                    }
                    if !src_inode.is_dir() && dest_inode.is_dir() {
                        return Err(OrfsError::IsADirectory);
                    }
                    if dest_inode.is_dir()
                        && self
                            .index
                            .readdir(dest)
                            .map(|c| !c.is_empty())
                            .unwrap_or(false)
                    {
                        return Err(OrfsError::DirectoryNotEmpty);
                    }
                    // Replace the destination: append its removal first.
                    let rm = DentryRemovePayload {
                        parent: new_parent,
                        name: new_name.to_vec(),
                    };
                    if dest_inode.is_dir() {
                        let bytes = rm.encode(DENTRY_REMOVE_MAGIC);
                        let prev = plan.prev_for(dest, &self.index);
                        plan.add(RecordType::DentryRemove, dest, prev, bytes)?;
                        plan.bump_nlink(dest, -2, &self.index)?;
                        plan.bump_nlink(new_parent, -1, &self.index)?;
                    } else if dest_inode.nlink > 1 {
                        let bytes = rm.encode(HARDLINK_REMOVE_MAGIC);
                        let prev = plan.prev_for(dest, &self.index);
                        plan.add(RecordType::HardlinkRemove, dest, prev, bytes)?;
                        plan.bump_nlink(dest, -1, &self.index)?;
                    } else {
                        let bytes = rm.encode(DENTRY_REMOVE_MAGIC);
                        let prev = plan.prev_for(dest, &self.index);
                        plan.add(RecordType::DentryRemove, dest, prev, bytes)?;
                        plan.bump_nlink(dest, -1, &self.index)?;
                    }
                }
                self.emit_move(
                    &mut plan, old_parent, old_name, new_parent, new_name, &src_inode,
                )?;
            }
        }
        self.commit_plan(plan)?;
        Ok(())
    }

    fn emit_move(
        &self,
        plan: &mut Plan,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        src_inode: &Inode,
    ) -> Result<()> {
        if src_inode.is_dir() && self.index.is_ancestor(src_inode.id, new_parent) {
            return Err(OrfsError::DirectoryCycle);
        }
        let payload = DentryRenamePayload {
            flags: RenameFlags::Move,
            old_parent,
            new_parent,
            old_name: old_name.to_vec(),
            new_name: new_name.to_vec(),
        }
        .encode();
        let prev = plan.prev_for(src_inode.id, &self.index);
        plan.add(RecordType::DentryRename, src_inode.id, prev, payload)?;
        if src_inode.is_dir() && old_parent != new_parent {
            plan.bump_nlink(old_parent, -1, &self.index)?;
            plan.bump_nlink(new_parent, 1, &self.index)?;
        }
        Ok(())
    }

    /// Set an extended attribute.
    pub fn setxattr(&mut self, inode: u64, name: &[u8], value: &[u8], create: bool) -> Result<()> {
        validate_xattr_name(name)?;
        let ino = self.index.inode(inode).ok_or(OrfsError::NotFound)?;
        let present = ino.xattrs.contains_key(name);
        if create && present {
            return Err(OrfsError::AlreadyExists);
        }
        let payload = XattrSetPayload {
            inode_id: inode,
            name: name.to_vec(),
            value: value.to_vec(),
        }
        .encode()?;
        let mut plan = self.plan()?;
        let prev = plan.prev_for(inode, &self.index);
        plan.add(RecordType::XattrSet, inode, prev, payload)?;
        self.commit_plan(plan)?;
        Ok(())
    }

    /// Remove an extended attribute.
    pub fn removexattr(&mut self, inode: u64, name: &[u8]) -> Result<()> {
        validate_xattr_name(name)?;
        let ino = self.index.inode(inode).ok_or(OrfsError::NotFound)?;
        if !ino.xattrs.contains_key(name) {
            return Err(OrfsError::NoData);
        }
        let payload = XattrRemovePayload {
            inode_id: inode,
            name: name.to_vec(),
        }
        .encode();
        let mut plan = self.plan()?;
        let prev = plan.prev_for(inode, &self.index);
        plan.add(RecordType::XattrRemove, inode, prev, payload)?;
        self.commit_plan(plan)?;
        Ok(())
    }

    /// Publish a named committed snapshot of the current root.
    pub fn publish_snapshot(&mut self, name: &[u8]) -> Result<u64> {
        if name.is_empty() {
            return Err(OrfsError::InvalidArgument("empty snapshot name".into()));
        }
        let snapshot_root = self.index.root();
        let payload = SnapshotRootPayload {
            root: snapshot_root,
            name: name.to_vec(),
        }
        .encode();
        let mut plan = self.plan()?;
        let inode = ROOT_INODE;
        let prev = plan.prev_for(inode, &self.index);
        plan.add(RecordType::SnapshotRoot, inode, prev, payload)?;
        self.commit_plan(plan)?;
        Ok(snapshot_root)
    }

    /// Append an index checkpoint over the current index.
    pub fn write_index_checkpoint(&mut self) -> Result<()> {
        let payload = IndexCheckpointPayload {
            root: self.index.root(),
            inode_count: self.index.inode_count() as u64,
            dentry_count: self.index.dentry_count() as u64,
            digest: self.index.canonical_digest(),
        }
        .encode();
        let mut plan = self.plan()?;
        let inode = ROOT_INODE;
        let prev = plan.prev_for(inode, &self.index);
        plan.add(RecordType::IndexCheckpoint, inode, prev, payload)?;
        self.commit_plan(plan)?;
        Ok(())
    }

    /// Flush the authoritative log (durability hook).
    pub fn sync(&mut self) -> Result<()> {
        self.volume.sync()
    }

    /// Attempt to engage the io_uring backing engine for authoritative writes and
    /// reads (research §17 Domain A, §20). Returns a truthful report; on failure
    /// the engine stays synchronous and the reason is recorded.
    pub fn enable_backing_io(
        &mut self,
        cfg: &crate::uring::UringConfig,
    ) -> crate::uring::UringReport {
        self.volume.enable_backing_io(cfg)
    }

    /// Whether the backing I/O actually runs on io_uring.
    pub fn backing_io_is_uring(&self) -> bool {
        self.volume.log.backing_io_is_uring()
    }

    /// Resolve `SEEK_DATA`/`SEEK_HOLE` against the current logical extent map.
    ///
    /// Returns the absolute file offset of the next data (or hole) region at or
    /// after `offset`, or `None` when POSIX requires `ENXIO` (no data at or after
    /// `offset`, or `offset` beyond EOF).
    pub fn seek_data_hole(
        &self,
        inode: u64,
        root: u64,
        offset: u64,
        hole: bool,
    ) -> Result<Option<u64>> {
        let view = self.view(root)?;
        let ino = view.inode(inode).ok_or(OrfsError::NotFound)?;
        if !ino.is_file() {
            return Err(if ino.is_dir() {
                OrfsError::IsADirectory
            } else {
                OrfsError::InvalidArgument("not a regular file".into())
            });
        }
        let size = ino.extents.size();
        if hole {
            if offset > size {
                return Ok(None);
            }
            for e in ino.extents.extents() {
                if e.end() <= offset {
                    continue;
                }
                if matches!(e.kind, ExtentKind::Zero) {
                    return Ok(Some(e.start.max(offset)));
                }
            }
            // Past the last mapped extent, and at/before EOF, is a hole.
            Ok(Some(size))
        } else {
            if offset >= size {
                return Ok(None);
            }
            for e in ino.extents.extents() {
                if e.end() <= offset {
                    continue;
                }
                if matches!(e.kind, ExtentKind::Data { .. }) {
                    return Ok(Some(e.start.max(offset)));
                }
            }
            Ok(None)
        }
    }
}

fn adjust_parent_nlink_for_swap(
    plan: &mut Plan,
    index: &Index,
    parent: u64,
    removed_is_dir: bool,
    added_is_dir: bool,
) -> Result<()> {
    let delta = i64::from(added_is_dir) - i64::from(removed_is_dir);
    if delta != 0 {
        plan.bump_nlink(parent, delta, index)?;
    }
    Ok(())
}

/// The derived, read-only `user.orfs.*` attributes (research §8).
const DERIVED_XATTRS: [&str; 4] = [
    "user.orfs.creation_root",
    "user.orfs.current_root",
    "user.orfs.history_available",
    "user.orfs.version",
];

fn derived_xattr(inode: &Inode, name: &[u8]) -> Option<Vec<u8>> {
    let value = match name {
        b"user.orfs.creation_root" => inode
            .versions
            .first()
            .map(|v| v.record_offset)
            .unwrap_or(0)
            .to_string(),
        b"user.orfs.current_root" => inode.latest_record_offset.to_string(),
        b"user.orfs.version" => inode.current_version().to_string(),
        b"user.orfs.history_available" => "1".to_string(),
        _ => return None,
    };
    Some(value.into_bytes())
}

fn now() -> Timespec {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => Timespec::new(d.as_secs() as i64, d.subsec_nanos()),
        Err(_) => Timespec::ZERO,
    }
}

// ---------------------------------------------------------------------------
// Transaction plan
// ---------------------------------------------------------------------------

/// A transaction under construction. Tracks planned record offsets so that each
/// record's `previous_inode_offset` chains within the transaction.
struct Plan {
    begin: u64,
    builder: TransactionBuilder,
    cursor: u64,
    touched: HashMap<u64, u64>,
    nlink: HashMap<u64, u32>,
}

impl Plan {
    fn new(id: u64, begin: u64) -> Result<Plan> {
        let builder = TransactionBuilder::new(id)?;
        Ok(Plan {
            begin,
            builder,
            cursor: begin + TX_BEGIN_RECORD_LEN,
            touched: HashMap::new(),
            nlink: HashMap::new(),
        })
    }

    fn prev_for(&self, inode: u64, index: &Index) -> u64 {
        *self
            .touched
            .get(&inode)
            .unwrap_or(&index.latest_offset(inode))
    }

    fn add(&mut self, ty: RecordType, inode: u64, prev: u64, payload: Vec<u8>) -> Result<()> {
        let len = (HEADER_LEN + FOOTER_LEN) as u64 + payload.len() as u64;
        self.touched.insert(inode, self.cursor);
        self.cursor = self.cursor.checked_add(len).ok_or(OrfsError::Overflow {
            what: "plan cursor",
        })?;
        self.builder.add(ty, inode, prev, payload)?;
        Ok(())
    }

    fn bump_nlink(&mut self, inode: u64, delta: i64, index: &Index) -> Result<()> {
        let current = self
            .nlink
            .get(&inode)
            .copied()
            .unwrap_or_else(|| index.inode(inode).map(|i| i.nlink).unwrap_or(0));
        let updated = (current as i64 + delta).max(0) as u32;
        self.nlink.insert(inode, updated);
        let payload = InodeMetadataPayload {
            inode_id: inode,
            nlink: updated,
        }
        .encode();
        let prev = self.prev_for(inode, index);
        self.add(RecordType::InodeMetadata, inode, prev, payload)
    }

    fn build(self) -> Result<Transaction> {
        self.builder.build()
    }
}

// ---------------------------------------------------------------------------
// The transport-neutral trait (research §13)
// ---------------------------------------------------------------------------

/// The transport-neutral filesystem core that the FUSE layer (Phase 4) calls.
///
/// `root` selects the view: the live committed root, or a pinned historical root
/// for snapshot reads. Reads return derived data; mutations append authoritative
/// transactions.
#[allow(clippy::too_many_arguments)]
pub trait OrfsCore {
    /// The live committed root offset (the view selector for reads).
    fn root(&self) -> u64;
    /// The sole parent directory of `inode`, if it has one (the root has none).
    fn parent_of(&self, inode: u64) -> Option<u64>;
    fn lookup(&self, parent: u64, name: &[u8], root: u64) -> Result<u64>;
    fn getattr(&self, inode: u64, root: u64) -> Result<InodeStat>;
    fn setattr(&mut self, inode: u64, attrs: &SetAttr) -> Result<()>;
    fn read_at(&self, inode: u64, root: u64, offset: u64, length: u32) -> Result<Vec<u8>>;
    fn write_at(&mut self, inode: u64, offset: u64, data: &[u8]) -> Result<u32>;
    /// Append an explicit zero range (hole punch / zero range).
    fn zero_range(&mut self, inode: u64, offset: u64, len: u64) -> Result<()>;
    /// Resolve `SEEK_DATA`/`SEEK_HOLE` (`None` means POSIX `ENXIO`).
    fn seek_data_hole(&self, inode: u64, root: u64, offset: u64, hole: bool)
        -> Result<Option<u64>>;
    /// Flush the authoritative log (durability hook).
    fn sync(&mut self) -> Result<()>;
    fn create(&mut self, parent: u64, name: &[u8], mode: u32, uid: u32, gid: u32) -> Result<u64>;
    fn mkdir(&mut self, parent: u64, name: &[u8], mode: u32, uid: u32, gid: u32) -> Result<u64>;
    fn unlink(&mut self, parent: u64, name: &[u8]) -> Result<()>;
    fn rmdir(&mut self, parent: u64, name: &[u8]) -> Result<()>;
    fn rename(
        &mut self,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        mode: RenameMode,
    ) -> Result<()>;
    fn link(&mut self, inode: u64, new_parent: u64, new_name: &[u8]) -> Result<()>;
    fn symlink(
        &mut self,
        parent: u64,
        name: &[u8],
        target: &[u8],
        uid: u32,
        gid: u32,
    ) -> Result<u64>;
    fn readlink(&self, inode: u64, root: u64) -> Result<Vec<u8>>;
    fn getxattr(&self, inode: u64, name: &[u8], root: u64) -> Result<Vec<u8>>;
    fn setxattr(&mut self, inode: u64, name: &[u8], value: &[u8], create: bool) -> Result<()>;
    fn listxattr(&self, inode: u64, root: u64) -> Result<Vec<Vec<u8>>>;
    fn removexattr(&mut self, inode: u64, name: &[u8]) -> Result<()>;
    fn readdir(&self, parent: u64, root: u64) -> Result<Vec<(Vec<u8>, u64)>>;
}

impl OrfsCore for Namespace {
    fn root(&self) -> u64 {
        Namespace::root(self)
    }
    fn parent_of(&self, inode: u64) -> Option<u64> {
        if inode == ROOT_INODE {
            Some(ROOT_INODE)
        } else {
            self.index.parent_of(inode)
        }
    }
    fn lookup(&self, parent: u64, name: &[u8], root: u64) -> Result<u64> {
        Namespace::lookup(self, parent, name, root)
    }
    fn getattr(&self, inode: u64, root: u64) -> Result<InodeStat> {
        Namespace::getattr(self, inode, root)
    }
    fn setattr(&mut self, inode: u64, attrs: &SetAttr) -> Result<()> {
        Namespace::setattr(self, inode, attrs)
    }
    fn read_at(&self, inode: u64, root: u64, offset: u64, length: u32) -> Result<Vec<u8>> {
        Namespace::read_at(self, inode, root, offset, length)
    }
    fn write_at(&mut self, inode: u64, offset: u64, data: &[u8]) -> Result<u32> {
        Namespace::write_at(self, inode, offset, data)
    }
    fn zero_range(&mut self, inode: u64, offset: u64, len: u64) -> Result<()> {
        Namespace::zero_range(self, inode, offset, len)
    }
    fn seek_data_hole(
        &self,
        inode: u64,
        root: u64,
        offset: u64,
        hole: bool,
    ) -> Result<Option<u64>> {
        Namespace::seek_data_hole(self, inode, root, offset, hole)
    }
    fn sync(&mut self) -> Result<()> {
        Namespace::sync(self)
    }
    fn create(&mut self, parent: u64, name: &[u8], mode: u32, uid: u32, gid: u32) -> Result<u64> {
        Namespace::create(self, parent, name, mode, uid, gid)
    }
    fn mkdir(&mut self, parent: u64, name: &[u8], mode: u32, uid: u32, gid: u32) -> Result<u64> {
        Namespace::mkdir(self, parent, name, mode, uid, gid)
    }
    fn unlink(&mut self, parent: u64, name: &[u8]) -> Result<()> {
        Namespace::unlink(self, parent, name)
    }
    fn rmdir(&mut self, parent: u64, name: &[u8]) -> Result<()> {
        Namespace::rmdir(self, parent, name)
    }
    fn rename(
        &mut self,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        mode: RenameMode,
    ) -> Result<()> {
        Namespace::rename(self, old_parent, old_name, new_parent, new_name, mode)
    }
    fn link(&mut self, inode: u64, new_parent: u64, new_name: &[u8]) -> Result<()> {
        Namespace::link(self, inode, new_parent, new_name)
    }
    fn symlink(
        &mut self,
        parent: u64,
        name: &[u8],
        target: &[u8],
        uid: u32,
        gid: u32,
    ) -> Result<u64> {
        Namespace::symlink(self, parent, name, target, uid, gid)
    }
    fn readlink(&self, inode: u64, root: u64) -> Result<Vec<u8>> {
        Namespace::readlink(self, inode, root)
    }
    fn getxattr(&self, inode: u64, name: &[u8], root: u64) -> Result<Vec<u8>> {
        Namespace::getxattr(self, inode, name, root)
    }
    fn setxattr(&mut self, inode: u64, name: &[u8], value: &[u8], create: bool) -> Result<()> {
        Namespace::setxattr(self, inode, name, value, create)
    }
    fn listxattr(&self, inode: u64, root: u64) -> Result<Vec<Vec<u8>>> {
        Namespace::listxattr(self, inode, root)
    }
    fn removexattr(&mut self, inode: u64, name: &[u8]) -> Result<()> {
        Namespace::removexattr(self, inode, name)
    }
    fn readdir(&self, parent: u64, root: u64) -> Result<Vec<(Vec<u8>, u64)>> {
        Namespace::readdir(self, parent, root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_and_checkpoint_payloads_round_trip() {
        let s = SnapshotRootPayload {
            root: 77,
            name: b"v1".to_vec(),
        };
        assert_eq!(SnapshotRootPayload::decode(&s.encode()).unwrap(), s);
        let c = IndexCheckpointPayload {
            root: 77,
            inode_count: 4,
            dentry_count: 3,
            digest: [9u8; 32],
        };
        assert_eq!(IndexCheckpointPayload::decode(&c.encode()).unwrap(), c);
        let mut bad = c.encode();
        bad[30] ^= 0xFF;
        assert!(IndexCheckpointPayload::decode(&bad).is_err());
    }
}
