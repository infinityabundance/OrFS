//! Historical snapshots: read-only views of a committed root (research §2, §7.4,
//! §8, §14).
//!
//! A **root** is a position — the committed end offset of the authoritative log
//! (research §2, I2). A historical root reference is therefore the pair
//! `(volume UUID, root)`: the UUID scopes the position to one volume, because an
//! offset alone is not globally unique (§2, I2).
//!
//! A [`Snapshot`] reconstructs the namespace at that root by validating that the
//! root is a committed transaction boundary (§2, I3) and replaying the committed
//! prefix `L[0:root]` into an index ([`Index::from_log`]). It then answers lookups,
//! `getattr`, `readdir`, `readlink`, `read`, and extended-attribute queries from
//! **that reconstructed state** — never from live state. Because a root is a
//! prefix, a snapshot never observes a write committed after it (§7.4).
//!
//! # Reference, not contents
//!
//! The root is a *reference into retained history*; it does not contain the
//! history bytes. A snapshot requires the corresponding authoritative log body to
//! be available (research §8). A self-contained historical carrier — an export
//! that embeds the log prefix so the state can be reproduced without the volume —
//! is a **separate, optional feature** and is not implemented here.
//!
//! # Read-only and pinned
//!
//! Every mutation returns [`OrfsError::ReadOnly`] (FUSE `EROFS`): snapshot mounts
//! are read-only unless OrFS explicitly implements branching history (§7.4, §14).
//! The snapshot holds a [`crate::log::RootPin`] for its lifetime, so while any
//! read is in flight the segments covering its root cannot be quarantined or
//! rolled over ([`Snapshot`] is `Send + Sync`, so many readers may share one).
//!
//! # Stability across remounts
//!
//! Reconstructing at the same `(uuid, root)` over the same retained log always
//! yields the same view: the reconstruction is a pure function of the committed
//! prefix.

use std::path::Path;
use std::sync::Arc;

use crate::error::{OrfsError, Result};
use crate::extent::ReadPiece;
use crate::index::{Index, ROOT_INODE};
use crate::inode::InodeStat;
use crate::log::{Log, OpenMode, RootPin};
use crate::namespace::{derived_xattr, OrfsCore, RenameMode, SetAttr, DERIVED_XATTRS};
use crate::volume::Volume;

/// A historical root reference: `(volume UUID, committed end offset)`.
///
/// The UUID scopes the position; the root alone is not globally unique
/// (research §2, I2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct HistoricalRoot {
    /// The volume UUID.
    pub uuid: [u8; 16],
    /// The committed end offset that selects the prefix `L[0:root]`.
    pub root: u64,
}

impl HistoricalRoot {
    /// Construct a reference.
    pub fn new(uuid: [u8; 16], root: u64) -> HistoricalRoot {
        HistoricalRoot { uuid, root }
    }

    /// The canonical hyphenated UUID string (`8-4-4-4-12`).
    pub fn uuid_string(&self) -> String {
        let b = &self.uuid;
        let mut s = String::with_capacity(36);
        for (i, byte) in b.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                s.push('-');
            }
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }

    /// Parse a reference of the form `uuid@root` or `uuid:root`.
    pub fn parse(s: &str) -> Result<HistoricalRoot> {
        let (uuid_str, root_str) =
            s.split_once('@')
                .or_else(|| s.split_once(':'))
                .ok_or_else(|| {
                    OrfsError::InvalidArgument(format!(
                        "historical root {s:?} must be `uuid@root` or `uuid:root`"
                    ))
                })?;
        let uuid = parse_uuid(uuid_str)?;
        let root = root_str.parse::<u64>().map_err(|_| {
            OrfsError::InvalidArgument(format!("historical root {s:?} has a non-numeric offset"))
        })?;
        Ok(HistoricalRoot { uuid, root })
    }
}

impl std::fmt::Display for HistoricalRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.uuid_string(), self.root)
    }
}

fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(OrfsError::InvalidArgument(format!(
            "volume uuid {s:?} must be 32 hexadecimal digits"
        )));
    }
    let mut uuid = [0u8; 16];
    for (i, byte) in uuid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
            OrfsError::InvalidArgument(format!("volume uuid {s:?} contains a non-hex digit"))
        })?;
    }
    Ok(uuid)
}

/// A read-only historical view of a committed root.
///
/// `Snapshot` is `Send + Sync`: it owns an `Arc<Log>` read-only handle and a
/// [`RootPin`], so it can be moved between threads and shared by many readers
/// concurrently without any of them perturbing the others.
pub struct Snapshot {
    identity: HistoricalRoot,
    index: Index,
    log: Arc<Log>,
    pin: RootPin,
}

impl Snapshot {
    /// Open a snapshot of `root` over an already-open [`Volume`].
    ///
    /// The snapshot shares the volume's committed-root pin registry, so a live
    /// writer cannot roll over or quarantine a segment the snapshot depends on.
    pub fn open(volume: &Volume, root: u64) -> Result<Snapshot> {
        let log = Log::open_with_pins(
            &Volume::log_dir(&volume.root_dir),
            volume.meta.segment_size,
            OpenMode::ReadOnly,
            volume.log.root_pins(),
        )?;
        Snapshot::from_read_log(Arc::new(log), volume.meta.uuid, root)
    }

    /// Open a snapshot of `root` directly from a backing directory (a fresh,
    /// self-contained read handle with its own pin registry).
    pub fn open_dir(dir: &Path, root: u64) -> Result<Snapshot> {
        let meta = Volume::read_meta(dir)?;
        let log = Log::open(&Volume::log_dir(dir), meta.segment_size, OpenMode::ReadOnly)?;
        Snapshot::from_read_log(Arc::new(log), meta.uuid, root)
    }

    /// Build a snapshot from a read-only [`Log`] handle.
    ///
    /// Validates that `root` is a committed transaction boundary (research §2,
    /// I3): an offset inside a record or an incomplete transaction is not a
    /// valid snapshot.
    pub fn from_read_log(log: Arc<Log>, uuid: [u8; 16], root: u64) -> Result<Snapshot> {
        if root > log.committed_end_offset() {
            return Err(OrfsError::InvalidArgument(format!(
                "snapshot root {root} exceeds the committed root {}",
                log.committed_end_offset()
            )));
        }
        if root != 0 && !log.is_boundary(root) {
            return Err(OrfsError::InvalidArgument(format!(
                "snapshot root {root} is not a committed transaction boundary"
            )));
        }
        let pin = log.pin_root(root)?;
        let index = Index::from_log(&log, root)?;
        Ok(Snapshot {
            identity: HistoricalRoot { uuid, root },
            index,
            log,
            pin,
        })
    }

    /// The historical root reference `(uuid, root)`.
    pub fn identity(&self) -> HistoricalRoot {
        self.identity
    }

    /// The committed root this snapshot reconstructs.
    pub fn root(&self) -> u64 {
        self.identity.root
    }

    /// The reconstructed index (the namespace state as of the root).
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// The reserved root inode id (`1`).
    pub fn root_inode(&self) -> u64 {
        ROOT_INODE
    }

    /// A snapshot is always read-only (research §7.4, §14).
    pub fn is_read_only(&self) -> bool {
        true
    }

    /// The committed root this snapshot holds pinned for its lifetime, so its
    /// segments cannot be quarantined or rolled over while reads are in flight.
    pub fn pinned_root(&self) -> u64 {
        self.pin.root()
    }

    // -- reads (historical) -------------------------------------------------

    /// Resolve `(parent, name)` as of the root.
    pub fn lookup(&self, parent: u64, name: &[u8]) -> Result<u64> {
        self.index.inode(parent).ok_or(OrfsError::NotFound)?;
        self.index.lookup(parent, name).ok_or(OrfsError::NotFound)
    }

    /// The stat projection of `inode` as of the root.
    pub fn getattr(&self, inode: u64) -> Result<InodeStat> {
        Ok(self.index.inode(inode).ok_or(OrfsError::NotFound)?.stat())
    }

    /// The visible children of `parent` as of the root, sorted by name.
    pub fn readdir(&self, parent: u64) -> Result<Vec<(Vec<u8>, u64)>> {
        let ino = self.index.inode(parent).ok_or(OrfsError::NotFound)?;
        if !ino.is_dir() {
            return Err(OrfsError::NotADirectory);
        }
        Ok(self.index.readdir(parent).unwrap_or_default())
    }

    /// The target of a symbolic link as of the root.
    pub fn readlink(&self, inode: u64) -> Result<Vec<u8>> {
        let ino = self.index.inode(inode).ok_or(OrfsError::NotFound)?;
        match &ino.symlink_target {
            Some(t) => Ok(t.clone()),
            None => Err(OrfsError::InvalidArgument(
                "readlink on a non-symlink inode".into(),
            )),
        }
    }

    /// Read `length` bytes at `offset` from a file's historical extent map.
    ///
    /// Extent bytes are immutable and are read from the retained log at the
    /// offsets recorded in the reconstructed index.
    pub fn read_at(&self, inode: u64, offset: u64, length: u32) -> Result<Vec<u8>> {
        let ino = self.index.inode(inode).ok_or(OrfsError::NotFound)?;
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
                ReadPiece::Zero { len } => out.resize(out.len() + len as usize, 0),
                ReadPiece::Data {
                    logical_offset,
                    len,
                } => {
                    let bytes = self.log.read_range(logical_offset, len)?;
                    out.extend_from_slice(&bytes);
                }
            }
        }
        Ok(out)
    }

    /// Read an extended attribute (including the derived `user.orfs.*` set) as of
    /// the root.
    pub fn getxattr(&self, inode: u64, name: &[u8]) -> Result<Vec<u8>> {
        let ino = self.index.inode(inode).ok_or(OrfsError::NotFound)?;
        if let Some(v) = derived_xattr(ino, name) {
            return Ok(v);
        }
        ino.xattrs.get(name).cloned().ok_or(OrfsError::NoData)
    }

    /// List extended attribute names (stored plus derived) as of the root.
    pub fn listxattr(&self, inode: u64) -> Result<Vec<Vec<u8>>> {
        let ino = self.index.inode(inode).ok_or(OrfsError::NotFound)?;
        let mut names: Vec<Vec<u8>> = ino.xattrs.keys().cloned().collect();
        for d in DERIVED_XATTRS {
            names.push(d.as_bytes().to_vec());
        }
        names.sort();
        names.dedup();
        Ok(names)
    }

    /// `SEEK_DATA`/`SEEK_HOLE` against the historical extent map.
    pub fn seek_data_hole(&self, inode: u64, offset: u64, hole: bool) -> Result<Option<u64>> {
        let ino = self.index.inode(inode).ok_or(OrfsError::NotFound)?;
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
                if matches!(e.kind, crate::extent::ExtentKind::Zero) {
                    return Ok(Some(e.start.max(offset)));
                }
            }
            Ok(Some(size))
        } else {
            if offset >= size {
                return Ok(None);
            }
            for e in ino.extents.extents() {
                if e.end() <= offset {
                    continue;
                }
                if matches!(e.kind, crate::extent::ExtentKind::Data { .. }) {
                    return Ok(Some(e.start.max(offset)));
                }
            }
            Ok(None)
        }
    }
}

/// The deliverable constructor: `open_snapshot(volume, root)`.
///
/// See [`Snapshot::open`].
pub fn open_snapshot(volume: &Volume, root: u64) -> Result<Snapshot> {
    Snapshot::open(volume, root)
}

/// The read-only error every snapshot mutation returns (FUSE `EROFS`).
fn read_only() -> OrfsError {
    OrfsError::ReadOnly("snapshots are read-only".to_string())
}

impl OrfsCore for Snapshot {
    fn root(&self) -> u64 {
        Snapshot::root(self)
    }

    fn parent_of(&self, inode: u64) -> Option<u64> {
        if inode == ROOT_INODE {
            Some(ROOT_INODE)
        } else {
            self.index.parent_of(inode)
        }
    }

    fn lookup(&self, parent: u64, name: &[u8], _root: u64) -> Result<u64> {
        Snapshot::lookup(self, parent, name)
    }

    fn getattr(&self, inode: u64, _root: u64) -> Result<InodeStat> {
        Snapshot::getattr(self, inode)
    }

    fn setattr(&mut self, _inode: u64, _attrs: &SetAttr) -> Result<()> {
        Err(read_only())
    }

    fn read_at(&self, inode: u64, _root: u64, offset: u64, length: u32) -> Result<Vec<u8>> {
        Snapshot::read_at(self, inode, offset, length)
    }

    fn write_at(&mut self, _inode: u64, _offset: u64, _data: &[u8]) -> Result<u32> {
        Err(read_only())
    }

    fn zero_range(&mut self, _inode: u64, _offset: u64, _len: u64) -> Result<()> {
        Err(read_only())
    }

    fn seek_data_hole(
        &self,
        inode: u64,
        _root: u64,
        offset: u64,
        hole: bool,
    ) -> Result<Option<u64>> {
        Snapshot::seek_data_hole(self, inode, offset, hole)
    }

    fn sync(&mut self) -> Result<()> {
        Ok(())
    }

    fn create(
        &mut self,
        _parent: u64,
        _name: &[u8],
        _mode: u32,
        _uid: u32,
        _gid: u32,
    ) -> Result<u64> {
        Err(read_only())
    }

    fn mkdir(
        &mut self,
        _parent: u64,
        _name: &[u8],
        _mode: u32,
        _uid: u32,
        _gid: u32,
    ) -> Result<u64> {
        Err(read_only())
    }

    fn unlink(&mut self, _parent: u64, _name: &[u8]) -> Result<()> {
        Err(read_only())
    }

    fn rmdir(&mut self, _parent: u64, _name: &[u8]) -> Result<()> {
        Err(read_only())
    }

    fn rename(
        &mut self,
        _old_parent: u64,
        _old_name: &[u8],
        _new_parent: u64,
        _new_name: &[u8],
        _mode: RenameMode,
    ) -> Result<()> {
        Err(read_only())
    }

    fn link(&mut self, _inode: u64, _new_parent: u64, _new_name: &[u8]) -> Result<()> {
        Err(read_only())
    }

    fn symlink(
        &mut self,
        _parent: u64,
        _name: &[u8],
        target: &[u8],
        _uid: u32,
        _gid: u32,
    ) -> Result<u64> {
        // Validate the target so a malformed call is EINVAL rather than EROFS,
        // matching the live engine's argument checking.
        if target.is_empty() {
            return Err(OrfsError::InvalidArgument("empty symlink target".into()));
        }
        Err(read_only())
    }

    fn readlink(&self, inode: u64, _root: u64) -> Result<Vec<u8>> {
        Snapshot::readlink(self, inode)
    }

    fn getxattr(&self, inode: u64, name: &[u8], _root: u64) -> Result<Vec<u8>> {
        Snapshot::getxattr(self, inode, name)
    }

    fn setxattr(&mut self, _inode: u64, _name: &[u8], _value: &[u8], _create: bool) -> Result<()> {
        Err(read_only())
    }

    fn listxattr(&self, inode: u64, _root: u64) -> Result<Vec<Vec<u8>>> {
        Snapshot::listxattr(self, inode)
    }

    fn removexattr(&mut self, _inode: u64, _name: &[u8]) -> Result<()> {
        Err(read_only())
    }

    fn readdir(&self, parent: u64, _root: u64) -> Result<Vec<(Vec<u8>, u64)>> {
        Snapshot::readdir(self, parent)
    }
}
