//! Versioned inode model and the inode-scoped authoritative payload codecs
//! (research §6, §8, §25).
//!
//! An inode has a **stable identity** ([`Inode::id`]) that is independent of any
//! name; the namespace (`crate::directory`, `crate::index`) maps names to that
//! identity. Every authoritative record that changes an inode appends a **new
//! version**; prior versions are never overwritten (Law I). This module owns the
//! inode data model, the [`InodeStat`] projection used by the transport plane,
//! and the little-endian, CRC32C-checked payload codecs for the record types that
//! mutate an inode's own attributes:
//!
//! ```text
//!   INODE_CREATE      new inode (first version)
//!   SYMLINK_CREATE    new symbolic-link inode carrying its target
//!   INODE_METADATA    new version: link count
//!   PERMISSION_CHANGE new version: mode/uid/gid
//!   INODE_SETATTR     new version: atime/mtime
//!   XATTR_SET         new version: set one extended attribute
//!   XATTR_REMOVE      new version: remove one extended attribute
//! ```
//!
//! Names are deliberately **not** part of an inode's identity (research §6).

use std::collections::BTreeMap;

use crate::error::{OrfsError, Result};
use crate::extent::ExtentMap;
use crate::record::{get_i64, get_u32, get_u64, put_i64, put_u32, put_u64};

// ---------------------------------------------------------------------------
// Payload magics (LE bytes spell the mnemonic)
// ---------------------------------------------------------------------------

/// `INODE_CREATE` magic; LE bytes spell `ICR1`.
pub const INODE_CREATE_MAGIC: u32 = 0x3152_4349;
/// `SYMLINK_CREATE` magic; LE bytes spell `SLK1`.
pub const SYMLINK_CREATE_MAGIC: u32 = 0x314B_4C53;
/// `INODE_METADATA` magic; LE bytes spell `IMT1`.
pub const INODE_METADATA_MAGIC: u32 = 0x3154_4D49;
/// `PERMISSION_CHANGE` magic; LE bytes spell `PCH1`.
pub const PERMISSION_CHANGE_MAGIC: u32 = 0x3148_4350;
/// `INODE_SETATTR` magic; LE bytes spell `ISA1`.
pub const INODE_SETATTR_MAGIC: u32 = 0x3141_5349;
/// `XATTR_SET` magic; LE bytes spell `XAS1`.
pub const XATTR_SET_MAGIC: u32 = 0x3153_4158;
/// `XATTR_REMOVE` magic; LE bytes spell `XAR1`.
pub const XATTR_REMOVE_MAGIC: u32 = 0x3152_4158;

/// Fixed length of an encoded `INODE_CREATE` payload.
pub const INODE_CREATE_PAYLOAD_LEN: usize = 88;
/// Fixed length of an encoded `INODE_METADATA` payload.
pub const INODE_METADATA_PAYLOAD_LEN: usize = 20;
/// Fixed length of an encoded `PERMISSION_CHANGE` payload.
pub const PERMISSION_CHANGE_PAYLOAD_LEN: usize = 32;
/// Fixed length of an encoded `INODE_SETATTR` payload.
pub const INODE_SETATTR_PAYLOAD_LEN: usize = 44;

/// Upper bound on an extended-attribute name (bytes). Mirrors the Linux VFS
/// practical bound (`XATTR_NAME_MAX`).
pub const XATTR_NAME_MAX: usize = 255;
/// Upper bound on an extended-attribute value carried in a payload.
pub const XATTR_VALUE_MAX: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// A POSIX timestamp with nanosecond resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    pub secs: i64,
    pub nanos: u32,
}

impl Timespec {
    pub const fn new(secs: i64, nanos: u32) -> Timespec {
        Timespec { secs, nanos }
    }

    pub const ZERO: Timespec = Timespec { secs: 0, nanos: 0 };
}

fn put_timespec(b: &mut [u8], off: usize, t: Timespec) {
    put_i64(b, off, t.secs);
    put_u32(b, off + 8, t.nanos);
}

fn get_timespec(b: &[u8], off: usize) -> Timespec {
    Timespec {
        secs: get_i64(b, off),
        nanos: get_u32(b, off + 8),
    }
}

// ---------------------------------------------------------------------------
// Inode type
// ---------------------------------------------------------------------------

/// The object type of an inode (research §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum InodeType {
    /// A regular file with an extent map.
    File = 0,
    /// A directory whose children are `(parent, name)` relations.
    Directory = 1,
    /// A symbolic link carrying a target byte string.
    Symlink = 2,
}

impl InodeType {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<InodeType> {
        Some(match code {
            0 => InodeType::File,
            1 => InodeType::Directory,
            2 => InodeType::Symlink,
            _ => return None,
        })
    }

    pub const fn name(self) -> &'static str {
        match self {
            InodeType::File => "file",
            InodeType::Directory => "directory",
            InodeType::Symlink => "symlink",
        }
    }
}

// ---------------------------------------------------------------------------
// The inode
// ---------------------------------------------------------------------------

/// One historical metadata version of an inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InodeVersion {
    /// Monotonic version number, starting at 1.
    pub version: u64,
    /// The authoritative record offset that produced this version.
    pub record_offset: u64,
    pub kind: InodeType,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size: u64,
}

/// A versioned inode (research §6, §25).
///
/// `names` and parent directories are **not** stored here: identity is the
/// inode id alone. The current visible content is [`Inode::extents`]; every prior
/// version is retained in the authoritative log and summarised in
/// [`Inode::versions`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inode {
    /// Stable inode identity (1 is the volume root).
    pub id: u64,
    /// Inode generation; bumped only if an id were ever reused (never today).
    pub generation: u64,
    pub kind: InodeType,
    /// Permission bits (the low 12 bits of `st_mode`).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    /// Current logical length in bytes.
    pub size: u64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
    /// Extended attributes (stored, not virtual).
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Current logical extent map (derived; rebuilt from the log).
    pub extents: ExtentMap,
    /// Symbolic-link target, for [`InodeType::Symlink`] inodes.
    pub symlink_target: Option<Vec<u8>>,
    /// Historical metadata versions, oldest first (never pruned).
    pub versions: Vec<InodeVersion>,
    /// Offset of the latest authoritative record for this inode, or 0.
    pub latest_record_offset: u64,
}

impl Inode {
    /// Create a brand-new inode (version 1) with no extents.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        generation: u64,
        kind: InodeType,
        mode: u32,
        uid: u32,
        gid: u32,
        nlink: u32,
        size: u64,
        atime: Timespec,
        mtime: Timespec,
        ctime: Timespec,
        record_offset: u64,
    ) -> Inode {
        let version = InodeVersion {
            version: 1,
            record_offset,
            kind,
            mode,
            uid,
            gid,
            nlink,
            size,
        };
        Inode {
            id,
            generation,
            kind,
            mode,
            uid,
            gid,
            nlink,
            size,
            atime,
            mtime,
            ctime,
            xattrs: BTreeMap::new(),
            extents: ExtentMap::default(),
            symlink_target: None,
            versions: vec![version],
            latest_record_offset: record_offset,
        }
    }

    /// The current version number (`>= 1`).
    pub fn current_version(&self) -> u64 {
        self.versions.last().map(|v| v.version).unwrap_or(0)
    }

    /// Record a new metadata version after an authoritative record mutated this
    /// inode. Called only by the index replay engine.
    pub fn bump_version(&mut self, record_offset: u64) {
        let version = InodeVersion {
            version: self.current_version() + 1,
            record_offset,
            kind: self.kind,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            nlink: self.nlink,
            size: self.size,
        };
        self.versions.push(version);
        self.latest_record_offset = record_offset;
    }

    pub fn is_dir(&self) -> bool {
        self.kind == InodeType::Directory
    }

    pub fn is_file(&self) -> bool {
        self.kind == InodeType::File
    }

    pub fn is_symlink(&self) -> bool {
        self.kind == InodeType::Symlink
    }

    /// The transport-facing projection of this inode.
    pub fn stat(&self) -> InodeStat {
        InodeStat {
            id: self.id,
            kind: self.kind,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            nlink: self.nlink,
            size: self.size,
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
            version: self.current_version(),
            blocks: self.size.div_ceil(512),
        }
    }
}

// ---------------------------------------------------------------------------
// POSIX access checks (research §12: the query interface uses the *same*
// permission checks and inode-version rules as ordinary reads)
// ---------------------------------------------------------------------------

/// POSIX permission classification: owner, group, or other.
pub fn perm_class(uid: u32, gid: u32, st: &InodeStat) -> u32 {
    if uid == st.uid {
        6
    } else if gid == st.gid {
        3
    } else {
        0
    }
}

/// Check `mask` (bit 2 = read, bit 1 = write, bit 0 = execute) against `st`.
///
/// This is the single authoritative POSIX access rule for the whole crate: both
/// the FUSE transport (`src/fuse.rs`) and the query API (`src/query.rs`) call it,
/// so a mounted read and a search can never disagree about who may read a file.
pub fn has_permission(uid: u32, gid: u32, st: &InodeStat, mask: u32) -> bool {
    let perm = st.mode & 0o777;
    if uid == 0 {
        // Root bypasses read/write; execute needs at least one x bit set on a
        // regular file, and is always allowed on directories.
        if mask & 0o1 != 0 && st.kind == InodeType::File {
            return perm & 0o111 != 0;
        }
        return true;
    }
    let shift = perm_class(uid, gid, st);
    let class = (perm >> shift) & 0o7;
    (class & mask) == mask
}

/// The POSIX `stat`-like view of an inode, returned by `getattr`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InodeStat {
    pub id: u64,
    pub kind: InodeType,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size: u64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
    /// The current inode version.
    pub version: u64,
    /// Number of 512-byte blocks (notional).
    pub blocks: u64,
}

impl serde::Serialize for Timespec {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("timespec", 2)?;
        st.serialize_field("secs", &self.secs)?;
        st.serialize_field("nanos", &self.nanos)?;
        st.end()
    }
}

impl serde::Serialize for InodeType {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// Codec helpers
// ---------------------------------------------------------------------------

fn check_prefix(buf: &[u8], magic: u32, len: usize, what: &str) -> Result<()> {
    if buf.len() != len {
        return Err(OrfsError::Corrupt(format!(
            "{what} payload is {} bytes, expected {len}",
            buf.len()
        )));
    }
    if get_u32(buf, 0) != magic {
        return Err(OrfsError::Corrupt(format!("{what} payload bad magic")));
    }
    Ok(())
}

/// Validate a trailing CRC32C that covers every preceding byte.
fn check_trailing_crc(buf: &[u8], what: &str) -> Result<()> {
    let n = buf.len();
    if n < 4 {
        return Err(OrfsError::Corrupt(format!("{what} payload too short")));
    }
    let stored = get_u32(buf, n - 4);
    if stored != crc32c::crc32c(&buf[..n - 4]) {
        return Err(OrfsError::Corrupt(format!(
            "{what} payload checksum mismatch"
        )));
    }
    Ok(())
}

fn finish_crc(b: &mut Vec<u8>) {
    let check = crc32c::crc32c(b);
    b.extend_from_slice(&check.to_le_bytes());
}

fn put_len_bytes(b: &mut Vec<u8>, bytes: &[u8]) {
    b.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    b.extend_from_slice(bytes);
}

fn take_len_bytes(buf: &[u8], off: usize, what: &str) -> Result<(Vec<u8>, usize)> {
    if off + 4 > buf.len() {
        return Err(OrfsError::Corrupt(format!(
            "{what} truncated length prefix"
        )));
    }
    let len = get_u32(buf, off) as usize;
    let start = off + 4;
    let end = start.checked_add(len).ok_or(OrfsError::Overflow {
        what: "payload field",
    })?;
    if end > buf.len() {
        return Err(OrfsError::Corrupt(format!("{what} truncated field")));
    }
    Ok((buf[start..end].to_vec(), end))
}

// ---------------------------------------------------------------------------
// INODE_CREATE
// ---------------------------------------------------------------------------

/// Payload of `INODE_CREATE` (fixed 88 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeCreatePayload {
    pub inode_id: u64,
    pub generation: u64,
    pub kind: InodeType,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size: u64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
}

impl InodeCreatePayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; INODE_CREATE_PAYLOAD_LEN];
        put_u32(&mut b, 0, INODE_CREATE_MAGIC);
        put_u64(&mut b, 4, self.inode_id);
        put_u64(&mut b, 12, self.generation);
        b[20] = self.kind.code();
        put_u32(&mut b, 24, self.mode);
        put_u32(&mut b, 28, self.uid);
        put_u32(&mut b, 32, self.gid);
        put_u32(&mut b, 36, self.nlink);
        put_u64(&mut b, 40, self.size);
        put_timespec(&mut b, 48, self.atime);
        put_timespec(&mut b, 60, self.mtime);
        put_timespec(&mut b, 72, self.ctime);
        let check = crc32c::crc32c(&b[..84]);
        put_u32(&mut b, 84, check);
        b
    }

    pub fn decode(buf: &[u8]) -> Result<InodeCreatePayload> {
        check_prefix(
            buf,
            INODE_CREATE_MAGIC,
            INODE_CREATE_PAYLOAD_LEN,
            "INODE_CREATE",
        )?;
        if get_u32(buf, 84) != crc32c::crc32c(&buf[..84]) {
            return Err(OrfsError::Corrupt(
                "INODE_CREATE payload checksum mismatch".into(),
            ));
        }
        let kind = InodeType::from_code(buf[20])
            .ok_or_else(|| OrfsError::Corrupt("INODE_CREATE unknown inode type".into()))?;
        Ok(InodeCreatePayload {
            inode_id: get_u64(buf, 4),
            generation: get_u64(buf, 12),
            kind,
            mode: get_u32(buf, 24),
            uid: get_u32(buf, 28),
            gid: get_u32(buf, 32),
            nlink: get_u32(buf, 36),
            size: get_u64(buf, 40),
            atime: get_timespec(buf, 48),
            mtime: get_timespec(buf, 60),
            ctime: get_timespec(buf, 72),
        })
    }
}

// ---------------------------------------------------------------------------
// SYMLINK_CREATE
// ---------------------------------------------------------------------------

/// Payload of `SYMLINK_CREATE` (variable; carries the link target).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymlinkCreatePayload {
    pub inode_id: u64,
    pub generation: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: Timespec,
    pub target: Vec<u8>,
}

impl SymlinkCreatePayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(60 + self.target.len() + 4);
        b.extend_from_slice(&SYMLINK_CREATE_MAGIC.to_le_bytes());
        b.extend_from_slice(&self.inode_id.to_le_bytes());
        b.extend_from_slice(&self.generation.to_le_bytes());
        b.extend_from_slice(&self.mode.to_le_bytes());
        b.extend_from_slice(&self.uid.to_le_bytes());
        b.extend_from_slice(&self.gid.to_le_bytes());
        b.extend_from_slice(&self.mtime.secs.to_le_bytes());
        b.extend_from_slice(&self.mtime.nanos.to_le_bytes());
        put_len_bytes(&mut b, &self.target);
        finish_crc(&mut b);
        b
    }

    pub fn decode(buf: &[u8]) -> Result<SymlinkCreatePayload> {
        if buf.len() < 52 || get_u32(buf, 0) != SYMLINK_CREATE_MAGIC {
            return Err(OrfsError::Corrupt(
                "SYMLINK_CREATE payload bad magic or short".into(),
            ));
        }
        check_trailing_crc(buf, "SYMLINK_CREATE")?;
        let (target, end) = take_len_bytes(buf, 44, "SYMLINK_CREATE")?;
        if end + 4 != buf.len() {
            return Err(OrfsError::Corrupt(
                "SYMLINK_CREATE payload trailing bytes".into(),
            ));
        }
        Ok(SymlinkCreatePayload {
            inode_id: get_u64(buf, 4),
            generation: get_u64(buf, 12),
            mode: get_u32(buf, 20),
            uid: get_u32(buf, 24),
            gid: get_u32(buf, 28),
            mtime: get_timespec(buf, 32),
            target,
        })
    }
}

// ---------------------------------------------------------------------------
// INODE_METADATA (link count)
// ---------------------------------------------------------------------------

/// Payload of `INODE_METADATA` (fixed 20 bytes); publishes a new link count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeMetadataPayload {
    pub inode_id: u64,
    pub nlink: u32,
}

impl InodeMetadataPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; INODE_METADATA_PAYLOAD_LEN];
        put_u32(&mut b, 0, INODE_METADATA_MAGIC);
        put_u64(&mut b, 4, self.inode_id);
        put_u32(&mut b, 12, self.nlink);
        let check = crc32c::crc32c(&b[..16]);
        put_u32(&mut b, 16, check);
        b
    }

    pub fn decode(buf: &[u8]) -> Result<InodeMetadataPayload> {
        check_prefix(
            buf,
            INODE_METADATA_MAGIC,
            INODE_METADATA_PAYLOAD_LEN,
            "INODE_METADATA",
        )?;
        if get_u32(buf, 16) != crc32c::crc32c(&buf[..16]) {
            return Err(OrfsError::Corrupt(
                "INODE_METADATA payload checksum mismatch".into(),
            ));
        }
        Ok(InodeMetadataPayload {
            inode_id: get_u64(buf, 4),
            nlink: get_u32(buf, 12),
        })
    }
}

// ---------------------------------------------------------------------------
// PERMISSION_CHANGE
// ---------------------------------------------------------------------------

/// Payload of `PERMISSION_CHANGE` (fixed 32 bytes); a field-masked new version
/// over `{mode, uid, gid}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionChangePayload {
    pub inode_id: u64,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

impl PermissionChangePayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; PERMISSION_CHANGE_PAYLOAD_LEN];
        put_u32(&mut b, 0, PERMISSION_CHANGE_MAGIC);
        put_u64(&mut b, 4, self.inode_id);
        b[12] = u8::from(self.mode.is_some());
        b[13] = u8::from(self.uid.is_some());
        b[14] = u8::from(self.gid.is_some());
        put_u32(&mut b, 16, self.mode.unwrap_or(0));
        put_u32(&mut b, 20, self.uid.unwrap_or(0));
        put_u32(&mut b, 24, self.gid.unwrap_or(0));
        let check = crc32c::crc32c(&b[..28]);
        put_u32(&mut b, 28, check);
        b
    }

    pub fn decode(buf: &[u8]) -> Result<PermissionChangePayload> {
        check_prefix(
            buf,
            PERMISSION_CHANGE_MAGIC,
            PERMISSION_CHANGE_PAYLOAD_LEN,
            "PERMISSION_CHANGE",
        )?;
        if get_u32(buf, 28) != crc32c::crc32c(&buf[..28]) {
            return Err(OrfsError::Corrupt(
                "PERMISSION_CHANGE payload checksum mismatch".into(),
            ));
        }
        let has = |v: u8| v != 0;
        Ok(PermissionChangePayload {
            inode_id: get_u64(buf, 4),
            mode: has(buf[12]).then(|| get_u32(buf, 16)),
            uid: has(buf[13]).then(|| get_u32(buf, 20)),
            gid: has(buf[14]).then(|| get_u32(buf, 24)),
        })
    }
}

// ---------------------------------------------------------------------------
// INODE_SETATTR (timestamps)
// ---------------------------------------------------------------------------

/// Payload of `INODE_SETATTR` (fixed 44 bytes); a field-masked new version over
/// `{atime, mtime}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeSetattrPayload {
    pub inode_id: u64,
    pub atime: Option<Timespec>,
    pub mtime: Option<Timespec>,
}

impl InodeSetattrPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; INODE_SETATTR_PAYLOAD_LEN];
        put_u32(&mut b, 0, INODE_SETATTR_MAGIC);
        put_u64(&mut b, 4, self.inode_id);
        b[12] = u8::from(self.atime.is_some());
        b[13] = u8::from(self.mtime.is_some());
        put_timespec(&mut b, 16, self.atime.unwrap_or(Timespec::ZERO));
        put_timespec(&mut b, 28, self.mtime.unwrap_or(Timespec::ZERO));
        let check = crc32c::crc32c(&b[..40]);
        put_u32(&mut b, 40, check);
        b
    }

    pub fn decode(buf: &[u8]) -> Result<InodeSetattrPayload> {
        check_prefix(
            buf,
            INODE_SETATTR_MAGIC,
            INODE_SETATTR_PAYLOAD_LEN,
            "INODE_SETATTR",
        )?;
        if get_u32(buf, 40) != crc32c::crc32c(&buf[..40]) {
            return Err(OrfsError::Corrupt(
                "INODE_SETATTR payload checksum mismatch".into(),
            ));
        }
        Ok(InodeSetattrPayload {
            inode_id: get_u64(buf, 4),
            atime: (buf[12] != 0).then(|| get_timespec(buf, 16)),
            mtime: (buf[13] != 0).then(|| get_timespec(buf, 28)),
        })
    }
}

// ---------------------------------------------------------------------------
// XATTR_SET / XATTR_REMOVE
// ---------------------------------------------------------------------------

/// Payload of `XATTR_SET` (variable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XattrSetPayload {
    pub inode_id: u64,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl XattrSetPayload {
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_xattr_name(&self.name)?;
        if self.value.len() > XATTR_VALUE_MAX {
            return Err(OrfsError::InvalidArgument(format!(
                "xattr value is {} bytes, limit {XATTR_VALUE_MAX}",
                self.value.len()
            )));
        }
        let mut b = Vec::with_capacity(16 + self.name.len() + self.value.len() + 4);
        b.extend_from_slice(&XATTR_SET_MAGIC.to_le_bytes());
        b.extend_from_slice(&self.inode_id.to_le_bytes());
        put_len_bytes(&mut b, &self.name);
        put_len_bytes(&mut b, &self.value);
        finish_crc(&mut b);
        Ok(b)
    }

    pub fn decode(buf: &[u8]) -> Result<XattrSetPayload> {
        if buf.len() < 12 || get_u32(buf, 0) != XATTR_SET_MAGIC {
            return Err(OrfsError::Corrupt("XATTR_SET payload bad magic".into()));
        }
        check_trailing_crc(buf, "XATTR_SET")?;
        let (name, off) = take_len_bytes(buf, 12, "XATTR_SET name")?;
        let (value, end) = take_len_bytes(buf, off, "XATTR_SET value")?;
        if end + 4 != buf.len() {
            return Err(OrfsError::Corrupt(
                "XATTR_SET payload trailing bytes".into(),
            ));
        }
        Ok(XattrSetPayload {
            inode_id: get_u64(buf, 4),
            name,
            value,
        })
    }
}

/// Payload of `XATTR_REMOVE` (variable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XattrRemovePayload {
    pub inode_id: u64,
    pub name: Vec<u8>,
}

impl XattrRemovePayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(12 + self.name.len() + 4);
        b.extend_from_slice(&XATTR_REMOVE_MAGIC.to_le_bytes());
        b.extend_from_slice(&self.inode_id.to_le_bytes());
        put_len_bytes(&mut b, &self.name);
        finish_crc(&mut b);
        b
    }

    pub fn decode(buf: &[u8]) -> Result<XattrRemovePayload> {
        if buf.len() < 12 || get_u32(buf, 0) != XATTR_REMOVE_MAGIC {
            return Err(OrfsError::Corrupt("XATTR_REMOVE payload bad magic".into()));
        }
        check_trailing_crc(buf, "XATTR_REMOVE")?;
        let (name, end) = take_len_bytes(buf, 12, "XATTR_REMOVE name")?;
        if end + 4 != buf.len() {
            return Err(OrfsError::Corrupt(
                "XATTR_REMOVE payload trailing bytes".into(),
            ));
        }
        Ok(XattrRemovePayload {
            inode_id: get_u64(buf, 4),
            name,
        })
    }
}

/// Validate an extended-attribute name against the documented bounds.
pub fn validate_xattr_name(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(OrfsError::InvalidArgument(
            "xattr name must not be empty".into(),
        ));
    }
    if name.len() > XATTR_NAME_MAX {
        return Err(OrfsError::InvalidArgument(format!(
            "xattr name is {} bytes, limit {XATTR_NAME_MAX}",
            name.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(n: i64) -> Timespec {
        Timespec::new(n, 7)
    }

    #[test]
    fn inode_create_round_trips() {
        let p = InodeCreatePayload {
            inode_id: 7,
            generation: 1,
            kind: InodeType::Directory,
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            nlink: 2,
            size: 0,
            atime: ts(1),
            mtime: ts(2),
            ctime: ts(3),
        };
        let bytes = p.encode();
        assert_eq!(bytes.len(), INODE_CREATE_PAYLOAD_LEN);
        assert_eq!(InodeCreatePayload::decode(&bytes).unwrap(), p);
        let mut bad = bytes.clone();
        bad[30] ^= 0xFF;
        assert!(InodeCreatePayload::decode(&bad).is_err());
    }

    #[test]
    fn symlink_create_round_trips_and_rejects_trailing_bytes() {
        let p = SymlinkCreatePayload {
            inode_id: 3,
            generation: 1,
            mode: 0o777,
            uid: 0,
            gid: 0,
            mtime: ts(5),
            target: b"../a/b".to_vec(),
        };
        let bytes = p.encode();
        assert_eq!(SymlinkCreatePayload::decode(&bytes).unwrap(), p);
        let mut padded = bytes.clone();
        padded.insert(bytes.len() - 4, 0);
        assert!(SymlinkCreatePayload::decode(&padded).is_err());
    }

    #[test]
    fn masked_payloads_round_trip() {
        let perm = PermissionChangePayload {
            inode_id: 2,
            mode: Some(0o600),
            uid: None,
            gid: Some(5),
        };
        assert_eq!(
            PermissionChangePayload::decode(&perm.encode()).unwrap(),
            perm
        );

        let set = InodeSetattrPayload {
            inode_id: 2,
            atime: Some(ts(9)),
            mtime: None,
        };
        assert_eq!(InodeSetattrPayload::decode(&set.encode()).unwrap(), set);

        let meta = InodeMetadataPayload {
            inode_id: 2,
            nlink: 3,
        };
        assert_eq!(InodeMetadataPayload::decode(&meta.encode()).unwrap(), meta);
    }

    #[test]
    fn xattr_payloads_round_trip() {
        let set = XattrSetPayload {
            inode_id: 4,
            name: b"user.k".to_vec(),
            value: b"v".to_vec(),
        };
        assert_eq!(
            XattrSetPayload::decode(&set.encode().unwrap()).unwrap(),
            set
        );

        let rm = XattrRemovePayload {
            inode_id: 4,
            name: b"user.k".to_vec(),
        };
        assert_eq!(XattrRemovePayload::decode(&rm.encode()).unwrap(), rm);
        assert!(validate_xattr_name(b"").is_err());
    }
}
