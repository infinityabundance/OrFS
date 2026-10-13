//! OrFS error model.
//!
//! Every failure is explicit. FUSE-facing errors carry a mapping to a POSIX
//! errno so that transport adapters (traditional `/dev/fuse` and FUSE-over-
//! `io_uring`) can translate uniformly without re-deriving intent.

use std::io;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, OrfsError>;

/// The single OrFS error type. Variants are stable and map to defined errnos.
#[derive(Debug, thiserror::Error)]
pub enum OrfsError {
    /// Underlying operating-system I/O failure.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// A failure surfaced by the EKBLOOM acceleration engine.
    #[error("ekbloom error: {0}")]
    Ekbloom(#[from] ekbloom::EkbloomError),

    /// Functionality that is part of the target design but not yet wired in
    /// this build phase. The string names the owning phase so the CLI can be
    /// honest rather than advertising placeholder behaviour.
    #[error("not implemented in this build phase: {0}")]
    Unimplemented(&'static str),

    /// A caller argument was structurally invalid.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// No such inode, dentry, or volume object.
    #[error("no such object")]
    NotFound,

    /// The object already exists.
    #[error("object already exists")]
    AlreadyExists,

    /// A path component exceeded the filesystem `NAME_MAX` (255 bytes). POSIX
    /// requires `ENAMETOOLONG` here, distinct from a generic `EINVAL`.
    #[error("file name too long")]
    NameTooLong,

    /// An extended attribute was requested that is not present.
    #[error("no such extended attribute")]
    NoData,

    /// The operation is denied by the permission model.
    #[error("permission denied")]
    PermissionDenied,

    /// The operation is not permitted for a reason other than the permission
    /// bits (e.g. the POSIX sticky-directory removal rule); maps to `EPERM`.
    #[error("operation not permitted")]
    NotPermitted,

    /// A path component was not a directory.
    #[error("not a directory")]
    NotADirectory,

    /// An operation expected a directory but found another object type.
    #[error("is a directory")]
    IsADirectory,

    /// `rmdir` on a non-empty directory.
    #[error("directory not empty")]
    DirectoryNotEmpty,

    /// A directory cycle would be created by a rename.
    #[error("invalid rename: would create a directory cycle")]
    DirectoryCycle,

    /// The backing store cannot accept further authoritative records.
    #[error("no space on backing store: {0}")]
    NoSpace(String),

    /// The configured **capacity guard** refused a transaction *before any byte
    /// was written* (Phase 68): the framed transaction plus the configured
    /// reserve would not fit in the live backing free space (`needed` bytes are
    /// required, `admissible` are available while keeping the reserve).
    ///
    /// This is a **predictable** refusal — the guard runs ahead of the write, so
    /// the previous committed root is left intact and the transaction is
    /// aborted cleanly, never half-written. It maps to `ENOSPC`. Unlike
    /// [`OrfsError::NoSpace`] it does **not** by itself latch the volume
    /// read-only: a smaller transaction (one that still leaves the reserve
    /// intact) remains admissible. Only when the reserve floor itself is
    /// breached (zero admissible headroom) does the log latch degraded, after
    /// which further mutations return [`OrfsError::ReadOnly`] (`EROFS`).
    #[error(
        "capacity guard refusal: {needed} byte(s) needed, {admissible} admissible before the reserve"
    )]
    CapacityExhausted { needed: u64, admissible: u64 },

    /// Committed state failed an integrity or structural check.
    #[error("corrupt committed state: {0}")]
    Corrupt(String),

    /// A requested capability or record is not supported by this build/format.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// A record or volume on disk was framed for a format this build cannot
    /// safely interpret (for example an unknown *mandatory* record type, or a
    /// newer record format version). This is a controlled compatibility
    /// failure: mounting must not proceed on a guess.
    #[error("incompatible on-disk format: {0}")]
    Compatibility(String),

    /// The authoritative log declares a format version this build does not
    /// implement — a version **newer** than [`crate::LOG_FORMAT_VERSION`]. This
    /// is distinct from [`OrfsError::Compatibility`] so a caller can report the
    /// exact on-disk version, and so a compatibility test can assert the typed
    /// refusal. A reader must refuse rather than interpret the bytes on a guess.
    ///
    /// Version `0` is *legacy* (the field was absent) and every known version
    /// `<= LOG_FORMAT_VERSION` is accepted; only an unknown **higher** version
    /// produces this error.
    #[error("unsupported log format version {found} (this build supports up to {supported})")]
    UnsupportedFormatVersion { found: u16, supported: u16 },

    /// A read or write range lies outside the object.
    #[error("out of bounds: offset {offset} length {length} (object limit {limit})")]
    OutOfBounds {
        offset: u64,
        length: u64,
        limit: u64,
    },

    /// The volume is in a degraded/read-only recovery mode and refused a write.
    #[error("volume is read-only: {0}")]
    ReadOnly(String),

    /// A live committed-root pin still needs a resource that an operation would
    /// discard (for example a segment a snapshot read depends on). The operation
    /// is refused rather than silently withdrawing committed history.
    #[error("resource is pinned by a historical root: {0}")]
    Pinned(String),

    /// Checked integer arithmetic overflowed while decoding an untrusted value.
    #[error("integer overflow while decoding {what}")]
    Overflow { what: &'static str },

    /// A fault-injection failpoint fired (only reachable in `failpoints` builds).
    /// The write path must be discarded; see `docs/TRANSACTIONS.md`.
    #[error("injected failpoint: {0}")]
    Failpoint(&'static str),
}

impl OrfsError {
    /// Whether this error is an *unrecoverable authoritative-store failure*: the
    /// backing store cannot accept authoritative records (out of space) or
    /// returned a device error. Such a failure must latch the volume into
    /// degraded/read-only mode (research I8, §31) rather than accept further
    /// writes. Injected failpoints are excluded: they are a test artefact, not a
    /// store failure.
    pub fn is_authoritative_store_failure(&self) -> bool {
        match self {
            OrfsError::NoSpace(_) => true,
            OrfsError::Io(e) => matches!(e.raw_os_error(), Some(libc::ENOSPC) | Some(libc::EIO)),
            // The Phase-68 capacity guard's *predictable* refusal is not (by
            // itself) a store failure: it refuses a too-large transaction before
            // writing anything, and a smaller transaction may still be admitted.
            // The guard latches degraded itself only when the reserve floor is
            // breached (zero headroom).
            OrfsError::CapacityExhausted { .. } => false,
            _ => false,
        }
    }

    /// Map this error to the POSIX errno a FUSE reply should carry.
    pub fn errno(&self) -> i32 {
        match self {
            OrfsError::Io(e) => e.raw_os_error().unwrap_or(libc::EIO),
            OrfsError::Ekbloom(_) => libc::EIO,
            OrfsError::Unimplemented(_) => libc::ENOSYS,
            OrfsError::InvalidArgument(_) => libc::EINVAL,
            OrfsError::NotFound => libc::ENOENT,
            OrfsError::AlreadyExists => libc::EEXIST,
            OrfsError::NameTooLong => libc::ENAMETOOLONG,
            OrfsError::NoData => libc::ENODATA,
            OrfsError::PermissionDenied => libc::EACCES,
            OrfsError::NotPermitted => libc::EPERM,
            OrfsError::NotADirectory => libc::ENOTDIR,
            OrfsError::IsADirectory => libc::EISDIR,
            OrfsError::DirectoryNotEmpty => libc::ENOTEMPTY,
            OrfsError::DirectoryCycle => libc::EINVAL,
            OrfsError::NoSpace(_) => libc::ENOSPC,
            OrfsError::CapacityExhausted { .. } => libc::ENOSPC,
            OrfsError::Corrupt(_) => libc::EIO,
            OrfsError::Unsupported(_) => libc::EOPNOTSUPP,
            OrfsError::Compatibility(_) => libc::EPROTONOSUPPORT,
            // An on-disk format-version mismatch is the same class of failure as
            // an incompatible framing: the store is a protocol this build cannot
            // speak. EPROTONOSUPPORT is the honest, non-overloaded errno.
            OrfsError::UnsupportedFormatVersion { .. } => libc::EPROTONOSUPPORT,
            OrfsError::OutOfBounds { .. } => libc::EINVAL,
            OrfsError::ReadOnly(_) => libc::EROFS,
            OrfsError::Pinned(_) => libc::EBUSY,
            OrfsError::Overflow { .. } => libc::EIO,
            OrfsError::Failpoint(_) => libc::EIO,
        }
    }
}

/// FUSE-facing alias; kept distinct so the transport layer reads clearly.
pub type FsError = OrfsError;
