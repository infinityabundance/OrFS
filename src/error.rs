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

    /// The **recovery working set** could not be made durable because the backing
    /// store is at or below its reserve (Phase 77). A writable recovery must
    /// quarantine an abandoned tail and continue in a fresh segment; when the
    /// backing cannot accept that working set the open is refused **before**
    /// mutating anything, leaving committed history intact and fully readable
    /// read-only.
    ///
    /// The remedy is to free space with `orfs reclaim` (relocate sealed segments
    /// to a cold tier and/or drop rebuildable structures) or to move the volume to
    /// a larger backing, then re-run `orfs recover`. Maps to `ENOSPC`.
    #[error(
        "recovery needs {needed} byte(s) of working space but only {admissible} are \
         admissible: free space with `orfs reclaim` (or a larger backing) and re-run `orfs recover`"
    )]
    RecoverySpaceExhausted { needed: u64, admissible: u64 },

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

    /// The **cold tier** holding a relocated (released) segment is unreachable
    /// (Phase 76): the tier root does not exist, or a segment the relocation
    /// catalogue marks `Released` cannot be resolved. A read that needs a
    /// released segment returns this typed error rather than wrong or truncated
    /// data; the open is refused rather than silently shortening history.
    #[error("cold tier unavailable: {0}")]
    TierUnavailable(String),

    /// A relocated segment's cold-tier copy is missing or its digest does not
    /// match the digest recorded in the relocation catalogue (Phase 76). Authority
    /// is never fabricated or destroyed: the fault is reported and the read is
    /// refused.
    #[error("cold tier copy is corrupt or missing: {0}")]
    TierCorrupt(String),

    /// An operation was **in flight** at the moment of a power cut and its
    /// completion was never observed (Phase 80). The caller did not receive a
    /// success, so it **must not** treat the operation as durable; unlike an EIO
    /// or ENOSPC it is **not** an unrecoverable authoritative-store failure, so
    /// it does not latch the volume read-only — the device simply did not finish
    /// the operation. Maps to `EAGAIN`. See `docs/DURABILITY.md`.
    #[error("operation in flight, completion not observed: {0}")]
    InFlight(String),

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
            // An in-flight completion is not a store failure: the device accepted
            // nothing reliably and did not error; the caller simply did not
            // observe a success. It must not latch the volume (Phase 80).
            OrfsError::InFlight(_) => false,
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
            OrfsError::RecoverySpaceExhausted { .. } => libc::ENOSPC,
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
            OrfsError::TierUnavailable(_) => libc::EIO,
            OrfsError::TierCorrupt(_) => libc::EIO,
            // A completion that was never observed is transient, not fatal.
            OrfsError::InFlight(_) => libc::EAGAIN,
            OrfsError::Failpoint(_) => libc::EIO,
        }
    }
}

/// FUSE-facing alias; kept distinct so the transport layer reads clearly.
pub type FsError = OrfsError;
