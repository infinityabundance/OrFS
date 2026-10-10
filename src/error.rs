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

    /// An extended attribute was requested that is not present.
    #[error("no such extended attribute")]
    NoData,

    /// The operation is denied by the permission model.
    #[error("permission denied")]
    PermissionDenied,

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

    /// Checked integer arithmetic overflowed while decoding an untrusted value.
    #[error("integer overflow while decoding {what}")]
    Overflow { what: &'static str },

    /// A fault-injection failpoint fired (only reachable in `failpoints` builds).
    /// The write path must be discarded; see `docs/TRANSACTIONS.md`.
    #[error("injected failpoint: {0}")]
    Failpoint(&'static str),
}

impl OrfsError {
    /// Map this error to the POSIX errno a FUSE reply should carry.
    pub fn errno(&self) -> i32 {
        match self {
            OrfsError::Io(e) => e.raw_os_error().unwrap_or(libc::EIO),
            OrfsError::Ekbloom(_) => libc::EIO,
            OrfsError::Unimplemented(_) => libc::ENOSYS,
            OrfsError::InvalidArgument(_) => libc::EINVAL,
            OrfsError::NotFound => libc::ENOENT,
            OrfsError::AlreadyExists => libc::EEXIST,
            OrfsError::NoData => libc::ENODATA,
            OrfsError::PermissionDenied => libc::EACCES,
            OrfsError::NotADirectory => libc::ENOTDIR,
            OrfsError::IsADirectory => libc::EISDIR,
            OrfsError::DirectoryNotEmpty => libc::ENOTEMPTY,
            OrfsError::DirectoryCycle => libc::EINVAL,
            OrfsError::NoSpace(_) => libc::ENOSPC,
            OrfsError::Corrupt(_) => libc::EIO,
            OrfsError::Unsupported(_) => libc::EOPNOTSUPP,
            OrfsError::Compatibility(_) => libc::EPROTONOSUPPORT,
            OrfsError::OutOfBounds { .. } => libc::EINVAL,
            OrfsError::ReadOnly(_) => libc::EROFS,
            OrfsError::Overflow { .. } => libc::EIO,
            OrfsError::Failpoint(_) => libc::EIO,
        }
    }
}

/// FUSE-facing alias; kept distinct so the transport layer reads clearly.
pub type FsError = OrfsError;
