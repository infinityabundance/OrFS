//! # OrFS
//!
//! A non-withdrawal, concealed-expansion Linux filesystem.
//!
//! Two independent laws govern the design:
//!
//! * **Non-withdrawal** — committed authoritative history is never overwritten,
//!   physically truncated, reused, or garbage-collected: `L_{n+1} = L_n ⊕ Δ_n`.
//! * **Concealed expansion** — extra operational structure is deliberately
//!   manifested behind the ordinary logical namespace to accelerate reads.
//!
//! The crate is organised into four functional planes, each independently
//! testable. A fault in the manifested plane must never corrupt the
//! authoritative plane; a change to the transport plane must never change
//! filesystem semantics.
//!
//! ```text
//!   Plane D  transport & storage     (fuse, fuse_uring, uring, buffers)
//!   Plane B  namespace interpretation (inode, directory, extent, namespace, snapshot)
//!   Plane C  manifested acceleration (manifestation, query, checkpoint)
//!   Plane A  authoritative history   (volume, log, segment, record, transaction, commit, recovery)
//! ```
//!
//! See `docs/` for the normative specifications. EKBLOOM is consumed as an
//! independent, version-pinned native-Rust dependency; its mathematical state
//! machine is never reimplemented here.

pub mod bench;
pub mod buffers;
pub mod capabilities;
pub mod checkpoint;
pub mod commit;
pub mod directory;
pub mod error;
pub mod extent;
pub mod failpoints;
pub mod fuse;
pub mod fuse_native;
pub mod fuse_uring;
pub mod historical;
pub mod image;
pub mod index;
pub mod inode;
pub mod log;
pub mod manifestation;
pub mod namespace;

/// The simulated power-loss device model (Phase 17). See `docs/POWERLOSS.md`.
#[cfg(feature = "powerloss")]
pub mod powerloss;

/// Compile-out stub: with the `powerloss` feature disabled every seam call is a
/// no-op, so a production build (`--no-default-features`) carries none of the
/// model and behaves exactly as before.
#[cfg(not(feature = "powerloss"))]
pub mod powerloss {
    use std::path::Path;

    /// No-op: no device can be attached in this build.
    #[inline]
    pub fn record_create(_dir: &Path, _name: &str) {}
    /// No-op: no device can be attached in this build.
    #[inline]
    pub fn record_write(_dir: &Path, _name: &str, _offset: u64, _bytes: &[u8]) {}
    /// No-op: no device can be attached in this build.
    #[inline]
    pub fn flush_file(_dir: &Path, _name: &str) {}
    /// No-op: reports that no device handled the directory sync.
    #[inline]
    pub fn sync_dir(_dir: &Path) -> bool {
        false
    }
    /// No-op: no device can be attached in this build.
    #[inline]
    pub fn record_remove(_dir: &Path, _name: &str) {}
    /// No-op: no device handled the watermark write.
    #[inline]
    pub fn write_watermark(
        _dir: &Path,
        _wm: &crate::watermark::Watermark,
    ) -> Option<crate::error::Result<()>> {
        None
    }
}

pub mod query;
pub mod readpath;
pub mod record;
pub mod segment;
pub mod snapshot;
pub mod stats;
pub mod suffix;
pub mod transaction;
pub mod trigram;
pub mod uring;
pub mod volume;
pub mod watermark;

pub use error::{FsError, OrfsError, Result};
pub use fuse_uring::{FuseUringNegotiation, FuseUringReport, TransportProfile};
pub use namespace::{Namespace, OrfsCore, RenameMode, SetAttr};
pub use query::{
    Credential, MatchFlow, QueryEngine, QueryMatch, QueryRequest, QueryResult, QueryStats,
};
pub use snapshot::{HistoricalRoot, Snapshot};

/// Crate version, surfaced by the CLI and evidence receipts.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The on-disk authoritative record format version implemented by this build.
pub const FORMAT_VERSION: u16 = 1;

/// Human-readable product name. `orfs` is the filesystem; `EKBLOOM` is the
/// acceleration technology. No additional competing product names are used.
pub const PRODUCT: &str = "OrFS";
