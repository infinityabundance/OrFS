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

pub mod capabilities;
pub mod error;
pub mod log;
pub mod record;
pub mod segment;
pub mod volume;

pub use error::{FsError, OrfsError, Result};

/// Crate version, surfaced by the CLI and evidence receipts.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The on-disk authoritative record format version implemented by this build.
pub const FORMAT_VERSION: u16 = 1;

/// Human-readable product name. `orfs` is the filesystem; `EKBLOOM` is the
/// acceleration technology. No additional competing product names are used.
pub const PRODUCT: &str = "OrFS";
