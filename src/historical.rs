//! Persistent, cached historical-root indexes (Phase 20; external review §3D),
//! the immutable binary accelerator format (Phase 43), and the derived
//! committed-root directory (Phase 43).
//!
//! Reconstructing the namespace at a historical root `(uuid, R)` means replaying
//! the committed prefix `L[0:R]`. Before Phase 20, [`crate::namespace::Namespace::view`]
//! called [`Index::from_log`] on **every** request that named a non-current root,
//! so repeated historical lookups each paid a full replay. This module resolves a
//! historical root **once**, verifies it, and reuses it across arbitrarily many
//! lookups and reads:
//!
//! * an **in-memory LRU cache** keyed by `(volume uuid, root)` with a bounded
//!   number of entries, so the working set of hot historical roots is served
//!   without any replay;
//! * a **persisted derived accelerator** under `index/historical/`, validated on
//!   load (identity, root, whole-representation digest, committed boundary) so it
//!   can be reused across remounts; and
//! * a **committed-root directory** under `index/roots/` — an append-only,
//!   reconstructible catalogue of checkpoint locations and verified
//!   historical-index locations, so an ordinary restart or a historical-root open
//!   can locate an in-log checkpoint **without a whole-log discovery scan**.
//!
//! # The log always wins
//!
//! None of these layers is authoritative. The in-memory index is only ever
//! produced by the same [`Index`] replay the log yields. A persisted accelerator
//! is *derived*: if it is absent, torn, tampered, foreign (wrong uuid), or names a
//! root that is not a committed boundary, it is dropped and the index is rebuilt
//! from the log. The committed-root directory is likewise derived and
//! reconstructible: every entry it holds is re-validated against the log before it
//! is used, and a directory that cannot be trusted is ignored. A derived structure
//! never overrides committed history.
//!
//! # Quick open vs. complete audit
//!
//! These are two deliberately distinct operations and must never be confused:
//!
//! * A **quick open** ([`HistoricalIndexCache`] persisted hit, [`load_persisted_historical`],
//!   [`crate::checkpoint::open_index_quick`]) reuses a persisted accelerator that
//!   has been validated for *exactly* `(uuid, root)` and self-consistency. It is
//!   fast, but it asserts only what the validated accelerator says: it has not
//!   re-replayed the log. Callers that need authoritative verification must use
//!   the audited reconstruction ([`crate::checkpoint::mount_index`],
//!   [`crate::checkpoint::mount_index_at`]), which reads and validates the
//!   authoritative records.
//! * A **complete audit** reads checkpoint and log records and replays them; its
//!   report carries a [`crate::checkpoint::DiscoverySource`] that is *not*
//!   [`crate::checkpoint::DiscoverySource::ValidatedAccelerator`].
//!
//! If the derived directory (or an accelerator) is corrupt, missing, or cannot be
//! trusted, the audited reconstruction remains available and is used; the fast
//! path never fabricates history it has not verified.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::checkpoint::{self, HistoricalMountReport};
use crate::error::{OrfsError, Result};
use crate::index::Index;
use crate::log::Log;
use crate::snapshot::HistoricalRoot;

/// Schema tag for the **legacy** (JSON) persisted historical-index accelerator.
///
/// Retained for backward compatibility: a volume written by an older OrFS still
/// has `index/historical/<root>.v1.json`, and OrFS keeps reading it. New writes
/// use the binary form ([`HISTORICAL_ACCELERATOR_MAGIC`]).
pub const HISTORICAL_INDEX_SCHEMA: &str = "orfs.historical-index.v1";

/// Magic of the immutable **binary** historical-accelerator container.
pub const HISTORICAL_ACCELERATOR_MAGIC: [u8; 8] = *b"ORFSHIX2";
/// Container format version of the binary accelerator.
pub const HISTORICAL_ACCELERATOR_VERSION: u32 = 2;
/// Fixed header length of the binary accelerator container.
pub const HISTORICAL_ACCELERATOR_HEADER_LEN: usize = 88;
/// Trailing whole-representation BLAKE3 digest length.
pub const HISTORICAL_ACCELERATOR_DIGEST_LEN: usize = 32;

/// Default in-memory cache capacity (number of distinct historical roots).
///
/// Bounded so a workload that walks a long tail of historical roots cannot pin
/// unbounded memory; least-recently-used entries are evicted first.
pub const DEFAULT_CACHE_CAPACITY: usize = 8;

/// Subdirectory (under `<volume>/index/`) holding the committed-root directory.
pub const ROOT_CATALOGUE_DIR: &str = "roots";

/// The persisted accelerator document for one historical root (legacy JSON form).
///
/// `snapshot` is the exact [`Index::encode_snapshot`] document (its JSON text),
/// `digest` is BLAKE3 over that document's bytes, and `uuid`/`root` bind the
/// accelerator to one volume and one committed boundary so it can never be
/// reinterpreted against another volume or root.
#[derive(serde::Serialize, serde::Deserialize)]
struct HistoricalIndexFile {
    schema: String,
    uuid: String,
    root: u64,
    digest: String,
    snapshot: String,
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn uuid_string(uuid: &[u8; 16]) -> String {
    HistoricalRoot::new(*uuid, 0).uuid_string()
}

/// The path of the **legacy** persisted accelerator for `root` under the volume's
/// `index/` directory (JSON form; read-only backward compatibility).
pub fn historical_index_path(index_dir: &Path, root: u64) -> PathBuf {
    index_dir.join("historical").join(format!("{root}.v1.json"))
}

/// The path of the **binary** persisted accelerator for `root`.
pub fn historical_accelerator_path(index_dir: &Path, root: u64) -> PathBuf {
    index_dir.join("historical").join(format!("{root}.v2.bin"))
}

// ---------------------------------------------------------------------------
// Binary accelerator container (Phase 43)
// ---------------------------------------------------------------------------

fn accel_u32(b: &[u8], off: usize) -> Result<u32> {
    let end = off.checked_add(4).ok_or(OrfsError::Overflow {
        what: "accelerator offset",
    })?;
    let s = b
        .get(off..end)
        .ok_or_else(|| OrfsError::Corrupt("historical accelerator is truncated".into()))?;
    Ok(u32::from_le_bytes(s.try_into().expect("4 bytes")))
}

fn accel_u64(b: &[u8], off: usize) -> Result<u64> {
    let end = off.checked_add(8).ok_or(OrfsError::Overflow {
        what: "accelerator offset",
    })?;
    let s = b
        .get(off..end)
        .ok_or_else(|| OrfsError::Corrupt("historical accelerator is truncated".into()))?;
    Ok(u64::from_le_bytes(s.try_into().expect("8 bytes")))
}

/// Encode `index` as an immutable, versioned **binary** accelerator.
///
/// Layout (little-endian):
///
/// ```text
///   off  size field
///   0    8    magic  = "ORFSHIX2"
///   8    4    version = 2
///   12   4    header_len = 88
///   16   16   volume uuid
///   32   8    root
///   40   8    blob_offset (= header_len)
///   48   8    blob_len
///   56   8    asserted inode count
///   64   8    asserted dentry count
///   72   4    flags (0)
///   76   4    reserved (0)
///   80   8    reserved (0)
///   88   ..   packed index blob (explicit table of contents; see `Index::encode_packed`)
///   end  32   BLAKE3 digest over every preceding byte
/// ```
///
/// The header is deliberately tiny and independently validated; the embedded blob
/// carries its own table of contents so its inode/directory tables are directly
/// addressable. The trailing digest covers the whole representation, so no mapped
/// byte is trusted before it has been checked.
pub fn encode_historical_accelerator(index: &Index, uuid: &[u8; 16]) -> Result<Vec<u8>> {
    let blob = index.encode_packed();
    let mut out = Vec::with_capacity(HISTORICAL_ACCELERATOR_HEADER_LEN + blob.len() + 32);
    out.extend_from_slice(&HISTORICAL_ACCELERATOR_MAGIC);
    out.extend_from_slice(&HISTORICAL_ACCELERATOR_VERSION.to_le_bytes());
    out.extend_from_slice(&(HISTORICAL_ACCELERATOR_HEADER_LEN as u32).to_le_bytes());
    out.extend_from_slice(uuid);
    out.extend_from_slice(&index.root().to_le_bytes());
    out.extend_from_slice(&(HISTORICAL_ACCELERATOR_HEADER_LEN as u64).to_le_bytes());
    out.extend_from_slice(&(blob.len() as u64).to_le_bytes());
    out.extend_from_slice(&(index.inode_count() as u64).to_le_bytes());
    out.extend_from_slice(&(index.dentry_count() as u64).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    debug_assert_eq!(out.len(), HISTORICAL_ACCELERATOR_HEADER_LEN);
    out.extend_from_slice(&blob);
    let digest = blake3::hash(&out);
    out.extend_from_slice(digest.as_bytes());
    Ok(out)
}

/// Decode a binary accelerator, rejecting it unless it is a valid,
/// self-consistent document for exactly `(uuid, expected_root)`.
///
/// Validation is strictly ordered so that **no untrusted byte is parsed**:
///
/// 1. the container is long enough and the header's own fields agree;
/// 2. the magic, format version, and declared header length are exact;
/// 3. the volume uuid and root match `(uuid, expected_root)`;
/// 4. the declared offsets/lengths tile the file exactly (checked arithmetic);
/// 5. the whole-representation BLAKE3 digest matches.
///
/// Only after step 5 is the packed inode/directory table decoded, and only after
/// that are the asserted inode/dentry counts and root cross-checked.
pub fn decode_historical_accelerator(
    bytes: &[u8],
    uuid: &[u8; 16],
    expected_root: u64,
) -> Result<Index> {
    let hdr = HISTORICAL_ACCELERATOR_HEADER_LEN;
    let min = hdr + HISTORICAL_ACCELERATOR_DIGEST_LEN;
    if bytes.len() < min {
        return Err(OrfsError::Corrupt(
            "historical accelerator is shorter than its header + digest".into(),
        ));
    }
    if bytes.get(0..8) != Some(&HISTORICAL_ACCELERATOR_MAGIC[..]) {
        return Err(OrfsError::Corrupt(
            "historical accelerator bad magic".into(),
        ));
    }
    let version = accel_u32(bytes, 8)?;
    if version != HISTORICAL_ACCELERATOR_VERSION {
        return Err(OrfsError::Compatibility(format!(
            "historical accelerator version {version}"
        )));
    }
    if accel_u32(bytes, 12)? as usize != hdr {
        return Err(OrfsError::Corrupt(
            "historical accelerator header length disagreement".into(),
        ));
    }
    if bytes.get(16..32) != Some(&uuid[..]) {
        return Err(OrfsError::Corrupt(
            "historical accelerator names a different volume".into(),
        ));
    }
    let root = accel_u64(bytes, 32)?;
    if root != expected_root {
        return Err(OrfsError::Corrupt(format!(
            "historical accelerator root {root} does not match {expected_root}"
        )));
    }
    let blob_offset = usize::try_from(accel_u64(bytes, 40)?).map_err(|_| OrfsError::Overflow {
        what: "accelerator blob offset",
    })?;
    let blob_len = usize::try_from(accel_u64(bytes, 48)?).map_err(|_| OrfsError::Overflow {
        what: "accelerator blob length",
    })?;
    let inode_count = accel_u64(bytes, 56)?;
    let dentry_count = accel_u64(bytes, 64)?;
    if blob_offset != hdr {
        return Err(OrfsError::Corrupt(
            "historical accelerator blob offset is not the header length".into(),
        ));
    }
    let body_end = blob_offset
        .checked_add(blob_len)
        .ok_or(OrfsError::Overflow {
            what: "accelerator body end",
        })?;
    let file_end = body_end
        .checked_add(HISTORICAL_ACCELERATOR_DIGEST_LEN)
        .ok_or(OrfsError::Overflow {
            what: "accelerator file end",
        })?;
    if file_end != bytes.len() {
        return Err(OrfsError::Corrupt(
            "historical accelerator length disagreement (torn or truncated)".into(),
        ));
    }
    // Whole-representation digest, verified before any blob byte is decoded.
    let stored = blake3::hash(&bytes[..body_end]);
    if stored.as_bytes() != &bytes[body_end..file_end] {
        return Err(OrfsError::Corrupt(
            "historical accelerator digest mismatch (tampered or torn)".into(),
        ));
    }
    let index = Index::decode_packed(&bytes[blob_offset..body_end])?;
    if index.root() != expected_root {
        return Err(OrfsError::Corrupt(format!(
            "historically accelerated index root {} does not match {expected_root}",
            index.root()
        )));
    }
    if index.inode_count() as u64 != inode_count || index.dentry_count() as u64 != dentry_count {
        return Err(OrfsError::Corrupt(
            "historical accelerator index counts disagree with the header".into(),
        ));
    }
    Ok(index)
}

/// A read-only memory mapping of one file.
///
/// Used so the accelerator's small header and digest can be validated directly
/// from mapped, page-cache-backed bytes without materialising the file into an
/// owned `Vec`. Falls back to an ordinary read when `mmap` is unavailable.
struct MappedFile {
    ptr: *mut libc::c_void,
    len: usize,
}

impl MappedFile {
    fn open(path: &Path) -> Option<MappedFile> {
        let file = File::open(path).ok()?;
        let len = usize::try_from(file.metadata().ok()?.len()).ok()?;
        if len == 0 {
            return None;
        }
        // SAFETY: `fd` is a valid read-only descriptor and the mapping is private,
        // read-only, and released in `Drop` with the same length.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return None;
        }
        Some(MappedFile { ptr, len })
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: the mapping is valid for `self.len` readable bytes for as long as
        // `self` is alive and is never mutated.
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`len` came from `libc::mmap` in `open` and are unmapped once.
        unsafe {
            libc::munmap(self.ptr, self.len);
        }
    }
}

/// Load the binary accelerator for `(uuid, root)` under `index_dir`, if present
/// and valid. Returns the decoded index and the number of bytes examined.
pub fn load_historical_accelerator(
    index_dir: &Path,
    uuid: &[u8; 16],
    root: u64,
) -> Result<Option<(Index, u64)>> {
    let path = historical_accelerator_path(index_dir, root);
    if let Some(mapped) = MappedFile::open(&path) {
        let bytes = mapped.as_slice();
        return match decode_historical_accelerator(bytes, uuid, root) {
            Ok(index) => Ok(Some((index, bytes.len() as u64))),
            Err(_) => Ok(None),
        };
    }
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)?;
    match decode_historical_accelerator(&bytes, uuid, root) {
        Ok(index) => Ok(Some((index, bytes.len() as u64))),
        Err(_) => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Legacy (JSON) accelerator — backward-compatible read
// ---------------------------------------------------------------------------

/// Encode a historical index as a validated accelerator document (legacy JSON).
///
/// New writes use [`encode_historical_accelerator`]; this remains so a volume
/// written by an older OrFS is still readable, and so the legacy path stays
/// exercised by tests.
pub fn encode_historical(index: &Index, uuid: &[u8; 16]) -> Result<Vec<u8>> {
    let inner = index.encode_snapshot()?;
    let digest = hex32(blake3::hash(&inner).as_bytes());
    let snapshot = String::from_utf8(inner)
        .map_err(|e| OrfsError::Corrupt(format!("historical index is not utf-8: {e}")))?;
    let file = HistoricalIndexFile {
        schema: HISTORICAL_INDEX_SCHEMA.to_string(),
        uuid: uuid_string(uuid),
        root: index.root(),
        digest,
        snapshot,
    };
    let mut out = serde_json::to_vec_pretty(&file)
        .map_err(|e| OrfsError::Corrupt(format!("historical index encode: {e}")))?;
    out.push(b'\n');
    Ok(out)
}

/// Decode a legacy JSON accelerator document, rejecting it unless it is a valid,
/// self-consistent document for exactly `(uuid, expected_root)`.
pub fn decode_historical(bytes: &[u8], uuid: &[u8; 16], expected_root: u64) -> Result<Index> {
    let file: HistoricalIndexFile = serde_json::from_slice(bytes)
        .map_err(|e| OrfsError::Corrupt(format!("historical index decode: {e}")))?;
    if file.schema != HISTORICAL_INDEX_SCHEMA {
        return Err(OrfsError::Compatibility(format!(
            "historical index schema {}",
            file.schema
        )));
    }
    if file.uuid != uuid_string(uuid) {
        return Err(OrfsError::Corrupt(
            "historical index names a different volume".into(),
        ));
    }
    if file.root != expected_root {
        return Err(OrfsError::Corrupt(format!(
            "historical index root {} does not match {expected_root}",
            file.root
        )));
    }
    let inner = file.snapshot.as_bytes();
    if file.digest != hex32(blake3::hash(inner).as_bytes()) {
        return Err(OrfsError::Corrupt(
            "historical index digest mismatch (tampered or torn)".into(),
        ));
    }
    let mut index = Index::decode_snapshot(inner)?;
    if index.root() != expected_root {
        return Err(OrfsError::Corrupt(format!(
            "historical index snapshot root {} does not match {expected_root}",
            index.root()
        )));
    }
    // The legacy JSON accelerator is also an immutable historical root, so seal
    // the inode-id spine (Phase 58) exactly as the binary form does.
    index.seal_inodes();
    Ok(index)
}

/// Which on-disk form an accelerator was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceleratorFormat {
    /// The immutable binary container ([`encode_historical_accelerator`]).
    Binary,
    /// The legacy JSON envelope (backward-compatible read).
    LegacyJson,
}

/// What a persisted-accelerator load examined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct AcceleratorLoadReport {
    /// The on-disk form that was read.
    pub format: AcceleratorFormat,
    /// Bytes examined (the whole file for the JSON form; the file size for the
    /// binary form, whose digest covers every byte).
    pub bytes: u64,
}

/// Load the persisted historical accelerator for `(uuid, root)` under `index_dir`,
/// preferring the binary form and falling back to the legacy JSON form.
pub fn load_persisted_historical_traced(
    index_dir: &Path,
    uuid: &[u8; 16],
    root: u64,
) -> Result<(Option<Index>, Option<AcceleratorLoadReport>)> {
    if let Some((index, bytes)) = load_historical_accelerator(index_dir, uuid, root)? {
        return Ok((
            Some(index),
            Some(AcceleratorLoadReport {
                format: AcceleratorFormat::Binary,
                bytes,
            }),
        ));
    }
    let legacy = historical_index_path(index_dir, root);
    if legacy.exists() {
        let bytes = std::fs::read(&legacy)?;
        if let Ok(index) = decode_historical(&bytes, uuid, root) {
            return Ok((
                Some(index),
                Some(AcceleratorLoadReport {
                    format: AcceleratorFormat::LegacyJson,
                    bytes: bytes.len() as u64,
                }),
            ));
        }
    }
    Ok((None, None))
}

/// Load the persisted historical accelerator for `(uuid, root)` under `index_dir`,
/// if present and valid.
///
/// Returns `Ok(None)` for an absent file, or when it fails to validate; a derived
/// accelerator never overrides the log.
pub fn load_persisted_historical(
    index_dir: &Path,
    uuid: &[u8; 16],
    root: u64,
) -> Result<Option<Index>> {
    Ok(load_persisted_historical_traced(index_dir, uuid, root)?.0)
}

/// Persist `index` as the historical accelerator for its root, in the immutable
/// binary form. Best-effort via a temp file + rename so a torn write can never
/// masquerade as a valid accelerator.
///
/// The verified location is also recorded (best-effort) in the volume's
/// committed-root directory, so a later open knows a validated accelerator exists
/// for this root.
pub fn persist_historical(index_dir: &Path, uuid: &[u8; 16], index: &Index) -> Result<()> {
    let bytes = encode_historical_accelerator(index, uuid)?;
    let path = historical_accelerator_path(index_dir, index.root());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, &path)?;
    if let Some(volume_root) = index_dir.parent() {
        let digest: [u8; 32] = bytes[bytes.len() - 32..]
            .try_into()
            .expect("accelerator footer digest");
        let _ = RootCatalogue::new(volume_root).record_accelerator(index.root(), digest);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Committed-root directory (Phase 43)
// ---------------------------------------------------------------------------
//
// An append-only, reconstructible catalogue of *derived discovery facts* about
// the committed log:
//
// ```text
//   index/roots/CURRENT          pointer to the active segment ("ORCQ")
//   index/roots/seg-<n:010>.cat  fixed-size CRC32C-framed records, append-only
//   index/roots/sum-<n:010>.sum  folded "latest per key" summary
// ```
//
// * **Non-withdrawal** — a sealed segment is never rewritten; publication only
//   appends. The authoritative log is untouched.
// * **Torn-safety** — every record is fixed-size and CRC32C-checked; a torn or
//   truncated tail is detected and skipped, and a corrupt summary is ignored so a
//   reader falls back to an earlier summary or a full segment replay.
// * **Reconstructible** — the directory is derived: it is rebuildable from the
//   authoritative log at any time, and every entry it holds is re-validated
//   against the log before use. It never asserts history the log does not have.

const RC_FAMILY: u32 = 0x4F52_4352; // "ORCR"
const RC_SCHEMA: u32 = 1;
const RC_POINTER_MAGIC: u32 = 0x4F52_4351; // "ORCQ"
const RC_SUMMARY_MAGIC: u32 = 0x4F52_4355; // "ORCU"
/// A record body is fixed-size: `kind`, `watermark`, `offset`, `root`, `digest`.
const RC_RECORD_BODY: usize = 4 + 8 + 8 + 8 + 32;
/// Bytes of one on-disk record (`body_len` + body + `crc32c`).
const RC_RECORD_BYTES: u64 = RC_RECORD_BODY as u64 + 8;
/// Seal the active segment once it reaches this size (immutable thereafter).
const RC_SEGMENT_BYTES: u64 = 128 * 1024;

/// A directory record: a checkpoint location.
pub const ROOT_ENTRY_CHECKPOINT: u32 = 0;
/// A directory record: a verified persisted historical-index location.
pub const ROOT_ENTRY_HISTORICAL: u32 = 1;
/// A directory record: the committed root a completed discovery scan covered.
pub const ROOT_ENTRY_WATERMARK: u32 = 2;

/// One immutable committed-root directory record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootEntry {
    /// [`ROOT_ENTRY_CHECKPOINT`], [`ROOT_ENTRY_HISTORICAL`], or
    /// [`ROOT_ENTRY_WATERMARK`].
    pub kind: u32,
    /// The committed root the publishing scan covered (`0` for historical-index
    /// records, which make no completeness claim).
    pub watermark: u64,
    /// The logical offset of the checkpoint record (checkpoints only).
    pub offset: u64,
    /// The root the record names: the accelerator root (historical) or the
    /// committed root (watermark). `0` for checkpoint records, whose root is
    /// recovered from the validated record at read time.
    pub root: u64,
    /// The verified accelerator's whole-representation digest (historical only).
    pub digest: [u8; 32],
}

impl RootEntry {
    fn body(&self) -> Vec<u8> {
        let mut b = vec![0u8; RC_RECORD_BODY];
        crate::record::put_u32(&mut b, 0, self.kind);
        crate::record::put_u64(&mut b, 4, self.watermark);
        crate::record::put_u64(&mut b, 12, self.offset);
        crate::record::put_u64(&mut b, 20, self.root);
        b[28..60].copy_from_slice(&self.digest);
        b
    }

    /// The framed record: `[body_len:u32][body][crc32c:u32]` where the checksum
    /// covers `body_len || body`.
    fn encode_record(&self) -> Vec<u8> {
        let body = self.body();
        let mut out = Vec::with_capacity(body.len() + 8);
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        let crc = crc32c::crc32c(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    /// Decode one framed record, returning the entry and the bytes consumed, or
    /// `None` for any torn/truncated/corrupt/wrong-family record.
    fn decode_record(bytes: &[u8]) -> Option<(RootEntry, usize)> {
        if bytes.len() < 8 {
            return None;
        }
        let len = u32::from_le_bytes(bytes[0..4].try_into().ok()?) as usize;
        if len != RC_RECORD_BODY {
            return None;
        }
        let total = len + 8;
        if bytes.len() < total {
            return None;
        }
        let stored = u32::from_le_bytes(bytes[len + 4..len + 8].try_into().ok()?);
        if crc32c::crc32c(&bytes[..len + 4]) != stored {
            return None;
        }
        let kind = crate::record::get_u32(&bytes[4..4 + len], 0);
        if kind > ROOT_ENTRY_WATERMARK {
            return None;
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[4 + 28..4 + 60]);
        Some((
            RootEntry {
                kind,
                watermark: crate::record::get_u64(&bytes[4..], 4),
                offset: crate::record::get_u64(&bytes[4..], 12),
                root: crate::record::get_u64(&bytes[4..], 20),
                digest,
            },
            total,
        ))
    }
}

/// The folded directory: the newest record per `(kind, root, offset)` key.
type RootFold = BTreeMap<(u32, u64, u64), RootEntry>;

/// The derived, append-only committed-root directory for one volume.
#[derive(Debug, Clone)]
pub struct RootCatalogue {
    dir: PathBuf,
}

impl RootCatalogue {
    /// The directory under `<volume>/index/roots/`.
    pub fn new(volume_root: &Path) -> RootCatalogue {
        RootCatalogue {
            dir: volume_root.join("index").join(ROOT_CATALOGUE_DIR),
        }
    }

    /// The backing directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn pointer_path(&self) -> PathBuf {
        self.dir.join("CURRENT")
    }

    fn segment_path(&self, index: u64) -> PathBuf {
        self.dir.join(format!("seg-{index:010}.cat"))
    }

    fn summary_path(&self, through: u64) -> PathBuf {
        self.dir.join(format!("sum-{through:010}.sum"))
    }

    /// The active segment index.
    ///
    /// * If `CURRENT` decodes, it names the segment subsequent appends target
    ///   (written by [`RootCatalogue::seal`] before a segment is summarised).
    /// * If `CURRENT` is absent the last segment has never been sealed, so it is
    ///   the active one.
    /// * If `CURRENT` is present but torn it may name a *sealed* segment, so a
    ///   fresh segment after the highest existing one is used to be safe.
    fn active_segment(&self) -> u64 {
        match fs::read(self.pointer_path()) {
            Ok(b) => match decode_rc_pointer(&b) {
                Some(idx) => idx,
                None => self.segment_indices().last().map(|s| s + 1).unwrap_or(0),
            },
            Err(_) => self.segment_indices().last().copied().unwrap_or(0),
        }
    }

    fn segment_indices(&self) -> Vec<u64> {
        named_indices(&self.dir, "seg-", ".cat")
    }

    fn summary_indices(&self) -> Vec<u64> {
        named_indices(&self.dir, "sum-", ".sum")
    }

    /// Whether the directory has no segments (a fresh or pre-directory volume).
    pub fn is_empty(&self) -> bool {
        self.segment_indices().is_empty()
    }

    /// Append one immutable record, sealing the segment if it grows past
    /// [`RC_SEGMENT_BYTES`]. Returns whether the append sealed the segment.
    fn append(&self, entry: &RootEntry) -> Result<bool> {
        fs::create_dir_all(&self.dir)?;
        let index = self.active_segment();
        let record = entry.encode_record();
        let size = {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.segment_path(index))?;
            f.write_all(&record)?;
            f.sync_all()?;
            f.metadata()?.len()
        };
        if size >= RC_SEGMENT_BYTES {
            self.seal(index)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn seal(&self, index: u64) -> Result<()> {
        self.write_pointer(index + 1)?;
        let (folded, count) = self.fold_through(index);
        let bytes = encode_rc_summary(index, count, &folded);
        write_atomic(&self.summary_path(index), &bytes)?;
        crate::segment::fsync_dir(&self.dir)?;
        Ok(())
    }

    fn write_pointer(&self, index: u64) -> Result<()> {
        write_atomic(&self.pointer_path(), &encode_rc_pointer(index))
    }

    fn read_segment(&self, index: u64) -> Vec<RootEntry> {
        let Ok(bytes) = fs::read(self.segment_path(index)) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + RC_RECORD_BYTES as usize <= bytes.len() {
            match RootEntry::decode_record(&bytes[off..]) {
                Some((e, used)) => {
                    out.push(e);
                    off += used;
                }
                None => break,
            }
        }
        out
    }

    fn read_summary(&self, through: u64) -> Option<(RootFold, u64)> {
        let bytes = fs::read(self.summary_path(through)).ok()?;
        decode_rc_summary(&bytes, through)
    }

    /// The folded "latest per key" map through segment `through`, reusing the
    /// newest usable summary at or below it so a seal reads only a suffix.
    fn fold_through(&self, through: u64) -> (RootFold, u64) {
        let mut sums = self.summary_indices();
        sums.reverse();
        let mut base = None;
        for s in sums {
            if s > through {
                continue;
            }
            if let Some((map, count)) = self.read_summary(s) {
                base = Some((s, map, count));
                break;
            }
        }
        let (start, mut map, mut count) = match base {
            Some((s, m, c)) => (s + 1, m, c),
            None => (0u64, BTreeMap::new(), 0u64),
        };
        for seg in self.segment_indices() {
            if seg < start || seg > through {
                continue;
            }
            for e in self.read_segment(seg) {
                count += 1;
                map.insert((e.kind, e.root, e.offset), e);
            }
        }
        (map, count)
    }

    /// The folded directory, or `None` when it is absent or cannot be trusted.
    ///
    /// A contiguous run of segments from `0` is required: a hole means a whole
    /// segment was lost, so the directory cannot be trusted for discovery and the
    /// caller must fall back to an authoritative scan (never silently miss a
    /// checkpoint).
    fn fold(&self) -> Option<(RootFold, u64)> {
        let segments = self.segment_indices();
        let active = *segments.last()?;
        if self.active_segment() < active {
            return None;
        }
        if segments.len() as u64 != active + 1 {
            return None;
        }
        let (map, count) = self.fold_through(active);
        if map.is_empty() {
            return None;
        }
        Some((map, count))
    }

    /// The greatest committed root this directory is complete up to, or `None`
    /// when the directory is absent or unusable. A completed discovery scan over
    /// `[0, W)` publishes a watermark record, so `W` is a sound completeness bound
    /// for checkpoint locations.
    pub fn watermark(&self) -> Option<u64> {
        let (map, _) = self.fold()?;
        map.values()
            .filter(|e| e.kind == ROOT_ENTRY_WATERMARK)
            .map(|e| e.root)
            .max()
    }

    /// Every checkpoint record offset the directory records within `[0, end)`,
    /// newest (largest offset) first.
    ///
    /// `None` when the directory is absent/unusable **or** is not complete for
    /// `[0, end)`; the caller must then scan authoritatively.
    pub fn checkpoint_offsets_below(&self, end: u64) -> Option<Vec<u64>> {
        let (map, _) = self.fold()?;
        let watermark = map
            .values()
            .filter(|e| e.kind == ROOT_ENTRY_WATERMARK)
            .map(|e| e.root)
            .max()?;
        if watermark < end {
            return None;
        }
        let mut offs: Vec<u64> = map
            .values()
            .filter(|e| e.kind == ROOT_ENTRY_CHECKPOINT && e.offset < end)
            .map(|e| e.offset)
            .collect();
        offs.sort_unstable();
        offs.dedup();
        Some(offs)
    }

    /// The recorded whole-representation digest of the verified accelerator for
    /// `root`, if the directory knows one.
    pub fn historical_digest(&self, root: u64) -> Option<[u8; 32]> {
        let (map, _) = self.fold()?;
        map.get(&(ROOT_ENTRY_HISTORICAL, root, 0)).map(|e| e.digest)
    }

    /// Publish the outcome of a **completed discovery scan** over `[0, watermark)`:
    /// every checkpoint offset found, followed by a watermark record. Entries
    /// already known are not rewritten. Returns how many records were appended.
    ///
    /// The watermark record is appended *last*, so a crash mid-publication can
    /// never claim completeness the scan did not establish.
    pub fn publish(&self, watermark: u64, checkpoint_offsets: &[u64]) -> Result<usize> {
        let mut known = match self.fold() {
            Some((map, _)) => map,
            None => {
                // A directory that exists but cannot be folded must not be
                // extended (that would deepen the damage); only a fresh one is
                // safe to start.
                if !self.is_empty() {
                    return Ok(0);
                }
                BTreeMap::new()
            }
        };
        let mut appended = 0usize;
        for &offset in checkpoint_offsets {
            let key = (ROOT_ENTRY_CHECKPOINT, 0, offset);
            if known.contains_key(&key) {
                continue;
            }
            let entry = RootEntry {
                kind: ROOT_ENTRY_CHECKPOINT,
                watermark,
                offset,
                root: 0,
                digest: [0u8; 32],
            };
            self.append(&entry)?;
            known.insert(key, entry);
            appended += 1;
        }
        let wkey = (ROOT_ENTRY_WATERMARK, watermark, 0);
        if !known.contains_key(&wkey) {
            self.append(&RootEntry {
                kind: ROOT_ENTRY_WATERMARK,
                watermark,
                offset: 0,
                root: watermark,
                digest: [0u8; 32],
            })?;
            appended += 1;
        }
        Ok(appended)
    }

    /// Record a verified persisted accelerator location (best-effort, no
    /// completeness claim — `watermark` stays `0`).
    pub fn record_accelerator(&self, root: u64, digest: [u8; 32]) -> Result<()> {
        let known = self.fold();
        if known.is_none() && !self.is_empty() {
            return Ok(());
        }
        let map = known.map(|(m, _)| m).unwrap_or_default();
        if map.contains_key(&(ROOT_ENTRY_HISTORICAL, root, 0)) {
            return Ok(());
        }
        self.append(&RootEntry {
            kind: ROOT_ENTRY_HISTORICAL,
            watermark: 0,
            offset: 0,
            root,
            digest,
        })?;
        Ok(())
    }
}

fn named_indices(dir: &Path, prefix: &str, suffix: &str) -> Vec<u64> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for ent in rd.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if let Some(stem) = name
                .strip_prefix(prefix)
                .and_then(|s| s.strip_suffix(suffix))
            {
                if let Ok(i) = stem.parse::<u64>() {
                    out.push(i);
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn encode_rc_pointer(index: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(20);
    body.extend_from_slice(&RC_POINTER_MAGIC.to_le_bytes());
    body.extend_from_slice(&RC_SCHEMA.to_le_bytes());
    body.extend_from_slice(&RC_FAMILY.to_le_bytes());
    body.extend_from_slice(&index.to_le_bytes());
    let mut out = body.clone();
    out.extend_from_slice(&crc32c::crc32c(&body).to_le_bytes());
    out
}

fn decode_rc_pointer(bytes: &[u8]) -> Option<u64> {
    let body = bytes.get(..bytes.len().checked_sub(4)?)?;
    let stored = u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().ok()?);
    if crc32c::crc32c(body) != stored {
        return None;
    }
    if body.len() != 20
        || crate::record::get_u32(body, 0) != RC_POINTER_MAGIC
        || crate::record::get_u32(body, 4) != RC_SCHEMA
        || crate::record::get_u32(body, 8) != RC_FAMILY
    {
        return None;
    }
    Some(crate::record::get_u64(body, 12))
}

fn encode_rc_summary(through: u64, count: u64, folded: &RootFold) -> Vec<u8> {
    let mut body = Vec::with_capacity(24 + folded.len() * RC_RECORD_BODY);
    body.extend_from_slice(&RC_SUMMARY_MAGIC.to_le_bytes());
    body.extend_from_slice(&RC_SCHEMA.to_le_bytes());
    body.extend_from_slice(&RC_FAMILY.to_le_bytes());
    body.extend_from_slice(&(folded.len() as u32).to_le_bytes());
    body.extend_from_slice(&through.to_le_bytes());
    body.extend_from_slice(&count.to_le_bytes());
    for entry in folded.values() {
        body.extend_from_slice(&entry.body());
    }
    let mut out = body.clone();
    out.extend_from_slice(&crc32c::crc32c(&body).to_le_bytes());
    out
}

fn decode_rc_summary(bytes: &[u8], through: u64) -> Option<(RootFold, u64)> {
    let body = bytes.get(..bytes.len().checked_sub(4)?)?;
    let stored = u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().ok()?);
    if crc32c::crc32c(body) != stored {
        return None;
    }
    if body.len() < 32
        || crate::record::get_u32(body, 0) != RC_SUMMARY_MAGIC
        || crate::record::get_u32(body, 4) != RC_SCHEMA
        || crate::record::get_u32(body, 8) != RC_FAMILY
    {
        return None;
    }
    let n = crate::record::get_u32(body, 12) as usize;
    if crate::record::get_u64(body, 16) != through {
        return None;
    }
    let count = crate::record::get_u64(body, 24);
    if body.len() != 32 + n.checked_mul(RC_RECORD_BODY)? {
        return None;
    }
    let mut map = BTreeMap::new();
    for i in 0..n {
        let off = 32 + i * RC_RECORD_BODY;
        let kind = crate::record::get_u32(body, off);
        if kind > ROOT_ENTRY_WATERMARK {
            return None;
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&body[off + 28..off + 60]);
        let entry = RootEntry {
            kind,
            watermark: crate::record::get_u64(body, off + 4),
            offset: crate::record::get_u64(body, off + 12),
            root: crate::record::get_u64(body, off + 20),
            digest,
        };
        map.insert((entry.kind, entry.root, entry.offset), entry);
    }
    Some((map, count))
}

/// Atomic small-file write: `tmp` → fsync → rename → fsync(dir).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        crate::segment::fsync_dir(dir)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Accelerated discovery used by `checkpoint::mount_index{,_at}`
// ---------------------------------------------------------------------------

/// The volume root that owns `log`'s supporting directories.
fn volume_root_of(log: &Log) -> Option<&Path> {
    log.dir().parent()
}

/// Checkpoint record offsets at or below `end`, taken from the derived
/// committed-root directory when it is complete for `[0, end)`; otherwise `None`
/// and the caller must scan the log authoritatively.
///
/// A directory that claims a completeness bound *beyond* the log's committed root
/// is over-claiming (itself corruption) and is distrusted.
pub fn catalogue_checkpoint_offsets(log: &Log, end: u64) -> Option<Vec<u64>> {
    let catalogue = RootCatalogue::new(volume_root_of(log)?);
    let watermark = catalogue.watermark()?;
    if watermark > log.committed_end_offset() {
        return None;
    }
    catalogue.checkpoint_offsets_below(end)
}

/// Publish a completed discovery scan of `[0, watermark)` into the volume's
/// committed-root directory (best-effort: failures never affect recovery).
pub fn publish_catalogue_scan(log: &Log, checkpoint_offsets: &[u64], watermark: u64) {
    if checkpoint_offsets.is_empty() && watermark == 0 {
        return;
    }
    let Some(root) = volume_root_of(log) else {
        return;
    };
    let _ = RootCatalogue::new(root).publish(watermark, checkpoint_offsets);
}

/// The volume uuid, read from the volume metadata next to `log`.
fn volume_uuid_of(log: &Log) -> Option<[u8; 16]> {
    crate::volume::Volume::read_meta(volume_root_of(log)?)
        .ok()
        .map(|m| m.uuid)
}

/// A **validated quick open**: load a persisted accelerator for exactly the
/// committed root of `log`, if one is present and valid.
///
/// This is *not* an audit: it never replays the log. It is exposed so the
/// distinction between a quick open and a complete audit is explicit in the API,
/// and so callers can opt into it deliberately. A missing, torn, tampered, or
/// foreign accelerator returns `Ok(None)` and the caller must fall back to
/// [`checkpoint::mount_index`].
pub fn open_index_quick(log: &Log, root: u64) -> Result<Option<Index>> {
    if root != 0 && !log.is_boundary(root) {
        return Ok(None);
    }
    let Some(volume_root) = volume_root_of(log) else {
        return Ok(None);
    };
    let uuid = match crate::volume::Volume::read_meta(volume_root) {
        Ok(meta) => meta.uuid,
        Err(_) => return Ok(None),
    };
    let index_dir = volume_root.join("index");
    Ok(load_historical_accelerator(&index_dir, &uuid, root)?.map(|(index, _)| index))
}

/// Publish a validated accelerator for the recovered committed root, so a later
/// restart at the same root can be a validated quick open.
pub fn publish_head_accelerator(log: &Log, index: &Index) -> Result<()> {
    let Some(volume_root) = volume_root_of(log) else {
        return Ok(());
    };
    let Some(uuid) = volume_uuid_of(log) else {
        return Ok(());
    };
    persist_historical(&volume_root.join("index"), &uuid, index)
}

// ---------------------------------------------------------------------------
// In-memory cache
// ---------------------------------------------------------------------------

/// How a historical index was obtained for one access.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct HistoricalAccessCounts {
    /// Immutable in-memory hits.
    pub memory_hits: u64,
    /// Validated persisted-accelerator hits (reused across remounts).
    pub persisted_hits: u64,
    /// Cold materializations from the log (checkpoint suffix replay or full).
    pub materializations: u64,
    /// Materializations that used an in-log checkpoint base.
    pub checkpoint_bases: u64,
    /// Total canonical bytes replayed across all materializations.
    pub bytes_replayed: u64,
    /// Total wall time spent in materialization, in microseconds.
    pub materialize_micros: u128,
    /// Bytes examined loading validated persisted accelerators.
    pub accelerator_bytes: u64,
}

impl HistoricalAccessCounts {
    /// Total resolved accesses (hits + cold materializations).
    pub fn accesses(&self) -> u64 {
        self.memory_hits + self.persisted_hits + self.materializations
    }
}

/// The observable outcome of one historical-index resolution.
#[derive(Debug, Clone)]
pub struct HistoricalAccess {
    /// The root that was resolved.
    pub root: u64,
    /// `true` when the index came from a cache (memory or persisted), so no log
    /// replay was performed. A persisted hit is a **validated quick open**.
    pub reused: bool,
    /// `true` when the value was served from the in-memory cache.
    pub memory_hit: bool,
    /// `true` when the value was served from the persisted accelerator.
    pub persisted_hit: bool,
    /// The on-disk form the persisted accelerator was read from, if any.
    pub accelerator_format: Option<AcceleratorFormat>,
    /// The materialization report, present only on a cold miss.
    pub materialization: Option<HistoricalMountReport>,
}

/// A bounded in-memory cache of immutable historical-root indexes, backed by an
/// optional persisted accelerator directory.
///
/// # Bound
///
/// The in-memory map holds at most `capacity` roots and evicts the
/// least-recently-used entry when full. The persisted layer holds one small file
/// per *resolved* root; it is written only when a root is first materialized,
/// never for a cache hit.
pub struct HistoricalIndexCache {
    uuid: [u8; 16],
    capacity: usize,
    index_dir: Option<PathBuf>,
    inner: parking_lot::Mutex<CacheInner>,
    memory_hits: AtomicU64,
    persisted_hits: AtomicU64,
    materializations: AtomicU64,
    checkpoint_bases: AtomicU64,
    bytes_replayed: AtomicU64,
    materialize_micros: AtomicU64,
    accelerator_bytes: AtomicU64,
}

struct CacheInner {
    entries: HashMap<u64, CacheEntry>,
    clock: u64,
}

struct CacheEntry {
    index: Arc<Index>,
    last_used: u64,
}

impl HistoricalIndexCache {
    /// A cache for one volume, persisting accelerators under `index_dir` when
    /// supplied, holding at most `capacity` in-memory entries.
    pub fn new(
        uuid: [u8; 16],
        index_dir: Option<PathBuf>,
        capacity: usize,
    ) -> HistoricalIndexCache {
        HistoricalIndexCache {
            uuid,
            capacity: capacity.max(1),
            index_dir,
            inner: parking_lot::Mutex::new(CacheInner {
                entries: HashMap::new(),
                clock: 0,
            }),
            memory_hits: AtomicU64::new(0),
            persisted_hits: AtomicU64::new(0),
            materializations: AtomicU64::new(0),
            checkpoint_bases: AtomicU64::new(0),
            bytes_replayed: AtomicU64::new(0),
            materialize_micros: AtomicU64::new(0),
            accelerator_bytes: AtomicU64::new(0),
        }
    }

    /// A cache with the default capacity.
    pub fn with_default_capacity(
        uuid: [u8; 16],
        index_dir: Option<PathBuf>,
    ) -> HistoricalIndexCache {
        HistoricalIndexCache::new(uuid, index_dir, DEFAULT_CACHE_CAPACITY)
    }

    /// The configured in-memory capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The number of roots currently resident in memory.
    pub fn resident(&self) -> usize {
        self.inner.lock().entries.len()
    }

    /// A snapshot of the access counters.
    pub fn counts(&self) -> HistoricalAccessCounts {
        HistoricalAccessCounts {
            memory_hits: self.memory_hits.load(Ordering::Relaxed),
            persisted_hits: self.persisted_hits.load(Ordering::Relaxed),
            materializations: self.materializations.load(Ordering::Relaxed),
            checkpoint_bases: self.checkpoint_bases.load(Ordering::Relaxed),
            bytes_replayed: self.bytes_replayed.load(Ordering::Relaxed),
            materialize_micros: self.materialize_micros.load(Ordering::Relaxed) as u128,
            accelerator_bytes: self.accelerator_bytes.load(Ordering::Relaxed),
        }
    }

    /// Resolve the historical index at `root`, reusing a cached/replayed value.
    ///
    /// This is the hot path: no report is constructed.
    pub fn resolve(&self, log: &Log, root: u64) -> Result<Arc<Index>> {
        Ok(self.resolve_traced(log, root)?.0)
    }

    /// Resolve the historical index at `root` and report how it was obtained.
    ///
    /// `root` must be a committed transaction boundary (or `0`) that does not
    /// exceed the committed root, otherwise `Err(InvalidArgument)`.
    pub fn resolve_traced(&self, log: &Log, root: u64) -> Result<(Arc<Index>, HistoricalAccess)> {
        if root > log.committed_end_offset() {
            return Err(OrfsError::InvalidArgument(format!(
                "historical root {root} exceeds the committed root {}",
                log.committed_end_offset()
            )));
        }
        if root != 0 && !log.is_boundary(root) {
            return Err(OrfsError::InvalidArgument(format!(
                "historical root {root} is not a committed transaction boundary"
            )));
        }

        // 1. In-memory hit: an immutable index never changes, so no invalidation.
        if let Some(index) = self.memory_hit(root) {
            self.memory_hits.fetch_add(1, Ordering::Relaxed);
            return Ok((
                index,
                HistoricalAccess {
                    root,
                    reused: true,
                    memory_hit: true,
                    persisted_hit: false,
                    accelerator_format: None,
                    materialization: None,
                },
            ));
        }

        // 2. Persisted accelerator: validated, else dropped (log wins). This is a
        //    validated quick open — it does not replay the log.
        if let Some(dir) = self.index_dir.clone() {
            if let Ok((Some(index), report)) =
                load_persisted_historical_traced(&dir, &self.uuid, root)
            {
                if let Some(r) = report {
                    self.accelerator_bytes.fetch_add(r.bytes, Ordering::Relaxed);
                }
                let arc = Arc::new(index);
                self.insert(root, arc.clone());
                self.persisted_hits.fetch_add(1, Ordering::Relaxed);
                return Ok((
                    arc,
                    HistoricalAccess {
                        root,
                        reused: true,
                        memory_hit: false,
                        persisted_hit: true,
                        accelerator_format: report.map(|r| r.format),
                        materialization: None,
                    },
                ));
            }
        }

        // 3. Cold miss: materialize from the log, preferring an in-log checkpoint
        //    so the replay is a suffix, never the whole history. This is an audit.
        let (index, report) = checkpoint::mount_index_at(log, root)?;
        self.materializations.fetch_add(1, Ordering::Relaxed);
        if report.used_checkpoint {
            self.checkpoint_bases.fetch_add(1, Ordering::Relaxed);
        }
        self.bytes_replayed
            .fetch_add(report.bytes_replayed, Ordering::Relaxed);
        self.materialize_micros.fetch_add(
            u64::try_from(report.wall_micros).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        let arc = Arc::new(index);

        // Persist the accelerator (best-effort): a failure here never affects the
        // returned index, which came from the authoritative log.
        if let Some(dir) = &self.index_dir {
            let _ = persist_historical(dir, &self.uuid, &arc);
        }
        self.insert(root, arc.clone());
        Ok((
            arc,
            HistoricalAccess {
                root,
                reused: false,
                memory_hit: false,
                persisted_hit: false,
                accelerator_format: None,
                materialization: Some(report),
            },
        ))
    }

    fn memory_hit(&self, root: u64) -> Option<Arc<Index>> {
        let mut inner = self.inner.lock();
        inner.clock += 1;
        let clock = inner.clock;
        let entry = inner.entries.get_mut(&root)?;
        entry.last_used = clock;
        Some(entry.index.clone())
    }

    fn insert(&self, root: u64, index: Arc<Index>) {
        let mut inner = self.inner.lock();
        inner.clock += 1;
        let clock = inner.clock;
        inner.entries.insert(
            root,
            CacheEntry {
                index,
                last_used: clock,
            },
        );
        while inner.entries.len() > self.capacity {
            let victim = inner
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(&k, _)| k);
            match victim {
                Some(k) => {
                    inner.entries.remove(&k);
                }
                None => break,
            }
        }
    }
}

impl std::fmt::Debug for HistoricalIndexCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoricalIndexCache")
            .field("uuid", &uuid_string(&self.uuid))
            .field("capacity", &self.capacity)
            .field("index_dir", &self.index_dir)
            .field("resident", &self.resident())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_index() -> Index {
        // A minimal valid index: the empty index (root 0) round-trips, which is
        // enough to exercise the container's validation branches.
        Index::empty()
    }

    #[test]
    fn legacy_envelope_round_trips() {
        let uuid = [7u8; 16];
        let index = sample_index();
        let bytes = encode_historical(&index, &uuid).unwrap();
        let decoded = decode_historical(&bytes, &uuid, index.root()).unwrap();
        assert_eq!(decoded, index);
    }

    #[test]
    fn legacy_envelope_rejects_foreign_uuid_and_root() {
        let uuid = [7u8; 16];
        let index = sample_index();
        let bytes = encode_historical(&index, &uuid).unwrap();
        assert!(decode_historical(&bytes, &[9u8; 16], index.root()).is_err());
        assert!(decode_historical(&bytes, &uuid, index.root() + 1).is_err());
    }

    #[test]
    fn legacy_envelope_rejects_tampering() {
        let uuid = [7u8; 16];
        let index = sample_index();
        let mut bytes = encode_historical(&index, &uuid).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        assert!(decode_historical(&bytes, &uuid, index.root()).is_err());
    }

    #[test]
    fn binary_accelerator_round_trips_and_matches_legacy() {
        let uuid = [7u8; 16];
        let index = sample_index();
        let bytes = encode_historical_accelerator(&index, &uuid).unwrap();
        let decoded = decode_historical_accelerator(&bytes, &uuid, index.root()).unwrap();
        assert_eq!(decoded, index);
        // The binary format and the legacy JSON document decode to the same index.
        let legacy = encode_historical(&index, &uuid).unwrap();
        assert_eq!(
            decode_historical(&legacy, &uuid, index.root()).unwrap(),
            index
        );
    }

    #[test]
    fn binary_accelerator_header_is_small_and_explicit() {
        let uuid = [7u8; 16];
        let bytes = encode_historical_accelerator(&sample_index(), &uuid).unwrap();
        assert!(bytes.len() > HISTORICAL_ACCELERATOR_HEADER_LEN + 32);
        assert_eq!(
            u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize,
            HISTORICAL_ACCELERATOR_HEADER_LEN
        );
        // blob_offset == header_len, and blob+footer tiles the file exactly.
        let blob_off = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
        let blob_len = u64::from_le_bytes(bytes[48..56].try_into().unwrap()) as usize;
        assert_eq!(blob_off, HISTORICAL_ACCELERATOR_HEADER_LEN);
        assert_eq!(blob_off + blob_len + 32, bytes.len());
    }

    #[test]
    fn binary_accelerator_rejects_foreign_uuid_root_and_tampering() {
        let uuid = [7u8; 16];
        let index = sample_index();
        let bytes = encode_historical_accelerator(&index, &uuid).unwrap();
        assert!(decode_historical_accelerator(&bytes, &[9u8; 16], index.root()).is_err());
        assert!(decode_historical_accelerator(&bytes, &uuid, index.root() + 1).is_err());
        // Flip a blob byte: the whole-representation digest must catch it.
        let mut tampered = bytes.clone();
        let mid = HISTORICAL_ACCELERATOR_HEADER_LEN + 4;
        tampered[mid] ^= 0xFF;
        assert!(decode_historical_accelerator(&tampered, &uuid, index.root()).is_err());
        // Truncation (a torn write) must be rejected.
        assert!(
            decode_historical_accelerator(&bytes[..bytes.len() - 4], &uuid, index.root()).is_err()
        );
        assert!(decode_historical_accelerator(&bytes[..10], &uuid, index.root()).is_err());
    }

    #[test]
    fn lru_evicts_beyond_capacity() {
        let cache = HistoricalIndexCache::new([0u8; 16], None, 2);
        for root in 0..5u64 {
            cache.insert(root, Arc::new(Index::empty()));
        }
        assert_eq!(cache.resident(), 2);
        assert!(cache.memory_hit(4).is_some());
        assert!(cache.memory_hit(3).is_some());
        assert!(cache.memory_hit(0).is_none());
    }

    #[test]
    fn root_catalogue_watermark_and_checkpoints() {
        let td = tempfile::TempDir::new().unwrap();
        let cat = RootCatalogue::new(td.path());
        assert!(cat.is_empty());
        assert!(cat.watermark().is_none());
        assert!(cat.checkpoint_offsets_below(100).is_none());

        cat.publish(500, &[100, 300]).unwrap();
        assert_eq!(cat.watermark(), Some(500));
        // Complete for [0, 500): the offsets are returned in ascending log order.
        assert_eq!(cat.checkpoint_offsets_below(500), Some(vec![100, 300]));
        assert_eq!(cat.checkpoint_offsets_below(300), Some(vec![100]));
        // Not complete for [0, 501) or beyond: the caller must scan.
        assert!(cat.checkpoint_offsets_below(501).is_none());
        assert!(cat.checkpoint_offsets_below(900).is_none());

        // Extending the scan to a later root keeps old entries and adds new ones.
        cat.publish(900, &[100, 700]).unwrap();
        assert_eq!(cat.watermark(), Some(900));
        assert_eq!(cat.checkpoint_offsets_below(900), Some(vec![100, 300, 700]));

        // Historical-index locations are recorded without a completeness claim.
        cat.record_accelerator(300, [3u8; 32]).unwrap();
        assert_eq!(cat.historical_digest(300), Some([3u8; 32]));
        assert_eq!(cat.watermark(), Some(900), "accelerators never raise it");
    }

    #[test]
    fn root_catalogue_detects_a_hole_and_a_torn_tail() {
        let td = tempfile::TempDir::new().unwrap();
        let cat = RootCatalogue::new(td.path());
        cat.publish(100, &[50]).unwrap();
        // A torn record at the tail is simply skipped.
        let seg = cat.segment_path(0);
        {
            let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
            f.write_all(&[0xAB; 7]).unwrap();
            f.sync_all().unwrap();
        }
        assert_eq!(cat.watermark(), Some(100));
        // Removing an interior segment is a hole; the directory must not be
        // trusted for discovery.
        fs::write(cat.segment_path(2), b"x").unwrap();
        assert!(cat.fold().is_none() || cat.watermark().is_none());
    }
}
