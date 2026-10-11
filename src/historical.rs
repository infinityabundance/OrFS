//! Persistent, cached historical-root indexes (Phase 20; external review §3D).
//!
//! Reconstructing the namespace at a historical root `(uuid, R)` means replaying
//! the committed prefix `L[0:R]`. Before this phase, [`crate::namespace::Namespace::view`]
//! called [`Index::from_log`] on **every** request that named a non-current root,
//! so repeated historical lookups each paid a full replay.
//!
//! A **root is immutable**: once `R` is committed, the prefix `L[0:R]` never
//! changes (Law I: history is never withdrawn). The index reconstructed from it is
//! therefore also immutable and needs **no invalidation**. This module resolves a
//! historical root **once**, verifies it, and reuses it across arbitrarily many
//! lookups and reads:
//!
//! * an **in-memory LRU cache** keyed by `(volume uuid, root)` with a bounded
//!   number of entries, so the working set of hot historical roots is served
//!   without any replay; and
//! * a **persisted derived accelerator** under `index/historical/`, validated on
//!   load (schema + uuid + root + self-digest + committed boundary) so it can be
//!   reused across remounts.
//!
//! # The log always wins
//!
//! Neither layer is authoritative. The in-memory index is only ever produced by
//! the same [`Index`] replay the log yields ([`crate::checkpoint::mount_index_at`],
//! which prefers an in-log checkpoint and replays only the suffix). A persisted
//! accelerator is *derived*: if it is absent, torn, tampered, foreign (wrong
//! uuid), or names a root that is not a committed boundary, it is dropped and the
//! index is rebuilt from the log. A derived file never overrides committed
//! history.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::checkpoint::{self, HistoricalMountReport};
use crate::error::{OrfsError, Result};
use crate::index::Index;
use crate::log::Log;
use crate::snapshot::HistoricalRoot;

/// Schema tag for a persisted historical-index accelerator.
pub const HISTORICAL_INDEX_SCHEMA: &str = "orfs.historical-index.v1";

/// Default in-memory cache capacity (number of distinct historical roots).
///
/// Bounded so a workload that walks a long tail of historical roots cannot pin
/// unbounded memory; least-recently-used entries are evicted first.
pub const DEFAULT_CACHE_CAPACITY: usize = 8;

/// The persisted accelerator document for one historical root.
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

/// The path of the persisted accelerator for `root` under the volume's `index/`
/// directory.
pub fn historical_index_path(index_dir: &Path, root: u64) -> PathBuf {
    index_dir.join("historical").join(format!("{root}.v1.json"))
}

/// Encode a historical index as a validated accelerator document.
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

/// Decode a historical accelerator document, rejecting it unless it is a valid,
/// self-consistent document for exactly `(uuid, expected_root)`.
///
/// The inner `Index::decode_snapshot` re-validates the embedded index's own
/// self-digest, so there are two independent integrity checks (the envelope
/// digest and the inner digest) before any state is trusted.
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
    let index = Index::decode_snapshot(inner)?;
    if index.root() != expected_root {
        return Err(OrfsError::Corrupt(format!(
            "historical index snapshot root {} does not match {expected_root}",
            index.root()
        )));
    }
    Ok(index)
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
    let path = historical_index_path(index_dir, root);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)?;
    match decode_historical(&bytes, uuid, root) {
        Ok(index) => Ok(Some(index)),
        Err(_) => Ok(None),
    }
}

/// Persist `index` as the historical accelerator for its root. Best-effort via a
/// temp file + rename so a torn write can never masquerade as a valid accelerator.
pub fn persist_historical(index_dir: &Path, uuid: &[u8; 16], index: &Index) -> Result<()> {
    let bytes = encode_historical(index, uuid)?;
    let path = historical_index_path(index_dir, index.root());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

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
    /// replay was performed.
    pub reused: bool,
    /// `true` when the value was served from the in-memory cache.
    pub memory_hit: bool,
    /// `true` when the value was served from the persisted accelerator.
    pub persisted_hit: bool,
    /// The materialization report, present only on a cold miss.
    pub materialization: Option<HistoricalMountReport>,
}

/// A bounded in-memory cache of immutable historical-root indexes, backed by an
/// optional persisted accelerator directory.
///
/// # Bound
///
/// The in-memory map holds at most `capacity` roots and evicts the
/// least-recently-used entry when full. The persisted layer holds one small JSON
/// document per *resolved* root; it is written only when a root is first
/// materialized, never for a cache hit.
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
                    materialization: None,
                },
            ));
        }

        // 2. Persisted accelerator: validated, else dropped (log wins).
        if let Some(dir) = self.index_dir.clone() {
            if let Ok(Some(index)) = load_persisted_historical(&dir, &self.uuid, root) {
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
                        materialization: None,
                    },
                ));
            }
        }

        // 3. Cold miss: materialize from the log, preferring an in-log checkpoint
        //    so the replay is a suffix, never the whole history.
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
        // enough to exercise the envelope's validation branches.
        Index::empty()
    }

    #[test]
    fn historical_envelope_round_trips() {
        let uuid = [7u8; 16];
        let index = sample_index();
        let bytes = encode_historical(&index, &uuid).unwrap();
        let decoded = decode_historical(&bytes, &uuid, index.root()).unwrap();
        assert_eq!(decoded, index);
    }

    #[test]
    fn historical_envelope_rejects_foreign_uuid_and_root() {
        let uuid = [7u8; 16];
        let index = sample_index();
        let bytes = encode_historical(&index, &uuid).unwrap();
        // Wrong uuid.
        assert!(decode_historical(&bytes, &[9u8; 16], index.root()).is_err());
        // Wrong root.
        assert!(decode_historical(&bytes, &uuid, index.root() + 1).is_err());
    }

    #[test]
    fn historical_envelope_rejects_tampering() {
        let uuid = [7u8; 16];
        let index = sample_index();
        let mut bytes = encode_historical(&index, &uuid).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        assert!(decode_historical(&bytes, &uuid, index.root()).is_err());
    }

    #[test]
    fn lru_evicts_beyond_capacity() {
        let cache = HistoricalIndexCache::new([0u8; 16], None, 2);
        for root in 0..5u64 {
            cache.insert(root, Arc::new(Index::empty()));
        }
        assert_eq!(cache.resident(), 2);
        // The most recently inserted roots survive.
        assert!(cache.memory_hit(4).is_some());
        assert!(cache.memory_hit(3).is_some());
        assert!(cache.memory_hit(0).is_none());
    }
}
