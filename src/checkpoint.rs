//! Index checkpoints and checkpoint-based mount recovery (research §23, §24).
//!
//! Full log replay is `O(|L|)`. OrFS therefore stores periodic **index
//! checkpoints inside the authoritative log**. A checkpoint record
//! (`INDEX_CHECKPOINT`) embeds the serialized namespace index at a committed
//! root together with integrity information (a BLAKE3 digest of the canonical
//! index, the asserted inode/dentry counts, and a payload CRC32C).
//!
//! On mount, [`mount_index`] performs exactly the research §24 procedure:
//!
//! 1. discover the newest valid authoritative index checkpoint;
//! 2. load and validate it;
//! 3. replay only the committed records after its root;
//! 4. reconstruct the latest committed state.
//!
//! If the newest checkpoint fails validation the next earlier one is tried; if
//! none is valid the index is rebuilt by full replay. A committed record is
//! **never** silently skipped: a corrupt checkpoint is an accelerator that is
//! discarded, never authoritative history.
//!
//! Checkpoints do not make mount constant-time. Discovery is an `O(#records)`
//! header scan (bodies are not materialised), and replay is
//! `O(bytes after the newest checkpoint)`. Both quantities, and the actual wall
//! time, are measured and reported in [`MountReport`] rather than claimed.

use std::time::Instant;

use crate::error::{OrfsError, Result};
use crate::index::Index;
use crate::log::Log;
use crate::namespace::IndexCheckpointPayload;
use crate::record::RecordType;

/// Where a mount/reconstruction learned the checkpoint it used.
///
/// This is the machine-readable statement of the **quick open vs. complete
/// audit** contract (docs/SNAPSHOTS.md §6, docs/RECOVERY.md §8): only
/// [`DiscoverySource::ValidatedAccelerator`] is a quick open, and it is the only
/// variant for which [`DiscoverySource::is_audit`] is `false`. Every other
/// variant read and validated authoritative records (a checkpoint record from the
/// log, and/or a full replay) before returning an index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    /// The index came from a persisted accelerator validated for exactly
    /// `(uuid, root)` (identity, root, whole-representation digest, committed
    /// boundary). This is a **quick open**: the log was *not* replayed.
    ValidatedAccelerator,
    /// Checkpoint locations came from the derived committed-root directory, but
    /// the checkpoint record itself was read from the log and fully validated,
    /// and the suffix was replayed. This is an **audit**.
    Catalogue,
    /// The authoritative header-only log scan discovered the checkpoint. This is
    /// an **audit**.
    LogScan,
    /// No checkpoint was usable: the index was rebuilt by full replay. This is
    /// the strongest form of **audit**.
    FullReplay,
}

impl DiscoverySource {
    /// Whether the reconstruction read and validated authoritative records.
    /// `false` only for a validated-accelerator quick open.
    pub fn is_audit(self) -> bool {
        !matches!(self, DiscoverySource::ValidatedAccelerator)
    }
}

/// A checkpoint found in the authoritative log during discovery.
#[derive(Debug, Clone)]
pub struct DiscoveredCheckpoint {
    /// The logical offset of the checkpoint record.
    pub offset: u64,
    /// The raw payload length in bytes.
    pub raw_len: usize,
    /// The decoded payload, or `None` when its framing/CRC did not validate.
    pub payload: Option<IndexCheckpointPayload>,
}

impl DiscoveredCheckpoint {
    /// The committed root this checkpoint reflects, if it decoded.
    pub fn root(&self) -> Option<u64> {
        self.payload.as_ref().map(|p| p.root)
    }
}

/// A truthful account of the mount/recovery work actually performed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MountReport {
    /// The committed root recovered (the log's committed end offset).
    pub target_root: u64,
    /// Whether a valid checkpoint was used (false means full replay).
    pub used_checkpoint: bool,
    /// The root of the checkpoint that was loaded, if any.
    pub checkpoint_root: Option<u64>,
    /// The logical offset of the checkpoint record that supplied the base, if any.
    pub checkpoint_offset: Option<u64>,
    /// How the checkpoint (if any) was discovered.
    pub discovery_source: DiscoverySource,
    /// Number of `INDEX_CHECKPOINT` records discovered in the committed log.
    pub checkpoints_found: usize,
    /// Number of discovered checkpoints that failed validation and were skipped.
    pub checkpoints_rejected: usize,
    /// Number of committed records replayed into the index (after the checkpoint,
    /// or the whole log on full replay).
    pub records_replayed: u64,
    /// Number of committed canonical bytes replayed.
    pub bytes_replayed: u64,
    /// Whether reconstruction fell back to a full replay from genesis.
    pub full_replay_fallback: bool,
    /// The measured wall-clock cost of index reconstruction, in microseconds.
    pub wall_micros: u128,
    /// The reconstructed index's live inode count.
    pub index_inode_count: usize,
    /// The reconstructed index's live dentry count.
    pub index_dentry_count: usize,
}

impl MountReport {
    /// Whether this reconstruction was a complete audit (as opposed to a
    /// validated-accelerator quick open).
    pub fn audited(&self) -> bool {
        self.discovery_source.is_audit()
    }

    /// A one-line human summary.
    pub fn describe(&self) -> String {
        let how = match self.discovery_source {
            DiscoverySource::ValidatedAccelerator => "quick open (validated accelerator)",
            DiscoverySource::Catalogue => "committed-root directory",
            DiscoverySource::LogScan => "log discovery scan",
            DiscoverySource::FullReplay => "full replay (no usable checkpoint)",
        };
        match self.checkpoint_root {
            Some(root) if !self.full_replay_fallback => format!(
                "index: loaded checkpoint at root {root} via {how}, replayed {} record(s)/{} byte(s) \
                 ({} checkpoint(s) examined, {} rejected) in {} µs",
                self.records_replayed,
                self.bytes_replayed,
                self.checkpoints_found,
                self.checkpoints_rejected,
                self.wall_micros
            ),
            _ => format!(
                "index: full replay of {} record(s)/{} byte(s) via {how} ({} checkpoint(s) \
                 examined, {} rejected) in {} µs",
                self.records_replayed,
                self.bytes_replayed,
                self.checkpoints_found,
                self.checkpoints_rejected,
                self.wall_micros
            ),
        }
    }
}

/// Discover every `INDEX_CHECKPOINT` record in the committed prefix `[0, end)`.
///
/// Discovery reads only record headers (and the bodies of checkpoint records),
/// so it does not materialise intervening `DATA_EXTENT` payloads.
pub fn discover_checkpoints(log: &Log, end: u64) -> Result<Vec<DiscoveredCheckpoint>> {
    let raw = log.scan_records_of_types(end, &[RecordType::IndexCheckpoint])?;
    Ok(raw
        .into_iter()
        .map(|r| DiscoveredCheckpoint {
            offset: r.offset,
            raw_len: r.payload.len(),
            payload: IndexCheckpointPayload::decode(&r.payload).ok(),
        })
        .collect())
}

/// Load and fully validate one checkpoint's embedded index against the log.
///
/// Validation is strict enough that a corrupt or foreign checkpoint cannot
/// masquerade as the authoritative state, without an `O(|index|)` re-encoding:
///
/// * the embedded snapshot must parse and pass its **own self-digest** (which
///   is exactly the digest the payload recorded), so a torn, truncated, or
///   tampered index body is rejected here; and the payload's CRC32C already
///   covers the body bytes;
/// * its root must equal the payload's declared root and be a committed
///   boundary within `[0, target]`;
/// * its inode/dentry counts must equal the payload's asserted counts.
fn load_checkpoint(log: &Log, payload: &IndexCheckpointPayload, target: u64) -> Result<Index> {
    if payload.root > target {
        return Err(OrfsError::Corrupt(format!(
            "checkpoint root {} exceeds the committed root {target}",
            payload.root
        )));
    }
    if payload.root != 0 && !log.is_boundary(payload.root) {
        return Err(OrfsError::Corrupt(format!(
            "checkpoint root {} is not a committed transaction boundary",
            payload.root
        )));
    }
    // `decode_snapshot` validates the embedded snapshot's self-digest, which is
    // the same digest recorded in `payload.digest` at write time.
    let index = Index::decode_snapshot(&payload.index_bytes)?;
    if index.root() != payload.root {
        return Err(OrfsError::Corrupt(format!(
            "checkpoint index root {} disagrees with payload root {}",
            index.root(),
            payload.root
        )));
    }
    if index.inode_count() as u64 != payload.inode_count
        || index.dentry_count() as u64 != payload.dentry_count
    {
        return Err(OrfsError::Corrupt(
            "checkpoint index counts disagree with the payload header".into(),
        ));
    }
    Ok(index)
}

/// Replay the committed records in `[start, end)` into `index`, returning
/// `(records, bytes)` replayed. `start` must be a committed boundary.
fn replay_from(log: &Log, index: &mut Index, start: u64, end: u64) -> Result<(u64, u64)> {
    let mut offset = start;
    let mut records = 0u64;
    let mut bytes = 0u64;
    for record in log.records_from(start, end) {
        let record = record?;
        let total = record.header.total_len().map_err(OrfsError::from)?;
        index.apply_record(&record, offset)?;
        records += 1;
        bytes = bytes.checked_add(total).ok_or(OrfsError::Overflow {
            what: "checkpoint replay bytes",
        })?;
        offset = offset.checked_add(total).ok_or(OrfsError::Overflow {
            what: "checkpoint replay offset",
        })?;
    }
    if index.root() != end {
        return Err(OrfsError::Corrupt(format!(
            "replay from checkpoint ended at root {} (expected {end})",
            index.root()
        )));
    }
    Ok((records, bytes))
}

/// A successful reconstruction from an in-log checkpoint.
struct CandidateOutcome {
    index: Index,
    checkpoint_root: u64,
    checkpoint_offset: u64,
    records_replayed: u64,
    bytes_replayed: u64,
}

/// Try each candidate checkpoint offset, newest first, returning the first whose
/// record reads, decodes, validates, and whose suffix replays to `end`.
///
/// `offsets` must be in ascending log order (the order both
/// [`Log::scan_record_offsets_of_types`] and the derived committed-root directory
/// produce them).
fn materialize_from_candidates(
    log: &Log,
    end: u64,
    offsets: &[u64],
) -> Result<(Option<CandidateOutcome>, usize)> {
    let mut rejected = 0usize;
    for &offset in offsets.iter().rev() {
        let record = match log.read_record_at(offset, end) {
            Ok(r) => r,
            Err(_) => {
                rejected += 1;
                continue;
            }
        };
        let Ok(payload) = IndexCheckpointPayload::decode(&record.payload) else {
            rejected += 1;
            continue;
        };
        match load_checkpoint(log, &payload, end) {
            Ok(mut index) => {
                let (records_replayed, bytes_replayed) =
                    replay_from(log, &mut index, payload.root, end)?;
                return Ok((
                    Some(CandidateOutcome {
                        index,
                        checkpoint_root: payload.root,
                        checkpoint_offset: offset,
                        records_replayed,
                        bytes_replayed,
                    }),
                    rejected,
                ));
            }
            Err(_) => rejected += 1,
        }
    }
    Ok((None, rejected))
}

/// The truthfully-measured outcome of the audited reconstruction at `target`.
struct Audit {
    index: Index,
    used_checkpoint: bool,
    checkpoint_root: Option<u64>,
    checkpoint_offset: Option<u64>,
    checkpoints_found: usize,
    checkpoints_rejected: usize,
    records_replayed: u64,
    bytes_replayed: u64,
    discovery_source: DiscoverySource,
}

/// Reconstruct the committed index at `target` by reading and validating
/// authoritative records (an **audit**).
///
/// Discovery order:
///
/// 1. the derived committed-root directory, when it is complete for `[0, target)`
///    (no whole-log scan);
/// 2. otherwise an authoritative header-only scan of the log.
///
/// A candidate discovered via the directory is still read from the log and fully
/// validated, and the suffix is replayed, so a corrupt or stale directory can only
/// cost a fallback — never a wrong result. If the directory supplies no usable
/// checkpoint the authoritative scan is performed anyway, so the fast path can
/// checkpoint the log has. When `use_catalogue` is `false` the
/// directory is ignored entirely (the pre-Phase-43 algorithm), which is what the
/// acceptance court measures as the "before" baseline. When `publish` is `false`
/// the derived directory is never written (used by read-only views and by the
/// pure-audit baseline).
fn audit_index(log: &Log, target: u64, use_catalogue: bool, publish: bool) -> Result<Audit> {
    if use_catalogue {
        if let Some(offsets) = crate::historical::catalogue_checkpoint_offsets(log, target) {
            let found = offsets.len();
            let (outcome, rejected) = materialize_from_candidates(log, target, &offsets)?;
            if let Some(out) = outcome {
                return Ok(Audit {
                    index: out.index,
                    used_checkpoint: true,
                    checkpoint_root: Some(out.checkpoint_root),
                    checkpoint_offset: Some(out.checkpoint_offset),
                    checkpoints_found: found,
                    checkpoints_rejected: rejected,
                    records_replayed: out.records_replayed,
                    bytes_replayed: out.bytes_replayed,
                    discovery_source: DiscoverySource::Catalogue,
                });
            }
            // The directory produced no usable checkpoint; never let it hide one.
        }
    }

    // Authoritative header-only discovery scan.
    let offsets = log.scan_record_offsets_of_types(target, &[RecordType::IndexCheckpoint])?;
    let found = offsets.len();
    let (outcome, rejected) = materialize_from_candidates(log, target, &offsets)?;
    // Publish the completed scan (best-effort) so the next mount need not rescan.
    // Never on a read-only view: a derived structure is not worth a write during a
    // read-only open.
    if publish && found > 0 {
        crate::historical::publish_catalogue_scan(log, &offsets, target);
    }
    match outcome {
        Some(out) => Ok(Audit {
            index: out.index,
            used_checkpoint: true,
            checkpoint_root: Some(out.checkpoint_root),
            checkpoint_offset: Some(out.checkpoint_offset),
            checkpoints_found: found,
            checkpoints_rejected: rejected,
            records_replayed: out.records_replayed,
            bytes_replayed: out.bytes_replayed,
            discovery_source: DiscoverySource::LogScan,
        }),
        None => {
            let index = Index::from_log(log, target)?;
            Ok(Audit {
                index,
                used_checkpoint: false,
                checkpoint_root: None,
                checkpoint_offset: None,
                checkpoints_found: found,
                checkpoints_rejected: rejected,
                records_replayed: log.committed_record_count(),
                bytes_replayed: target,
                discovery_source: DiscoverySource::FullReplay,
            })
        }
    }
}

/// Build the truthful mount report for one completed audited reconstruction.
fn mount_report_from(target: u64, audit: &Audit, started: Instant) -> MountReport {
    MountReport {
        target_root: target,
        used_checkpoint: audit.used_checkpoint,
        checkpoint_root: audit.checkpoint_root,
        checkpoint_offset: audit.checkpoint_offset,
        discovery_source: audit.discovery_source,
        checkpoints_found: audit.checkpoints_found,
        checkpoints_rejected: audit.checkpoints_rejected,
        records_replayed: audit.records_replayed,
        bytes_replayed: audit.bytes_replayed,
        full_replay_fallback: !audit.used_checkpoint,
        wall_micros: started.elapsed().as_micros(),
        index_inode_count: audit.index.inode_count(),
        index_dentry_count: audit.index.dentry_count(),
    }
}

/// Reconstruct the latest committed index, preferring the newest valid
/// checkpoint (research §24) and using the derived committed-root directory to
/// avoid a whole-log discovery scan when it is complete (research programme §7).
///
/// Discovery is a header-only scan (or a lookup in the derived directory); only
/// **one** checkpoint body is read (the newest that validates). If none
/// validates, the index is rebuilt by full replay. The approach is measured in
/// [`MountReport`], not claimed, and the report records exactly how the index was
/// obtained ([`DiscoverySource`]).
///
/// This is an **audit**: it always reads and validates authoritative records. For
/// a deliberate validated-accelerator quick open use [`open_index_quick`].
pub fn mount_index(log: &Log) -> Result<(Index, MountReport)> {
    let started = Instant::now();
    let target = log.committed_end_offset();
    let audit = audit_index(log, target, true, true)?;
    let report = mount_report_from(target, &audit, started);
    Ok((audit.index, report))
}

/// As [`mount_index`], but a **read-only audit**: it consults the derived
/// committed-root directory (so discovery stays fast) but never *publishes* to
/// it. Used by read-only opens, where writing derived state would be a surprise.
pub fn mount_index_readonly(log: &Log) -> Result<(Index, MountReport)> {
    let started = Instant::now();
    let target = log.committed_end_offset();
    let audit = audit_index(log, target, true, false)?;
    let report = mount_report_from(target, &audit, started);
    Ok((audit.index, report))
}

/// The pre-Phase-43 authoritative discovery path: a whole-log header scan for
/// checkpoints, ignoring the derived committed-root directory.
///
/// Exposed as the always-available **complete audit** and as the acceptance
/// court's "before" baseline. It never trusts any derived structure.
pub fn mount_index_scan(log: &Log) -> Result<(Index, MountReport)> {
    let started = Instant::now();
    let target = log.committed_end_offset();
    let audit = audit_index(log, target, false, false)?;
    let report = mount_report_from(target, &audit, started);
    Ok((audit.index, report))
}

/// A **validated quick open** of the committed root of `log`.
///
/// If a persisted accelerator for exactly `(uuid, root)` exists and validates,
/// it is returned with a report whose `discovery_source` is
/// [`DiscoverySource::ValidatedAccelerator`] and whose [`MountReport::audited`] is
/// `false`: this is a quick open using validated trusted state, **not** a complete
/// historical audit. If the accelerator is absent, torn, tampered, foreign, or
/// names a different root, the audited reconstruction ([`mount_index`]) is used
/// instead and its report says so. The result is identical either way (proved by
/// the Phase-43 tests); the difference is only what was verified.
pub fn open_index_quick(log: &Log) -> Result<(Index, MountReport)> {
    let started = Instant::now();
    let target = log.committed_end_offset();
    if let Some(index) = crate::historical::open_index_quick(log, target)? {
        let report = MountReport {
            target_root: target,
            used_checkpoint: false,
            checkpoint_root: None,
            checkpoint_offset: None,
            discovery_source: DiscoverySource::ValidatedAccelerator,
            checkpoints_found: 0,
            checkpoints_rejected: 0,
            records_replayed: 0,
            bytes_replayed: 0,
            full_replay_fallback: false,
            wall_micros: started.elapsed().as_micros(),
            index_inode_count: index.inode_count(),
            index_dentry_count: index.dentry_count(),
        };
        return Ok((index, report));
    }
    mount_index(log)
}

/// A truthful account of a **historical** index materialization (Phase 20).
///
/// Unlike [`MountReport`] this targets an arbitrary committed boundary `root`
/// (not necessarily the head), so it deliberately omits a record count: the
/// point of the historical path is that the work is proportional to the suffix
/// `[checkpoint_root, root)`, which `bytes_replayed` reports directly.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HistoricalMountReport {
    /// The historical root that was materialized.
    pub root: u64,
    /// Whether a valid in-log checkpoint at or before `root` supplied the base.
    pub used_checkpoint: bool,
    /// The root of the checkpoint used as the base, if any.
    pub checkpoint_root: Option<u64>,
    /// The logical offset of the checkpoint record used as the base, if any.
    pub checkpoint_offset: Option<u64>,
    /// How the checkpoint (if any) was discovered.
    pub discovery_source: DiscoverySource,
    /// Number of `INDEX_CHECKPOINT` records discovered in the prefix `[0, root)`.
    pub checkpoints_found: usize,
    /// Number of discovered checkpoints that failed validation and were skipped.
    pub checkpoints_rejected: usize,
    /// Number of committed canonical bytes replayed (`root - checkpoint_root`, or
    /// `root` on a full-replay fallback).
    pub bytes_replayed: u64,
    /// Whether reconstruction fell back to a full replay from genesis.
    pub full_replay_fallback: bool,
    /// The measured wall-clock cost of materialization, in microseconds.
    pub wall_micros: u128,
    /// The materialized index's live inode count.
    pub index_inode_count: usize,
    /// The materialized index's live dentry count.
    pub index_dentry_count: usize,
}

/// Materialize the committed index at an arbitrary committed boundary `root`
/// (not necessarily the head), preferring the newest valid checkpoint at or
/// before `root` and replaying only the suffix `[checkpoint_root, root)`.
///
/// This is the historical-root analogue of [`mount_index`]: discovery covers only
/// the prefix `[0, root)` (records committed *after* `root` can never contribute
/// to a historical view), and replay begins at a checkpoint boundary via
/// [`Log::records_from`], so the work is proportional to the distance from the
/// nearest checkpoint, never to the total retained history. When the derived
/// committed-root directory is complete for `[0, root)` the whole-prefix scan is
/// avoided entirely.
///
/// The result is bit-identical to a full replay of `L[0:root]` (proved by the
/// Phase 20 tests); a corrupt checkpoint is a discarded accelerator and the log
/// always wins. This is an **audit** ([`DiscoverySource::Catalogue`],
/// [`DiscoverySource::LogScan`], or [`DiscoverySource::FullReplay`]).
pub fn mount_index_at(log: &Log, root: u64) -> Result<(Index, HistoricalMountReport)> {
    let started = Instant::now();
    let target = log.committed_end_offset();
    if root > target {
        return Err(OrfsError::InvalidArgument(format!(
            "historical index root {root} exceeds the committed root {target}"
        )));
    }
    if root != 0 && !log.is_boundary(root) {
        return Err(OrfsError::InvalidArgument(format!(
            "historical index root {root} is not a committed transaction boundary"
        )));
    }
    let audit = audit_index(log, root, true, false)?;
    let report = HistoricalMountReport {
        root,
        used_checkpoint: audit.used_checkpoint,
        checkpoint_root: audit.checkpoint_root,
        checkpoint_offset: audit.checkpoint_offset,
        discovery_source: audit.discovery_source,
        checkpoints_found: audit.checkpoints_found,
        checkpoints_rejected: audit.checkpoints_rejected,
        bytes_replayed: audit.bytes_replayed,
        full_replay_fallback: !audit.used_checkpoint,
        wall_micros: started.elapsed().as_micros(),
        index_inode_count: audit.index.inode_count(),
        index_dentry_count: audit.index.dentry_count(),
    };
    Ok((audit.index, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_describes_both_paths() {
        let full = MountReport {
            target_root: 100,
            used_checkpoint: false,
            checkpoint_root: None,
            checkpoint_offset: None,
            discovery_source: DiscoverySource::FullReplay,
            checkpoints_found: 0,
            checkpoints_rejected: 0,
            records_replayed: 4,
            bytes_replayed: 100,
            full_replay_fallback: true,
            wall_micros: 7,
            index_inode_count: 1,
            index_dentry_count: 0,
        };
        assert!(full.describe().contains("full replay"));
        assert!(full.audited());
        let cp = MountReport {
            used_checkpoint: true,
            checkpoint_root: Some(50),
            checkpoint_offset: Some(1234),
            discovery_source: DiscoverySource::Catalogue,
            full_replay_fallback: false,
            ..full.clone()
        };
        assert!(cp.describe().contains("loaded checkpoint at root 50"));
        assert!(cp.describe().contains("committed-root directory"));
        assert!(cp.audited());
        // Only a validated-accelerator open is not an audit.
        let quick = MountReport {
            used_checkpoint: false,
            checkpoint_root: None,
            discovery_source: DiscoverySource::ValidatedAccelerator,
            full_replay_fallback: false,
            ..full
        };
        assert!(!quick.audited());
        assert!(quick.describe().contains("quick open"));
    }
}
