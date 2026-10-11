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
    /// A one-line human summary.
    pub fn describe(&self) -> String {
        match self.checkpoint_root {
            Some(root) if !self.full_replay_fallback => format!(
                "index: loaded checkpoint at root {root}, replayed {} record(s)/{} byte(s) \
                 ({} checkpoint(s) examined, {} rejected) in {} µs",
                self.records_replayed,
                self.bytes_replayed,
                self.checkpoints_found,
                self.checkpoints_rejected,
                self.wall_micros
            ),
            _ => format!(
                "index: full replay of {} record(s)/{} byte(s) ({} checkpoint(s) examined, \
                 {} rejected) in {} µs",
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

/// Reconstruct the latest committed index, preferring the newest valid
/// checkpoint (research §24). This is the checkpoint-aware mount path.
///
/// Discovery is a header-only scan; only **one** checkpoint body is read (the
/// newest that validates). If none validates, the index is rebuilt by full
/// replay. The approach is measured in [`MountReport`], not claimed.
pub fn mount_index(log: &Log) -> Result<(Index, MountReport)> {
    let started = Instant::now();
    let target = log.committed_end_offset();
    let offsets = log.scan_record_offsets_of_types(target, &[RecordType::IndexCheckpoint])?;
    let checkpoints_found = offsets.len();
    let mut checkpoints_rejected = 0usize;

    // Newest checkpoint first. Read and validate exactly one body at a time; an
    // earlier valid checkpoint is the documented fallback when a more recent one
    // fails validation.
    for &offset in offsets.iter().rev() {
        let record = match log.read_record_at(offset, target) {
            Ok(r) => r,
            Err(_) => {
                checkpoints_rejected += 1;
                continue;
            }
        };
        let Ok(payload) = IndexCheckpointPayload::decode(&record.payload) else {
            checkpoints_rejected += 1;
            continue;
        };
        match load_checkpoint(log, &payload, target) {
            Ok(mut index) => {
                let (records_replayed, bytes_replayed) =
                    replay_from(log, &mut index, payload.root, target)?;
                let report = MountReport {
                    target_root: target,
                    used_checkpoint: true,
                    checkpoint_root: Some(payload.root),
                    checkpoints_found,
                    checkpoints_rejected,
                    records_replayed,
                    bytes_replayed,
                    full_replay_fallback: false,
                    wall_micros: started.elapsed().as_micros(),
                    index_inode_count: index.inode_count(),
                    index_dentry_count: index.dentry_count(),
                };
                return Ok((index, report));
            }
            Err(_) => checkpoints_rejected += 1,
        }
    }

    // No valid checkpoint: rebuild from genesis, the authoritative fallback.
    let index = Index::from_log(log, target)?;
    let report = MountReport {
        target_root: target,
        used_checkpoint: false,
        checkpoint_root: None,
        checkpoints_found,
        checkpoints_rejected,
        records_replayed: log.committed_record_count(),
        bytes_replayed: target,
        full_replay_fallback: true,
        wall_micros: started.elapsed().as_micros(),
        index_inode_count: index.inode_count(),
        index_dentry_count: index.dentry_count(),
    };
    Ok((index, report))
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
/// This is the historical-root analogue of [`mount_index`]: discovery scans only
/// the prefix `[0, root)` (records committed *after* `root` can never contribute
/// to a historical view), and replay begins at a checkpoint boundary via
/// [`Log::records_from`], so the work is proportional to the distance from the
/// nearest checkpoint, never to the total retained history.
///
/// The result is bit-identical to a full replay of `L[0:root]` (proved by the
/// Phase 20 tests); a corrupt checkpoint is a discarded accelerator and the log
/// always wins.
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
    // Scan only [0, root): a historical view can never depend on later records.
    let offsets = log.scan_record_offsets_of_types(root, &[RecordType::IndexCheckpoint])?;
    let checkpoints_found = offsets.len();
    let mut checkpoints_rejected = 0usize;

    for &offset in offsets.iter().rev() {
        let record = match log.read_record_at(offset, root) {
            Ok(r) => r,
            Err(_) => {
                checkpoints_rejected += 1;
                continue;
            }
        };
        let Ok(payload) = IndexCheckpointPayload::decode(&record.payload) else {
            checkpoints_rejected += 1;
            continue;
        };
        match load_checkpoint(log, &payload, root) {
            Ok(mut index) => {
                let (_, bytes_replayed) = replay_from(log, &mut index, payload.root, root)?;
                let report = HistoricalMountReport {
                    root,
                    used_checkpoint: true,
                    checkpoint_root: Some(payload.root),
                    checkpoints_found,
                    checkpoints_rejected,
                    bytes_replayed,
                    full_replay_fallback: false,
                    wall_micros: started.elapsed().as_micros(),
                    index_inode_count: index.inode_count(),
                    index_dentry_count: index.dentry_count(),
                };
                return Ok((index, report));
            }
            Err(_) => checkpoints_rejected += 1,
        }
    }

    let index = Index::from_log(log, root)?;
    let report = HistoricalMountReport {
        root,
        used_checkpoint: false,
        checkpoint_root: None,
        checkpoints_found,
        checkpoints_rejected,
        bytes_replayed: root,
        full_replay_fallback: true,
        wall_micros: started.elapsed().as_micros(),
        index_inode_count: index.inode_count(),
        index_dentry_count: index.dentry_count(),
    };
    Ok((index, report))
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
        let cp = MountReport {
            used_checkpoint: true,
            checkpoint_root: Some(50),
            full_replay_fallback: false,
            ..full
        };
        assert!(cp.describe().contains("loaded checkpoint at root 50"));
    }
}
