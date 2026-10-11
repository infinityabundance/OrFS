//! The authoritative append-only logical log (§4, §5.4, §21, §23).
//!
//! # Model
//!
//! `or.log` is a **canonical logical byte stream**: the concatenation, in order,
//! of every *committed* record. A **root** `R` is the committed end offset — a
//! position in that stream, never a content hash (§2, I2). A root is only ever
//! published when a complete, valid `TX_COMMIT` (or the `VOLUME_GENESIS` record)
//! has been appended, so every root sits exactly on a transaction boundary
//! (§5.4, §23).
//!
//! Physically the stream is realized as immutable [`Segment`]s. Records never
//! straddle segments. When a segment ends with a torn or abandoned tail the
//! segment is **retained** and the writer continues in a fresh segment whose id
//! equals the current committed root, so the canonical stream stays contiguous
//! while no committed byte is rewritten (§4, I1).
//!
//! # Writes
//!
//! Appends are **reserve-then-write**: [`Log::reserve`] selects a segment and
//! returns the exact physical/logical position, and [`Log::write_reserved`]
//! writes the bytes there. [`Log::append`] wraps both for a whole record.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::error::{OrfsError, Result};
use crate::failpoints::{self, Failpoint};
use crate::record::{Record, RecordHeader, RecordType, TypeClass, HEADER_LEN, MAX_PAYLOAD_LEN};
use crate::segment::{
    discover_segment_ids, fsync_dir, segment_file_name, ReadAt, Segment, SegmentExtent,
    SegmentLocator,
};
use crate::transaction::{
    bracket_checksum, verify_bracket, AbortReason, TxAbortPayload, TxBeginPayload, TxCommitPayload,
};
use crate::uring::{BackingEngine, ReadJob, UringConfig, UringReport};
use crate::watermark;

/// Default segment size policy: 64 MiB per segment file.
pub const DEFAULT_SEGMENT_SIZE: u64 = 64 * 1024 * 1024;

/// How a log is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Read-only: the log is scanned and validated but never modified.
    ReadOnly,
    /// Read-write: a recoverable tail is quarantined and a writer is prepared.
    ReadWrite,
}

/// The kind of physical tail a scan found beyond the committed root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TailKind {
    /// A record whose framing did not validate (torn write).
    TornRecord,
    /// Well-framed records that were never published by a `TX_COMMIT`.
    Uncommitted,
}

/// Description of an abandoned physical tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct TailInfo {
    pub kind: TailKind,
    /// The segment id containing the start of the tail.
    pub segment_id: u64,
    /// The committed boundary: the tail begins here.
    pub boundary_offset: u64,
    /// Physical end of the log (last segment id + its physical length).
    pub physical_end: u64,
    /// Number of physical bytes beyond the committed boundary.
    pub abandoned_bytes: u64,
}

/// What recovery found and did when a log was opened (research §23, §35).
///
/// This is the *explicit* classification of the on-disk state that `Log::open`
/// observed, distinguishing the cases the directive requires:
///
/// * [`RecoveryDisposition::Clean`] — the physical log is exactly the committed
///   prefix; nothing was refused and nothing was retained.
/// * [`RecoveryDisposition::RetainedTail`] — a harmless **uncommitted** tail (a
///   torn record, or well-framed records after the last `TX_COMMIT`) was found.
///   It is never exposed as authoritative content; a writable open quarantines it
///   and continues in a fresh segment, a read-only open leaves it untouched.
///
/// The remaining two required distinctions are **refusals**, reported as `Err`
/// (never as a successful recovery): an *incomplete commit* that is not a clean
/// uncommitted tail, and a *malformed committed record* or *corruption* (a hard
/// fault, a torn record in a non-final segment, a physical gap, a duplicate
/// segment id, or an unsupported format version). The returned error is the
/// classification; recovery never silently repairs (§23.1).
///
/// A read-only open ([`OpenMode::ReadOnly`]) is the *degraded* mode: it validates
/// and classifies identically but never mutates a single on-disk byte, so a
/// damaged-but-readable volume can be inspected without altering it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RecoveryDisposition {
    /// The log is exactly the committed prefix.
    Clean,
    /// A harmless uncommitted tail was retained (and quarantined on a writable
    /// open).
    RetainedTail {
        /// Whether the tail is a torn record or fully-framed uncommitted records.
        kind: TailKind,
        /// Physical bytes beyond the committed boundary.
        abandoned_bytes: u64,
        /// Whether a writable open moved it aside into `quarantine/`.
        quarantined: bool,
    },
}

/// Aggregate record statistics for a log.
#[derive(Debug, Clone, Default)]
pub struct LogStats {
    /// Number of well-framed records scanned (including an uncommitted tail).
    pub record_count: u64,
    /// Number of committed transactions (excluding genesis).
    pub transaction_count: u64,
    /// Total canonical bytes (sum of segment valid lengths).
    pub bytes: u64,
    /// Committed bytes (== the current root).
    pub committed_bytes: u64,
    /// The greatest transaction id observed anywhere in the log (committed or
    /// abandoned), used to allocate ids monotonically.
    pub max_transaction_id: u64,
    /// Record counts by raw type code.
    pub by_type: BTreeMap<u16, u64>,
}

/// The result of scanning the physical segments.
#[derive(Debug, Clone)]
pub struct LogScan {
    /// Canonical extents (valid framed bytes per segment), in order.
    pub extents: Vec<SegmentExtent>,
    /// The committed root / committed end offset.
    pub committed_end_offset: u64,
    /// Number of records within the committed prefix.
    pub committed_record_count: u64,
    /// Every committed transaction boundary (ascending).
    pub boundaries: Vec<u64>,
    /// Record statistics.
    pub stats: LogStats,
    /// Physical end offset (last segment id + physical length).
    pub physical_end: u64,
    /// An abandoned tail, if any.
    pub tail: Option<TailInfo>,
}

enum FrameOutcome {
    Complete(Record),
    Incomplete,
}

fn read_frame(reader: &ReadAt, phys: u64, physical_len: u64) -> Result<FrameOutcome> {
    let avail = physical_len
        .checked_sub(phys)
        .ok_or_else(|| OrfsError::Corrupt("segment offset beyond physical length".to_string()))?;
    if avail < HEADER_LEN as u64 {
        return Ok(FrameOutcome::Incomplete);
    }
    let mut header_bytes = [0u8; HEADER_LEN];
    reader.read_exact_at(phys, &mut header_bytes)?;
    let header = match RecordHeader::decode(&header_bytes) {
        Ok(h) => h,
        Err(crate::record::DecodeError::Compatibility(m)) => {
            return Err(OrfsError::Compatibility(m))
        }
        Err(_) => return Ok(FrameOutcome::Incomplete),
    };
    // Reject an unknown *mandatory* type before allocating any payload.
    if let Err(crate::record::DecodeError::Compatibility(m)) = header.classify_type() {
        return Err(OrfsError::Compatibility(m));
    }
    let total = match header.total_len() {
        Ok(t) => t,
        Err(crate::record::DecodeError::Compatibility(m)) => {
            return Err(OrfsError::Compatibility(m))
        }
        Err(_) => return Ok(FrameOutcome::Incomplete),
    };
    if total > avail {
        return Ok(FrameOutcome::Incomplete);
    }
    let total_usize = usize::try_from(total)
        .map_err(|_| OrfsError::Corrupt("record length overflow".to_string()))?;
    let mut buf = vec![0u8; total_usize];
    reader.read_exact_at(phys, &mut buf)?;
    match Record::decode(&buf) {
        Ok((record, _)) => Ok(FrameOutcome::Complete(record)),
        Err(crate::record::DecodeError::Compatibility(m)) => Err(OrfsError::Compatibility(m)),
        Err(_) => Ok(FrameOutcome::Incomplete),
    }
}

/// A structural fault found while validating a transaction.
#[derive(Debug)]
enum TxFault {
    /// A fault that may legitimately be an *uncommitted* tail in the final
    /// segment (sequence gap, record outside a transaction, ...).
    Soft(OrfsError),
    /// A fault in fully-framed content that must always be treated as
    /// corruption — in particular a committed record whose typed payload or
    /// `TX_COMMIT` bracket is inconsistent (never silently skipped, §23.1).
    Hard(OrfsError),
}

/// The accumulated bracket of the currently open transaction: the `TX_BEGIN`
/// payload plus the exact encoded bytes and record count of
/// `TX_BEGIN .. last data record`.
#[derive(Debug)]
struct BeginBracket {
    payload: TxBeginPayload,
    bytes: Vec<u8>,
    records: u64,
}

/// The transaction state machine used to locate the committed root while
/// scanning and to validate transaction structure and typed brackets.
#[derive(Debug, Default)]
struct TxMachine {
    started: bool,
    open_tx: Option<u64>,
    next_sequence: u64,
    record_index: u64,
    committed_end_offset: u64,
    committed_record_count: u64,
    transaction_count: u64,
    max_transaction_id: u64,
    begin: Option<BeginBracket>,
    boundaries: Vec<u64>,
}

impl TxMachine {
    fn accept(&mut self, record: &Record, end: u64) -> std::result::Result<(), TxFault> {
        self.max_transaction_id = self.max_transaction_id.max(record.header.transaction_id);
        if record.header.sequence_number != self.next_sequence {
            return Err(TxFault::Soft(OrfsError::Corrupt(format!(
                "record sequence number {} != expected {}",
                record.header.sequence_number, self.next_sequence
            ))));
        }
        let class = record
            .header
            .classify_type()
            .map_err(|e| TxFault::Hard(OrfsError::from(e)))?;
        if !self.started {
            if class != TypeClass::Known(RecordType::VolumeGenesis) {
                return Err(TxFault::Soft(OrfsError::Corrupt(
                    "first record is not VOLUME_GENESIS".to_string(),
                )));
            }
            self.started = true;
            self.committed_end_offset = end;
            self.committed_record_count = self.record_index + 1;
            self.boundaries.push(end);
        } else {
            match class {
                TypeClass::Known(RecordType::VolumeGenesis) => {
                    return Err(TxFault::Soft(OrfsError::Corrupt(
                        "duplicate VOLUME_GENESIS".to_string(),
                    )));
                }
                TypeClass::Known(RecordType::TxBegin) => {
                    if self.open_tx.is_some() {
                        return Err(TxFault::Soft(OrfsError::Corrupt(
                            "nested TX_BEGIN".to_string(),
                        )));
                    }
                    if record.header.transaction_id == 0 {
                        return Err(TxFault::Soft(OrfsError::Corrupt(
                            "TX_BEGIN with zero transaction id".to_string(),
                        )));
                    }
                    let payload = TxBeginPayload::decode(&record.payload).map_err(TxFault::Hard)?;
                    if payload.transaction_id != record.header.transaction_id {
                        return Err(TxFault::Hard(OrfsError::Corrupt(
                            "TX_BEGIN payload transaction id disagrees with header".to_string(),
                        )));
                    }
                    let bytes = record.encode().map_err(TxFault::Hard)?;
                    self.begin = Some(BeginBracket {
                        payload,
                        bytes,
                        records: 1,
                    });
                    self.open_tx = Some(record.header.transaction_id);
                }
                TypeClass::Known(RecordType::TxCommit) => {
                    let tx = self.open_tx.ok_or_else(|| {
                        TxFault::Soft(OrfsError::Corrupt("TX_COMMIT without TX_BEGIN".to_string()))
                    })?;
                    if record.header.transaction_id != tx {
                        return Err(TxFault::Soft(OrfsError::Corrupt(
                            "TX_COMMIT transaction id mismatch".to_string(),
                        )));
                    }
                    let commit = TxCommitPayload::decode(&record.payload).map_err(TxFault::Hard)?;
                    let bracket = self.begin.take().ok_or_else(|| {
                        TxFault::Hard(OrfsError::Corrupt(
                            "TX_COMMIT has no accumulated bracket".to_string(),
                        ))
                    })?;
                    verify_bracket(&commit, &bracket.bytes, &bracket.payload)
                        .map_err(TxFault::Hard)?;
                    if commit.record_count != bracket.records {
                        return Err(TxFault::Hard(OrfsError::Corrupt(format!(
                            "TX_COMMIT record count {} != actual bracket count {}",
                            commit.record_count, bracket.records
                        ))));
                    }
                    self.open_tx = None;
                    self.transaction_count += 1;
                    self.committed_end_offset = end;
                    self.committed_record_count = self.record_index + 1;
                    self.boundaries.push(end);
                }
                TypeClass::Known(RecordType::TxAbort) => {
                    let tx = self.open_tx.ok_or_else(|| {
                        TxFault::Soft(OrfsError::Corrupt("TX_ABORT without TX_BEGIN".to_string()))
                    })?;
                    if record.header.transaction_id != tx {
                        return Err(TxFault::Soft(OrfsError::Corrupt(
                            "TX_ABORT transaction id mismatch".to_string(),
                        )));
                    }
                    if let Some(bracket) = self.begin.take() {
                        if bracket.payload.expected_record_count != 0
                            && bracket.payload.expected_record_count as u64 != bracket.records
                        {
                            return Err(TxFault::Hard(OrfsError::Corrupt(format!(
                                "TX_BEGIN record count {} != actual bracket count {}",
                                bracket.payload.expected_record_count, bracket.records
                            ))));
                        }
                    }
                    self.open_tx = None;
                }
                TypeClass::Known(_) => {
                    if self.open_tx.is_none() {
                        return Err(TxFault::Soft(OrfsError::Corrupt(
                            "record outside a transaction".to_string(),
                        )));
                    }
                    if let Some(bracket) = self.begin.as_mut() {
                        let bytes = record.encode().map_err(TxFault::Hard)?;
                        bracket.bytes.extend_from_slice(&bytes);
                        bracket.records += 1;
                    }
                }
                TypeClass::OptionalUnknown(_) => {
                    if self.open_tx.is_none() {
                        return Err(TxFault::Soft(OrfsError::Corrupt(
                            "optional record outside a transaction".to_string(),
                        )));
                    }
                    if let Some(bracket) = self.begin.as_mut() {
                        let bytes = record.encode().map_err(TxFault::Hard)?;
                        bracket.bytes.extend_from_slice(&bytes);
                        bracket.records += 1;
                    }
                }
            }
        }
        self.next_sequence += 1;
        self.record_index += 1;
        Ok(())
    }
}

/// Scan the segments in `dir` without modifying anything.
///
/// This validates framing, transaction structure, and sequence continuity, and
/// locates both the committed root and any abandoned physical tail.
pub fn scan_log(dir: &Path) -> Result<LogScan> {
    let ids = discover_segment_ids(dir)?;
    if ids.is_empty() {
        return Err(OrfsError::Corrupt(format!(
            "log directory {} contains no segments",
            dir.display()
        )));
    }
    let mut machine = TxMachine::default();
    let mut extents: Vec<SegmentExtent> = Vec::with_capacity(ids.len());
    let mut by_type: BTreeMap<u16, u64> = BTreeMap::new();
    let mut tail: Option<TailInfo> = None;
    let mut total_valid: u64 = 0;
    let mut physical_end: u64 = 0;

    for (i, &id) in ids.iter().enumerate() {
        let is_last = i + 1 == ids.len();
        let reader = ReadAt::open(dir, id)?;
        let physical_len = reader.len()?;
        physical_end = id.checked_add(physical_len).ok_or(OrfsError::Overflow {
            what: "segment physical end",
        })?;
        let mut off: u64 = 0;
        let mut stopped = false;
        while off < physical_len {
            match read_frame(&reader, off, physical_len)? {
                FrameOutcome::Complete(record) => {
                    let total = record.header.total_len().map_err(OrfsError::from)?;
                    let end = off.checked_add(total).ok_or(OrfsError::Overflow {
                        what: "record end offset",
                    })?;
                    match machine.accept(&record, id + end) {
                        Ok(()) => {}
                        // A hard fault (an inconsistent typed payload or a
                        // committed bracket that does not validate) is always
                        // corruption, even in the final segment: never skipped.
                        Err(TxFault::Hard(e)) => return Err(e),
                        // A soft structural fault in a non-final segment, or
                        // before the genesis, is corruption; in the final
                        // segment it terminates the uncommitted tail.
                        Err(TxFault::Soft(e)) => {
                            if is_last && machine.started {
                                stopped = true;
                                break;
                            }
                            return Err(e);
                        }
                    }
                    *by_type.entry(record.header.record_type_code).or_insert(0) += 1;
                    off = end;
                }
                FrameOutcome::Incomplete => {
                    if is_last {
                        tail = Some(TailInfo {
                            kind: TailKind::TornRecord,
                            segment_id: id,
                            boundary_offset: id + off,
                            physical_end: id + physical_len,
                            abandoned_bytes: physical_len - off,
                        });
                        stopped = true;
                        break;
                    }
                    return Err(OrfsError::Corrupt(format!(
                        "torn record in non-final segment {id} at physical offset {off}"
                    )));
                }
            }
        }
        extents.push(SegmentExtent { id, valid_len: off });
        total_valid = total_valid.checked_add(off).ok_or(OrfsError::Overflow {
            what: "log canonical length",
        })?;
        if stopped {
            break;
        }
    }

    let committed_end_offset = machine.committed_end_offset;
    if physical_end > committed_end_offset && tail.is_none() {
        let segment_id = extents
            .iter()
            .rev()
            .find(|e| e.id <= committed_end_offset)
            .map(|e| e.id)
            .unwrap_or(0);
        tail = Some(TailInfo {
            kind: TailKind::Uncommitted,
            segment_id,
            boundary_offset: committed_end_offset,
            physical_end,
            abandoned_bytes: physical_end - committed_end_offset,
        });
    }

    let stats = LogStats {
        record_count: machine.record_index,
        transaction_count: machine.transaction_count,
        bytes: total_valid,
        committed_bytes: committed_end_offset,
        max_transaction_id: machine.max_transaction_id,
        by_type,
    };
    Ok(LogScan {
        extents,
        committed_end_offset,
        committed_record_count: machine.committed_record_count,
        boundaries: machine.boundaries,
        stats,
        physical_end,
        tail,
    })
}

/// Map a recovered committed root to its physical `(segment, valid_len)` witness.
///
/// Used to seed the in-memory watermark from the recovered root so a legacy
/// volume establishes protection at its next durability point.
fn recovered_watermark(committed: u64, locator: &SegmentLocator) -> watermark::Watermark {
    if committed == 0 {
        let segment_id = locator.extents().first().map(|e| e.id).unwrap_or(0);
        return watermark::Watermark {
            committed_root: 0,
            segment_id,
            segment_valid_len: 0,
        };
    }
    match locator.locate(committed - 1) {
        Some((segment_id, phys)) => watermark::Watermark {
            committed_root: committed,
            segment_id,
            segment_valid_len: phys + 1,
        },
        None => {
            let segment_id = locator
                .extents()
                .iter()
                .rev()
                .find(|e| e.id < committed)
                .map(|e| e.id)
                .unwrap_or(0);
            let segment_valid_len = locator
                .extent_of(segment_id)
                .map(|e| e.valid_len)
                .unwrap_or(0);
            watermark::Watermark {
                committed_root: committed,
                segment_id,
                segment_valid_len,
            }
        }
    }
}

/// Re-validate every committed transaction's typed bracket in `records`.
///
/// Used by `orfs verify --deep`. Returns the number of committed transactions
/// validated. A `TX_COMMIT` whose typed payload or bracket checksum disagrees
/// with the actual bracketed records is a hard error (research §23.1) — the log
/// must never be interpreted on a guess.
pub fn validate_committed_brackets(records: &[Record]) -> Result<u64> {
    let mut machine = TxMachine::default();
    let mut end = 0u64;
    for record in records {
        let total = record.header.total_len().map_err(OrfsError::from)?;
        end = end.checked_add(total).ok_or(OrfsError::Overflow {
            what: "verify offset",
        })?;
        match machine.accept(record, end) {
            Ok(()) => {}
            Err(TxFault::Hard(e)) | Err(TxFault::Soft(e)) => return Err(e),
        }
    }
    Ok(machine.transaction_count)
}

/// An append reservation: an exact position in the logical/physical stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendReservation {
    /// The logical byte offset of the reservation.
    pub logical_offset: u64,
    /// The segment the reservation lives in.
    pub segment_id: u64,
    /// The physical offset within that segment.
    pub physical_offset: u64,
    /// The reserved length in bytes.
    pub len: u64,
}

#[derive(Debug)]
struct Writer {
    seg: Segment,
    id: u64,
    /// Canonical bytes written so far.
    valid: u64,
    /// Bytes reserved but not yet written.
    pending: u64,
}

/// Truncate validated extents to the committed prefix.
fn truncate_extents(extents: &[SegmentExtent], committed: u64) -> Vec<SegmentExtent> {
    let mut out = Vec::new();
    for e in extents {
        if e.id >= committed {
            break;
        }
        let end = e.end();
        if end <= committed {
            out.push(*e);
        } else {
            out.push(SegmentExtent {
                id: e.id,
                valid_len: committed - e.id,
            });
            break;
        }
    }
    out
}

/// Move a segment file into `dir/quarantine/`, retaining every byte.
fn quarantine_segment(dir: &Path, id: u64) -> Result<()> {
    let name = segment_file_name(id)?;
    let src = dir.join(&name);
    if !src.exists() {
        return Ok(());
    }
    let qdir = dir.join("quarantine");
    std::fs::create_dir_all(&qdir)?;
    let mut dst = qdir.join(&name);
    let mut n = 0u32;
    while dst.exists() {
        n += 1;
        dst = qdir.join(format!("{name}.{n}"));
    }
    std::fs::rename(&src, &dst)?;
    // The moved segment's bytes are retained in `quarantine/`; the simulated
    // device must forget the old name so it does not resurrect it at power
    // failure. No-op without a device.
    crate::powerloss::record_remove(dir, &name);
    Ok(())
}

/// Quarantine every canonical segment at or beyond the committed root.
fn quarantine_after(dir: &Path, extents: &[SegmentExtent], committed: u64) -> Result<()> {
    let ids: Vec<u64> = extents
        .iter()
        .filter(|e| e.id >= committed)
        .map(|e| e.id)
        .collect();
    if ids.is_empty() {
        return Ok(());
    }
    let qdir = dir.join("quarantine");
    std::fs::create_dir_all(&qdir)?;
    for id in ids {
        quarantine_segment(dir, id)?;
    }
    fsync_dir(&qdir)?;
    fsync_dir(dir)?;
    Ok(())
}

/// A read-only iterator over validated canonical records.
pub struct RecordReader {
    reader: Option<(u64, ReadAt)>,
    dir: PathBuf,
    extents: Vec<SegmentExtent>,
    end: u64,
    offset: u64,
}

impl RecordReader {
    /// Iterate the canonical records in `[0, end)`.
    pub fn new(dir: &Path, extents: &[SegmentExtent], end: u64) -> RecordReader {
        RecordReader {
            reader: None,
            dir: dir.to_path_buf(),
            extents: extents.to_vec(),
            end,
            offset: 0,
        }
    }

    /// Iterate the canonical records in `[start, end)`.
    ///
    /// `start` must be a committed transaction boundary (a record boundary), so
    /// that iteration begins exactly at a framed record. Used by checkpoint
    /// recovery to replay only the records committed after a checkpoint root.
    pub fn starting_at(
        dir: &Path,
        extents: &[SegmentExtent],
        start: u64,
        end: u64,
    ) -> RecordReader {
        RecordReader {
            reader: None,
            dir: dir.to_path_buf(),
            extents: extents.to_vec(),
            end,
            offset: start,
        }
    }

    fn locate(&self, offset: u64) -> Option<(u64, u64, u64)> {
        let idx = self.extents.partition_point(|e| e.id <= offset);
        if idx == 0 {
            return None;
        }
        let e = self.extents[idx - 1];
        if offset < e.end() {
            Some((e.id, offset - e.id, e.valid_len))
        } else {
            None
        }
    }

    fn read_next(&mut self) -> Result<Record> {
        let (sid, phys, valid) = self.locate(self.offset).ok_or_else(|| {
            OrfsError::Corrupt(format!("no segment covers offset {}", self.offset))
        })?;
        if self.reader.as_ref().map(|(id, _)| *id) != Some(sid) {
            self.reader = Some((sid, ReadAt::open(&self.dir, sid)?));
        }
        let reader = &self.reader.as_ref().expect("reader opened").1;
        let avail = valid
            .checked_sub(phys)
            .ok_or_else(|| OrfsError::Corrupt("record offset beyond segment extent".to_string()))?
            .min(self.end - self.offset);
        if avail < HEADER_LEN as u64 {
            return Err(OrfsError::Corrupt(format!(
                "truncated record within committed region at offset {}",
                self.offset
            )));
        }
        let mut header_bytes = [0u8; HEADER_LEN];
        reader.read_exact_at(phys, &mut header_bytes)?;
        let header = RecordHeader::decode(&header_bytes).map_err(OrfsError::from)?;
        header.classify_type().map_err(OrfsError::from)?;
        let total = header.total_len().map_err(OrfsError::from)?;
        if total > avail {
            return Err(OrfsError::Corrupt(format!(
                "record at offset {} crosses the committed root",
                self.offset
            )));
        }
        let total_usize = usize::try_from(total)
            .map_err(|_| OrfsError::Corrupt("record length overflow".to_string()))?;
        let mut buf = vec![0u8; total_usize];
        reader.read_exact_at(phys, &mut buf)?;
        let (record, _) = Record::decode(&buf).map_err(OrfsError::from)?;
        Ok(record)
    }
}

impl Iterator for RecordReader {
    type Item = Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.end {
            return None;
        }
        match self.read_next() {
            Ok(record) => {
                let total = match record.header.total_len() {
                    Ok(t) => t,
                    Err(e) => return Some(Err(OrfsError::from(e))),
                };
                self.offset += total;
                Some(Ok(record))
            }
            Err(e) => {
                // Stop iteration after reporting the fault.
                self.offset = self.end;
                Some(Err(e))
            }
        }
    }
}

/// One committed record's payload selected by type during a header scan
/// (used for checkpoint discovery; see [`Log::scan_records_of_types`]).
#[derive(Debug, Clone)]
pub struct RawRecord {
    /// The logical offset of the record's first byte.
    pub offset: u64,
    /// The record's known type.
    pub record_type: RecordType,
    /// The raw typed payload bytes.
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Committed-root pinning
// ---------------------------------------------------------------------------

/// A shared registry of pinned committed roots (research §7.4, §24, §26).
///
/// A root `R` selects the historical prefix `L[0:R]`. While a snapshot or a
/// read-only handle is reading that prefix, the segments covering it must not be
/// quarantined or rolled over underneath it. Compile-time borrowing already
/// prevents a single [`Log`] from being mutated while it is read through `&self`;
/// this registry extends the [`crate::buffers`] pin discipline to **roots** so
/// that *distinct* handles sharing one volume (a writer and its readers, or a
/// live mount and a snapshot mount) observe the same rule at run time.
///
/// The registry is reference-counted: `Arc` so it can be shared by every handle
/// over a volume, and an internal per-root counter so concurrent readers
/// independently pin and release the same root.
#[derive(Debug, Default)]
pub struct RootPins {
    roots: Mutex<BTreeMap<u64, u64>>,
}

impl RootPins {
    /// A fresh, empty registry.
    pub fn new() -> Arc<RootPins> {
        Arc::new(RootPins::default())
    }

    /// Register a pin on `root`, returning the resulting pin count.
    fn register(&self, root: u64) -> u64 {
        let mut roots = self.roots.lock().unwrap_or_else(|e| e.into_inner());
        let count = roots.entry(root).or_insert(0);
        *count += 1;
        *count
    }

    /// Release one pin on `root`.
    fn release(&self, root: u64) {
        let mut roots = self.roots.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = roots.get_mut(&root) {
            *count -= 1;
            if *count == 0 {
                roots.remove(&root);
            }
        }
    }

    /// Whether `root` is currently pinned by at least one handle.
    pub fn is_pinned(&self, root: u64) -> bool {
        self.roots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&root)
    }

    /// The number of live pins on `root`.
    pub fn pin_count(&self, root: u64) -> u64 {
        self.roots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&root)
            .copied()
            .unwrap_or(0)
    }

    /// Every currently pinned root, ascending.
    pub fn pinned_roots(&self) -> Vec<u64> {
        self.roots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// Whether any pinned root still needs the segment with this id.
    ///
    /// A segment whose id `S` covers logical bytes `[S, S+len)`; it is required
    /// by a pinned root `R` exactly when `S < R` (some of its bytes lie below the
    /// root). `rollover`/quarantine consult this before discarding a segment.
    pub fn segment_required(&self, segment_id: u64) -> bool {
        self.roots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .any(|&r| segment_id < r)
    }
}

/// A live pin on a committed root. Dropping it releases the pin.
pub struct RootPin {
    pins: Arc<RootPins>,
    root: u64,
}

impl RootPin {
    /// The pinned root.
    pub fn root(&self) -> u64 {
        self.root
    }
}

impl Drop for RootPin {
    fn drop(&mut self) {
        self.pins.release(self.root);
    }
}

/// The authoritative append-only log.
pub struct Log {
    dir: PathBuf,
    segment_size: u64,
    locator: SegmentLocator,
    committed_end_offset: u64,
    committed_record_count: u64,
    boundaries: Vec<u64>,
    next_sequence_number: u64,
    open_tx: Option<u64>,
    writer: Option<Writer>,
    stats: LogStats,
    tail: Option<TailInfo>,
    /// Encoded bytes of `TX_BEGIN .. last data record` of the open transaction,
    /// accumulated by the low-level [`Log::append`] path so that
    /// [`Log::commit`]/[`Log::abort`] can emit a valid typed bracket.
    open_bracket: Vec<u8>,
    /// Number of records accumulated in `open_bracket` (includes `TX_BEGIN`).
    open_bracket_records: u64,
    /// The backing-I/O engine. [`BackingEngine::Sync`] unless io_uring was
    /// explicitly and successfully engaged (research §17 Domain A, §20).
    io: BackingEngine,
    /// The committed-root pin registry (research §7.4, §24, §26). Shared (`Arc`)
    /// with every read-only handle and snapshot opened over the same volume so a
    /// writer observes the pins a reader holds.
    pins: Arc<RootPins>,
    /// What recovery observed and did when this handle was opened (research §23,
    /// §35). [`RecoveryDisposition::Clean`] for a freshly created log.
    recovery: RecoveryDisposition,
    /// The latest committed-prefix watermark observed in memory. Set whenever a
    /// root is published; persisted at the next durability point (research §23).
    watermark: Option<watermark::Watermark>,
    /// The watermark last written durably to disk.
    durable_watermark: Option<watermark::Watermark>,
}

impl Log {
    /// Create a brand-new empty log (one empty segment with id 0).
    ///
    /// The caller is expected to append [`RecordType::VolumeGenesis`]
    /// immediately; the log is not a valid volume until it does.
    pub fn create(dir: &Path, segment_size: u64) -> Result<Log> {
        if segment_size == 0 {
            return Err(OrfsError::InvalidArgument(
                "segment size must be non-zero".to_string(),
            ));
        }
        std::fs::create_dir_all(dir)?;
        if !discover_segment_ids(dir)?.is_empty() {
            return Err(OrfsError::AlreadyExists);
        }
        let seg = Segment::create(dir, 0)?;
        fsync_dir(dir)?;
        let mut locator = SegmentLocator::default();
        locator.push(SegmentExtent {
            id: 0,
            valid_len: 0,
        });
        Ok(Log {
            dir: dir.to_path_buf(),
            segment_size,
            locator,
            committed_end_offset: 0,
            committed_record_count: 0,
            boundaries: Vec::new(),
            next_sequence_number: 0,
            open_tx: None,
            writer: Some(Writer {
                seg,
                id: 0,
                valid: 0,
                pending: 0,
            }),
            stats: LogStats::default(),
            tail: None,
            open_bracket: Vec::new(),
            open_bracket_records: 0,
            io: BackingEngine::Sync,
            pins: RootPins::new(),
            recovery: RecoveryDisposition::Clean,
            watermark: None,
            durable_watermark: None,
        })
    }

    /// Open an existing log.
    ///
    /// In [`OpenMode::ReadWrite`] a recoverable tail is quarantined first and a
    /// writer is prepared at the committed root. In [`OpenMode::ReadOnly`] the
    /// on-disk bytes are never touched.
    pub fn open(dir: &Path, segment_size: u64, mode: OpenMode) -> Result<Log> {
        Self::open_with_pins(dir, segment_size, mode, RootPins::new())
    }

    /// Open an existing log with a caller-supplied committed-root pin registry.
    ///
    /// A read-only handle opened over the same volume as a writer can share the
    /// writer's registry, so the writer's `rollover`/quarantine paths observe the
    /// reader's pins (Phase 6 root-pinning discipline).
    pub fn open_with_pins(
        dir: &Path,
        segment_size: u64,
        mode: OpenMode,
        pins: Arc<RootPins>,
    ) -> Result<Log> {
        let scan = scan_log(dir)?;
        let committed = scan.committed_end_offset;
        let mut locator = SegmentLocator::from_extents(scan.extents.clone())?;
        let mut writer = None;
        let mut quarantined = false;

        // Validate the durable commit watermark *before* acting on the volume. A
        // watermark ahead of the surviving committed bytes means a trailing
        // committed segment is missing or truncated: refuse, never silently
        // recover a shorter history (research §23, §35).
        let disk_watermark = watermark::validate(dir, committed)?;

        if mode == OpenMode::ReadWrite {
            if scan.physical_end > committed {
                // Retain the abandoned tail, then continue in a fresh segment.
                quarantine_after(dir, &scan.extents, committed)?;
                quarantined = true;
                locator = SegmentLocator::from_extents(truncate_extents(&scan.extents, committed))?;
                let seg = Segment::create(dir, committed)?;
                locator.push(SegmentExtent {
                    id: committed,
                    valid_len: 0,
                });
                writer = Some(Writer {
                    seg,
                    id: committed,
                    valid: 0,
                    pending: 0,
                });
                fsync_dir(dir)?;
            } else {
                let last = locator
                    .extents()
                    .last()
                    .copied()
                    .ok_or_else(|| OrfsError::Corrupt("empty log".to_string()))?;
                let seg = Segment::open(dir, last.id)?;
                if seg.len() != last.valid_len {
                    return Err(OrfsError::Corrupt(format!(
                        "segment {} length {} disagrees with canonical valid length {}",
                        last.id,
                        seg.len(),
                        last.valid_len
                    )));
                }
                writer = Some(Writer {
                    seg,
                    id: last.id,
                    valid: last.valid_len,
                    pending: 0,
                });
            }
        }

        let recovery = match scan.tail {
            None => RecoveryDisposition::Clean,
            Some(t) => RecoveryDisposition::RetainedTail {
                kind: t.kind,
                abandoned_bytes: t.abandoned_bytes,
                quarantined,
            },
        };
        // The recovered committed root is the best in-memory watermark. It is
        // persisted at the next durability point (establishing protection for a
        // legacy volume that predates the watermark on its first write).
        let recovered_wm = Some(recovered_watermark(committed, &locator));
        // The committed root must be physically covered by canonical bytes. A
        // deleted or truncated *committed* segment can otherwise leave a root
        // pointing past the bytes that exist (research §35: the recovered root is
        // a complete committed boundary, never a dangling position).
        if committed > locator.total_len() {
            return Err(OrfsError::Corrupt(format!(
                "committed root {committed} extends beyond the canonical bytes {} \
                 (a committed segment is missing or truncated)",
                locator.total_len()
            )));
        }
        Ok(Log {
            dir: dir.to_path_buf(),
            segment_size,
            locator,
            committed_end_offset: committed,
            committed_record_count: scan.committed_record_count,
            boundaries: scan.boundaries,
            next_sequence_number: scan.committed_record_count,
            open_tx: None,
            writer,
            stats: scan.stats,
            tail: scan.tail,
            open_bracket: Vec::new(),
            open_bracket_records: 0,
            io: BackingEngine::Sync,
            pins,
            recovery,
            watermark: recovered_wm,
            durable_watermark: disk_watermark,
        })
    }

    /// The committed-root pin registry shared by this handle.
    pub fn root_pins(&self) -> Arc<RootPins> {
        self.pins.clone()
    }

    /// What recovery observed and did when this handle was opened (research §23,
    /// §35). Lets a caller report a recovered tail explicitly instead of inferring
    /// it, and lets tests assert the classification.
    pub fn recovery(&self) -> RecoveryDisposition {
        self.recovery
    }

    /// Pin a committed root so its segments cannot be quarantined or rolled over
    /// while the returned [`RootPin`] is alive.
    ///
    /// `root` must be `0` or a committed transaction boundary that does not
    /// exceed the current committed root (research §2, I3): an arbitrary offset
    /// inside a record is not a snapshot.
    pub fn pin_root(&self, root: u64) -> Result<RootPin> {
        if root > self.committed_end_offset {
            return Err(OrfsError::InvalidArgument(format!(
                "pin root {root} exceeds the committed root {}",
                self.committed_end_offset
            )));
        }
        if root != 0 && !self.is_boundary(root) {
            return Err(OrfsError::InvalidArgument(format!(
                "pin root {root} is not a committed transaction boundary"
            )));
        }
        self.pins.register(root);
        Ok(RootPin {
            pins: self.pins.clone(),
            root,
        })
    }

    /// The log's directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The committed root `R` (committed end offset).
    pub fn committed_end_offset(&self) -> u64 {
        self.committed_end_offset
    }

    /// Segment size policy in bytes.
    pub fn segment_size(&self) -> u64 {
        self.segment_size
    }

    /// Number of records within the committed prefix.
    pub fn committed_record_count(&self) -> u64 {
        self.committed_record_count
    }

    /// Total number of well-framed records scanned (including any tail).
    pub fn record_count(&self) -> u64 {
        self.stats.record_count
    }

    /// Number of committed transactions (excluding genesis).
    pub fn transaction_count(&self) -> u64 {
        self.stats.transaction_count
    }

    /// The greatest transaction id observed anywhere in the log (committed or
    /// abandoned). Transaction ids are allocated strictly above this so they are
    /// unique and monotonic across the whole volume, never reusing an id that a
    /// previously aborted transaction consumed.
    pub fn max_transaction_id(&self) -> u64 {
        self.stats.max_transaction_id
    }

    /// The next transaction id to allocate (checked).
    pub fn next_transaction_id(&self) -> Result<u64> {
        self.stats
            .max_transaction_id
            .checked_add(1)
            .ok_or(OrfsError::Overflow {
                what: "transaction id",
            })
    }

    /// Total canonical bytes (sum of segment valid lengths).
    pub fn canonical_bytes(&self) -> u64 {
        self.stats.bytes
    }

    /// Record counts by raw type code.
    pub fn record_counts_by_type(&self) -> &BTreeMap<u16, u64> {
        &self.stats.by_type
    }

    /// Canonical extents.
    pub fn extents(&self) -> &[SegmentExtent] {
        self.locator.extents()
    }

    /// Committed transaction boundaries (ascending).
    pub fn boundaries(&self) -> &[u64] {
        &self.boundaries
    }

    /// The abandoned tail found at open time, if any.
    pub fn tail(&self) -> Option<TailInfo> {
        self.tail
    }

    /// Whether `offset` is a committed transaction boundary.
    pub fn is_boundary(&self, offset: u64) -> bool {
        offset == 0 || self.boundaries.binary_search(&offset).is_ok()
    }

    /// The current append frontier (logical offset of the next byte).
    pub fn append_end_offset(&self) -> u64 {
        match &self.writer {
            Some(w) => w.id + w.valid + w.pending,
            None => self.committed_end_offset,
        }
    }

    /// Reserve `len` bytes for an append, rolling over if required.
    pub fn reserve(&mut self, len: u64) -> Result<AppendReservation> {
        if len == 0 {
            return Err(OrfsError::InvalidArgument(
                "cannot reserve zero bytes".to_string(),
            ));
        }
        let w = self
            .writer
            .as_ref()
            .ok_or_else(|| OrfsError::ReadOnly("log opened read-only".to_string()))?;
        if w.pending == 0 && w.valid > 0 && w.valid.saturating_add(len) > self.segment_size {
            self.rollover()?;
        }
        let w = self.writer.as_ref().expect("writer present");
        let physical_offset = w.valid.checked_add(w.pending).ok_or(OrfsError::Overflow {
            what: "append physical offset",
        })?;
        let logical_offset =
            w.id.checked_add(physical_offset)
                .ok_or(OrfsError::Overflow {
                    what: "append logical offset",
                })?;
        let seg_id = w.id;
        let pending = w.pending.checked_add(len).ok_or(OrfsError::Overflow {
            what: "pending reservation bytes",
        })?;
        self.writer.as_mut().expect("writer present").pending = pending;
        Ok(AppendReservation {
            logical_offset,
            segment_id: seg_id,
            physical_offset,
            len,
        })
    }

    /// Write the bytes for a reservation. Reservations must be written in FIFO
    /// order.
    pub fn write_reserved(&mut self, res: &AppendReservation, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 != res.len {
            return Err(OrfsError::InvalidArgument(format!(
                "reservation length {} disagrees with {} bytes",
                res.len,
                bytes.len()
            )));
        }
        let w = self
            .writer
            .as_mut()
            .ok_or_else(|| OrfsError::ReadOnly("log opened read-only".to_string()))?;
        if w.id != res.segment_id || w.valid != res.physical_offset {
            return Err(OrfsError::Corrupt(
                "append reservation written out of order".to_string(),
            ));
        }
        match &self.io {
            BackingEngine::Sync => w.seg.write_at(res.physical_offset, bytes)?,
            BackingEngine::Uring(rings) => {
                let fd = w.seg.raw_fd();
                rings
                    .write()
                    .lock()
                    .write_at_all(fd, res.physical_offset, bytes)?;
            }
        }
        w.valid = w.valid.checked_add(res.len).ok_or(OrfsError::Overflow {
            what: "segment valid length",
        })?;
        w.pending -= res.len;
        let valid = w.valid;
        self.locator.set_last_valid_len(valid);
        Ok(())
    }

    /// Append a complete record, assigning its sequence number and enforcing
    /// transaction structure. Returns the record's logical offset.
    pub fn append(&mut self, mut record: Record) -> Result<u64> {
        self.prepare_record(&mut record)?;
        let bytes = record.encode()?;
        self.note_bracket(&record, &bytes);
        let res = self.reserve(bytes.len() as u64)?;
        self.write_reserved(&res, &bytes)?;
        let end = res
            .logical_offset
            .checked_add(res.len)
            .ok_or(OrfsError::Overflow {
                what: "record end offset",
            })?;
        self.finish_record(&record, res.logical_offset, end)?;
        Ok(res.logical_offset)
    }

    /// Track the encoded bracket of the open transaction for the low-level
    /// [`Log::append`] path so that [`Log::commit`]/[`Log::abort`] can emit a
    /// valid typed payload. The structured [`crate::commit`] sequencer writes
    /// its own payloads and leaves this bookkeeping empty.
    fn note_bracket(&mut self, record: &Record, bytes: &[u8]) {
        match record.known_type() {
            Ok(RecordType::TxBegin) => {
                self.open_bracket.clear();
                self.open_bracket.extend_from_slice(bytes);
                self.open_bracket_records = 1;
            }
            Ok(RecordType::TxCommit) | Ok(RecordType::TxAbort) => {
                self.open_bracket.clear();
                self.open_bracket_records = 0;
            }
            _ => {
                if self.open_tx.is_some() {
                    self.open_bracket.extend_from_slice(bytes);
                    self.open_bracket_records += 1;
                }
            }
        }
    }

    fn prepare_record(&mut self, record: &mut Record) -> Result<()> {
        let class = record.header.classify_type().map_err(OrfsError::from)?;
        let known = match class {
            TypeClass::Known(t) => Some(t),
            TypeClass::OptionalUnknown(_) => None,
        };
        match known {
            Some(RecordType::VolumeGenesis) => {
                if self.append_end_offset() != 0 || self.open_tx.is_some() {
                    return Err(OrfsError::InvalidArgument(
                        "VOLUME_GENESIS must be the first record".to_string(),
                    ));
                }
            }
            Some(RecordType::TxBegin) => {
                if self.open_tx.is_some() {
                    return Err(OrfsError::InvalidArgument(
                        "nested TX_BEGIN is not permitted".to_string(),
                    ));
                }
                if record.header.transaction_id == 0 {
                    return Err(OrfsError::InvalidArgument(
                        "transaction id must be non-zero".to_string(),
                    ));
                }
            }
            Some(RecordType::TxCommit) | Some(RecordType::TxAbort) => match self.open_tx {
                Some(tx) if tx == record.header.transaction_id => {}
                _ => {
                    return Err(OrfsError::InvalidArgument(
                        "commit/abort without a matching open transaction".to_string(),
                    ))
                }
            },
            Some(_) => match self.open_tx {
                Some(tx) if tx == record.header.transaction_id => {}
                _ => {
                    return Err(OrfsError::InvalidArgument(
                        "mutation record outside a matching transaction".to_string(),
                    ))
                }
            },
            None => {
                if let Some(tx) = self.open_tx {
                    if record.header.transaction_id != tx {
                        return Err(OrfsError::InvalidArgument(
                            "optional record transaction id mismatch".to_string(),
                        ));
                    }
                } else {
                    return Err(OrfsError::InvalidArgument(
                        "optional record outside a transaction".to_string(),
                    ));
                }
            }
        }
        record.header.payload_length = record.payload.len() as u64;
        if record.header.payload_length > MAX_PAYLOAD_LEN {
            return Err(OrfsError::InvalidArgument(
                "payload exceeds the format limit".to_string(),
            ));
        }
        record.header.sequence_number = self.next_sequence_number;
        record.header = record.header.with_recomputed_check();
        Ok(())
    }

    /// After writing a reserved record's bytes, update the log's structural
    /// bookkeeping and publish a root if the record is one that publishes (§5.4).
    ///
    /// This is the append path used by [`Log::append`]. The commit sequencer
    /// ([`crate::commit`]) instead calls [`Log::record_written`] and
    /// [`Log::publish_root_at`] separately so that in-memory publication happens
    /// strictly after the `TX_COMMIT` bytes are written and validated.
    fn finish_record(&mut self, record: &Record, start: u64, end: u64) -> Result<()> {
        self.record_written(record, start, end)?;
        if record
            .known_type()
            .map(|t| t.publishes_root())
            .unwrap_or(false)
        {
            self.publish_root_at(end)?;
        }
        Ok(())
    }

    /// Update statistics, the sequence counter, and open-transaction state after
    /// a record's bytes have been written. Does **not** publish a root.
    pub(crate) fn record_written(&mut self, record: &Record, start: u64, end: u64) -> Result<()> {
        let class = record.header.classify_type().map_err(OrfsError::from)?;
        if let TypeClass::Known(t) = class {
            match t {
                RecordType::TxBegin => {
                    self.open_tx = Some(record.header.transaction_id);
                }
                RecordType::TxCommit => {
                    self.open_tx = None;
                    self.stats.transaction_count += 1;
                }
                RecordType::TxAbort => {
                    self.open_tx = None;
                }
                _ => {}
            }
        }
        self.stats.record_count += 1;
        self.stats.max_transaction_id = self
            .stats
            .max_transaction_id
            .max(record.header.transaction_id);
        self.stats.bytes =
            self.stats
                .bytes
                .checked_add(end - start)
                .ok_or(OrfsError::Overflow {
                    what: "log canonical byte count",
                })?;
        *self
            .stats
            .by_type
            .entry(record.header.record_type_code)
            .or_insert(0) += 1;
        self.next_sequence_number =
            self.next_sequence_number
                .checked_add(1)
                .ok_or(OrfsError::Overflow {
                    what: "record sequence number",
                })?;
        Ok(())
    }

    /// Publish a new committed root. `end` must be strictly greater than the
    /// current root (a root never moves backward) and must be the end offset of
    /// a complete record that publishes a root.
    pub(crate) fn publish_root_at(&mut self, end: u64) -> Result<()> {
        if end <= self.committed_end_offset {
            return Err(OrfsError::Corrupt(format!(
                "attempt to publish non-advancing root {end} (current {})",
                self.committed_end_offset
            )));
        }
        self.committed_end_offset = end;
        self.committed_record_count = self.next_sequence_number;
        self.boundaries.push(end);
        self.stats.committed_bytes = end;
        // Record an in-memory watermark for the newly committed prefix. It is
        // persisted at the next durability point (research §23).
        self.watermark = Some(watermark::Watermark {
            committed_root: end,
            segment_id: self
                .writer
                .as_ref()
                .map(|w| w.id)
                .unwrap_or_else(|| self.locator.extents().last().map(|e| e.id).unwrap_or(0)),
            segment_valid_len: match &self.writer {
                Some(w) if end >= w.id => end - w.id,
                _ => 0,
            },
        });
        Ok(())
    }

    /// The committed-prefix watermark most recently observed in memory.
    pub fn watermark(&self) -> Option<watermark::Watermark> {
        self.watermark
    }

    /// The committed-prefix watermark last written durably to disk, if any.
    pub fn durable_watermark(&self) -> Option<watermark::Watermark> {
        self.durable_watermark
    }

    /// Persist the in-memory watermark if it has advanced beyond the durable one.
    ///
    /// Called only after the segment bytes are fsynced, so the watermark can
    /// never certify more durable history than the backing store holds.
    fn persist_watermark(&mut self) -> Result<()> {
        if let Some(wm) = self.watermark {
            if self.durable_watermark != Some(wm) {
                watermark::Watermark::write(&self.dir, &wm)?;
                self.durable_watermark = Some(wm);
            }
        }
        Ok(())
    }

    /// The sequence number the next record will receive.
    pub(crate) fn next_sequence_number(&self) -> u64 {
        self.next_sequence_number
    }

    /// The transaction id of the currently open transaction, if any.
    pub(crate) fn open_transaction(&self) -> Option<u64> {
        self.open_tx
    }

    /// Write a prefix of a reserved record's bytes at its reserved position
    /// **without** advancing the writer's valid length or pending count.
    ///
    /// Used only to model a torn write for fault injection; the caller must
    /// either complete the reservation with [`Log::write_reserved`] or discard
    /// the log.
    pub(crate) fn write_partial_reserved(
        &mut self,
        res: &AppendReservation,
        prefix: &[u8],
    ) -> Result<()> {
        if prefix.len() as u64 > res.len {
            return Err(OrfsError::InvalidArgument(
                "partial write longer than the reservation".into(),
            ));
        }
        let w = self
            .writer
            .as_ref()
            .ok_or_else(|| OrfsError::ReadOnly("log opened read-only".into()))?;
        if w.id != res.segment_id || w.valid != res.physical_offset {
            return Err(OrfsError::Corrupt(
                "partial reservation write out of order".into(),
            ));
        }
        match &self.io {
            BackingEngine::Sync => w.seg.write_at(res.physical_offset, prefix)?,
            BackingEngine::Uring(rings) => {
                let fd = w.seg.raw_fd();
                rings
                    .write()
                    .lock()
                    .write_at_all(fd, res.physical_offset, prefix)?;
            }
        }
        Ok(())
    }

    /// Read back the bytes at a reservation's physical position.
    ///
    /// Used by the commit sequencer to validate the `TX_COMMIT` record from the
    /// backing store (not merely from the in-memory buffer) before publishing.
    pub(crate) fn read_back(&self, res: &AppendReservation) -> Result<Vec<u8>> {
        let reader = ReadAt::open(&self.dir, res.segment_id)?;
        let mut buf = vec![0u8; res.len as usize];
        match &self.io {
            BackingEngine::Sync => reader.read_exact_at(res.physical_offset, &mut buf)?,
            BackingEngine::Uring(rings) => {
                rings.read().lock().read_exact_at(
                    reader.raw_fd(),
                    res.physical_offset,
                    &mut buf,
                )?;
            }
        }
        Ok(buf)
    }

    /// Begin a transaction (low-level convenience).
    ///
    /// The typed `TX_BEGIN` payload declares no expected size (the low-level API
    /// cannot know the bracket before it is written); the closing
    /// [`Log::commit`] still certifies the actual bracket. The structured
    /// [`crate::commit`] sequencer always declares and certifies exact sizes.
    pub fn begin(&mut self, tx_id: u64) -> Result<u64> {
        let payload = TxBeginPayload {
            transaction_id: tx_id,
            expected_byte_length: 0,
            expected_record_count: 0,
        };
        let rec = Record::new(
            RecordType::TxBegin,
            0,
            tx_id,
            0,
            0,
            0,
            payload.encode().to_vec(),
        )?;
        self.append(rec)
    }

    /// Commit the open transaction, publishing a new root. Returns the root.
    pub fn commit(&mut self) -> Result<u64> {
        let tx = self
            .open_tx
            .ok_or_else(|| OrfsError::InvalidArgument("no open transaction".to_string()))?;
        let payload = TxCommitPayload {
            transaction_id: tx,
            record_count: self.open_bracket_records,
            bracketed_byte_length: self.open_bracket.len() as u64,
            commit_sequence_number: self.next_sequence_number,
            bracket_checksum: bracket_checksum(&self.open_bracket),
        };
        let rec = Record::new(
            RecordType::TxCommit,
            0,
            tx,
            0,
            0,
            0,
            payload.encode().to_vec(),
        )?;
        self.append(rec)?;
        Ok(self.committed_end_offset)
    }

    /// Abort the open transaction. The committed root does not advance.
    pub fn abort(&mut self) -> Result<()> {
        let tx = self
            .open_tx
            .ok_or_else(|| OrfsError::InvalidArgument("no open transaction".to_string()))?;
        let payload = TxAbortPayload {
            transaction_id: tx,
            reason: AbortReason::UserRequested,
            message: "log-level abort".to_string(),
        };
        let rec = Record::new(RecordType::TxAbort, 0, tx, 0, 0, 0, payload.encode()?)?;
        self.append(rec)?;
        Ok(())
    }

    fn rollover(&mut self) -> Result<()> {
        failpoints::check(Failpoint::DuringSegmentRollover)?;
        let w = self
            .writer
            .take()
            .ok_or_else(|| OrfsError::ReadOnly("log opened read-only".to_string()))?;
        if w.pending != 0 {
            self.writer = Some(w);
            return Err(OrfsError::Corrupt(
                "segment rollover with outstanding reservations".to_string(),
            ));
        }
        match &self.io {
            BackingEngine::Sync => w.seg.sync()?,
            BackingEngine::Uring(rings) => {
                rings.write().lock().fsync_order_barrier(w.seg.raw_fd())?;
            }
        }
        let next_id =
            w.id.checked_add(w.valid)
                .ok_or(OrfsError::Overflow { what: "segment id" })?;
        let name = segment_file_name(next_id)?;
        if self.dir.join(&name).exists() {
            // Reusing this name would discard the bytes it currently holds. If a
            // live root pin still needs a segment at or above `next_id`, that
            // discard would withdraw committed history, so refuse loudly rather
            // than silently invalidate a snapshot (research §2, I1; §24).
            if self.pins.segment_required(next_id) {
                return Err(OrfsError::Pinned(format!(
                    "segment {next_id} is required by a pinned historical root"
                )));
            }
            quarantine_segment(&self.dir, next_id)?;
        }
        let seg = Segment::create(&self.dir, next_id)?;
        self.locator.push(SegmentExtent {
            id: next_id,
            valid_len: 0,
        });
        self.writer = Some(Writer {
            seg,
            id: next_id,
            valid: 0,
            pending: 0,
        });
        fsync_dir(&self.dir)?;
        Ok(())
    }

    /// Flush and fsync the current segment (durability hook).
    pub fn sync(&mut self) -> Result<()> {
        if let Some(w) = &self.writer {
            match &self.io {
                BackingEngine::Sync => w.seg.sync()?,
                // Explicit ordered durability barrier: the fsync is flagged
                // IOSQE_IO_DRAIN so it cannot start before earlier SQEs complete.
                BackingEngine::Uring(rings) => {
                    rings.write().lock().fsync_order_barrier(w.seg.raw_fd())?;
                }
            }
        }
        // The bytes are durable: now make the completeness witness durable too.
        self.persist_watermark()?;
        Ok(())
    }

    /// Attempt to engage the io_uring backing engine (research §17 Domain A).
    ///
    /// On success every subsequent authoritative write, read, and `fsync` in this
    /// log is performed through `io_uring` and the returned report has
    /// `engaged: true`. If the ring cannot be created (or a required opcode is
    /// unsupported) the log keeps using synchronous positional I/O and the report
    /// carries the reason. This method never weakens any correctness or durability
    /// contract: it only changes *how* the same bytes are moved.
    pub fn enable_uring(&mut self, cfg: &UringConfig) -> UringReport {
        match BackingEngine::engage(cfg) {
            Ok(engine) => {
                let engaged = engine.is_uring();
                let (depth, read_depth, registered_buffers) = match engine.rings() {
                    Some(r) => (r.write_depth(), r.read_depth(), r.registered_buffers()),
                    None => (0, 0, 0),
                };
                self.io = engine;
                UringReport {
                    requested: cfg.enabled,
                    engaged,
                    depth,
                    read_depth,
                    registered_buffers,
                    reason: None,
                }
            }
            Err(reason) => UringReport {
                requested: true,
                engaged: false,
                depth: cfg.write_depth,
                read_depth: cfg.read_depth,
                registered_buffers: 0,
                reason: Some(reason),
            },
        }
    }

    /// Whether this log's backing I/O actually runs on io_uring.
    pub fn backing_io_is_uring(&self) -> bool {
        self.io.is_uring()
    }

    /// Combined `(write_ring, read_ring)` io_uring statistics, if engaged.
    pub fn uring_stats(&self) -> Option<(crate::uring::UringStats, crate::uring::UringStats)> {
        self.io.rings().map(|r| r.stats())
    }

    /// Replay validated records from the start of the log up to `end`.
    ///
    /// `end` must be a committed transaction boundary and must not exceed the
    /// committed root.
    pub fn replay_upto(&self, end: u64) -> Result<Vec<Record>> {
        if end > self.committed_end_offset {
            return Err(OrfsError::InvalidArgument(format!(
                "replay end {end} exceeds the committed root {}",
                self.committed_end_offset
            )));
        }
        if end != 0 && !self.is_boundary(end) {
            return Err(OrfsError::InvalidArgument(format!(
                "replay end {end} is not a committed transaction boundary"
            )));
        }
        let mut reader = self.records_upto(end);
        let mut out = Vec::new();
        for r in &mut reader {
            out.push(r?);
        }
        Ok(out)
    }

    /// A validated record iterator over `[0, end)`.
    pub fn records_upto(&self, end: u64) -> RecordReader {
        RecordReader::new(&self.dir, self.locator.extents(), end)
    }

    /// A validated record iterator over `[start, end)`.
    ///
    /// `start` must be a committed transaction boundary; the returned reader
    /// begins exactly there and reads no bytes before it (the checkpoint-replay
    /// fast path).
    pub fn records_from(&self, start: u64, end: u64) -> RecordReader {
        RecordReader::starting_at(&self.dir, self.locator.extents(), start, end)
    }

    /// Read the single committed record whose first byte is at `offset`.
    ///
    /// `offset` must be a committed transaction boundary. Used to load exactly
    /// one `INDEX_CHECKPOINT` body once its header-scan offset is known.
    pub fn read_record_at(&self, offset: u64, end: u64) -> Result<Record> {
        if offset >= end {
            return Err(OrfsError::InvalidArgument(format!(
                "record offset {offset} is not before {end}"
            )));
        }
        self.records_from(offset, end)
            .next()
            .ok_or_else(|| OrfsError::Corrupt(format!("no record at offset {offset}")))?
    }

    /// Header-only scan of `[0, end)` returning the offsets of the records whose
    /// type is in `wanted`, **without reading any record body**.
    ///
    /// This lets checkpoint recovery locate candidate checkpoints cheaply and
    /// then read exactly one body, instead of materialising every checkpoint's
    /// embedded index (research §24).
    pub fn scan_record_offsets_of_types(
        &self,
        end: u64,
        wanted: &[RecordType],
    ) -> Result<Vec<u64>> {
        if end > self.committed_end_offset {
            return Err(OrfsError::InvalidArgument(format!(
                "scan end {end} exceeds the committed root {}",
                self.committed_end_offset
            )));
        }
        if end != 0 && !self.is_boundary(end) {
            return Err(OrfsError::InvalidArgument(format!(
                "scan end {end} is not a committed transaction boundary"
            )));
        }
        let mut out = Vec::new();
        let mut offset = 0u64;
        let mut reader: Option<(u64, ReadAt)> = None;
        while offset < end {
            let (sid, phys) = self.locator.locate(offset).ok_or_else(|| {
                OrfsError::Corrupt(format!("no segment covers logical offset {offset}"))
            })?;
            let extent = self
                .locator
                .extent_of(sid)
                .ok_or_else(|| OrfsError::Corrupt(format!("missing extent for segment {sid}")))?;
            if reader.as_ref().map(|(id, _)| *id) != Some(sid) {
                reader = Some((sid, ReadAt::open(&self.dir, sid)?));
            }
            let r = &reader.as_ref().expect("reader opened").1;
            let avail = extent
                .valid_len
                .checked_sub(phys)
                .ok_or_else(|| OrfsError::Corrupt("scan offset beyond extent".to_string()))?
                .min(end - offset);
            if avail < HEADER_LEN as u64 {
                return Err(OrfsError::Corrupt(format!(
                    "truncated record within committed region at offset {offset}"
                )));
            }
            let mut header_bytes = [0u8; HEADER_LEN];
            r.read_exact_at(phys, &mut header_bytes)?;
            let header = RecordHeader::decode(&header_bytes).map_err(OrfsError::from)?;
            let class = header.classify_type().map_err(OrfsError::from)?;
            let total = header.total_len().map_err(OrfsError::from)?;
            if total > avail {
                return Err(OrfsError::Corrupt(format!(
                    "record at offset {offset} crosses the committed root"
                )));
            }
            if let TypeClass::Known(t) = class {
                if wanted.contains(&t) {
                    out.push(offset);
                }
            }
            offset = offset.checked_add(total).ok_or(OrfsError::Overflow {
                what: "scan offset",
            })?;
        }
        Ok(out)
    }

    /// Scan the committed frames in `[0, end)` and return the payloads of only
    /// the records whose type is in `wanted`.
    ///
    /// This is the checkpoint-discovery primitive: it walks record **headers**
    /// (60 bytes each) and reads a record's body only when its type is wanted, so
    /// discovering an `INDEX_CHECKPOINT` does not require materialising every
    /// intervening `DATA_EXTENT` payload. The full log was already framed and
    /// checksum-validated by [`scan_log`] when the log was opened, so skipping
    /// bodies here cannot hide a corrupt committed record (research §23.1, §24).
    pub fn scan_records_of_types(&self, end: u64, wanted: &[RecordType]) -> Result<Vec<RawRecord>> {
        if end > self.committed_end_offset {
            return Err(OrfsError::InvalidArgument(format!(
                "scan end {end} exceeds the committed root {}",
                self.committed_end_offset
            )));
        }
        if end != 0 && !self.is_boundary(end) {
            return Err(OrfsError::InvalidArgument(format!(
                "scan end {end} is not a committed transaction boundary"
            )));
        }
        let mut out = Vec::new();
        let mut offset = 0u64;
        let mut reader: Option<(u64, ReadAt)> = None;
        while offset < end {
            let (sid, phys) = self.locator.locate(offset).ok_or_else(|| {
                OrfsError::Corrupt(format!("no segment covers logical offset {offset}"))
            })?;
            let extent = self
                .locator
                .extent_of(sid)
                .ok_or_else(|| OrfsError::Corrupt(format!("missing extent for segment {sid}")))?;
            if reader.as_ref().map(|(id, _)| *id) != Some(sid) {
                reader = Some((sid, ReadAt::open(&self.dir, sid)?));
            }
            let r = &reader.as_ref().expect("reader opened").1;
            let avail = extent
                .valid_len
                .checked_sub(phys)
                .ok_or_else(|| OrfsError::Corrupt("scan offset beyond extent".to_string()))?
                .min(end - offset);
            if avail < HEADER_LEN as u64 {
                return Err(OrfsError::Corrupt(format!(
                    "truncated record within committed region at offset {offset}"
                )));
            }
            let mut header_bytes = [0u8; HEADER_LEN];
            r.read_exact_at(phys, &mut header_bytes)?;
            let header = RecordHeader::decode(&header_bytes).map_err(OrfsError::from)?;
            let class = header.classify_type().map_err(OrfsError::from)?;
            let total = header.total_len().map_err(OrfsError::from)?;
            if total > avail {
                return Err(OrfsError::Corrupt(format!(
                    "record at offset {offset} crosses the committed root"
                )));
            }
            if let TypeClass::Known(t) = class {
                if wanted.contains(&t) {
                    let n = usize::try_from(total)
                        .map_err(|_| OrfsError::Corrupt("record length overflow".to_string()))?;
                    let mut buf = vec![0u8; n];
                    r.read_exact_at(phys, &mut buf)?;
                    let (record, _) = Record::decode(&buf).map_err(OrfsError::from)?;
                    out.push(RawRecord {
                        offset,
                        record_type: t,
                        payload: record.payload,
                    });
                }
            }
            offset = offset.checked_add(total).ok_or(OrfsError::Overflow {
                what: "scan offset",
            })?;
        }
        Ok(out)
    }

    /// Read `len` canonical bytes at logical `offset`, crossing segment
    /// boundaries as needed.
    ///
    /// Used to fetch immutable extent bytes referenced by a derived index. The
    /// range must lie within the canonical bytes (committed data always does).
    pub fn read_range(&self, offset: u64, len: u64) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let end = offset.checked_add(len).ok_or(OrfsError::Overflow {
            what: "read range end",
        })?;
        let limit = self.locator.total_len();
        if end > limit {
            return Err(OrfsError::OutOfBounds {
                offset,
                length: len,
                limit,
            });
        }
        // Plan the segment-by-segment reads first, so the io_uring path can issue
        // them concurrently (Ring R) while the sync path performs them in order.
        let mut plan: Vec<(ReadAt, u64, usize)> = Vec::new();
        let mut cur = offset;
        while cur < end {
            let (seg_id, phys) = self.locator.locate(cur).ok_or_else(|| {
                OrfsError::Corrupt(format!("no segment covers logical offset {cur}"))
            })?;
            let extent = self.locator.extent_of(seg_id).ok_or_else(|| {
                OrfsError::Corrupt(format!("missing extent for segment {seg_id}"))
            })?;
            let avail = extent.valid_len.checked_sub(phys).ok_or_else(|| {
                OrfsError::Corrupt("read offset beyond segment extent".to_string())
            })?;
            let want = (end - cur).min(avail) as usize;
            let reader = ReadAt::open(&self.dir, seg_id)?;
            plan.push((reader, phys, want));
            cur += want as u64;
        }

        let mut out = Vec::with_capacity(len as usize);
        match &self.io {
            BackingEngine::Sync => {
                for (reader, phys, want) in &plan {
                    let mut buf = vec![0u8; *want];
                    reader.read_exact_at(*phys, &mut buf)?;
                    out.extend_from_slice(&buf);
                }
            }
            BackingEngine::Uring(rings) => {
                let mut bufs: Vec<Vec<u8>> =
                    plan.iter().map(|(_, _, want)| vec![0u8; *want]).collect();
                let mut jobs: Vec<ReadJob<'_>> = plan
                    .iter()
                    .zip(bufs.iter_mut())
                    .map(|((reader, phys, _), buf)| ReadJob::new(reader.raw_fd(), *phys, buf))
                    .collect();
                rings.read().lock().read_batch(&mut jobs)?;
                for buf in &bufs {
                    out.extend_from_slice(buf);
                }
            }
        }
        Ok(out)
    }

    /// Read the exact committed canonical bytes `[0, R)`.
    pub fn read_committed_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut remaining = self.committed_end_offset;
        for e in self.locator.extents() {
            if remaining == 0 {
                break;
            }
            let take = e.valid_len.min(remaining);
            if take > 0 {
                let reader = ReadAt::open(&self.dir, e.id)?;
                let mut buf = vec![0u8; take as usize];
                reader.read_exact_at(0, &mut buf)?;
                out.extend_from_slice(&buf);
            }
            remaining -= take;
            if take < e.valid_len {
                break;
            }
        }
        if remaining != 0 {
            return Err(OrfsError::Corrupt(
                "committed root extends beyond the canonical bytes".to_string(),
            ));
        }
        Ok(out)
    }

    /// A BLAKE3 digest (lowercase hex) of the committed canonical bytes.
    ///
    /// This is *evidence*, not identity: a root is a position, never a hash
    /// (§2, I2).
    pub fn committed_digest_hex(&self) -> Result<String> {
        Ok(blake3::hash(&self.read_committed_bytes()?)
            .to_hex()
            .to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time proof that the shared read path is genuinely shareable: a
    /// `Log` (and therefore an `Arc<Log>`) can be sent to and shared by many
    /// reader threads at once (Phase 6 carry-over fix; a `RefCell` read ring
    /// would make `Log` `!Sync` and this assertion fail to compile).
    #[test]
    fn log_and_pins_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_send<T: Send>() {}
        // The log is shareable (`Arc<Log>`) because the rings are behind a
        // `Mutex`, not a `RefCell`.
        assert_send_sync::<Log>();
        assert_send_sync::<RootPins>();
        assert_send_sync::<crate::uring::BackingRings>();
        assert_send_sync::<crate::snapshot::Snapshot>();
        // The engine itself is only `Send` (it owns `Cell`/`RefCell` state and
        // raw staging buffers); the `Mutex` makes it shareable safely.
        assert_send::<crate::uring::UringEngine>();
    }

    #[test]
    fn pins_are_reference_counted_and_released() {
        let pins = RootPins::new();
        assert!(!pins.is_pinned(100));
        let a = {
            pins.register(100);
            RootPin {
                pins: pins.clone(),
                root: 100,
            }
        };
        pins.register(100);
        assert_eq!(pins.pin_count(100), 2);
        assert!(pins.is_pinned(100));
        drop(a);
        assert_eq!(pins.pin_count(100), 1);
        pins.release(100);
        assert!(!pins.is_pinned(100));
        assert_eq!(pins.pinned_roots(), Vec::<u64>::new());
    }

    #[test]
    fn a_segment_below_a_pinned_root_is_required() {
        let pins = RootPins::new();
        let _pin = {
            pins.register(4096);
            RootPin {
                pins: pins.clone(),
                root: 4096,
            }
        };
        // Segments whose id is strictly below the pinned root are required.
        assert!(pins.segment_required(0));
        assert!(pins.segment_required(4095));
        assert!(!pins.segment_required(4096));
        assert!(!pins.segment_required(9999));
    }
}
