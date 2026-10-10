//! Shared helpers for the Phase 2 transaction and crash-recovery tests.
//!
//! This module is included by `tests/transaction_model.rs` and
//! `tests/crash_recovery.rs` via `mod support;`. It is not a test target of its
//! own. Some helpers are used by only one of the two test binaries.
#![allow(dead_code)]

use std::path::Path;

use orfs::commit::{CommitSequencer, DurabilityMode};
use orfs::log::OpenMode;
use orfs::namespace::Namespace;
use orfs::record::RecordType;
use orfs::segment::segment_file_name;
use orfs::transaction::Transaction;
use orfs::volume::Volume;

/// A fixed volume UUID so evidence volumes are byte-reproducible.
pub const FIXED_UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x02, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
/// A fixed creation timestamp for reproducible volumes.
pub const FIXED_CREATED: u64 = 1_700_000_000;

/// The mutating record types used by the randomized tests.
pub const MUTATING_TYPES: [RecordType; 6] = [
    RecordType::InodeCreate,
    RecordType::InodeMetadata,
    RecordType::DentryAdd,
    RecordType::DentryRemove,
    RecordType::DataExtent,
    RecordType::XattrSet,
];

/// Initialise a fresh, reproducible volume.
pub fn init_volume(dir: &Path, segment_size: u64) -> Volume {
    Volume::init_with_uuid(dir, segment_size, FIXED_UUID, FIXED_CREATED).expect("init volume")
}

/// Initialise a fresh, reproducible namespace (Phase 3).
pub fn init_namespace(dir: &Path, segment_size: u64, durability: DurabilityMode) -> Namespace {
    Namespace::init_with_uuid(dir, segment_size, FIXED_UUID, FIXED_CREATED, durability)
        .expect("init namespace")
}

/// Deterministic payload of `len` bytes derived from `(tx, i)`.
pub fn payload(tx: u64, i: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|k| {
            ((tx as u8).wrapping_mul(31))
                .wrapping_add((i as u8).wrapping_mul(17))
                .wrapping_add(k as u8)
        })
        .collect()
}

/// Build a transaction with `records` data records of deterministic payloads.
pub fn build_transaction(id: u64, records: usize) -> Transaction {
    let mut b = orfs::transaction::TransactionBuilder::new(id).expect("builder");
    for i in 0..records {
        b.add(
            MUTATING_TYPES[i % MUTATING_TYPES.len()],
            id,
            0,
            payload(id, i as u64, 16 + (i * 7) % 64),
        )
        .expect("add record");
    }
    b.build().expect("build transaction")
}

/// A physical snapshot of one segment's valid prefix at a point in time.
#[derive(Debug, Clone)]
pub struct SegmentSnapshot {
    pub id: u64,
    pub bytes: Vec<u8>,
}

/// Capture the physical valid prefix of every non-empty canonical segment.
pub fn snapshot_segments(log: &orfs::log::Log) -> Vec<SegmentSnapshot> {
    let dir = log.dir();
    log.extents()
        .iter()
        .filter(|e| e.valid_len > 0)
        .map(|e| {
            let path = dir.join(segment_file_name(e.id).expect("segment name"));
            let mut bytes = vec![0u8; e.valid_len as usize];
            use std::os::unix::fs::FileExt;
            let f = std::fs::File::open(path).expect("open segment");
            f.read_exact_at(&mut bytes, 0).expect("read segment");
            SegmentSnapshot { id: e.id, bytes }
        })
        .collect()
}

/// The machine-checkable verdicts of a post-crash recovery check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RecoveryVerdicts {
    /// The recovered committed root is a complete transaction boundary.
    pub recovered_root_is_transaction_boundary: bool,
    /// Every previously committed root remains a valid boundary.
    pub previously_committed_roots_still_valid: bool,
    /// The final recovered record is a `TX_COMMIT` (or `VOLUME_GENESIS`).
    pub no_uncommitted_record_exposed: bool,
    /// The committed bytes at the earlier root are a byte-exact prefix of the
    /// recovered committed bytes (nothing was rewritten).
    pub no_committed_record_rewritten: bool,
    /// The committed physical bytes of pre-existing segments are unchanged.
    pub committed_physical_bytes_unchanged: bool,
    /// The next transaction begins exactly at the recovered root: failed bytes
    /// were retained, never reused.
    pub next_transaction_does_not_reuse_failed_bytes: bool,
    /// The next transaction commits successfully at a strictly greater root.
    pub next_transaction_succeeds: bool,
}

impl RecoveryVerdicts {
    /// Whether every verdict holds.
    pub fn all_ok(&self) -> bool {
        self.recovered_root_is_transaction_boundary
            && self.previously_committed_roots_still_valid
            && self.no_uncommitted_record_exposed
            && self.no_committed_record_rewritten
            && self.committed_physical_bytes_unchanged
            && self.next_transaction_does_not_reuse_failed_bytes
            && self.next_transaction_succeeds
    }
}

/// Reopen a volume that was crashed, verify the recovery invariants
/// (research §35), then commit one fresh transaction to prove progress.
///
/// `baseline_root` and `baseline_bytes` describe the last known-good committed
/// state before the crash; `baseline_segments` are its physical snapshots.
pub fn verify_recovered(
    dir: &Path,
    baseline_root: u64,
    baseline_bytes: &[u8],
    baseline_segments: &[SegmentSnapshot],
) -> (RecoveryVerdicts, u64) {
    let mut vol = Volume::open(dir, OpenMode::ReadWrite).expect("reopen volume");

    let recovered = vol.log.committed_end_offset();
    let recovered_root_is_boundary = vol.log.is_boundary(recovered);

    let previously_committed_roots_still_valid =
        baseline_root <= recovered && vol.log.is_boundary(baseline_root);

    // The committed prefix must end on a committed transaction record.
    let recs = vol
        .log
        .replay_upto(recovered)
        .expect("replay recovered root");
    let no_uncommitted_record_exposed = match recs.last() {
        Some(r) => matches!(
            r.known_type().expect("known type"),
            RecordType::TxCommit | RecordType::VolumeGenesis
        ),
        None => false,
    };

    let now = vol
        .log
        .read_committed_bytes()
        .expect("read committed bytes");
    let no_committed_record_rewritten =
        now.len() >= baseline_bytes.len() && now[..baseline_bytes.len()] == *baseline_bytes;

    // Physical byte-exactness of every pre-existing segment prefix.
    let mut committed_physical_bytes_unchanged = true;
    for snap in baseline_segments {
        let path = vol
            .log
            .dir()
            .join(segment_file_name(snap.id).expect("name"));
        match std::fs::read(&path) {
            Ok(actual) => {
                if actual.len() < snap.bytes.len() || actual[..snap.bytes.len()] != snap.bytes[..] {
                    committed_physical_bytes_unchanged = false;
                    break;
                }
            }
            Err(_) => {
                committed_physical_bytes_unchanged = false;
                break;
            }
        }
    }

    // The next transaction must begin exactly at the recovered root and succeed.
    let mut next_transaction_does_not_reuse_failed_bytes = false;
    let mut next_transaction_succeeds = false;
    {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
        let tx = build_transaction(seq.peek_transaction_id(), 2);
        match seq.commit(tx) {
            Ok(out) => {
                next_transaction_does_not_reuse_failed_bytes = out.begin_offset == recovered;
                next_transaction_succeeds = out.root > recovered && vol.log.is_boundary(out.root);
            }
            Err(e) => {
                eprintln!("verify_recovered: next commit failed: {e}");
            }
        }
    }

    (
        RecoveryVerdicts {
            recovered_root_is_transaction_boundary: recovered_root_is_boundary,
            previously_committed_roots_still_valid,
            no_uncommitted_record_exposed,
            no_committed_record_rewritten,
            committed_physical_bytes_unchanged,
            next_transaction_does_not_reuse_failed_bytes,
            next_transaction_succeeds,
        },
        recovered,
    )
}

/// Write pretty JSON (with a trailing newline) to `path`.
pub fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create evidence dir");
    }
    let mut s = serde_json::to_string_pretty(value).expect("serialize json");
    s.push('\n');
    std::fs::write(path, s).expect("write evidence");
}
