//! Phase 1 log-model tests: committed-root identity, deterministic replay,
//! torn-tail quarantine, non-withdrawal across appends and rollover, locator
//! continuity, and framing robustness.
//!
//! The evidence test at the bottom regenerates, from actual runs, the
//! machine-readable artifacts under `evidence/correctness/`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::Path;

use orfs::log::{scan_log, Log, OpenMode, TailKind};
use orfs::record::{Record, RecordType};
use orfs::segment::{segment_file_name, SegmentExtent, SegmentLocator};
use orfs::volume::Volume;

use proptest::prelude::*;
use tempfile::TempDir;

/// A deterministic identity for reproducible volumes and evidence.
const FIXED_UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x00, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const FIXED_CREATED: u64 = 1_700_000_000;

/// Deterministic payload generator.
fn payload(tx: u64, i: u64) -> Vec<u8> {
    let len = ((tx * 37 + i * 13) % 200) as usize;
    let mut v = Vec::with_capacity(len);
    for k in 0..len {
        v.push(
            ((tx as u8).wrapping_mul(31))
                .wrapping_add((i as u8).wrapping_mul(17))
                .wrapping_add(k as u8),
        );
    }
    v
}

/// Build a reproducible volume and run `txns` committed transactions.
fn build(dir: &Path, segment_size: u64, txns: u64) -> (Volume, Vec<u64>) {
    let mut vol =
        Volume::init_with_uuid(dir, segment_size, FIXED_UUID, FIXED_CREATED).expect("init volume");
    let roots = append_transactions(&mut vol.log, txns);
    (vol, roots)
}

fn append_transactions(log: &mut Log, txns: u64) -> Vec<u64> {
    let mut roots = Vec::new();
    for tx in 1..=txns {
        log.begin(tx).expect("begin");
        let off0 = log
            .append(Record::new(RecordType::InodeCreate, 0, tx, tx, 0, 0, payload(tx, 0)).unwrap())
            .expect("append inode");
        log.append(
            Record::new(RecordType::DataExtent, 0, tx, tx, off0, 0, payload(tx, 1)).unwrap(),
        )
        .expect("append extent");
        roots.push(log.commit().expect("commit"));
    }
    roots
}

fn segment_prefix_bytes(log_dir: &Path, e: &SegmentExtent) -> Vec<u8> {
    let mut buf = vec![0u8; e.valid_len as usize];
    if e.valid_len > 0 {
        let f = File::open(log_dir.join(segment_file_name(e.id).unwrap())).unwrap();
        f.read_exact_at(&mut buf, 0).unwrap();
    }
    buf
}

fn append_raw(path: &Path, bytes: &[u8]) {
    let mut f = OpenOptions::new().append(true).open(path).unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

// ---------------------------------------------------------------------------
// Root identity and replay
// ---------------------------------------------------------------------------

#[test]
fn genesis_is_the_first_boundary() {
    let td = TempDir::new().unwrap();
    let (vol, _) = build(td.path(), 1024, 3);
    let genesis_root = vol.log.boundaries()[0];
    assert_eq!(genesis_root, (60 + 24 + 16) as u64);
    let recs = vol.log.replay_upto(genesis_root).unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].known_type().unwrap(), RecordType::VolumeGenesis);
}

#[test]
fn every_published_root_is_a_complete_transaction_boundary() {
    let td = TempDir::new().unwrap();
    let (vol, roots) = build(td.path(), 1024, 20);
    assert!(roots.windows(2).all(|w| w[0] < w[1]));
    for &root in &roots {
        assert!(vol.log.is_boundary(root));
        let recs = vol.log.replay_upto(root).unwrap();
        assert_eq!(
            recs.last().unwrap().known_type().unwrap(),
            RecordType::TxCommit
        );
        // A root never points into a record.
        assert!(!vol.log.is_boundary(root - 1));
        assert!(vol.log.replay_upto(root - 1).is_err());
    }
    // The committed root is the last transaction boundary.
    assert_eq!(*roots.last().unwrap(), vol.log.committed_end_offset());
}

#[test]
fn replay_from_committed_prefixes_is_deterministic() {
    let td = TempDir::new().unwrap();
    let (_vol, roots) = build(td.path(), 1024, 20);
    let a = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    let b = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    let full = a.log.replay_upto(a.log.committed_end_offset()).unwrap();
    for &root in &roots {
        let ra = a.log.replay_upto(root).unwrap();
        let rb = b.log.replay_upto(root).unwrap();
        assert_eq!(ra, rb, "two replays of root {root} disagree");
        // Prefix property: L[0:R] is exactly the head of the full replay.
        assert_eq!(&full[..ra.len()], &ra[..], "root {root} is not a prefix");
    }
    assert_eq!(
        a.log.read_committed_bytes().unwrap(),
        b.log.read_committed_bytes().unwrap()
    );
    assert_eq!(
        a.log.committed_digest_hex().unwrap(),
        b.log.committed_digest_hex().unwrap()
    );
    // Beyond the committed root is rejected.
    let r = a.log.committed_end_offset();
    assert!(a.log.replay_upto(r + 1).is_err());
}

// ---------------------------------------------------------------------------
// Non-withdrawal
// ---------------------------------------------------------------------------

#[test]
fn committed_bytes_never_rewritten_across_appends_and_rollover() {
    let td = TempDir::new().unwrap();
    let log_dir = Volume::log_dir(td.path());
    let mut vol = Volume::init_with_uuid(td.path(), 512, FIXED_UUID, FIXED_CREATED).unwrap();

    let mut logical_snapshots: Vec<Vec<u8>> = Vec::new();
    let mut physical_snapshots: Vec<(u64, Vec<u8>)> = Vec::new();
    for tx in 1..=40u64 {
        vol.log.begin(tx).unwrap();
        vol.log
            .append(Record::new(RecordType::InodeCreate, 0, tx, tx, 0, 0, payload(tx, 0)).unwrap())
            .unwrap();
        vol.log
            .append(Record::new(RecordType::DataExtent, 0, tx, tx, 0, 0, payload(tx, 1)).unwrap())
            .unwrap();
        vol.log.commit().unwrap();
        if tx % 5 == 0 {
            logical_snapshots.push(vol.log.read_committed_bytes().unwrap());
            for e in vol.log.extents() {
                if e.valid_len > 0 {
                    physical_snapshots.push((e.id, segment_prefix_bytes(&log_dir, e)));
                }
            }
        }
    }

    assert!(
        vol.log.extents().len() > 1,
        "test must exercise segment rollover"
    );

    let final_logical = vol.log.read_committed_bytes().unwrap();
    for snap in &logical_snapshots {
        assert_eq!(
            &final_logical[..snap.len()],
            &snap[..],
            "a committed logical byte changed"
        );
    }
    for (id, snap) in &physical_snapshots {
        let f = File::open(log_dir.join(segment_file_name(*id).unwrap())).unwrap();
        let mut now = vec![0u8; snap.len()];
        f.read_exact_at(&mut now, 0).unwrap();
        assert_eq!(
            &now, snap,
            "a committed physical byte in segment {id} changed"
        );
    }
}

#[test]
fn aborted_transaction_does_not_publish_a_root() {
    let td = TempDir::new().unwrap();
    let mut vol = Volume::init_with_uuid(td.path(), 1 << 20, FIXED_UUID, FIXED_CREATED).unwrap();
    let r0 = vol.log.committed_end_offset();
    vol.log.begin(1).unwrap();
    vol.log
        .append(Record::new(RecordType::InodeCreate, 0, 1, 1, 0, 0, vec![0]).unwrap())
        .unwrap();
    vol.log.abort().unwrap();
    assert_eq!(vol.log.committed_end_offset(), r0);

    let scan = scan_log(&Volume::log_dir(td.path())).unwrap();
    assert_eq!(scan.committed_end_offset, r0);
    assert!(scan.physical_end > r0);
    assert!(scan.tail.is_some());
}

// ---------------------------------------------------------------------------
// Recovery: torn tail
// ---------------------------------------------------------------------------

#[test]
fn torn_tail_is_quarantined_not_truncated() {
    let td = TempDir::new().unwrap();
    let log_dir = Volume::log_dir(td.path());
    let (vol, roots) = build(td.path(), 1 << 20, 3);
    let committed = vol.log.committed_end_offset();
    let last_id = vol.log.extents().last().unwrap().id;
    let seg_path = log_dir.join(segment_file_name(last_id).unwrap());
    let before_bytes = std::fs::read(&seg_path).unwrap();
    drop(vol);

    // Simulate a torn write: a plausible header prefix that never completes.
    let mut torn = vec![0u8; 40];
    torn[0..4].copy_from_slice(&0x5346_524Fu32.to_le_bytes()); // "ORFS"
    append_raw(&seg_path, &torn);
    let physical_after_torn = before_bytes.len() as u64 + torn.len() as u64;

    let scan = scan_log(&log_dir).unwrap();
    assert_eq!(scan.committed_end_offset, committed);
    let tail = scan.tail.expect("torn tail must be detected");
    assert_eq!(tail.kind, TailKind::TornRecord);
    assert_eq!(tail.abandoned_bytes, physical_after_torn - committed);

    // Recovery retains the torn bytes and continues in a fresh segment.
    let mut vol = Volume::open(td.path(), OpenMode::ReadWrite).unwrap();
    vol.sync().unwrap();
    assert_eq!(vol.log.committed_end_offset(), committed);

    // The old segment is unchanged apart from the retained torn bytes: nothing
    // was truncated or rewritten.
    let after_bytes = std::fs::read(&seg_path).unwrap();
    let mut expected = before_bytes.clone();
    expected.extend_from_slice(&torn);
    assert_eq!(after_bytes, expected);
    assert_eq!(
        std::fs::metadata(&seg_path).unwrap().len(),
        physical_after_torn
    );
    assert!(log_dir.join(segment_file_name(committed).unwrap()).exists());

    // New writes continue the canonical stream.
    vol.log.begin(999).unwrap();
    vol.log
        .append(Record::new(RecordType::InodeCreate, 0, 999, 999, 0, 0, vec![9, 9]).unwrap())
        .unwrap();
    let root = vol.log.commit().unwrap();
    assert!(root > committed);
    assert!(roots.last().copied().unwrap() <= committed);
}

// ---------------------------------------------------------------------------
// Locator continuity
// ---------------------------------------------------------------------------

#[test]
fn locator_continuity_across_segments() {
    let td = TempDir::new().unwrap();
    let (vol, _) = build(td.path(), 512, 30);
    let extents = vol.log.extents();
    assert!(extents.len() > 1, "expected multiple segments");
    assert_eq!(extents[0].id, 0);
    for w in extents.windows(2) {
        assert_eq!(w[0].end(), w[1].id, "segments are not contiguous");
    }

    let locator = SegmentLocator::from_extents(extents.to_vec()).unwrap();
    for e in extents {
        assert_eq!(locator.locate(e.id), Some((e.id, 0)));
        if e.valid_len > 0 {
            assert!(locator.locate(e.end() - 1).is_some());
        }
    }
    let root = vol.log.committed_end_offset();
    assert_eq!(locator.locate(root), None);
    assert!(locator.locate(root - 1).is_some());
    assert_eq!(locator.total_len(), root);

    // Reopening reproduces the same mapping.
    let reopened = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    assert_eq!(reopened.log.extents(), extents);
}

// ---------------------------------------------------------------------------
// Framing robustness
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn framing_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = orfs::record::RecordHeader::decode(&bytes);
        let _ = Record::decode(&bytes);
    }

    #[test]
    fn framing_round_trips_arbitrary_payloads(
        payload in proptest::collection::vec(any::<u8>(), 0..2048)
    ) {
        let rec = Record::new(RecordType::DataExtent, 5, 2, 7, 1, 0, payload.clone()).unwrap();
        let bytes = rec.encode().unwrap();
        let (decoded, used) = Record::decode(&bytes).unwrap();
        prop_assert_eq!(used, bytes.len());
        prop_assert_eq!(decoded.clone(), rec);
        prop_assert_eq!(decoded.payload, payload);
    }
}

// ---------------------------------------------------------------------------
// Evidence generation
// ---------------------------------------------------------------------------

fn write_json(path: &Path, value: &serde_json::Value) {
    let mut s = serde_json::to_string_pretty(value).unwrap();
    s.push('\n');
    std::fs::write(path, s).unwrap();
}

#[test]
fn evidence_artifacts_are_generated() {
    let evidence_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/correctness");
    std::fs::create_dir_all(&evidence_dir).unwrap();

    // --- Scenario A: deterministic committed history with rollovers. ---
    let td = TempDir::new().unwrap();
    let (vol, roots) = build(td.path(), 1024, 24);
    let log = &vol.log;
    let committed_root = log.committed_end_offset();
    let digest = log.committed_digest_hex().unwrap();

    // Independently replay twice and compare (no hard-coded claims).
    let a = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    let b = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    let replayed_twice_equal = roots
        .iter()
        .all(|&r| a.log.replay_upto(r).unwrap() == b.log.replay_upto(r).unwrap());
    let distinct_replays_agree =
        a.log.read_committed_bytes().unwrap() == b.log.read_committed_bytes().unwrap();
    assert!(replayed_twice_equal);
    assert!(distinct_replays_agree);

    let genesis_root = log.boundaries()[0];
    let mut root_entries = Vec::new();
    for (i, &root) in roots.iter().enumerate() {
        let recs = log.replay_upto(root).unwrap();
        let last = recs.last().unwrap().known_type().unwrap();
        root_entries.push(serde_json::json!({
            "index": i,
            "root": root,
            "records_upto": recs.len(),
            "last_record_type": last.name(),
            "is_transaction_boundary": log.is_boundary(root),
        }));
    }

    let committed_roots = serde_json::json!({
        "schema": "orfs.evidence.committed-roots.v1",
        "generator": "tests/log_model.rs",
        "format_version": orfs::FORMAT_VERSION,
        "segment_size": log.segment_size(),
        "genesis": {
            "root": genesis_root,
            "records_upto": 1,
            "last_record_type": "VOLUME_GENESIS",
            "is_transaction_boundary": true,
        },
        "roots": root_entries,
        "invariants": {
            "every_root_is_a_transaction_boundary": roots.iter().all(|r| log.is_boundary(*r)),
            "roots_monotonic_increasing": roots.windows(2).all(|w| w[0] < w[1]),
            "committed_root_equals_last_boundary": committed_root == *roots.last().unwrap(),
            "no_root_points_into_a_record": roots.iter().all(|r| !log.is_boundary(r - 1)),
        },
        "committed_digest_blake3": digest,
    });
    write_json(&evidence_dir.join("committed-roots.json"), &committed_roots);

    // --- Scenario B: torn tail quarantined, bytes retained. ---
    let td2 = TempDir::new().unwrap();
    let log_dir2 = Volume::log_dir(td2.path());
    let (vol2, _) = build(td2.path(), 1 << 20, 3);
    let committed2 = vol2.log.committed_end_offset();
    let last_id = vol2.log.extents().last().unwrap().id;
    let seg_path = log_dir2.join(segment_file_name(last_id).unwrap());
    let physical_before = std::fs::metadata(&seg_path).unwrap().len();
    drop(vol2);

    let mut torn = vec![0u8; 40];
    torn[0..4].copy_from_slice(&0x5346_524Fu32.to_le_bytes());
    append_raw(&seg_path, &torn);

    let scan = scan_log(&log_dir2).unwrap();
    let mut vol2 = Volume::open(td2.path(), OpenMode::ReadWrite).unwrap();
    vol2.sync().unwrap();
    let retained = std::fs::metadata(&seg_path).unwrap().len();
    let fresh_segment_created = log_dir2
        .join(segment_file_name(committed2).unwrap())
        .exists();
    assert!(scan.tail.is_some());
    assert_eq!(retained, physical_before + torn.len() as u64);
    assert!(fresh_segment_created);

    let mut by_type = serde_json::Map::new();
    for (code, count) in log.record_counts_by_type() {
        by_type.insert(
            orfs::record::record_type_name(*code),
            serde_json::json!(count),
        );
    }

    let log_replay = serde_json::json!({
        "schema": "orfs.evidence.log-replay.v1",
        "generator": "tests/log_model.rs",
        "format_version": orfs::FORMAT_VERSION,
        "workload": {
            "segment_size": log.segment_size(),
            "transactions": roots.len(),
        },
        "replay": {
            "committed_root": committed_root,
            "committed_record_count": log.committed_record_count(),
            "transaction_count": log.transaction_count(),
            "canonical_bytes": log.canonical_bytes(),
            "segments": log.extents().len(),
            "records_by_type": by_type,
            "committed_digest_blake3": digest,
            "deterministic": {
                "committed_prefixes_replayed_twice_equal": replayed_twice_equal,
                "distinct_replays_agree": distinct_replays_agree,
            },
        },
        "torn_tail": {
            "detected": scan.tail.is_some(),
            "kind": scan.tail.map(|t| format!("{:?}", t.kind)),
            "committed_root_before": committed2,
            "committed_root_after_recovery": vol2.log.committed_end_offset(),
            "committed_root_unchanged": vol2.log.committed_end_offset() == committed2,
            "physical_bytes_retained": retained == physical_before + torn.len() as u64,
            "fresh_segment_created": fresh_segment_created,
        },
    });
    write_json(&evidence_dir.join("log-replay.json"), &log_replay);
}
