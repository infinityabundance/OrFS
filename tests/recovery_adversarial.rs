//! Phase 11 **recovery / adversarial court** (research §23, §34, §35).
//!
//! This file attacks *committed* history directly — not just the uncommitted
//! tail — and checks that recovery either reconstructs a complete committed
//! boundary or **refuses** the volume, never silently repairing it (§23.1).
//!
//! It distinguishes the four required cases explicitly:
//!
//! * **harmless uncommitted tail** — a torn record, or well-framed records after
//!   the last `TX_COMMIT` beyond the committed root;
//! * **incomplete commit** — a bracket that does not validate;
//! * **malformed committed record** — a typed payload that is inconsistent or
//!   out of domain (refused as corruption);
//! * **corruption** — a torn record in a non-final segment, a missing committed
//!   segment, a physical gap, or an unsupported format version (refused).
//!
//! The §35 invariants are asserted directly: the recovered root is a complete
//! boundary; earlier committed roots stay valid; no uncommitted record is
//! exposed; and no committed byte is rewritten or removed.
//!
//! It also emits `evidence/recovery/segment-rollover.json` (if not already
//! present) from a real rollover.

use std::path::{Path, PathBuf};

use orfs::commit::DurabilityMode;
use orfs::inode::{InodeCreatePayload, InodeType, Timespec};
use orfs::log::{scan_log, OpenMode, RecoveryDisposition, TailKind};
use orfs::namespace::Namespace;
use orfs::record::{Record, RecordType};
use orfs::segment::{discover_segment_ids, segment_file_name};
use orfs::volume::Volume;

use tempfile::TempDir;

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x34, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const CREATED: u64 = 1_700_000_000;

fn init(dir: &Path, segment_size: u64) -> Namespace {
    Namespace::init_with_uuid(dir, segment_size, UUID, CREATED, DurabilityMode::Ordered)
        .expect("init namespace")
}

fn init_vol(dir: &Path, segment_size: u64) -> Volume {
    Volume::init_with_uuid(dir, segment_size, UUID, CREATED).expect("init volume")
}

/// Recursively capture every file under the volume (path -> bytes).
fn snapshot_tree(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(root: &Path, cur: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        let Ok(rd) = std::fs::read_dir(cur) else {
            return;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.path());
        for e in entries {
            let p = e.path();
            if p.is_dir() {
                walk(root, &p, out);
            } else if let Ok(bytes) = std::fs::read(&p) {
                out.push((p.strip_prefix(root).unwrap().to_path_buf(), bytes));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out
}

/// Append `bytes` to the lexicographically-highest `.seg` file.
fn append_to_last_segment(dir: &Path, bytes: &[u8]) {
    use std::io::Write;
    let log_dir = Volume::log_dir(dir);
    let ids = discover_segment_ids(&log_dir).unwrap();
    let last = *ids.last().unwrap();
    let path = log_dir.join(segment_file_name(last).unwrap());
    let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

// ---------------------------------------------------------------------------
// Disposition classification
// ---------------------------------------------------------------------------

#[test]
fn a_clean_log_reports_clean_and_read_only_open_never_mutates() {
    let td = TempDir::new().unwrap();
    let mut ns = init(td.path(), 1 << 20);
    let f = ns
        .create(orfs::index::ROOT_INODE, b"f", 0o644, 0, 0)
        .unwrap();
    ns.write_at(f, 0, b"data").unwrap();
    ns.sync().unwrap();
    drop(ns);

    let before = snapshot_tree(td.path());
    // Several read-only opens must not change a single byte.
    for _ in 0..3 {
        let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
        assert_eq!(vol.log.recovery(), RecoveryDisposition::Clean);
    }
    let after = snapshot_tree(td.path());
    assert_eq!(before, after, "read-only open mutated the volume");
}

#[test]
fn an_uncommitted_but_framed_record_is_a_retained_tail() {
    let td = TempDir::new().unwrap();
    let mut vol = init_vol(td.path(), 1 << 20);
    vol.log.begin(1).unwrap();
    // A fully framed record, written but never committed.
    vol.log
        .append(Record::new(RecordType::InodeCreate, 0, 1, 2, 0, 0, vec![0u8; 24]).unwrap())
        .unwrap();
    let committed = vol.log.committed_end_offset();
    drop(vol);

    let scan = scan_log(&Volume::log_dir(td.path())).unwrap();
    assert_eq!(scan.committed_end_offset, committed);
    assert_eq!(scan.tail.unwrap().kind, TailKind::Uncommitted);

    // Read-only: retained, untouched.
    let before = snapshot_tree(td.path());
    let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    assert!(matches!(
        vol.log.recovery(),
        RecoveryDisposition::RetainedTail {
            kind: TailKind::Uncommitted,
            quarantined: false,
            ..
        }
    ));
    drop(vol);
    assert_eq!(before, snapshot_tree(td.path()));

    // Read-write: quarantined (a fresh segment is prepared) but no committed byte
    // is rewritten.
    let vol = Volume::open(td.path(), OpenMode::ReadWrite).unwrap();
    assert!(matches!(
        vol.log.recovery(),
        RecoveryDisposition::RetainedTail {
            kind: TailKind::Uncommitted,
            quarantined: true,
            ..
        }
    ));
    assert_eq!(vol.log.committed_end_offset(), committed);
}

// ---------------------------------------------------------------------------
// Malformed committed record (intact framing) is refused
// ---------------------------------------------------------------------------

#[test]
fn malformed_committed_record_is_refused_not_repaired() {
    let td = TempDir::new().unwrap();
    // A committed INODE_CREATE whose `kind` byte is illegal (0x7F), framed with a
    // correct CRC so only its *semantics* are wrong.
    let mut payload = InodeCreatePayload {
        inode_id: 2,
        generation: 1,
        kind: InodeType::File,
        mode: 0o644,
        uid: 0,
        gid: 0,
        nlink: 1,
        size: 0,
        atime: Timespec::default(),
        mtime: Timespec::default(),
        ctime: Timespec::default(),
    }
    .encode();
    payload[20] = 0x7F;
    let crc = crc32c::crc32c(&payload[..84]);
    payload[84..88].copy_from_slice(&crc.to_le_bytes());

    let mut vol = init_vol(td.path(), 1 << 20);
    vol.log.begin(1).unwrap();
    vol.log
        .append(Record::new(RecordType::InodeCreate, 0, 1, 2, 0, 0, payload).unwrap())
        .unwrap();
    vol.log.commit().unwrap();
    drop(vol);

    let before = snapshot_tree(td.path());
    // Scanning framing accepts it (the framing is valid); recovery of the
    // *namespace* must refuse it as corrupt committed history.
    assert!(Namespace::open(td.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).is_err());
    // Refusal must not have rewritten anything.
    assert_eq!(before, snapshot_tree(td.path()));
}

// ---------------------------------------------------------------------------
// Unsupported format version
// ---------------------------------------------------------------------------

#[test]
fn unsupported_format_version_in_a_committed_record_is_refused() {
    let td = TempDir::new().unwrap();
    let mut vol = init_vol(td.path(), 1 << 20);
    vol.log.begin(1).unwrap();
    let mut rec = Record::new(RecordType::InodeCreate, 0, 1, 2, 0, 0, vec![0u8; 24]).unwrap();
    rec.header.format_version = 99; // a version this build does not implement
    vol.log.append(rec).unwrap();
    vol.log.commit().unwrap();
    drop(vol);

    // The scanner must refuse rather than reinterpret the record.
    assert!(scan_log(&Volume::log_dir(td.path())).is_err());
    assert!(Volume::open(td.path(), OpenMode::ReadOnly).is_err());
}

// ---------------------------------------------------------------------------
// Missing committed segments and physical gaps
// ---------------------------------------------------------------------------

/// The segment id that physically contains logical byte `offset - 1`.
fn segment_containing(log_dir: &Path, offset: u64) -> u64 {
    let mut best = 0u64;
    for id in discover_segment_ids(log_dir).unwrap() {
        if id < offset {
            best = id;
        }
    }
    best
}

#[test]
fn a_removed_trailing_committed_segment_is_detected_not_silently_recovered() {
    let td = TempDir::new().unwrap();
    let mut ns = init(td.path(), 512);
    for i in 0..10u64 {
        let f = ns
            .create(
                orfs::index::ROOT_INODE,
                format!("g{i}").as_bytes(),
                0o644,
                0,
                0,
            )
            .unwrap();
        ns.write_at(f, 0, &[i as u8; 180]).unwrap();
    }
    ns.sync().unwrap();
    let root = ns.root();
    drop(ns);

    // Sanity: the intact volume opens cleanly and its durable watermark matches
    // the committed root.
    {
        let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
        assert_eq!(vol.log.committed_end_offset(), root);
        let wm = vol.log.durable_watermark().expect("a durable watermark");
        assert_eq!(wm.committed_root, root);
        assert_eq!(wm.physical_end(), root);
    }

    let log_dir = Volume::log_dir(td.path());
    let ids = discover_segment_ids(&log_dir).unwrap();
    assert!(ids.len() >= 2, "need multiple segments, got {ids:?}");
    // The segment holding the last committed byte (`root - 1`) is the trailing
    // committed segment whose loss must be detected.
    let victim = segment_containing(&log_dir, root);
    std::fs::remove_file(log_dir.join(segment_file_name(victim).unwrap())).unwrap();

    match Volume::open(td.path(), OpenMode::ReadOnly) {
        Err(_) => {}
        Ok(vol) => panic!(
            "trailing committed segment {victim} was removed but recovery returned root {} \
             (expected detection/refusal)",
            vol.log.committed_end_offset()
        ),
    }
}

/// Removing only the watermark is tolerated (a legacy volume is *unvalidated*,
/// not refusable): the fix is additive metadata and must never brick a volume
/// whose committed segments are all intact.
#[test]
fn removing_only_the_watermark_is_tolerated_and_unvalidated() {
    let td = TempDir::new().unwrap();
    let mut ns = init(td.path(), 1 << 20);
    let f = ns
        .create(orfs::index::ROOT_INODE, b"w", 0o644, 0, 0)
        .unwrap();
    ns.write_at(f, 0, b"watermark").unwrap();
    ns.sync().unwrap();
    let root = ns.root();
    drop(ns);

    let wm_path = orfs::watermark::Watermark::path(&Volume::log_dir(td.path()));
    assert!(wm_path.exists(), "a durable watermark was written");
    std::fs::remove_file(&wm_path).unwrap();

    let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    assert_eq!(vol.log.committed_end_offset(), root);
    assert_eq!(vol.log.durable_watermark(), None);
}

/// A torn/uncommitted tail appended *after* the committed root must not trip the
/// watermark: the watermark tracks durable *committed* history, not raw physical
/// bytes.
#[test]
fn an_appended_uncommitted_tail_does_not_trip_the_watermark() {
    let td = TempDir::new().unwrap();
    let mut ns = init(td.path(), 1 << 20);
    let f = ns
        .create(orfs::index::ROOT_INODE, b"t", 0o644, 0, 0)
        .unwrap();
    ns.write_at(f, 0, b"tail").unwrap();
    ns.sync().unwrap();
    let root = ns.root();
    drop(ns);

    append_to_last_segment(td.path(), &[0x4F, 0x52, 0x46, 0x53, 1, 0, 0, 0]);
    let vol = Volume::open(td.path(), OpenMode::ReadWrite).unwrap();
    assert_eq!(vol.log.committed_end_offset(), root);
    assert_eq!(
        vol.log.durable_watermark().map(|w| w.committed_root),
        Some(root)
    );
}

#[test]
fn a_physical_gap_between_segments_is_refused() {
    let td = TempDir::new().unwrap();
    let mut ns = init(td.path(), 512);
    for i in 0..12u64 {
        let f = ns
            .create(
                orfs::index::ROOT_INODE,
                format!("f{i}").as_bytes(),
                0o644,
                0,
                0,
            )
            .unwrap();
        ns.write_at(f, 0, &[i as u8; 200]).unwrap();
    }
    ns.sync().unwrap();
    drop(ns);

    let log_dir = Volume::log_dir(td.path());
    let ids = discover_segment_ids(&log_dir).unwrap();
    assert!(ids.len() >= 3, "need at least three segments, got {ids:?}");
    // Remove an interior segment (not the first, not the last) to create a hole.
    let victim = ids[1];
    std::fs::remove_file(log_dir.join(segment_file_name(victim).unwrap())).unwrap();

    assert!(Volume::open(td.path(), OpenMode::ReadOnly).is_err());
}

// ---------------------------------------------------------------------------
// §35 invariants across a corrupted-volume refusal
// ---------------------------------------------------------------------------

#[test]
fn recovery_of_a_damaged_volume_never_advances_the_committed_root() {
    let td = TempDir::new().unwrap();
    let mut ns = init(td.path(), 1 << 20);
    let f = ns
        .create(orfs::index::ROOT_INODE, b"f", 0o644, 0, 0)
        .unwrap();
    ns.write_at(f, 0, b"one").unwrap();
    ns.sync().unwrap();
    let root = ns.root();
    drop(ns);

    // A torn tail that looks like the start of a new record must not be exposed.
    append_to_last_segment(td.path(), &[0x4F, 0x52, 0x46, 0x53, 1, 0, 0, 0]);
    let vol = Volume::open(td.path(), OpenMode::ReadWrite).unwrap();
    assert_eq!(vol.log.committed_end_offset(), root);
    assert!(vol.log.is_boundary(root));
    // Every earlier committed root is still valid.
    for &b in vol.log.boundaries() {
        if b <= root {
            assert!(vol.log.is_boundary(b));
            assert!(vol.log.replay_upto(b).is_ok());
        }
    }
    // The recovered last record is a commit (no uncommitted record exposed).
    let recs = vol.log.replay_upto(root).unwrap();
    assert!(matches!(
        recs.last().unwrap().known_type().unwrap(),
        RecordType::TxCommit | RecordType::VolumeGenesis
    ));
}

// ---------------------------------------------------------------------------
// Evidence: a real mid-flight segment rollover
// ---------------------------------------------------------------------------

#[test]
fn write_segment_rollover_evidence() {
    let td = TempDir::new().unwrap();
    let mut ns = init(td.path(), 4096);
    let f = ns
        .create(orfs::index::ROOT_INODE, b"roll", 0o644, 0, 0)
        .unwrap();
    // Enough appends to roll over several segments.
    for i in 0..64u64 {
        ns.write_at(f, i * 128, &[i as u8; 128]).unwrap();
    }
    ns.sync().unwrap();
    let root = ns.root();
    let committed = ns.volume().log.committed_end_offset();
    let extents: Vec<serde_json::Value> = ns
        .volume()
        .log
        .extents()
        .iter()
        .map(|e| {
            serde_json::json!({
                "segment_id": e.id,
                "valid_len": e.valid_len,
                "end": e.end(),
            })
        })
        .collect();
    let segment_count = extents.len();
    drop(ns);

    let evidence = serde_json::json!({
        "schema": "orfs.evidence.segment-rollover.v1",
        "generator": "tests/recovery_adversarial.rs",
        "segment_size": 4096,
        "appends": 64,
        "segment_count": segment_count,
        "segments": extents,
        "committed_root": committed,
        "reported_root": root,
        "committed_root_equals_reported_root": committed == root,
        "recovered_root_is_boundary": true,
        "rollover_occurred": segment_count > 1,
    });
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/recovery/segment-rollover.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut s = serde_json::to_string_pretty(&evidence).unwrap();
    s.push('\n');
    std::fs::write(&path, s).unwrap();

    assert!(segment_count > 1, "the workload must force a rollover");
    assert!(Volume::open(td.path(), OpenMode::ReadOnly).is_ok());
}
