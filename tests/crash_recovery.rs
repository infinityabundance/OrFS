//! Phase 2 **process-crash** recovery tests (research §34, §35).
//!
//! # Process crash is not power loss
//!
//! These tests simulate a *process* crash: a child process is terminated with
//! `SIGABRT` in the middle of the authoritative write path. The operating-system
//! page cache survives the crash, so every byte that reached a `write` syscall is
//! still present when the parent reopens the volume. This is a genuine, strong
//! test of OrFS's own logic — no destructor runs, no user-space buffer is
//! flushed, and in-memory state is gone — but it does **not** model storage
//! device reordering, lost write-back cache contents, or torn sectors at the
//! device level. A `sync` acknowledgment is therefore tested to the extent the
//! backing filesystem's `fsync` semantics allow; power-loss durability is a
//! separate, explicitly-identified proof obligation (`docs/TRANSACTIONS.md`).
//!
//! # Method
//!
//! For each [`Failpoint`] the parent:
//!
//! 1. initialises a volume and commits a known-good baseline (no failpoint);
//! 2. spawns *this same test binary* as a child, which opens the volume, arms
//!    exactly one failpoint with the `abort` action, and commits transactions
//!    until it dies;
//! 3. independently reopens the volume and verifies the recovery invariants;
//! 4. records the recovered root and verdicts as machine-generated evidence.
//!
//! Run with `cargo test --features failpoints`.

#![cfg(feature = "failpoints")]

mod support;

use std::path::Path;
use std::process::{Command, Stdio};

use orfs::commit::{CommitSequencer, DurabilityMode};
use orfs::failpoints::{self, FailAction, Failpoint};
use orfs::log::{scan_log, OpenMode};
use orfs::record::RecordType;
use orfs::volume::Volume;

use support::{build_transaction, init_volume, verify_recovered, SegmentSnapshot};
use tempfile::TempDir;

/// Segment size for crash tests: small enough that the write path rolls over.
const CRASH_SEGMENT_SIZE: u64 = 1024;
/// Baseline transactions committed by the parent before the crash.
const BASELINE_TXNS: u64 = 3;

// ---------------------------------------------------------------------------
// Child role
// ---------------------------------------------------------------------------

/// The child process body. When `ORFS_CRASH_CHILD` is unset this returns
/// immediately (so the ordinary test run is unaffected).
///
/// The parent passes the failpoint name and the volume directory; the child arms
/// the failpoint *after* opening the volume so that open-time directory
/// synchronization is not itself the injected failure.
#[test]
fn crash_child_role() {
    let Ok(fp_name) = std::env::var("ORFS_CRASH_CHILD") else {
        return;
    };
    let dir = std::env::var("ORFS_CRASH_DIR").expect("ORFS_CRASH_DIR");
    let fp = Failpoint::from_name(&fp_name).expect("known failpoint");

    let mut vol = Volume::open(Path::new(&dir), OpenMode::ReadWrite).expect("child open volume");
    let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
    failpoints::configure_one(fp.name(), FailAction::Abort, 0);

    // Commit until the armed failpoint aborts the process. The loop is bounded
    // only so that a mistaken configuration terminates rather than hangs.
    for i in 0..5000u64 {
        let mut b = seq.begin().expect("begin");
        b.add(RecordType::InodeCreate, i + 1, 0, vec![0u8; 64])
            .expect("add inode record");
        b.add(RecordType::DataExtent, i + 1, 0, vec![0u8; 48])
            .expect("add extent record");
        let tx = b.build().expect("build");
        // With the `abort` action this call never returns once the failpoint is
        // hit; if it does return, the log is discarded by process exit anyway.
        let _ = seq.commit(tx);
    }
    // The failpoint never fired: report a distinct status so the parent fails.
    eprintln!("child: failpoint {fp_name} never fired");
    std::process::exit(7);
}

// ---------------------------------------------------------------------------
// Parent role
// ---------------------------------------------------------------------------

fn spawn_child(dir: &Path, fp: Failpoint) -> std::process::ExitStatus {
    let exe = std::env::current_exe().expect("current exe");
    Command::new(exe)
        .args([
            "crash_child_role",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ORFS_CRASH_CHILD", fp.name())
        .env("ORFS_CRASH_DIR", dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn crash child")
}

/// Set up the known-good baseline. Returns `(root, committed_bytes, segments)`.
fn baseline(dir: &Path) -> (u64, Vec<u8>, Vec<SegmentSnapshot>) {
    failpoints::clear();
    let mut vol = init_volume(dir, CRASH_SEGMENT_SIZE);
    let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
    for i in 1..=BASELINE_TXNS {
        seq.commit(build_transaction(i, 2))
            .expect("baseline commit");
    }
    seq.flush().expect("baseline flush");
    let root = vol.log.committed_end_offset();
    let bytes = vol.log.read_committed_bytes().expect("baseline bytes");
    let segments = support::snapshot_segments(&vol.log);
    (root, bytes, segments)
}

/// One failpoint's crash-and-recover experiment.
struct CrashRecord {
    failpoint: Failpoint,
    crashed_by_sigabrt: bool,
    baseline_root: u64,
    scan_committed_root: u64,
    scan_physical_end: u64,
    scan_tail_kind: Option<String>,
    scan_tail_abandoned_bytes: Option<u64>,
    recovered_root: u64,
    verdicts: support::RecoveryVerdicts,
}

fn run_one(fp: Failpoint) -> CrashRecord {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().to_path_buf();
    let (baseline_root, baseline_bytes, baseline_segments) = baseline(&dir);

    let status = spawn_child(&dir, fp);
    use std::os::unix::process::ExitStatusExt;
    let crashed_by_sigabrt = status.signal() == Some(libc::SIGABRT);

    // Scan the crashed volume BEFORE recovery mutates anything.
    let scan = scan_log(&Volume::log_dir(&dir)).expect("scan crashed log");

    let (verdicts, recovered_root) =
        verify_recovered(&dir, baseline_root, &baseline_bytes, &baseline_segments);

    CrashRecord {
        failpoint: fp,
        crashed_by_sigabrt,
        baseline_root,
        scan_committed_root: scan.committed_end_offset,
        scan_physical_end: scan.physical_end,
        scan_tail_kind: scan.tail.map(|t| format!("{:?}", t.kind)),
        scan_tail_abandoned_bytes: scan.tail.map(|t| t.abandoned_bytes),
        recovered_root,
        verdicts,
    }
}

fn record_json(r: &CrashRecord) -> serde_json::Value {
    serde_json::json!({
        "failpoint": r.failpoint.name(),
        "crashed_by_sigabrt": r.crashed_by_sigabrt,
        "baseline_root": r.baseline_root,
        "scan_committed_root": r.scan_committed_root,
        "scan_physical_end": r.scan_physical_end,
        "scan_tail_kind": r.scan_tail_kind,
        "scan_tail_abandoned_bytes": r.scan_tail_abandoned_bytes,
        "recovered_root": r.recovered_root,
        "recovered_root_advanced": r.recovered_root > r.baseline_root,
        "verdicts": r.verdicts,
    })
}

/// Failpoints whose injection leaves torn (partially written) bytes.
const TORN_FAILPOINTS: [Failpoint; 3] = [
    Failpoint::DuringRecordWrite,
    Failpoint::AfterPartialRecordWrite,
    Failpoint::DuringCommitRecordWrite,
];

#[test]
fn process_crash_at_every_failpoint_recovers_to_a_valid_boundary() {
    let mut records = Vec::new();
    for fp in Failpoint::ALL {
        let rec = run_one(fp);
        assert!(
            rec.crashed_by_sigabrt,
            "failpoint {}: child was not killed by SIGABRT",
            fp.name()
        );
        assert!(
            rec.verdicts.all_ok(),
            "failpoint {}: recovery verdicts failed: {:?}",
            fp.name(),
            rec.verdicts
        );
        records.push(rec);
    }

    // The baseline differs per experiment but is identical by construction.
    let baseline_root = records[0].baseline_root;

    let evidence_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/recovery");

    let all_entries: Vec<serde_json::Value> = records.iter().map(record_json).collect();
    let commit_interruption = serde_json::json!({
        "schema": "orfs.evidence.commit-interruption.v1",
        "generator": "tests/crash_recovery.rs",
        "evidence_kind": "process-crash (NOT power-loss)",
        "method": "child process terminated with SIGABRT at each failpoint, then an independent reopen",
        "segment_size": CRASH_SEGMENT_SIZE,
        "baseline_transactions": BASELINE_TXNS,
        "baseline_root": baseline_root,
        "failpoints": all_entries,
        "all_verdicts_ok": records.iter().all(|r| r.verdicts.all_ok()),
        "all_children_crashed": records.iter().all(|r| r.crashed_by_sigabrt),
    });
    support::write_json(
        &evidence_dir.join("commit-interruption.json"),
        &commit_interruption,
    );

    let torn_entries: Vec<serde_json::Value> = records
        .iter()
        .filter(|r| TORN_FAILPOINTS.contains(&r.failpoint))
        .map(record_json)
        .collect();
    let torn_write = serde_json::json!({
        "schema": "orfs.evidence.torn-write.v1",
        "generator": "tests/crash_recovery.rs",
        "evidence_kind": "process-crash (NOT power-loss)",
        "method": "SIGABRT mid-record-write, then an independent reopen",
        "segment_size": CRASH_SEGMENT_SIZE,
        "baseline_root": baseline_root,
        "failpoints": torn_entries,
        "all_verdicts_ok": records
            .iter()
            .filter(|r| TORN_FAILPOINTS.contains(&r.failpoint))
            .all(|r| r.verdicts.all_ok()),
    });
    support::write_json(&evidence_dir.join("torn-write.json"), &torn_write);
}
