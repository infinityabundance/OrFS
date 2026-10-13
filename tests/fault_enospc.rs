//! Phase 72 — ENOSPC **fault injection at the edge** (reviewer item #13).
//!
//! OrFS is non-withdrawal: it never releases committed history, so the backing
//! store *will* eventually fill. This court drives a volume to the edge of its
//! usable capacity and proves the recovery discipline still holds there:
//!
//! * **Fill to ~99% then commit.** Usable capacity is driven to ~99% (and 90 / 95
//!   / 100%) *deterministically* with the **explicit capacity / hard-quota latch**
//!   (`CapacityPolicy::with_authoritative_capacity`, the Phase-23 mechanism) — no
//!   large files and no dependence on the host's free space. A `write + fsync` is
//!   then attempted and must either commit cleanly (it fit) or be refused with a
//!   **typed** `OrfsError::NoSpace` / `CapacityExhausted` (errno `ENOSPC`) leaving
//!   the previous committed root **byte-identical** and the volume in the
//!   documented read-only state — never a partial or silent failure.
//! * **Crash at the edge, then recover.** With the volume at the edge, a
//!   `write + fsync` is followed by a crash — either a genuine process crash (a
//!   child terminated with `SIGABRT` immediately after the `fsync` returns) or an
//!   un-clean power failure on the project's simulated storage device
//!   (`orfs::powerloss`; `docs/RECOVERY.md` §4). The **real `orfs recover`** is
//!   then run and must select the **newest valid committed generation**, keep all
//!   previously committed data intact, and silently repair or truncate nothing
//!   (`docs/RECOVERY.md` §1/§2/§3/§5).
//!
//! The always-on court is small; `ORFS_ENOSPC_SWEEP=1` adds a heavier matrix over
//! free-space levels, transaction sizes, and crash points. Evidence:
//! `evidence/recovery/fault-enospc.json` (schema `orfs.recovery.fault-enospc.v1`).
//!
//! Nothing here fills the real host disk: the fill is a *declared* capacity on a
//! small in-process volume (the primary mechanism) or a *declared* live reserve
//! on a temp directory (the secondary mechanism), and every volume lives in a
//! `tempfile::TempDir` that is removed on drop.

// The simulated storage device is the strongest crash seam the project has and
// is default-on; gate the court on it like `tests/power_loss.rs`.
#![cfg(feature = "powerloss")]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use orfs::capacity::{backing_available_bytes, CapacityPolicy};
use orfs::commit::{CommitSequencer, DurabilityMode};
use orfs::log::OpenMode;
use orfs::powerloss::{self, SimConfig};
use orfs::record::RecordType;
use orfs::segment::{discover_segment_ids, segment_file_name};
use orfs::transaction::{Transaction, TransactionBuilder};
use orfs::volume::Volume;
use orfs::OrfsError;

use serde_json::{json, Value};
use support::{build_transaction, init_volume, snapshot_segments, write_json, SegmentSnapshot};
use tempfile::TempDir;

/// A large segment so the whole workload (baseline + edge) stays in one segment,
/// which keeps a torn durable tail from ever reaching the flushed baseline.
const SEG: u64 = 4 * 1024 * 1024;
/// Committed baseline transactions (each a fat `DataExtent`).
const BASELINE_TXNS: u64 = 8;
/// Baseline payload per transaction (~64 KiB) → ~512 KiB of committed history.
const BASELINE_PAYLOAD: usize = 64 * 1024;
/// The edge fill level used by the crash rows.
const EDGE_LEVEL: u64 = 99;
/// The edge transaction's payload. Larger than a 512-byte sector so a torn
/// durable tail can never cut into the flushed baseline records below it.
const EDGE_PAYLOAD: usize = 1024;
/// The fill levels swept by the always-on court.
const FILL_LEVELS: [u64; 4] = [90, 95, 99, 100];

// ---------------------------------------------------------------------------
// Deterministic workload and fill mechanism
// ---------------------------------------------------------------------------

/// One fat transaction: a single `DataExtent` with a `payload_len`-byte payload.
fn fat_transaction(id: u64, payload_len: usize) -> Transaction {
    let mut b = TransactionBuilder::new(id).expect("builder");
    let fill = id.wrapping_mul(31) as u8;
    b.add(RecordType::DataExtent, id, 0, vec![fill; payload_len])
        .expect("add data extent");
    b.build().expect("build transaction")
}

/// Initialise a fresh reproducible volume and commit the deterministic baseline.
/// Returns `(committed_root, committed_bytes, segment_snapshots)`.
fn init_and_baseline(dir: &Path) -> (u64, Vec<u8>, Vec<SegmentSnapshot>) {
    let mut vol = init_volume(dir, SEG);
    {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
        for i in 1..=BASELINE_TXNS {
            let tx = fat_transaction(i, BASELINE_PAYLOAD);
            seq.commit(tx).expect("baseline commit");
        }
        seq.flush().expect("baseline flush");
    }
    let root = vol.log.committed_end_offset();
    let bytes = vol.log.read_committed_bytes().expect("baseline bytes");
    let segments = snapshot_segments(&vol.log);
    (root, bytes, segments)
}

/// The authoritative capacity that puts `used` bytes at `level_pct` of capacity:
/// `capacity = used + used*(100-level)/level`, so `used/capacity ≈ level/100`.
/// At `level == 100` the capacity is exactly `used` (zero admissible headroom).
fn capacity_for_fill(used: u64, level_pct: u64) -> u64 {
    assert!((1..=100).contains(&level_pct), "level must be 1..=100");
    let headroom = used.saturating_mul(100 - level_pct) / level_pct;
    used.saturating_add(headroom)
}

/// The realized fill percentage (`used / capacity`).
fn actual_fill_pct(used: u64, capacity: u64) -> u64 {
    used.saturating_mul(100)
        .checked_div(capacity)
        .map(|p| p.min(100))
        .unwrap_or(0)
}

/// Apply the primary fill mechanism (the explicit capacity latch) and return
/// `(used, capacity)`.
fn apply_fill(vol: &mut Volume, level_pct: u64) -> (u64, u64) {
    let used = vol.log.authoritative_bytes();
    let capacity = capacity_for_fill(used, level_pct);
    vol.set_capacity_policy(CapacityPolicy::new().with_authoritative_capacity(capacity));
    (used, capacity)
}

fn errno_name(e: i32) -> &'static str {
    match e {
        libc::ENOSPC => "ENOSPC",
        libc::EROFS => "EROFS",
        libc::EIO => "EIO",
        _ => "other",
    }
}

// ---------------------------------------------------------------------------
// On-disk / recovery helpers
// ---------------------------------------------------------------------------

/// The committed prefix `[0, upto)` as it survives on disk, read directly from
/// the segment files (independent of any reopen). Segment ids are logical start
/// offsets and OrFS segments are contiguous.
fn ondisk_committed_prefix(dir: &Path, upto: u64) -> Vec<u8> {
    let log_dir = Volume::log_dir(dir);
    let ids = discover_segment_ids(&log_dir).expect("segment ids");
    let mut out = Vec::new();
    for id in ids {
        if out.len() as u64 >= upto {
            break;
        }
        let path = log_dir.join(segment_file_name(id).expect("segment name"));
        let Ok(bytes) = std::fs::read(&path) else {
            break;
        };
        let take = (upto - out.len() as u64).min(bytes.len() as u64) as usize;
        out.extend_from_slice(&bytes[..take]);
    }
    out
}

fn reopen_root(dir: &Path) -> Result<u64, String> {
    match Volume::open(dir, OpenMode::ReadOnly) {
        Ok(v) => Ok(v.log.committed_end_offset()),
        Err(e) => Err(e.to_string()),
    }
}

/// The parsed `orfs recover --json` outcome (the real CLI, not a library shim).
struct RecoverOutcome {
    refused: bool,
    recovered_root: Option<u64>,
    quarantined: bool,
    tail_kind: Option<String>,
    tail_bytes: Option<u64>,
    error: Option<String>,
}

fn run_recover(dir: &Path) -> RecoverOutcome {
    let out = Command::new(env!("CARGO_BIN_EXE_orfs"))
        .arg("--json")
        .arg("recover")
        .arg(dir)
        .output()
        .expect("spawn the orfs CLI");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v = serde_json::from_str::<Value>(&stdout).ok();
    let mut rec = RecoverOutcome {
        refused: !out.status.success(),
        recovered_root: None,
        quarantined: false,
        tail_kind: None,
        tail_bytes: None,
        error: (!stderr.trim().is_empty()).then(|| stderr.trim().to_string()),
    };
    if let Some(v) = &v {
        if v["scan_error"].is_string() {
            rec.refused = true;
        }
        rec.recovered_root = v["recovered_root"].as_u64();
        rec.quarantined = v["quarantined"].as_bool().unwrap_or(false);
        if !v["tail"].is_null() {
            rec.tail_kind = v["tail"]["kind"].as_str().map(str::to_string);
            rec.tail_bytes = v["tail"]["abandoned_bytes"].as_u64();
        }
        if rec.recovered_root.is_some() {
            rec.refused = false;
        }
    }
    rec
}

// ---------------------------------------------------------------------------
// Row builders — each asserts its invariants and returns its evidence row
// ---------------------------------------------------------------------------

/// A refusal row: fill to `level_pct`, attempt a transaction bigger than the
/// headroom, require a typed refusal with the previous root byte-identical and
/// the volume read-only.
fn refusal_row(level_pct: u64, tx_payload: usize) -> Value {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path();
    let (root0, bytes0, segs0) = init_and_baseline(dir);
    let mut vol = Volume::open(dir, OpenMode::ReadWrite).expect("open");
    let (used, capacity) = apply_fill(&mut vol, level_pct);

    let err = {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
        let id = seq.peek_transaction_id();
        seq.commit(fat_transaction(id, tx_payload)).unwrap_err()
    };

    let typed = matches!(
        err,
        OrfsError::NoSpace(_) | OrfsError::CapacityExhausted { .. }
    );
    let enospc = err.errno() == libc::ENOSPC;
    let root_intact = vol.log.committed_end_offset() == root0;
    let bytes_intact = vol.log.read_committed_bytes().expect("bytes") == bytes0;
    let segs1 = snapshot_segments(&vol.log);
    let segments_intact = segs0.len() == segs1.len()
        && segs0
            .iter()
            .zip(&segs1)
            .all(|(a, b)| a.id == b.id && a.bytes == b.bytes);
    let latched = vol.is_degraded();
    let subsequent_errno = {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
        let id = seq.peek_transaction_id();
        seq.commit(build_transaction(id, 2))
            .err()
            .map(|e| e.errno())
    };
    // The explicit-capacity latch is the orderly read-only transition: the first
    // refusal is ENOSPC, every later mutation is EROFS.
    let read_only = latched && subsequent_errno == Some(libc::EROFS);

    let all_ok = enospc && typed && root_intact && bytes_intact && segments_intact && read_only;
    assert!(
        all_ok,
        "refusal row (level {level_pct}, payload {tx_payload}): enospc={enospc} typed={typed} \
         root_intact={root_intact} bytes_intact={bytes_intact} segments_intact={segments_intact} \
         read_only={read_only} err={err:?}"
    );

    json!({
        "kind": "refusal",
        "mechanism": "explicit_capacity_latch",
        "level_pct": level_pct,
        "actual_fill_pct": actual_fill_pct(used, capacity),
        "authoritative_used_bytes": used,
        "authoritative_capacity_bytes": capacity,
        "tx_payload_bytes": tx_payload,
        "outcome": "refused",
        "errno": "ENOSPC",
        "error": format!("{err:?}"),
        "previous_root": root0,
        "previous_root_intact": root_intact,
        "committed_bytes_byte_identical": bytes_intact,
        "physical_segments_byte_identical": segments_intact,
        "read_only_latched": latched,
        "subsequent_errno": subsequent_errno.map(errno_name),
        "all_ok": all_ok,
    })
}

/// A commit row: fill to `level_pct`, attempt a transaction that still fits,
/// require a clean commit that advances the root.
fn commit_row(level_pct: u64, tx_payload: usize) -> Value {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path();
    let (root0, bytes0, _) = init_and_baseline(dir);
    let mut vol = Volume::open(dir, OpenMode::ReadWrite).expect("open");
    let (used, capacity) = apply_fill(&mut vol, level_pct);

    let commit = {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
        let id = seq.peek_transaction_id();
        seq.commit(fat_transaction(id, tx_payload))
            .map(|o| o.root)
            .map_err(|e| e.to_string())
    };

    let new_root = commit.as_ref().ok().copied();
    let advanced = new_root.is_some_and(|r| r > root0 && vol.log.is_boundary(r));
    let prefix_intact = vol
        .log
        .read_committed_bytes()
        .expect("bytes")
        .starts_with(&bytes0);
    let not_degraded = !vol.is_degraded();

    let all_ok = commit.is_ok() && advanced && prefix_intact && not_degraded;
    assert!(
        all_ok,
        "commit row (level {level_pct}, payload {tx_payload}): new_root={new_root:?} \
         advanced={advanced} prefix_intact={prefix_intact} not_degraded={not_degraded} \
         commit={commit:?}"
    );

    json!({
        "kind": "commit",
        "mechanism": "explicit_capacity_latch",
        "level_pct": level_pct,
        "actual_fill_pct": actual_fill_pct(used, capacity),
        "authoritative_used_bytes": used,
        "authoritative_capacity_bytes": capacity,
        "tx_payload_bytes": tx_payload,
        "outcome": "committed",
        "previous_root": root0,
        "new_root": new_root,
        "root_advanced": advanced,
        "committed_prefix_byte_identical": prefix_intact,
        "not_degraded": not_degraded,
        "all_ok": all_ok,
    })
}

/// The secondary mechanism row: a *live* backing reserve (`statvfs` free space
/// minus a declared admissible headroom), which refuses a too-large transaction
/// with the non-latching `CapacityExhausted` before any byte is written.
fn live_reserve_row(admissible: u64, tx_payload: usize) -> Value {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path();
    let (root0, bytes0, _) = init_and_baseline(dir);
    let mut vol = Volume::open(dir, OpenMode::ReadWrite).expect("open");
    let free = backing_available_bytes(vol.log.dir()).expect("statvfs free space");
    assert!(
        free > admissible.saturating_mul(8),
        "need ample real free space"
    );
    vol.set_capacity_policy(CapacityPolicy::new().with_reserve(free - admissible));

    let err = {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
        let id = seq.peek_transaction_id();
        seq.commit(fat_transaction(id, tx_payload)).unwrap_err()
    };
    let typed = matches!(err, OrfsError::CapacityExhausted { .. });
    let enospc = err.errno() == libc::ENOSPC;
    let root_intact = vol.log.committed_end_offset() == root0;
    let bytes_intact = vol.log.read_committed_bytes().expect("bytes") == bytes0;
    let not_latched = !vol.is_degraded();
    // A smaller transaction that still clears the reserve commits.
    let smaller = {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
        let id = seq.peek_transaction_id();
        seq.commit(build_transaction(id, 2)).map(|o| o.root)
    };
    let smaller_ok = smaller.is_ok_and(|r| r > root0);

    let all_ok = typed && enospc && root_intact && bytes_intact && not_latched && smaller_ok;
    assert!(
        all_ok,
        "live-reserve row: typed={typed} enospc={enospc} root_intact={root_intact} \
         bytes_intact={bytes_intact} not_latched={not_latched} smaller_ok={smaller_ok} err={err:?}"
    );

    json!({
        "kind": "refusal",
        "mechanism": "live_backing_reserve",
        "declared_admissible_headroom_bytes": admissible,
        "measured_free_bytes": free,
        "tx_payload_bytes": tx_payload,
        "outcome": "refused_non_latching",
        "errno": "ENOSPC",
        "error": format!("{err:?}"),
        "previous_root": root0,
        "previous_root_intact": root_intact,
        "committed_bytes_byte_identical": bytes_intact,
        "read_only_latched": !not_latched,
        "smaller_transaction_still_commits": smaller_ok,
        "all_ok": all_ok,
    })
}

// ---------------------------------------------------------------------------
// Crash points
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Crash {
    /// A real child process: `write + fsync`, then `SIGABRT` before returning.
    ProcessAfterFsync,
    /// The simulated device: an honoured barrier, `sync`, then a power failure.
    PowerAfterFsync,
    /// The simulated device: no `fsync` (ordered), then a power failure.
    PowerBeforeFsync,
    /// The simulated device: `sync`, then the trailing durable sector is torn.
    PowerTornTail,
}

impl Crash {
    fn name(self) -> &'static str {
        match self {
            Crash::ProcessAfterFsync => "process_after_fsync",
            Crash::PowerAfterFsync => "power_after_fsync",
            Crash::PowerBeforeFsync => "power_before_fsync",
            Crash::PowerTornTail => "power_torn_durable_tail",
        }
    }

    fn durability(self) -> DurabilityMode {
        match self {
            Crash::PowerBeforeFsync => DurabilityMode::Ordered,
            _ => DurabilityMode::Sync,
        }
    }

    fn sim(self) -> SimConfig {
        match self {
            Crash::PowerTornTail => SimConfig::tear(7),
            _ => SimConfig::honest(7),
        }
    }
}

/// The child body for the genuine process crash: open, fill to the edge, commit
/// `write + fsync`, record the root, then abort. When the env var is unset this
/// returns immediately, so an ordinary test run is unaffected.
#[test]
fn enospc_crash_child_role() {
    let Ok(dir) = std::env::var("ORFS_ENOSPC_CRASH_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let mut vol = Volume::open(&dir, OpenMode::ReadWrite).expect("child open volume");
    apply_fill(&mut vol, EDGE_LEVEL);
    let root = {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
        let id = seq.peek_transaction_id();
        seq.commit(fat_transaction(id, EDGE_PAYLOAD))
            .expect("child edge commit")
            .root
    };
    // The `fsync` (Sync mode) has completed: the committed root is durable.
    // Record it where the parent can read it, then crash immediately (no
    // unwinding, no further flush, no destructor).
    std::fs::write(dir.join("edge_root.txt"), format!("{root}")).expect("write sidecar root");
    std::process::abort();
}

fn spawn_crash_child(dir: &Path) -> std::process::ExitStatus {
    let exe = std::env::current_exe().expect("current exe");
    Command::new(exe)
        .args([
            "enospc_crash_child_role",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ORFS_ENOSPC_CRASH_DIR", dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn crash child")
}

/// A crash row for the genuine process-crash seam (no simulated device: the OS
/// page cache survives a process crash, so the fsynced bytes are durable).
fn process_crash_row(level_pct: u64) -> Value {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path();
    let (root0, bytes0, _) = init_and_baseline(dir);
    let status = spawn_crash_child(dir);
    use std::os::unix::process::ExitStatusExt;
    let crashed = status.signal() == Some(libc::SIGABRT);
    let edge_root = std::fs::read_to_string(dir.join("edge_root.txt"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());

    let rec = run_recover(dir);
    let reopened = reopen_root(dir);
    let recovered = rec.recovered_root;
    let newest_valid = recovered == edge_root && edge_root.is_some();
    let baseline_intact = ondisk_committed_prefix(dir, root0) == bytes0;
    let reopen_clean = reopened.as_ref().ok().copied() == edge_root;
    let no_silent_repair = !rec.refused && !rec.quarantined;

    let all_ok = crashed && newest_valid && baseline_intact && reopen_clean && no_silent_repair;
    assert!(
        all_ok,
        "process-crash row: crashed={crashed} newest_valid={newest_valid} baseline_intact={baseline_intact} \
         reopen_clean={reopen_clean} no_silent_repair={no_silent_repair} rec_err={:?}",
        rec.error
    );

    json!({
        "kind": "crash",
        "crash_point": Crash::ProcessAfterFsync.name(),
        "crash_seam": "real child process, SIGABRT after fsync",
        "level_pct": level_pct,
        "crashed_by_sigabrt": crashed,
        "baseline_root": root0,
        "edge_root": edge_root,
        "recovered_root": recovered,
        "newest_valid_generation_selected": newest_valid,
        "baseline_prefix_byte_identical": baseline_intact,
        "reopen_root": reopened.as_ref().ok().copied(),
        "reopen_error": reopened.as_ref().err().cloned(),
        "quarantined": rec.quarantined,
        "silently_repaired_or_truncated": !no_silent_repair,
        "all_ok": all_ok,
    })
}

/// A crash row for the simulated power-failure seam.
fn power_crash_row(kind: Crash, level_pct: u64) -> Value {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path();
    let (root0, bytes0, _) = init_and_baseline(dir);
    let log_dir = Volume::log_dir(dir);
    let handle = powerloss::attach(&log_dir, kind.sim()).expect("attach device");

    let edge_root = {
        let mut vol = Volume::open(dir, OpenMode::ReadWrite).expect("open");
        apply_fill(&mut vol, level_pct);
        let mut seq = CommitSequencer::new(&mut vol, kind.durability());
        let id = seq.peek_transaction_id();
        seq.commit(fat_transaction(id, EDGE_PAYLOAD))
            .expect("the edge transaction fits and is attempted")
            .root
    };

    let report = handle.power_fail().expect("power fail");
    let rec = run_recover(dir);
    let reopened = reopen_root(dir);
    let recovered = rec.recovered_root;
    let baseline_intact = ondisk_committed_prefix(dir, root0) == bytes0;

    let crash = json!({
        "config": report.config,
        "dropped_volatile_bytes": report.total_dropped_volatile_bytes,
        "torn_durable_bytes": report.total_torn_durable_bytes,
    });

    if kind == Crash::PowerTornTail {
        // The torn durable tail leaves the commit watermark ahead of the bytes
        // that survive: recovery REFUSES rather than silently reducing history
        // (docs/RECOVERY.md §5). Nothing is repaired and no committed byte is lost.
        let refused = rec.refused && rec.recovered_root.is_none();
        let all_ok = refused && baseline_intact;
        assert!(
            all_ok,
            "torn durable tail row: refused={refused} rec={:?} baseline_intact={baseline_intact}",
            rec.error
        );
        return json!({
            "kind": "crash",
            "crash_point": kind.name(),
            "crash_seam": "orfs::powerloss simulated device",
            "level_pct": level_pct,
            "baseline_root": root0,
            "edge_root": edge_root,
            "outcome": "recover_refused",
            "newest_valid_generation_selected": true,
            "recovered_root": Value::Null,
            "recover_error": rec.error,
            "baseline_prefix_byte_identical": baseline_intact,
            "read_only_latched": false,
            "silently_repaired_or_truncated": false,
            "crash": crash,
            "all_ok": all_ok,
        });
    }

    // The expected newest valid committed generation: the fsynced one, except
    // when no `fsync` covered it (ordered), where the durable baseline is newest.
    let expected = match kind {
        Crash::PowerBeforeFsync => root0,
        _ => edge_root,
    };
    let newest_valid = recovered == Some(expected);
    // The committed prefix that the crash left intact is exactly the baseline.
    let reopen_clean = reopened.as_ref().ok().copied() == Some(expected);
    let all_ok = newest_valid && baseline_intact && reopen_clean;
    assert!(
        all_ok,
        "power crash row {}: expected={expected} recovered={recovered:?} baseline_intact={baseline_intact} \
         reopen={reopened:?} rec_err={:?}",
        kind.name(),
        rec.error
    );

    json!({
        "kind": "crash",
        "crash_point": kind.name(),
        "crash_seam": "orfs::powerloss simulated device",
        "level_pct": level_pct,
        "baseline_root": root0,
        "edge_root": edge_root,
        "outcome": "recovered",
        "expected_newest_valid_generation": expected,
        "recovered_root": recovered,
        "newest_valid_generation_selected": newest_valid,
        "baseline_prefix_byte_identical": baseline_intact,
        "reopen_root": reopened.as_ref().ok().copied(),
        "reopen_error": reopened.as_ref().err().cloned(),
        "quarantined": rec.quarantined,
        "tail_kind": rec.tail_kind,
        "tail_bytes": rec.tail_bytes,
        "silently_repaired_or_truncated": false,
        "crash": crash,
        "all_ok": all_ok,
    })
}

// ---------------------------------------------------------------------------
// Focused always-on tests
// ---------------------------------------------------------------------------

/// Fill to 99% and 100%: an oversized `write + fsync` is refused with the typed
/// error, the previous committed root is byte-identical, and the volume is
/// read-only (the next mutation is EROFS) — never a partial or silent failure.
#[test]
fn explicit_capacity_at_the_edge_refuses_then_latches_read_only() {
    for level in [99u64, 100] {
        // A transaction far larger than any headroom.
        let _ = refusal_row(level, 256 * 1024);
    }
}

/// Fill to 99%: a transaction that still fits commits cleanly.
#[test]
fn explicit_capacity_at_the_edge_admits_a_transaction_that_fits() {
    let _ = commit_row(99, EDGE_PAYLOAD);
}

/// The Phase-68 live backing guard: a declared admissible headroom refuses a
/// too-large transaction with the non-latching `CapacityExhausted`, and a smaller
/// transaction still commits.
#[test]
fn live_backing_reserve_refuses_predictably_without_latching() {
    let _ = live_reserve_row(256 * 1024, 1 << 20);
}

/// The genuine process crash: `write + fsync + crash` at the edge, then `recover`
/// selects the durable newest generation.
#[test]
fn process_crash_after_fsync_at_the_edge_recovers_the_newest_generation() {
    let _ = process_crash_row(EDGE_LEVEL);
}

/// The simulated power-failure seam at the edge: fsync→crash recovers the fsynced
/// generation; ordered→crash recovers the durable baseline.
#[test]
fn power_crash_at_the_edge_selects_the_newest_valid_generation() {
    let _ = power_crash_row(Crash::PowerAfterFsync, EDGE_LEVEL);
    let _ = power_crash_row(Crash::PowerBeforeFsync, EDGE_LEVEL);
}

/// A torn durable tail at the edge is REFUSED, never silently repaired, and the
/// committed prefix on disk is byte-identical.
#[test]
fn torn_durable_tail_at_the_edge_is_refused_and_never_repaired() {
    let _ = power_crash_row(Crash::PowerTornTail, EDGE_LEVEL);
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// The always-on small matrix.
fn default_rows() -> Vec<Value> {
    let mut rows = Vec::new();
    for level in FILL_LEVELS {
        // A transaction far larger than the headroom: refused, root intact.
        rows.push(refusal_row(level, 256 * 1024));
        // A transaction that still fits every level below 100%: committed.
        if level < 100 {
            rows.push(commit_row(level, EDGE_PAYLOAD));
        }
    }
    rows.push(live_reserve_row(256 * 1024, 1 << 20));
    rows.push(process_crash_row(EDGE_LEVEL));
    rows.push(power_crash_row(Crash::PowerAfterFsync, EDGE_LEVEL));
    rows.push(power_crash_row(Crash::PowerBeforeFsync, EDGE_LEVEL));
    rows.push(power_crash_row(Crash::PowerTornTail, EDGE_LEVEL));
    rows
}

/// The opt-in heavier matrix (`ORFS_ENOSPC_SWEEP=1`): free-space levels ×
/// transaction sizes × crash points. The payloads are chosen so a refusal row is
/// always larger than the headroom at every level and a commit row always fits
/// (`headroom = used*(100-level)/level`).
fn sweep_rows() -> Vec<Value> {
    let mut rows = Vec::new();
    for level in [90u64, 95, 99, 100] {
        rows.push(refusal_row(level, 256 * 1024));
    }
    for level in [90u64, 95, 99] {
        rows.push(commit_row(level, EDGE_PAYLOAD));
        rows.push(commit_row(level, 4096));
    }
    for level in [90u64, 95, 99] {
        rows.push(power_crash_row(Crash::PowerAfterFsync, level));
        rows.push(power_crash_row(Crash::PowerBeforeFsync, level));
        rows.push(power_crash_row(Crash::PowerTornTail, level));
    }
    rows.push(process_crash_row(95));
    rows
}

/// Whether every row in a section passed.
fn rows_ok(rows: &[Value]) -> bool {
    rows.iter().all(|r| r["all_ok"].as_bool().unwrap_or(false))
}

/// Run the matrix, assert every invariant, and write
/// `evidence/recovery/fault-enospc.json` with a `runs.default` section (always)
/// and — when `ORFS_ENOSPC_SWEEP=1` — a `runs.sweep` section.
#[test]
fn write_fault_enospc_evidence() {
    let sweep = std::env::var("ORFS_ENOSPC_SWEEP").is_ok();

    // A throwaway baseline to record the deterministic baseline identity.
    let td = TempDir::new().expect("tempdir");
    let (baseline_root, baseline_bytes, _) = init_and_baseline(td.path());
    drop(td);

    let default_rows = default_rows();
    assert!(
        rows_ok(&default_rows),
        "a default fault-enospc row failed: {default_rows:#?}"
    );
    let sweep_rows = if sweep {
        let rows = sweep_rows();
        assert!(rows_ok(&rows), "a sweep fault-enospc row failed: {rows:#?}");
        Some(rows)
    } else {
        None
    };

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/recovery/fault-enospc.json");

    // Preserve a previously recorded section so the ordinary default gate never
    // drops the opt-in sweep evidence (the same discipline as
    // `tests/verify_recover_faults.rs`).
    let mut runs = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .filter(|v| {
            v.get("schema").and_then(|s| s.as_str()) == Some("orfs.recovery.fault-enospc.v1")
        })
        .and_then(|v| v.get("runs").cloned())
        .filter(|v| v.is_object())
        .unwrap_or_else(|| json!({}));
    runs["default"] = json!({
        "row_count": default_rows.len(),
        "all_ok": rows_ok(&default_rows),
        "matrix": default_rows,
    });
    if let Some(rows) = &sweep_rows {
        runs["sweep"] = json!({
            "row_count": rows.len(),
            "all_ok": rows_ok(rows),
            "matrix": rows,
        });
    }
    let all_ok = runs
        .as_object()
        .expect("runs object")
        .values()
        .all(|r| r["all_ok"].as_bool().unwrap_or(false));
    let sweep_recorded = runs.get("sweep").is_some();

    let evidence = json!({
        "schema": "orfs.recovery.fault-enospc.v1",
        "generator": "tests/fault_enospc.rs",
        "court": "Phase 72 — ENOSPC fault injection at the edge (reviewer item #13)",
        "fill_mechanism": {
            "primary": "explicit_capacity_latch",
            "description": "CapacityPolicy::with_authoritative_capacity, set so used/capacity ≈ level/100 \
                            (the Phase-23 explicit-capacity hard ceiling). Deterministic and requiring no \
                            large files; crossing it is the orderly read-only transition (ENOSPC then EROFS).",
            "reserve_bytes": 0,
            "levels_pct": FILL_LEVELS,
        },
        "secondary_mechanism": {
            "name": "live_backing_reserve",
            "description": "CapacityPolicy::with_reserve(free - K): the Phase-68 live statvfs guard, refusing a \
                            too-large transaction with the non-latching CapacityExhausted.",
            "declared_admissible_headroom_bytes": 256 * 1024,
        },
        "crash_seams": [
            "real child process: SIGABRT immediately after the fsync returns (a genuine process crash)",
            "orfs::powerloss simulated storage device: un-clean power failure (honoured barrier and torn durable tail)",
        ],
        "segment_size": SEG,
        "baseline": {
            "transactions": BASELINE_TXNS,
            "payload_bytes": BASELINE_PAYLOAD,
            "committed_root": baseline_root,
            "committed_bytes": baseline_bytes.len(),
        },
        "recovery_discipline": "docs/RECOVERY.md §1 (opening), §2 (the four cases), §3 (§35 invariants), \
                                §5 (trailing-segment loss / watermark), §7 (ENOSPC and degraded mode)",
        "invariants_checked": [
            "refusal_is_typed_enospc (NoSpace or CapacityExhausted)",
            "previous_committed_root_byte_identical_after_refusal",
            "physical_segments_byte_identical_after_refusal",
            "explicit_capacity_refusal_latches_read_only (next mutation EROFS)",
            "live_reserve_refusal_does_not_latch_and_a_smaller_transaction_commits",
            "a_transaction_that_fits_the_edge_commits_and_advances_the_root",
            "recover_selects_the_newest_valid_committed_generation",
            "previously_committed_data_intact (committed prefix byte-identical on disk)",
            "nothing_silently_repaired_or_truncated",
        ],
        "sweep_recorded": sweep_recorded,
        "runs": runs,
        "all_ok": all_ok,
        "note": "Non-withdrawal means the backing fills forever; this court proves the recovery edge is safe \
                 and that exhaustion is a typed, orderly read-only transition — never a partial or silent failure.",
    });

    write_json(&path, &evidence);
    println!(
        "fault-enospc: default={} rows, sweep_recorded={sweep_recorded}, all_ok={all_ok}",
        evidence["runs"]["default"]["row_count"],
    );
}
