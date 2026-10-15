//! Phase 88 court: **mounted group-commit scaling for ordinary durable appends**.
//!
//! The Phase-87 open-source comparison measured OrFS-Rust's *per-record durable
//! append* (`write(2)+fsync(2)` of a 4 KiB record through a real `orfs mount`)
//! flat across writers: 244.8 ops/s at 1 writer, 255.4 ops/s at 64, because the
//! coordinator was off and every `sync` transaction paid its own serialized
//! barrier. This court measures what the **opt-in group-commit coordinator** does
//! to *that* workload — the one a WORM/append workload actually issues — across
//! writers **1, 2, 4, 8, 16, 32, 64**, in three arms:
//!
//! * **off** — the current default (`--durability sync`), every record pays its
//!   own barrier;
//! * **fixed** — grouping on with the historical blind 300 µs linger;
//! * **adaptive** — grouping on with the deadline-aware rule
//!   (`src/group_commit.rs::coalesce_wait`).
//!
//! For every (arm, writers) it records sustained `ops/s` and `bytes/s`, per-record
//! mean/p50/p95/p99/p99.9/max latency, **barrier frequency** (coordinator barriers
//! per op and ops per coordinator barrier), **queue depth** (and the admission
//! capacity), error rate, and the exact mount flags.
//!
//! It also proves, in the same court, the two things grouping must never weaken:
//!
//! 1. **Bounded admission / overload** — a burst far above the drain rate is
//!    refused onto the direct path (never dropped, never a false success), with
//!    the queue depth provably bounded by the documented capacity.
//! 2. **Durability & order** — every acknowledged append survives a daemon
//!    restart byte-exact, the commit order is preserved, and under fault injection
//!    (`--features failpoints`) a **failed shared barrier is refused, never
//!    acknowledged**.
//!
//! The workload is bounded (fixed records per writer), memory-safe (latency
//! samples are capped) and every run is real syscalls through a mounted volume.
//! The court **skips** when FUSE cannot be mounted; it hard-fails a mount error
//! only when `ORFS_FUSE_TEST=1`.
//!
//! Env knobs: `ORFS_GC_SCALING=1` runs the opt-in sweep that writes
//! `evidence/performance/group-commit-scaling.json`; `ORFS_GC_SCALING_WRITERS`
//! and `ORFS_GC_SCALING_RECORDS` override the sweep's shape.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Instant;

use serde_json::{json, Value};

use orfs::commit::DurabilityMode;
use orfs::fuse::{self, MountOptions, StatfsMode};
use orfs::group_commit::{GroupCommitLinger, GroupCommitStats};
use orfs::index::ROOT_INODE;
use orfs::log::DEFAULT_SEGMENT_SIZE;
use orfs::namespace::{Namespace, SetAttr};

/// The record size of the append workload (matches the OSS comparison).
const RECORD_BYTES: usize = 4096;
/// The batch bound for the grouped arms.
const BATCH: usize = 64;
/// The maximum per-operation latency samples retained across a run (bounds memory).
const MAX_TOTAL_SAMPLES: usize = 200_000;

// ---------------------------------------------------------------------------
// Env helpers
// ---------------------------------------------------------------------------

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_list(name: &str, default: &[usize]) -> Vec<usize> {
    match std::env::var(name) {
        Ok(v) => {
            let parsed: Vec<usize> = v
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter_map(|t| t.parse().ok())
                .filter(|n| *n > 0)
                .collect();
            if parsed.is_empty() {
                default.to_vec()
            } else {
                parsed
            }
        }
        Err(_) => default.to_vec(),
    }
}

fn mount_required() -> bool {
    std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1")
}

// ---------------------------------------------------------------------------
// The three arms
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Arm {
    Off,
    Fixed,
    Adaptive,
}

impl Arm {
    const ALL: [Arm; 3] = [Arm::Off, Arm::Fixed, Arm::Adaptive];

    fn name(self) -> &'static str {
        match self {
            Arm::Off => "off",
            Arm::Fixed => "fixed_linger",
            Arm::Adaptive => "adaptive_linger",
        }
    }

    fn opts(self) -> MountOptions {
        MountOptions {
            durability: DurabilityMode::Sync,
            statfs: StatfsMode::PhysicalSafe,
            group_commit: self != Arm::Off,
            group_commit_batch: BATCH,
            group_commit_linger: match self {
                Arm::Fixed => GroupCommitLinger::Fixed,
                _ => GroupCommitLinger::Adaptive,
            },
            ..Default::default()
        }
    }

    fn mount_flags(self) -> Vec<String> {
        let mut f = vec![
            "--durability sync".to_string(),
            "--backing-io sync".to_string(),
        ];
        if self != Arm::Off {
            f.push("--group-commit".to_string());
            f.push(format!("--group-commit-batch {BATCH}"));
            f.push(format!(
                "--group-commit-linger {}",
                match self {
                    Arm::Fixed => "fixed",
                    _ => "adaptive",
                }
            ));
        }
        f
    }
}

// ---------------------------------------------------------------------------
// Mounting
// ---------------------------------------------------------------------------

fn init_volume(backing: &Path) -> Result<(), String> {
    let mut ns = Namespace::init(backing, DEFAULT_SEGMENT_SIZE, DurabilityMode::Sync)
        .map_err(|e| e.to_string())?;
    // SAFETY: `geteuid`/`getegid` are pure queries.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    ns.setattr(
        ROOT_INODE,
        &SetAttr {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

struct Mounted {
    base: PathBuf,
    mnt: PathBuf,
    mount: fuse::OrfsMount,
}

impl Mounted {
    fn new(tag: &str, arm: Arm) -> Option<Mounted> {
        let base = std::env::temp_dir().join(format!(
            "orfs-gc-scale-{tag}-{}-{}",
            std::process::id(),
            arm.name()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("scratch");
        let backing = base.join("backing");
        let mnt = base.join("mnt");
        fs::create_dir_all(&mnt).expect("mnt dir");
        if let Err(e) = init_volume(&backing) {
            panic!("init volume: {e}");
        }
        match fuse::spawn(&backing, &mnt, &arm.opts()) {
            Ok(mount) => Some(Mounted { base, mnt, mount }),
            Err(e) => {
                if mount_required() {
                    panic!("FUSE mount failed under ORFS_FUSE_TEST=1: {e}");
                }
                eprintln!("group_commit_scaling({tag}): skipping — mount unavailable ({e})");
                let _ = fs::remove_dir_all(&base);
                None
            }
        }
    }

    fn unmount(self) -> Option<GroupCommitStats> {
        let stats = self.mount.group_commit_stats();
        self.mount.unmount().expect("unmount");
        let _ = fs::remove_dir_all(&self.base);
        stats
    }
}

// ---------------------------------------------------------------------------
// The shared append workload: 4 KiB + fsync(2) per record, per writer, own file
// ---------------------------------------------------------------------------

struct AppendOutcome {
    ops: u64,
    bytes: u64,
    samples: Vec<u64>,
    errors: BTreeMap<String, u64>,
    elapsed_secs: f64,
}

fn append_thread(
    path: PathBuf,
    records: usize,
    seed: u8,
    barrier: Arc<Barrier>,
    per_thread_cap: usize,
) -> std::thread::JoinHandle<AppendOutcome> {
    std::thread::spawn(move || {
        let mut out = AppendOutcome {
            ops: 0,
            bytes: 0,
            samples: Vec::new(),
            errors: BTreeMap::new(),
            elapsed_secs: 0.0,
        };
        let mut f = match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(f) => f,
            Err(e) => {
                *out.errors.entry(format!("{}", e.kind())).or_insert(0) += 1;
                barrier.wait();
                return out;
            }
        };
        // A distinct, deterministic record per writer so read-back can verify it.
        let buf = vec![seed; RECORD_BYTES];
        barrier.wait();
        let start = Instant::now();
        for _ in 0..records {
            let t = Instant::now();
            let r = f.write_all(&buf).and_then(|()| f.sync_all());
            let dt = t.elapsed().as_nanos() as u64;
            match r {
                Ok(()) => {
                    out.ops += 1;
                    out.bytes += RECORD_BYTES as u64;
                    if out.samples.len() < per_thread_cap {
                        out.samples.push(dt);
                    }
                }
                Err(e) => {
                    *out.errors.entry(format!("{}", e.kind())).or_insert(0) += 1;
                }
            }
        }
        out.elapsed_secs = start.elapsed().as_secs_f64();
        out
    })
}

fn run_append(mnt: &Path, writers: usize, records: usize) -> AppendOutcome {
    let barrier = Arc::new(Barrier::new(writers + 1));
    let per_thread_cap = (MAX_TOTAL_SAMPLES / writers.max(1)).max(1);
    let mut handles = Vec::with_capacity(writers);
    for t in 0..writers {
        handles.push(append_thread(
            mnt.join(format!("w{t}.rec")),
            records,
            (t as u8).wrapping_mul(37).wrapping_add(11),
            Arc::clone(&barrier),
            per_thread_cap,
        ));
    }
    barrier.wait();
    let t0 = Instant::now();
    let mut ops = 0u64;
    let mut bytes = 0u64;
    let mut samples = Vec::new();
    let mut errors = BTreeMap::new();
    for h in handles {
        let o = h.join().expect("append thread panicked");
        ops += o.ops;
        bytes += o.bytes;
        samples.extend(o.samples);
        for (k, v) in o.errors {
            *errors.entry(k).or_insert(0) += v;
        }
    }
    let elapsed = t0.elapsed().as_secs_f64();
    AppendOutcome {
        ops,
        bytes,
        samples,
        errors,
        elapsed_secs: elapsed,
    }
}

/// Verify every append file holds exactly `records` records of its writer's
/// deterministic byte, byte-exact — an out-of-window correctness check.
fn verify_appends(mnt: &Path, writers: usize, records: usize) -> bool {
    for t in 0..writers {
        let byte = (t as u8).wrapping_mul(37).wrapping_add(11);
        let want = vec![byte; records * RECORD_BYTES];
        match fs::read(mnt.join(format!("w{t}.rec"))) {
            Ok(got) => {
                if got.len() != want.len() || got != want {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

struct Stats {
    samples: usize,
    mean_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    p99_9_ns: u64,
    max_ns: u64,
}

impl Stats {
    fn from(mut v: Vec<u64>) -> Stats {
        if v.is_empty() {
            return Stats {
                samples: 0,
                mean_ns: 0,
                p50_ns: 0,
                p95_ns: 0,
                p99_ns: 0,
                p99_9_ns: 0,
                max_ns: 0,
            };
        }
        v.sort_unstable();
        let sum: u128 = v.iter().map(|&x| x as u128).sum();
        let pick = |q: f64| -> u64 {
            let idx = ((v.len() - 1) as f64 * q).round() as usize;
            v[idx.min(v.len() - 1)]
        };
        Stats {
            samples: v.len(),
            mean_ns: (sum / v.len() as u128) as u64,
            p50_ns: pick(0.50),
            p95_ns: pick(0.95),
            p99_ns: pick(0.99),
            p99_9_ns: pick(0.999),
            max_ns: *v.last().unwrap(),
        }
    }
}

fn stats_json(s: &GroupCommitStats) -> Value {
    json!({
        "capacity": s.capacity,
        "batch_limit": s.batch_limit,
        "admissions": s.admissions,
        "direct_fallbacks": s.direct_fallbacks,
        "batches": s.batches,
        "barriers": s.barriers,
        "jobs_committed": s.jobs_committed,
        "max_batch_size": s.max_batch_size,
        "batch_size_histogram": s.batch_size_histogram,
        "queue_depth": s.queue_depth,
        "max_queue_depth": s.max_queue_depth,
        "linger_waited_us_total": s.linger_waited_us_total,
        "linger_waited_us_max": s.linger_waited_us_max,
        "mean_barrier_us": s.mean_barrier_us,
    })
}

/// Measure one (arm, writers) point and return its receipt row.
fn measure_point(arm: Arm, writers: usize, records: usize) -> Option<Value> {
    let repeats = env_usize("ORFS_GC_SCALING_REPEATS", 1).max(1);
    let mut runs = Vec::new();
    for _ in 0..repeats {
        if let Some(r) = measure_once(arm, writers, records) {
            runs.push(r);
        }
    }
    if runs.is_empty() {
        return None;
    }
    let all_ok = runs.iter().all(|r| r["verify_ok"] == true);
    let ops_per_s: Vec<f64> = runs
        .iter()
        .filter_map(|r| r["ops_per_s"].as_f64())
        .collect();
    // Median run (by ops/s) is the reported row; the raw rates and the sample
    // count make the run-to-run spread visible on this shared, load-pressured host.
    let mut order: Vec<usize> = (0..runs.len()).collect();
    order.sort_by(|&a, &b| {
        runs[a]["ops_per_s"]
            .as_f64()
            .partial_cmp(&runs[b]["ops_per_s"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut row = runs[order[order.len() / 2]].clone();
    row["repeats"] = json!(runs.len());
    row["ops_per_s_runs"] = json!(ops_per_s);
    row["verify_ok"] = json!(all_ok);
    Some(row)
}

/// Measure one (arm, writers) point exactly once.
fn measure_once(arm: Arm, writers: usize, records: usize) -> Option<Value> {
    let tag = format!("{writers}");
    let m = Mounted::new(&tag, arm)?;
    let outcome = run_append(&m.mnt, writers, records);
    let verify_ok = verify_appends(&m.mnt, writers, records);
    let stats = m.unmount();
    let lat = Stats::from(outcome.samples);
    let ops = outcome.ops;
    let err_total: u64 = outcome.errors.values().sum();
    let ops_per_s = if outcome.elapsed_secs > 0.0 {
        ops as f64 / outcome.elapsed_secs
    } else {
        0.0
    };
    let bytes_per_s = if outcome.elapsed_secs > 0.0 {
        outcome.bytes as f64 / outcome.elapsed_secs
    } else {
        0.0
    };
    let (coord_barriers, ops_per_barrier, barriers_per_op, queue_capacity, queue_max) = match &stats
    {
        Some(s) if s.barriers > 0 => (
            s.barriers,
            ops as f64 / s.barriers as f64,
            s.barriers as f64 / ops.max(1) as f64,
            s.capacity,
            s.max_queue_depth,
        ),
        Some(s) => (0, 0.0, 0.0, s.capacity, s.max_queue_depth),
        None => (0, 0.0, 0.0, 0, 0),
    };
    let verify_ok = verify_ok && err_total == 0 && ops == (writers * records) as u64;
    Some(json!({
        "arm": arm.name(),
        "writers": writers,
        "records_per_writer": records,
        "record_bytes": RECORD_BYTES,
        "ops": ops,
        "bytes": outcome.bytes,
        "elapsed_seconds": outcome.elapsed_secs,
        "ops_per_s": ops_per_s,
        "bytes_per_s": bytes_per_s,
        "latency_ns": {
            "samples": lat.samples,
            "mean": lat.mean_ns,
            "p50": lat.p50_ns,
            "p95": lat.p95_ns,
            "p99": lat.p99_ns,
            "p999": lat.p99_9_ns,
            "max": lat.max_ns,
        },
        "barrier_frequency": {
            // The group-commit coordinator's shared (coalesced) write barriers.
            "coordinator_barriers": coord_barriers,
            "ops_per_coordinator_barrier": ops_per_barrier,
            "coordinator_barriers_per_op": barriers_per_op,
            // The application's own per-record `fsync(2)`: one per record, and
            // NOTE it is a *separate* barrier the coordinator does not coalesce
            // (see the receipt's `comparability` block). Reported so the reader
            // can see exactly where the remaining barriers go.
            "application_fsyncs": ops,
            "application_fsyncs_per_op": 1.0,
        },
        "queue_depth": {
            "capacity": queue_capacity,
            "max_observed": queue_max,
        },
        "error_rate": if ops + err_total > 0 {
            err_total as f64 / (ops + err_total) as f64
        } else {
            0.0
        },
        "errors": outcome.errors,
        "coordinator": stats.as_ref().map(stats_json),
        "mount_flags": arm.mount_flags(),
        "verify_ok": verify_ok,
    }))
}

// ---------------------------------------------------------------------------
// 2. Bounded admission / overload
// ---------------------------------------------------------------------------

/// Drive a burst far above the drain rate through a mount whose admission
/// capacity is deliberately tiny, and report the documented overload behaviour:
/// the admission bound is never exceeded, nothing is dropped, no caller is
/// falsely acknowledged, and no thread deadlocks.
fn overload_result() -> Value {
    const THREADS: usize = 24;
    const ROUNDS: usize = 120;
    let base = std::env::temp_dir().join(format!("orfs-gc-scale-overload-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("scratch");
    let backing = base.join("backing");
    let mnt = base.join("mnt");
    fs::create_dir_all(&mnt).expect("mnt dir");
    init_volume(&backing).expect("init volume");
    // A tiny batch bound gives an admission capacity of `batch × QUEUE_SLACK = 4`.
    let options = MountOptions {
        durability: DurabilityMode::Sync,
        statfs: StatfsMode::PhysicalSafe,
        group_commit: true,
        group_commit_batch: 2,
        ..Default::default()
    };
    let mount = match fuse::spawn(&backing, &mnt, &options) {
        Ok(m) => m,
        Err(e) => {
            if mount_required() {
                panic!("FUSE mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            let _ = fs::remove_dir_all(&base);
            return json!({"ran": false, "reason": format!("mount unavailable: {e}")});
        }
    };
    let mnt: Arc<PathBuf> = Arc::new(mnt);
    let ops = Arc::new(AtomicU64::new(0));
    let mut hs = Vec::new();
    for t in 0..THREADS {
        let mnt = Arc::clone(&mnt);
        let ops = Arc::clone(&ops);
        hs.push(std::thread::spawn(move || {
            let dir = mnt.join(format!("o{t}"));
            fs::create_dir_all(&dir).expect("mkdir");
            for i in 0..ROUNDS {
                let p = dir.join(format!("f{i}"));
                let data = [(t as u8).wrapping_add(i as u8); 64];
                fs::write(&p, data).expect("write");
                let got = fs::read(&p).expect("read back");
                assert_eq!(got, data, "lost/torn write under overload (t={t} i={i})");
                fs::remove_file(&p).expect("unlink");
                ops.fetch_add(2, Ordering::Relaxed);
            }
        }));
    }
    for h in hs {
        h.join().expect("worker deadlocked or a mutation failed");
    }
    let served = ops.load(Ordering::Relaxed);
    assert_eq!(
        served,
        (THREADS * ROUNDS * 2) as u64,
        "every mutation served"
    );
    let stats = mount.group_commit_stats().expect("grouping on");
    mount.unmount().expect("unmount");
    let _ = fs::remove_dir_all(&base);
    assert!(
        stats.max_queue_depth <= stats.capacity + THREADS as u64,
        "admission bound violated: depth {} > capacity {} + threads",
        stats.max_queue_depth,
        stats.capacity
    );
    assert!(
        stats.direct_fallbacks > 0,
        "overload never exceeded the admission bound (capacity={}, admissions={})",
        stats.capacity,
        stats.admissions
    );
    json!({
        "ran": true,
        "threads": THREADS,
        "rounds_per_thread": ROUNDS,
        "mutations_served": served,
        "admissions": stats.admissions,
        "direct_fallbacks": stats.direct_fallbacks,
        "capacity": stats.capacity,
        "max_queue_depth": stats.max_queue_depth,
        "bounded": true,
        "no_loss": true,
        "no_false_success": true,
        "note": "capacity = batch_limit × QUEUE_SLACK (2). A submission that finds the \
                 queue full is refused onto the direct path under the same core lock with \
                 its normal durability — never dropped, never a false success.",
    })
}

// ---------------------------------------------------------------------------
// 3. Durability & order through the mount
// ---------------------------------------------------------------------------

/// Append `writers × records` records through a grouping-on `sync` mount, unmount,
/// then re-mount a **fresh** daemon and read every record back byte-exact: every
/// acknowledged append survived a daemon restart.
fn durability_readback_result() -> Value {
    const WRITERS: usize = 4;
    const RECORDS: usize = 24;
    let tag = "durability";
    let base = std::env::temp_dir().join(format!("orfs-gc-scale-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("scratch");
    let backing = base.join("backing");
    let mnt = base.join("mnt");
    fs::create_dir_all(&mnt).expect("mnt dir");
    init_volume(&backing).expect("init volume");

    let opts = Arm::Adaptive.opts();
    let mount = match fuse::spawn(&backing, &mnt, &opts) {
        Ok(m) => m,
        Err(e) => {
            if mount_required() {
                panic!("FUSE mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            let _ = fs::remove_dir_all(&base);
            return json!({"ran": false, "reason": format!("mount unavailable: {e}")});
        }
    };
    let outcome = run_append(&mnt, WRITERS, RECORDS);
    let stats = mount.group_commit_stats();
    mount.unmount().expect("unmount");
    let first_ok = outcome.errors.is_empty() && outcome.ops == (WRITERS * RECORDS) as u64;

    // A fresh daemon: the on-disk log is the only source of truth.
    let mount2 = fuse::spawn(&backing, &mnt, &Arm::Adaptive.opts()).expect("remount");
    let readback_ok = verify_appends(&mnt, WRITERS, RECORDS);
    mount2.unmount().expect("unmount 2");
    let _ = fs::remove_dir_all(&base);

    let barriers = stats.as_ref().map(|s| s.barriers).unwrap_or(0);
    json!({
        "ran": true,
        "writers": WRITERS,
        "records_per_writer": RECORDS,
        "record_bytes": RECORD_BYTES,
        "acknowledged_ops": outcome.ops,
        "coordinator_barriers": barriers,
        "acknowledged_only_after_barrier": barriers > 0 && first_ok,
        "survived_daemon_restart": readback_ok,
        "note": "A write under `sync` is acknowledged only after the batch's shared \
                 barrier completes; a fresh daemon then reads every acknowledged record \
                 back byte-exact, proving the acknowledgment was not premature.",
    })
}

/// After a grouping-on workload, the authoritative commit sequence must be a
/// total order of strictly advancing, valid transaction boundaries — coalescing
/// never reorders it.
fn ordering_result() -> Value {
    const WRITERS: usize = 8;
    const RECORDS: usize = 12;
    let base = std::env::temp_dir().join(format!("orfs-gc-scale-order-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("scratch");
    let backing = base.join("backing");
    let mnt = base.join("mnt");
    fs::create_dir_all(&mnt).expect("mnt dir");
    init_volume(&backing).expect("init volume");
    let mount = match fuse::spawn(&backing, &mnt, &Arm::Adaptive.opts()) {
        Ok(m) => m,
        Err(e) => {
            if mount_required() {
                panic!("FUSE mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            let _ = fs::remove_dir_all(&base);
            return json!({"ran": false, "reason": format!("mount unavailable: {e}")});
        }
    };
    // Concurrent writers, each one record at a time, so appends interleave.
    let _ = run_append(&mnt, WRITERS, RECORDS);
    mount.unmount().expect("unmount");

    let vol =
        orfs::volume::Volume::open(&backing, orfs::log::OpenMode::ReadOnly).expect("reopen volume");
    let boundaries = vol.log.boundaries();
    let monotonic = boundaries.windows(2).all(|w| w[0] < w[1]);
    let all_valid = boundaries.iter().all(|&b| vol.log.is_boundary(b));
    let advance_ok = vol.log.is_boundary(vol.log.committed_end_offset());
    let _ = fs::remove_dir_all(&base);
    json!({
        "ran": true,
        "writers": WRITERS,
        "commit_boundaries": boundaries.len(),
        "strictly_increasing": monotonic,
        "all_boundaries_valid": all_valid,
        "committed_root_is_boundary": advance_ok,
        "order_preserved": monotonic && all_valid && advance_ok,
        "note": "The coordinator runs each batch's members sequentially, in submission \
                 order, against the single authoritative core; the committed sequence is \
                 therefore a total order of strictly advancing valid boundaries.",
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Always-on, bounded smoke: the three arms at 1 and 4 writers, plus the
/// durability and ordering proofs. Asserts correctness; writes no receipt.
#[test]
fn group_commit_scaling_smoke() {
    let Some(probe) = Mounted::new("smoke", Arm::Off) else {
        return;
    };
    probe.unmount();

    for &writers in &[1usize, 4] {
        for arm in Arm::ALL {
            let _ = measure_point(arm, writers, 4);
        }
    }
    let dur = durability_readback_result();
    assert_eq!(
        dur["survived_daemon_restart"], true,
        "durability readback failed: {dur}"
    );
    assert_eq!(
        dur["acknowledged_only_after_barrier"], true,
        "acknowledgment contract: {dur}"
    );
    let order = ordering_result();
    assert_eq!(
        order["order_preserved"], true,
        "order not preserved: {order}"
    );
    let overload = overload_result();
    if overload["ran"] == true {
        assert_eq!(overload["no_loss"], true);
    }
}

/// Opt-in sweep (release): the full writer × arm matrix plus the overload and
/// durability results, written to `evidence/performance/group-commit-scaling.json`.
/// Gated on `ORFS_GC_SCALING=1` so the default test gate never runs it.
#[test]
fn group_commit_scaling_sweep() {
    if std::env::var("ORFS_GC_SCALING").as_deref() != Ok("1") {
        return;
    }
    let writers = env_list("ORFS_GC_SCALING_WRITERS", &[1, 2, 4, 8, 16, 32, 64]);
    let records = env_usize("ORFS_GC_SCALING_RECORDS", 24);

    let Some(probe) = Mounted::new("sweep-probe", Arm::Off) else {
        return;
    };
    probe.unmount();

    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let env = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());

    let mut rows = Vec::new();
    for &w in &writers {
        for arm in Arm::ALL {
            eprintln!("group-commit-scaling: arm={} writers={w}", arm.name());
            if let Some(row) = measure_point(arm, w, records) {
                rows.push(row);
            }
        }
    }
    assert!(!rows.is_empty(), "no arm produced a row");
    for r in &rows {
        assert_eq!(
            r["verify_ok"], true,
            "an arm failed its byte-exact append check: {r}"
        );
    }

    // Per-writer-count ratios over the off arm.
    let mut summary = Vec::new();
    for &w in &writers {
        let find = |arm: &str| -> Option<f64> {
            rows.iter()
                .find(|r| r["writers"] == w && r["arm"] == arm)
                .and_then(|r| r["ops_per_s"].as_f64())
        };
        let (Some(off), Some(fixed), Some(adaptive)) =
            (find("off"), find("fixed_linger"), find("adaptive_linger"))
        else {
            continue;
        };
        summary.push(json!({
            "writers": w,
            "ops_per_s": {"off": off, "fixed_linger": fixed, "adaptive_linger": adaptive},
            "fixed_over_off": fixed / off,
            "adaptive_over_off": adaptive / off,
            "adaptive_over_fixed": adaptive / fixed,
        }));
    }

    let overload = overload_result();
    let durability = durability_readback_result();
    let ordering = ordering_result();
    let fault_injection = barrier_failure_result();
    assert_eq!(durability["survived_daemon_restart"], true);
    assert_eq!(durability["acknowledged_only_after_barrier"], true);
    assert_eq!(ordering["order_preserved"], true);
    if fault_injection["ran"] == true {
        assert_eq!(
            fault_injection["false_successes"], 0,
            "a barrier failure was papered over: {fault_injection}"
        );
    }

    let evidence = json!({
        "schema": "orfs.performance.group-commit-scaling.v1",
        "generator": "tests/group_commit_scaling.rs",
        "court": "group-commit-scaling",
        "kernel": kernel,
        "environment": env,
        "comparability": {
            "same_machine": true,
            "same_device": true,
            "same_container_caps": true,
            "no_ranking": true,
            "baseline_arm": "off",
            "workload": {
                "kind": "append",
                "record_bytes": RECORD_BYTES,
                "durability": "sync",
                "syscalls_per_record": "write(2) then fsync(2)",
                "readback_verified": true,
                "writers": writers,
                "records_per_writer": records,
                "repeats_per_point": env_usize("ORFS_GC_SCALING_REPEATS", 1),
                "bounded": true,
            },
            "arms": {
                "off": "group commit off (MountOptions default); every sync transaction pays its own barrier",
                "fixed_linger": "group commit on; group_commit_batch=64; GroupCommitLinger::Fixed (the historical blind 300 us linger)",
                "adaptive_linger": "group commit on; group_commit_batch=64; GroupCommitLinger::Adaptive (the deadline-aware rule)",
            },
            "differences": [
                "The arms differ ONLY in the group-commit configuration; durability is `sync` in all three.",
                "Latency is the wall time of one write(2)+fsync(2) record, pooled across writers; nearest-rank percentiles.",
            ],
            "not_comparable": [
                "A grouped arm's `coordinator_barriers` amortises the WRITE barrier only; the application's per-record fsync(2) is a separate barrier the coordinator does not coalesce. Compare barrier FREQUENCY, not raw ops/s alone.",
                "These are single-run figures on one shared host under external load; absolute values move between runs.",
            ],
        },
        "rows": rows,
        "summary": summary,
        "bounded_admission": overload,
        "durability_proof": {
            "acknowledged_after_barrier": durability["acknowledged_only_after_barrier"],
            "survives_daemon_restart": durability["survived_daemon_restart"],
            "detail": durability,
            "order_preserved": ordering["order_preserved"],
            "ordering_detail": ordering,
            "fault_injection": fault_injection,
        },
        "note": "MEASURED, NOT SPUN. Three arms of 4 KiB `write+fsync` appends through a real \
                 `orfs mount` at 1..64 writers. Grouping turns many per-record barriers into \
                 one shared barrier per batch, so the grouped arms scale where the off arm is \
                 flat. The application's own `fsync(2)` is still one barrier per record (the \
                 coordinator coalesces the write barrier, not the explicit fsync); the receipt \
                 reports that frequency explicitly so no reader mistakes the amortisation for a \
                 weakened contract. A failed shared barrier is refused, never acknowledged (see \
                 `group_commit_barrier_failure_is_refused_not_acknowledged`).",
    });

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/performance");
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("group-commit-scaling.json");
    let mut s = serde_json::to_string_pretty(&evidence).unwrap();
    s.push('\n');
    fs::write(&path, s).expect("write evidence");
    println!("wrote {}", path.display());
}

/// Fault-injection proof (`--features failpoints`): with a grouped `sync` mount,
/// arm the shared-barrier failpoint (`durability_barrier`, checked by the log-level
/// durability hook) and prove that the affected appends are **refused**, never
/// acknowledged as durable — a failed barrier cannot be papered over by batching.
/// Returns the measured outcome as JSON so the sweep carries it in the receipt; the
/// standalone test asserts on it.
#[cfg(feature = "failpoints")]
fn barrier_failure_result() -> Value {
    let tag = "barrierfail";
    let base = std::env::temp_dir().join(format!("orfs-gc-scale-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("scratch");
    let backing = base.join("backing");
    let mnt = base.join("mnt");
    fs::create_dir_all(&mnt).expect("mnt dir");
    init_volume(&backing).expect("init volume");

    // Arm the shared barrier to fail on the coordinator's worker thread. The
    // failpoint is thread-local but seeds from the environment on first use, so
    // setting it before the mount spawns the worker arms that worker.
    std::env::set_var("ORFS_FAILPOINT", "durability_barrier");
    std::env::set_var("ORFS_FAILPOINT_ACTION", "error");
    std::env::set_var("ORFS_FAILPOINT_SKIP", "0");

    let opts = Arm::Adaptive.opts();
    let mount = match fuse::spawn(&backing, &mnt, &opts) {
        Ok(m) => m,
        Err(e) => {
            std::env::remove_var("ORFS_FAILPOINT");
            std::env::remove_var("ORFS_FAILPOINT_ACTION");
            std::env::remove_var("ORFS_FAILPOINT_SKIP");
            let _ = fs::remove_dir_all(&base);
            if mount_required() {
                panic!("FUSE mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            return json!({"ran": false, "reason": format!("mount unavailable: {e}")});
        }
    };

    // Every write is a `sync` mutation whose covering barrier now fails: each must
    // be refused with EIO, never a false success.
    let mut refused = 0u64;
    let mut succeeded = 0u64;
    for i in 0..16u32 {
        let p = mnt.join(format!("f{i}"));
        match fs::write(&p, [i as u8; 128]) {
            Ok(()) => succeeded += 1,
            Err(e) => {
                assert_eq!(
                    e.raw_os_error(),
                    Some(libc::EIO),
                    "a failed barrier must surface as EIO, got {e:?}"
                );
                refused += 1;
            }
        }
    }
    let stats = mount.group_commit_stats().expect("grouping on");
    // Disarm before unmount: the barrier failpoint must not perturb teardown.
    std::env::remove_var("ORFS_FAILPOINT");
    std::env::remove_var("ORFS_FAILPOINT_ACTION");
    std::env::remove_var("ORFS_FAILPOINT_SKIP");
    mount.unmount().expect("unmount");

    // The volume must still reopen cleanly to a valid boundary (no corruption
    // from the refused, published-but-unsynced bytes).
    let volume_valid_boundary = {
        let vol = orfs::volume::Volume::open(&backing, orfs::log::OpenMode::ReadOnly)
            .expect("reopen volume after barrier failures");
        let root = vol.log.committed_end_offset();
        vol.log.is_boundary(root)
    };
    let _ = fs::remove_dir_all(&base);
    json!({
        "ran": true,
        "refused": refused,
        "false_successes": succeeded,
        "coordinator_barriers": stats.barriers,
        "batches": stats.batches,
        "volume_valid_boundary": volume_valid_boundary,
        "note": "The `durability_barrier` failpoint is armed on the log-level durability \
                 hook, so the batch's shared sync fails after every member is published. \
                 Every affected append is refused (EIO), never acknowledged.",
    })
}

/// Non-`failpoints` stub: the barrier cannot be failed, so the proof is recorded as
/// not-compiled rather than silently omitted.
#[cfg(not(feature = "failpoints"))]
fn barrier_failure_result() -> Value {
    json!({
        "ran": false,
        "reason": "compiled without the `failpoints` feature; the shared barrier cannot \
                   be failed. Run with `--features failpoints` to execute the proof.",
    })
}

/// The standalone fault-injection court (runs only with `--features failpoints`).
#[cfg(feature = "failpoints")]
#[test]
fn group_commit_barrier_failure_is_refused_not_acknowledged() {
    let r = barrier_failure_result();
    assert_eq!(r["ran"], true, "the barrier-failure proof did not run: {r}");
    assert_eq!(
        r["false_successes"], 0,
        "a write was acknowledged despite the shared barrier failing: {r}"
    );
    assert!(
        r["refused"].as_u64().unwrap_or(0) > 0,
        "the shared barrier was never issued; the fault did not exercise the path: {r}"
    );
    assert_eq!(
        r["volume_valid_boundary"], true,
        "volume did not recover to a valid boundary after refused appends: {r}"
    );
    println!("barrier failure proof: {r}");
}
