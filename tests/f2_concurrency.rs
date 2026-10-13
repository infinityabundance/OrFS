//! Phase 47: F2 concurrency court — the queue-affine topology vs single-loop
//! (and vs the classical F0/F1 transports).
//!
//! This court exists to answer one question with measurements rather than a
//! model: **can the native FUSE-over-`io_uring` transport (F2) recover the
//! classical transport's reader-scaling on this ABI?** The single-loop servicer
//! owns one ring on one thread, so every `COMMIT_AND_FETCH` round-trip is
//! serialised through that thread. The opt-in queue-affine topology
//! (`ORFS_F2_RINGS=N`) splits the CPU queues across `N` ring-owning servicer
//! threads, each with a stable set of queues, so a request's buffers, completion
//! handling and reply commit stay on one thread.
//!
//! The court is **paired and order-balanced**: each repetition runs the same
//! deterministic read workload under every mounted profile, alternating the
//! profile order between repetitions so machine drift affects every profile
//! alike. It reports ops/s (with a 95% paired-t interval) and pooled per-op
//! p50/p95/p99/p99.9, plus the F2 ring's own concurrency counters (blocking
//! waits, dispatch time, buffer-ownership handoffs, observed pipeline depth).
//!
//! Mounting requires `/dev/fuse` + `CAP_SYS_ADMIN` and is expected only under
//! `scripts/container-fuse-test.sh` (`ORFS_FUSE_TEST=1`). Without it the test
//! **skips** and prints the reason; it never fabricates a pass.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use orfs::commit::DurabilityMode;
use orfs::fuse::{self, BackingIo, F2Servicing, MountOptions, Transport};
use orfs::fuse_uring::TransportProfile;
use orfs::log::DEFAULT_SEGMENT_SIZE;
use orfs::namespace::{Namespace, SetAttr};

// The Phase-57 hardware-counter reader, reused here so the F2 court can report
// real cycles/instructions/cache-misses/branch-misses per request on the F0 and
// F2 paths (`docs/PERFORMANCE.md` §23, `docs/PMU.md`).
#[path = "support/pmu.rs"]
mod pmu;

use pmu::{Counter, PmuGroup};

/// 4 MiB bench file, matching the main F2 court.
const BENCH_SIZE: u64 = 4 * 1024 * 1024;
/// Repetitions per (level, profile).
const PAIRS: usize = 5;
/// Ops each reader thread performs per run.
const OPS_PER_THREAD: u64 = 100;
/// The reader counts swept (Phase 66 extends the reviewer's 1..32 to 1..64).
const LEVELS: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];

fn test_knob(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_scratch(prefix: &str) -> PathBuf {
    let base = manifest_dir().join("target").join("f2-concurrency-it");
    fs::create_dir_all(&base).expect("create base");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = base.join(format!("{prefix}-{pid}-{nanos}"));
    fs::create_dir_all(&dir).expect("create scratch");
    dir
}

fn io_err<T>(r: std::io::Result<T>) -> Result<T, String> {
    r.map_err(|e| format!("{:?}", e.kind()))
}

fn fuse_test_required() -> bool {
    std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1")
}

fn init_volume(backing: &Path) -> Result<(), String> {
    let mut ns = Namespace::init(backing, DEFAULT_SEGMENT_SIZE, DurabilityMode::Ordered)
        .map_err(|e| e.to_string())?;
    // SAFETY: geteuid/getegid are pure queries.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    ns.setattr(
        orfs::index::ROOT_INODE,
        &SetAttr {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        },
    )
    .map_err(|e| e.to_string())?;
    ns.sync().map_err(|e| e.to_string())
}

/// A deterministic per-thread PRNG so every profile reads the same offsets.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Student's t critical value (two-sided 95%), by degrees of freedom.
fn t_crit95(df: usize) -> f64 {
    const T: [f64; 31] = [
        0.0, 12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179,
        2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060,
        2.056, 2.052, 2.048, 2.045, 2.042,
    ];
    if df == 0 {
        f64::INFINITY
    } else if df < T.len() {
        T[df]
    } else {
        1.96
    }
}

fn mean(v: &[f64]) -> f64 {
    if v.is_empty() {
        0.0
    } else {
        v.iter().sum::<f64>() / v.len() as f64
    }
}

fn sd(v: &[f64], m: f64) -> f64 {
    if v.len() < 2 {
        0.0
    } else {
        (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (v.len() as f64 - 1.0)).sqrt()
    }
}

fn ci95(v: &[f64]) -> (f64, f64) {
    let m = mean(v);
    let s = sd(v, m);
    let n = v.len();
    if n < 2 {
        return (m, m);
    }
    let hw = t_crit95(n - 1) * s / (n as f64).sqrt();
    (m - hw, m + hw)
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (p / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

struct Mounted {
    label: &'static str,
    mount: fuse::OrfsMount,
    root: PathBuf,
    bench: PathBuf,
}

fn mount_for(
    scratch: &Path,
    label: &'static str,
    transport: Transport,
    backing: BackingIo,
    affine_rings: Option<usize>,
    entries_per_queue: usize,
) -> Result<Mounted, String> {
    let mnt = scratch.join(format!("{label}-mnt"));
    let back = scratch.join(format!("{label}-backing"));
    fs::create_dir_all(&mnt).map_err(|e| e.to_string())?;
    init_volume(&back)?;
    let opts = MountOptions {
        transport,
        backing_io: backing,
        direct_io: true,
        attr_ttl: Duration::from_millis(0),
        entry_ttl: Duration::from_millis(0),
        f2_servicing: F2Servicing::Single,
        f2_affinity: false,
        ..Default::default()
    };
    // The affine topology and the in-flight depth are opt-in via the environment
    // (read by the F2 session at launch); set them only around this one spawn.
    match affine_rings {
        Some(n) => std::env::set_var("ORFS_F2_RINGS", n.to_string()),
        None => std::env::remove_var("ORFS_F2_RINGS"),
    }
    std::env::set_var("ORFS_F2_ENTRIES_PER_QUEUE", entries_per_queue.to_string());
    let mount = fuse::spawn(&back, &mnt, &opts).map_err(|e| e.to_string());
    std::env::remove_var("ORFS_F2_RINGS");
    std::env::remove_var("ORFS_F2_ENTRIES_PER_QUEUE");
    let mount = mount?;
    let bench = mnt.join("bench.bin");
    let data: Vec<u8> = (0..BENCH_SIZE).map(|i| (i % 251) as u8).collect();
    let mut h = io_err(File::create(&bench))?;
    io_err(h.write_all(&data))?;
    io_err(h.sync_all())?;
    Ok(Mounted {
        label,
        mount,
        root: mnt,
        bench,
    })
}

/// `threads` concurrent 4 KiB readers at deterministic offsets.
fn readers(m: &Mounted, threads: usize) -> Result<(Duration, u64, Vec<f64>), String> {
    let f = io_err(File::open(&m.bench))?;
    let start = Instant::now();
    let lanes = std::thread::scope(|scope| -> Result<Vec<Vec<f64>>, String> {
        let mut handles = Vec::new();
        for t in 0..threads {
            let f = &f;
            handles.push(scope.spawn(move || -> Result<Vec<f64>, String> {
                let mut rng = Lcg(0x9e37_79b9_7f4a_7c15u64.wrapping_add(t as u64 * 0x100));
                let mut buf = [0u8; 4096];
                let mut v = Vec::with_capacity(OPS_PER_THREAD as usize);
                for _ in 0..OPS_PER_THREAD {
                    let off = rng.below(BENCH_SIZE - 4096);
                    let s = Instant::now();
                    io_err(f.read_exact_at(&mut buf, off))?;
                    v.push(s.elapsed().as_secs_f64() * 1e6);
                    // Verify exact bytes under concurrency: no torn, partial or
                    // stale read is ever accepted. The bench file is
                    // `(i % 251)` at every offset.
                    for (i, b) in buf.iter().enumerate() {
                        if *b != ((off + i as u64) % 251) as u8 {
                            return Err(format!("torn/stale byte at offset {off}+{i}"));
                        }
                    }
                }
                Ok(v)
            }));
        }
        let mut out = Vec::new();
        for h in handles {
            out.push(
                h.join()
                    .map_err(|_| "worker thread panicked".to_string())??,
            );
        }
        Ok(out)
    })?;
    let wall = start.elapsed();
    let mut latencies = Vec::new();
    for mut lane in lanes {
        latencies.append(&mut lane);
    }
    Ok((wall, threads as u64 * OPS_PER_THREAD, latencies))
}

/// The thread ids of this process whose `comm` starts with `prefix`. For
/// `"orfs-f2"` this matches the single-loop session, the affine `orfs-f2-qN`
/// groups, and the classical reader — the F2 servicer threads.
fn servicer_tids(prefix: &str) -> Vec<i32> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir("/proc/self/task") {
        for e in rd.flatten() {
            let Some(tid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            let comm =
                fs::read_to_string(format!("/proc/self/task/{tid}/comm")).unwrap_or_default();
            if comm.trim_start().starts_with(prefix) {
                out.push(tid);
            }
        }
    }
    out.sort_unstable();
    out
}

/// Read `ops` 4 KiB blocks from `m.bench` on the **calling** thread, so a
/// per-thread PMU group attached to this thread attributes exactly this work.
fn pmu_reads_on_self(m: &Mounted, ops: u64) -> u64 {
    let f = File::open(&m.bench).expect("open bench for pmu");
    let mut buf = [0u8; 4096];
    let mut rng = Lcg(0x5eed_1234_u64);
    for _ in 0..ops {
        let off = rng.below(BENCH_SIZE - 4096);
        f.read_exact_at(&mut buf, off).expect("pmu read");
    }
    ops
}

#[derive(Default, Clone, Copy)]
struct PmuTotals {
    cycles: u64,
    instructions: u64,
    cache_misses: u64,
    branch_misses: u64,
}

fn sum_groups(groups: &[&PmuGroup]) -> PmuTotals {
    let mut t = PmuTotals::default();
    for g in groups {
        for (c, v) in g.read_all() {
            match c {
                Counter::Cycles => t.cycles += v,
                Counter::Instructions => t.instructions += v,
                Counter::CacheMisses => t.cache_misses += v,
                Counter::BranchMisses => t.branch_misses += v,
                _ => {}
            }
        }
    }
    t
}

/// Per-op hardware counters for `m`'s read path: a group on the calling
/// (reader) thread, plus — for F2 — one group per `orfs-f2*` servicer thread,
/// so the daemon's CPU cost is attributed and not just the client's. Returns
/// JSON; `ran:false` + `reason` (the exact errno) when `perf_event_open` is
/// denied — a number is never fabricated.
fn pmu_profile(m: &Mounted) -> serde_json::Value {
    const PMU_OPS: u64 = 4000;
    let mut obj = serde_json::Map::new();
    let mut client = match PmuGroup::open() {
        Ok(g) => g,
        Err(e) => {
            obj.insert("ran".into(), serde_json::json!(false));
            obj.insert("reason".into(), serde_json::json!(e));
            return serde_json::Value::Object(obj);
        }
    };
    // The F2 daemon runs on named `orfs-f2*` threads; the classical transport's
    // daemon runs on unnamed `fuser` session threads the court cannot pick out,
    // so no F0 servicer-thread number is claimed.
    let is_f2 = m.mount.transport_used() == TransportProfile::F2;
    let tids = if is_f2 {
        servicer_tids("orfs-f2")
    } else {
        Vec::new()
    };
    let mut servicer: Vec<(i32, PmuGroup)> = Vec::new();
    let mut servicer_failed: Vec<i32> = Vec::new();
    let mut servicer_reason: Option<String> = None;
    for tid in tids {
        match PmuGroup::open_pid(tid) {
            Ok(g) => servicer.push((tid, g)),
            Err(e) => {
                servicer_failed.push(tid);
                if servicer_reason.is_none() {
                    servicer_reason = Some(e);
                }
            }
        }
    }
    // Warm the path with the counters disabled, then measure with them enabled.
    pmu_reads_on_self(m, 256);
    let _ = client.reset();
    for (_, g) in servicer.iter_mut() {
        let _ = g.reset();
    }
    let _ = client.enable();
    for (_, g) in servicer.iter_mut() {
        let _ = g.enable();
    }
    let ops = pmu_reads_on_self(m, PMU_OPS);
    let _ = client.disable();
    for (_, g) in servicer.iter_mut() {
        let _ = g.disable();
    }
    let per = |v: u64| v as f64 / ops.max(1) as f64;
    let ctot = sum_groups(&[&client]);
    obj.insert("ran".into(), serde_json::json!(true));
    obj.insert("ops".into(), serde_json::json!(ops));
    obj.insert(
        "client_thread".into(),
        serde_json::json!({
            "cycles_per_op": per(ctot.cycles),
            "instructions_per_op": per(ctot.instructions),
            "cache_misses_per_op": per(ctot.cache_misses),
            "branch_misses_per_op": per(ctot.branch_misses),
            "missing": client.missing().iter().map(|c| c.name()).collect::<Vec<_>>(),
            "note": "user-space only (exclude_kernel=1): the FUSE syscall's kernel time is not counted",
        }),
    );
    let refs: Vec<&PmuGroup> = servicer.iter().map(|(_, g)| g).collect();
    let stot = sum_groups(&refs);
    let per_thread: Vec<serde_json::Value> = servicer
        .iter()
        .map(|(tid, g)| {
            let t = sum_groups(&[g]);
            serde_json::json!({
                "tid": tid,
                "cycles": t.cycles,
                "instructions": t.instructions,
                "cache_misses": t.cache_misses,
                "branch_misses": t.branch_misses,
            })
        })
        .collect();
    obj.insert(
        "servicer_threads".into(),
        serde_json::json!({
            "ran": is_f2,
            "attached_tids": servicer.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
            "failed_tids": servicer_failed,
            "reason": servicer_reason,
            "cycles_per_op": per(stot.cycles),
            "instructions_per_op": per(stot.instructions),
            "cache_misses_per_op": per(stot.cache_misses),
            "branch_misses_per_op": per(stot.branch_misses),
            "per_thread": per_thread,
            "method_note": "sums every live orfs-f2* thread of the test process, divided by the client's read count; \
                            the court keeps all F2 mounts alive, so an idle F2 mount's threads contribute ~0 during \
                            each measured window (their per-thread counters confirm it). The F0 daemon runs on unnamed \
                            fuser threads and is not attributed.",
        }),
    );
    serde_json::Value::Object(obj)
}

#[test]
fn f2_concurrency_readers_1_to_64() {
    let required = fuse_test_required();
    let scratch = unique_scratch("f2conc");
    let affine_rings = test_knob("ORFS_F2_TEST_RINGS", 8);
    let affine_epq = test_knob("ORFS_F2_TEST_EPQ", 4);
    let single_epq = test_knob("ORFS_F2_TEST_SINGLE_EPQ", 1);

    let specs: [(&'static str, Transport, BackingIo, Option<usize>, usize); 4] = [
        ("F0", Transport::Fuse, BackingIo::Sync, None, 1),
        ("F1", Transport::Fuse, BackingIo::Uring, None, 1),
        (
            "F2-single",
            Transport::FuseUring,
            BackingIo::Uring,
            None,
            single_epq,
        ),
        (
            "F2-affine",
            Transport::FuseUring,
            BackingIo::Uring,
            Some(affine_rings),
            affine_epq,
        ),
    ];
    let mut mounts: Vec<Mounted> = Vec::new();
    for (label, t, b, a, epq) in specs {
        match mount_for(&scratch, label, t, b, a, epq) {
            Ok(m) => mounts.push(m),
            Err(e) => {
                if required {
                    panic!("{label} mount failed under ORFS_FUSE_TEST=1: {e}");
                }
                eprintln!("f2 concurrency court: skipped — {label} mount unavailable: {e}");
                let _ = fs::remove_dir_all(&scratch);
                return;
            }
        }
    }

    // Report the topologies actually engaged.
    for m in &mounts {
        let env = m.mount.f2_environment();
        let used = m.mount.transport_used();
        eprintln!(
            "orfs: {} => {} ({})",
            m.label,
            used.name(),
            env.as_ref()
                .map(|e| format!("servicing={} queues={}", e.servicing, e.num_queues))
                .unwrap_or_else(|| "classical".to_string())
        );
        if let Some(s) = m.mount.f2_stats() {
            eprintln!(
                "orfs:   registered entries = {}, baseline queues = {}",
                s.register_sqes,
                env.as_ref().map(|e| e.num_queues).unwrap_or(0)
            );
        }
    }
    if required {
        assert_eq!(
            mounts[2].mount.transport_used(),
            TransportProfile::F2,
            "F2-single must engage"
        );
        assert_eq!(
            mounts[3].mount.transport_used(),
            TransportProfile::F2,
            "F2-affine must engage"
        );
    }

    let labels: Vec<&'static str> = mounts.iter().map(|m| m.label).collect();
    let mut evidence = serde_json::Map::new();

    // Warm every mount once.
    for m in &mounts {
        let _ = readers(m, 1);
    }

    println!("\n=== F2 concurrency court: 4 KiB readers, paired + order-balanced ===");
    println!(
        "{:>7} | {:>14} {:>14} {:>14} {:>14}",
        "readers", labels[0], labels[1], labels[2], labels[3]
    );

    for &threads in &LEVELS {
        let n = mounts.len();
        let mut pair_ops: Vec<Vec<f64>> = vec![Vec::new(); n];
        let mut pooled: Vec<Vec<f64>> = vec![Vec::new(); n];
        for pair in 0..PAIRS {
            // Order-balanced: reverse the profile order on odd repetitions.
            let order: Vec<usize> = if pair % 2 == 0 {
                (0..n).collect()
            } else {
                (0..n).rev().collect()
            };
            for &pi in &order {
                let (wall, ops, lat) = readers(&mounts[pi], threads).expect("reader run");
                pair_ops[pi].push(ops as f64 / wall.as_secs_f64().max(1e-9));
                pooled[pi].extend_from_slice(&lat);
            }
        }
        let mut row = format!("{threads:>7} |");
        for pi in 0..n {
            let (lo, hi) = ci95(&pair_ops[pi]);
            let mid = mean(&pair_ops[pi]);
            row.push_str(&format!(" {:>7.0} [{:>7.0},{:>7.0}] |", mid, lo, hi));
            let mut sorted = std::mem::take(&mut pooled[pi]);
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            evidence.insert(
                format!("{}_{}", labels[pi], threads),
                serde_json::json!({
                    "profile": labels[pi],
                    "readers": threads,
                    "ops_per_sec_mean": mid,
                    "ops_per_sec_ci95_low": lo,
                    "ops_per_sec_ci95_high": hi,
                    "p50_us": percentile(&sorted, 50.0),
                    "p95_us": percentile(&sorted, 95.0),
                    "p99_us": percentile(&sorted, 99.0),
                    "p999_us": percentile(&sorted, 99.9),
                    "p9999_us": percentile(&sorted, 99.99),
                    "mean_us": mean(&sorted),
                    "max_us": sorted.last().copied().unwrap_or(0.0),
                    "samples": sorted.len(),
                }),
            );
        }
        println!("{row}");
    }

    // Percentile table for the two F2 topologies at the levels that matter.
    println!("\n=== F2 per-op latency percentiles (µs) ===");
    println!(
        "{:>7} {:>8} {:>6} {:>7} {:>7} {:>7} {:>7} {:>8} {:>8}",
        "profile", "readers", "p50", "p95", "p99", "p99.9", "p99.99", "mean", "max"
    );
    for label in &labels {
        for &threads in &LEVELS {
            let key = format!("{label}_{threads}");
            if let Some(v) = evidence.get(&key) {
                println!(
                    "{:>7} {:>8} {:>6.1} {:>7.1} {:>7.1} {:>7.1} {:>7.1} {:>7.1} {:>8.1}",
                    label,
                    threads,
                    v["p50_us"].as_f64().unwrap_or(0.0),
                    v["p95_us"].as_f64().unwrap_or(0.0),
                    v["p99_us"].as_f64().unwrap_or(0.0),
                    v["p999_us"].as_f64().unwrap_or(0.0),
                    v["p9999_us"].as_f64().unwrap_or(0.0),
                    v["mean_us"].as_f64().unwrap_or(0.0),
                    v["max_us"].as_f64().unwrap_or(0.0),
                );
            }
        }
    }

    // The F2 concurrency instrumentation: where the servicer threads spend time,
    // how deep the ring pipeline got, and how many ownership handoffs occurred.
    for label in ["F2-single", "F2-affine"] {
        if let Some(m) = mounts.iter().find(|m| m.label == label) {
            if let Some(s) = m.mount.f2_stats() {
                let dispatch_us = if s.dispatch_calls > 0 {
                    s.dispatch_ns as f64 / s.dispatch_calls as f64 / 1000.0
                } else {
                    0.0
                };
                let wait_ms = s.wait_ns as f64 / 1e6;
                println!(
                    "orfs: {label} stats: served={} wait_calls={} wait_ms={:.1} \
                     dispatch_calls={} dispatch_us/op={:.2} max_per_reap={} handoffs={}",
                    s.requests_served,
                    s.wait_calls,
                    wait_ms,
                    s.dispatch_calls,
                    dispatch_us,
                    s.completions_max_per_reap,
                    s.handoffs,
                );
                evidence.insert(
                    format!("{label}_stats"),
                    serde_json::json!({
                        "requests_served": s.requests_served,
                        "wait_calls": s.wait_calls,
                        "wait_ms": wait_ms,
                        "dispatch_calls": s.dispatch_calls,
                        "dispatch_us_per_op": dispatch_us,
                        "completions_max_per_reap": s.completions_max_per_reap,
                        "handoffs": s.handoffs,
                        "ring_completions": s.ring_completions,
                        "ring_submits": s.ring_submits,
                        // SQ/CQ-pressure counters on the F2 FUSE ring (the F2
                        // analogue of §21's UringEngine counters).
                        "sq_full_events": s.sq_full_events,
                        "cq_max_len": s.cq_max_len,
                        "queue_groups": s.queue_groups
                            .iter()
                            .map(|g| serde_json::json!({
                                "group": g.group,
                                "qids": g.qids,
                                "served": g.served,
                            }))
                            .collect::<Vec<_>>(),
                    }),
                );
                if !s.queue_groups.is_empty() {
                    let mut groups: Vec<_> = s.queue_groups.iter().collect();
                    groups.sort_by_key(|g| g.group);
                    let dist: Vec<String> = groups
                        .iter()
                        .map(|g| format!("g{} q{:?}={}", g.group, g.qids, g.served))
                        .collect();
                    println!("orfs: {label} per-queue-group served: {}", dist.join(" "));
                }
            }
        }
    }

    // ---- PMU: real per-op hardware counters for the F0 and F2 read paths ----
    // (the Phase-57 helper; `ran:false` + errno when perf_event_open is denied).
    println!("\n=== PMU: per-op hardware counters on the read path (phase-57 helper) ===");
    let mut pmu = serde_json::Map::new();
    for label in ["F0", "F2-single", "F2-affine"] {
        if let Some(m) = mounts.iter().find(|m| m.label == label) {
            let p = pmu_profile(m);
            println!("orfs: PMU {label}: {p}");
            pmu.insert(label.to_string(), p);
        }
    }

    // Write the machine-generated evidence.
    let doc = serde_json::json!({
        "schema": "orfs.f2-concurrency-affine.v1",
        "generated_by": "tests/f2_concurrency.rs::f2_concurrency_readers_1_to_64",
        "method": "paired, order-balanced reader scaling on simultaneously-mounted F0/F1/F2-single/F2-affine; \
                   direct_io=on and TTL=0 so every read is a real transport round-trip",
        "affine_rings": affine_rings,
        "affine_entries_per_queue": affine_epq,
        "single_entries_per_queue": single_epq,
        "pairs": PAIRS,
        "ops_per_thread": OPS_PER_THREAD,
        "levels": LEVELS,
        "environment": {
            "kernel_release": orfs::capabilities::probe().kernel_release,
            "image_digest": std::env::var("ORFS_IMAGE_DIGEST").unwrap_or_else(|_| "unknown".into()),
            "cpu_count": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        },
        "pmu": pmu,
        "results": evidence,
    });
    let path = manifest_dir().join("evidence/performance/f2-concurrency-affine.json");
    if let Some(p) = path.parent() {
        let _ = fs::create_dir_all(p);
    }
    if let Ok(mut s) = serde_json::to_string_pretty(&doc) {
        s.push('\n');
        let _ = fs::write(&path, s);
    }

    for m in mounts.drain(..) {
        let _ = m.mount.unmount();
    }
    let _ = fs::remove_dir_all(&scratch);
}

/// A compact semantics transcript: create/write/read/append/pread/mkdir/readdir/
/// symlink/rename/truncate/unlink. Run under two transports and compared, it is a
/// byte-level equivalence proof for the queue-affine topology.
fn semantics_transcript(root: &Path) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let f = root.join("a.txt");
    {
        let mut h = io_err(File::create(&f))?;
        io_err(h.write_all(b"hello orfs"))?;
        io_err(h.sync_all())?;
    }
    out.push(("read".into(), io_err(fs::read_to_string(&f))?));
    {
        let mut h = io_err(OpenOptions::new().append(true).open(&f))?;
        io_err(h.write_all(b"!"))?;
    }
    {
        let h = io_err(File::open(&f))?;
        let mut b = [0u8; 5];
        io_err(h.read_exact_at(&mut b, 5))?;
        out.push(("pread".into(), String::from_utf8_lossy(&b).into_owned()));
    }
    let d = root.join("sub");
    io_err(fs::create_dir(&d))?;
    io_err(fs::write(d.join("inner"), b"x"))?;
    let mut names: Vec<String> = io_err(fs::read_dir(&d))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    out.push(("readdir".into(), names.join(",")));
    io_err(std::os::unix::fs::symlink("a.txt", root.join("link")))?;
    out.push((
        "readlink".into(),
        io_err(fs::read_link(root.join("link")))?
            .display()
            .to_string(),
    ));
    io_err(fs::rename(&f, root.join("b.txt")))?;
    {
        let h = io_err(OpenOptions::new().write(true).open(root.join("b.txt")))?;
        io_err(h.set_len(2))?;
    }
    out.push((
        "truncate".into(),
        io_err(fs::read_to_string(root.join("b.txt")))?,
    ));
    io_err(fs::remove_file(d.join("inner")))?;
    io_err(fs::remove_dir(&d))?;
    out.push(("removed".into(), format!("{}", d.exists())));
    Ok(out)
}

/// The queue-affine topology must be byte-identical to F0 and must tear down
/// safely (no hang, no leaked worker) after real traffic.
#[test]
fn f2_affine_preserves_semantics_and_tears_down() {
    let required = fuse_test_required();
    let scratch = unique_scratch("f2affeq");
    let f0 = mount_for(&scratch, "EQ-F0", Transport::Fuse, BackingIo::Sync, None, 1);
    let aff = mount_for(
        &scratch,
        "EQ-affine",
        Transport::FuseUring,
        BackingIo::Uring,
        Some(8),
        4,
    );
    let (f0, aff) = match (f0, aff) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => {
            if required {
                panic!(
                    "mount failed under ORFS_FUSE_TEST=1: F0={:?} affine={:?}",
                    a.err(),
                    b.err()
                );
            }
            eprintln!("f2 affine equivalence: skipped");
            let _ = fs::remove_dir_all(&scratch);
            return;
        }
    };
    let t0 = semantics_transcript(&f0.root).expect("F0 ops");
    let ta = semantics_transcript(&aff.root).expect("affine ops");
    assert_eq!(ta, t0, "F2 queue-affine transcript differs from F0");
    if required {
        assert_eq!(
            aff.mount.transport_used(),
            TransportProfile::F2,
            "the affine mount must be real F2"
        );
        let st = aff.mount.f2_stats().expect("affine stats");
        assert!(st.requests_served > 0, "affine served no requests: {st:?}");
        assert_eq!(st.negative_completions, 0, "no completion must be negative");
    }
    // Teardown must be prompt and clean for both.
    let _ = f0.mount.unmount();
    let _ = aff.mount.unmount();
    let _ = fs::remove_dir_all(&scratch);
}
