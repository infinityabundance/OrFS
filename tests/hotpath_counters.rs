//! **Phase 83 — counter-guided forensics of the mounted metadata/read hot path.**
//!
//! The application-workload court (Phase 81, `docs/APPLICATIONS.md`) measured OrFS
//! **8.9×–52× slower** than a same-device baseline on real workloads, and Phase 82
//! fixed the `git` blocker. What was still missing was **attribution**: nobody had
//! used *real hardware counters* to say where the mounted metadata/read hot path
//! spends its cycles. This court does exactly that.
//!
//! It mounts a real OrFS volume with `fuse::spawn` — the same code path as
//! `orfs mount`, the classical `/dev/fuse` transport — and drives a **bounded**
//! `create`/`stat`/`rename`/`unlink` + small `read`/`write` workload through it
//! while:
//!
//! * a **counting global allocator** records allocations per operation (client and
//!   daemon both run in this process, so every allocation is counted);
//! * a **per-thread hardware group** is attached to the calling (client) thread and
//!   to every live `fuser*` **daemon** thread (`fuser-bg`, `fuser-0…N`), so the
//!   user-space cycles/instructions/cache-misses/branch-misses/TLB-misses of the
//!   dispatch + engine work are attributed, not just the caller's;
//! * a **`PERF_SAMPLE_IP` sampling ring** attached to the daemon threads produces a
//!   leaf-IP flamegraph of the daemon's hot path.
//!
//! ## What this court can and cannot separate
//!
//! Per-thread user-space counters (`exclude_kernel=1`) cannot see the kernel: the
//! FUSE syscall's kernel time, the VFS, and page-cache work are **outside** the
//! counters (they are visible only in the client-side wall-clock percentiles). The
//! court therefore attributes the hot path as: **client wall-clock per op type**
//! (which includes the kernel syscall), the **daemon user-space counter ratios**
//! (dispatch + engine lookup/getattr + transaction append, which run on daemon
//! threads), the **allocation counts per op**, and the **daemon flamegraph leaf
//! profile**. It does not pretend to split kernel time from daemon time.
//!
//! ## Honesty
//!
//! Every number comes from a real container run. When `perf_event_open` is denied
//! the court records `available:false` with the **exact errno** and still reports
//! the wall-clock percentiles and allocation counts — no counter is invented. The
//! workload is bounded and the mount is always unmounted. Mounting needs
//! `/dev/fuse` + `CAP_SYS_ADMIN`; the court is expected only under
//! `scripts/container-hotpath-counters.sh` (`ORFS_FUSE_TEST=1`). Evidence:
//! `evidence/performance/hotpath-counters.json`
//! (schema `orfs.performance.hotpath-counters.v1`) and
//! `evidence/performance/flamegraph-hotpath.{folded,svg,json}`.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use orfs::commit::DurabilityMode;
use orfs::fuse::{self, MountOptions};
use orfs::index::ROOT_INODE;
use orfs::log::DEFAULT_SEGMENT_SIZE;
use orfs::namespace::{Namespace, SetAttr};

#[path = "support/pmu.rs"]
mod pmu;

#[path = "support/flamegraph.rs"]
mod flamegraph;

use pmu::{Counter, PmuGroup};

// ---------------------------------------------------------------------------
// A counting global allocator (client + daemon allocations, same process)
// ---------------------------------------------------------------------------

static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

/// A pass-through allocator that counts every allocation request.
struct CountingAlloc;

unsafe impl std::alloc::GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        std::alloc::System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        std::alloc::System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        std::alloc::System.realloc(ptr, layout, new_size)
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        std::alloc::System.alloc_zeroed(layout)
    }
}

#[global_allocator]
static GLOBAL_ALLOC: CountingAlloc = CountingAlloc;

fn alloc_snapshot() -> (u64, u64) {
    (
        ALLOC_CALLS.load(Ordering::Relaxed),
        ALLOC_BYTES.load(Ordering::Relaxed),
    )
}

// ---------------------------------------------------------------------------
// Fixtures and helpers
// ---------------------------------------------------------------------------

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fuse_test_required() -> bool {
    std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1")
}

fn image_digest() -> String {
    std::env::var("ORFS_IMAGE_DIGEST").unwrap_or_else(|_| "unknown".into())
}

fn unique_scratch(prefix: &str) -> PathBuf {
    let base = manifest_dir().join("target").join("hotpath-counters-it");
    fs::create_dir_all(&base).expect("create base");
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = base.join(format!("{prefix}-{pid}-{nanos}"));
    fs::create_dir_all(&dir).expect("create scratch");
    dir
}

fn init_volume(backing: &Path) -> Result<(), String> {
    let mut ns = Namespace::init(backing, DEFAULT_SEGMENT_SIZE, DurabilityMode::Ordered)
        .map_err(|e| e.to_string())?;
    // SAFETY: geteuid/getegid are pure queries.
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
    ns.sync().map_err(|e| e.to_string())
}

/// The thread ids of this process whose `comm` starts with `prefix`. For the
/// classical `/dev/fuse` transport the daemon runs on `fuser-bg` plus
/// `fuser-0…N` (`fuser::Session::spawn`/`run`), so `"fuser"` picks them out.
fn daemon_tids(prefix: &str) -> Vec<i32> {
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

/// Discover the daemon threads, waiting (bounded) for the session's workers to
/// appear. `fuser::Session::spawn` returns after spawning only the `fuser-bg`
/// thread; the `fuser-0…N` workers are spawned asynchronously by the background
/// thread, so a snapshot taken immediately can miss them. Poll until the set is
/// non-empty and has stopped growing (or a 2 s bound elapses).
fn discover_daemon_tids(prefix: &str) -> Vec<i32> {
    let started = Instant::now();
    let mut best = daemon_tids(prefix);
    let mut stable = 0u32;
    while started.elapsed() < std::time::Duration::from_millis(2000) {
        std::thread::sleep(std::time::Duration::from_millis(40));
        let now = daemon_tids(prefix);
        if now.len() > best.len() {
            best = now;
            stable = 0;
        } else {
            stable += 1;
            if stable >= 5 && !best.is_empty() {
                break;
            }
        }
    }
    best
}

#[derive(Default, Clone, Copy)]
struct Totals {
    cycles: u64,
    instructions: u64,
    cache_references: u64,
    cache_misses: u64,
    branch_misses: u64,
    dtlb_read_misses: u64,
}

fn sum_groups(groups: &[&PmuGroup]) -> Totals {
    let mut t = Totals::default();
    for g in groups {
        for (c, v) in g.read_all() {
            match c {
                Counter::Cycles => t.cycles += v,
                Counter::Instructions => t.instructions += v,
                Counter::CacheReferences => t.cache_references += v,
                Counter::CacheMisses => t.cache_misses += v,
                Counter::BranchMisses => t.branch_misses += v,
                Counter::DTlbReadMisses => t.dtlb_read_misses += v,
                _ => {}
            }
        }
    }
    t
}

/// Latency summary in nanoseconds.
struct Latency {
    n: u64,
    mean: f64,
    p50: u64,
    p95: u64,
    p99: u64,
}

fn summarize(mut samples: Vec<u64>) -> Latency {
    let n = samples.len() as u64;
    if n == 0 {
        return Latency {
            n: 0,
            mean: 0.0,
            p50: 0,
            p95: 0,
            p99: 0,
        };
    }
    samples.sort_unstable();
    let mean = samples.iter().map(|&v| v as f64).sum::<f64>() / n as f64;
    let pick = |p: f64| -> u64 {
        let idx = ((p / 100.0) * (n as f64 - 1.0)).round() as usize;
        samples[idx.min(samples.len() - 1)]
    };
    Latency {
        n,
        mean,
        p50: pick(50.0),
        p95: pick(95.0),
        p99: pick(99.0),
    }
}

fn latency_json(l: &Latency) -> serde_json::Value {
    serde_json::json!({
        "n": l.n,
        "mean_ns": l.mean,
        "p50_ns": l.p50,
        "p95_ns": l.p95,
        "p99_ns": l.p99,
    })
}

/// The per-operation latencies of one measured workload pass.
#[derive(Default)]
struct Ops {
    create: Vec<u64>,
    stat: Vec<u64>,
    rename: Vec<u64>,
    unlink: Vec<u64>,
    read: Vec<u64>,
    write: Vec<u64>,
}

impl Ops {
    fn with_capacity(n: usize) -> Ops {
        Ops {
            create: Vec::with_capacity(n),
            stat: Vec::with_capacity(n),
            rename: Vec::with_capacity(n),
            unlink: Vec::with_capacity(n),
            read: Vec::with_capacity(n),
            write: Vec::with_capacity(n),
        }
    }

    /// Metadata/IO syscalls in one iteration: create, stat, rename, unlink, read,
    /// write.
    fn total(&self) -> u64 {
        (self.create.len()
            + self.stat.len()
            + self.rename.len()
            + self.unlink.len()
            + self.read.len()
            + self.write.len()) as u64
    }

    fn clear(&mut self) {
        self.create.clear();
        self.stat.clear();
        self.rename.clear();
        self.unlink.clear();
        self.read.clear();
        self.write.clear();
    }
}

const PAYLOAD: [u8; 96] = [0x5a; 96];

/// Drive one bounded `create`/`stat`/`rename`/`unlink` + small `read`/`write`
/// cycle against the mount at `root`, timing each syscall. Pre-allocated
/// vectors keep the timing loop itself free of growing allocations.
fn drive_workload(root: &Path, iters: usize, ops: &mut Ops) {
    let data_path = root.join(".__hotdata");
    let mut rbuf = [0u8; 96];
    {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&data_path)
            .expect("create data file");
        f.write_all_at(&PAYLOAD, 0).expect("seed data file");
    }
    let data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&data_path)
        .expect("open data file");

    for i in 0..iters {
        let a = root.join(format!(".__hot-{i}-a"));
        let b = root.join(format!(".__hot-{i}-b"));

        let t = Instant::now();
        let created = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&a)
            .expect("create");
        created.write_all_at(&PAYLOAD, 0).expect("write payload");
        ops.create.push(t.elapsed().as_nanos() as u64);
        drop(created);

        let t = Instant::now();
        let meta = fs::metadata(&a).expect("stat");
        ops.stat.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(meta.len());

        let t = Instant::now();
        fs::rename(&a, &b).expect("rename");
        ops.rename.push(t.elapsed().as_nanos() as u64);

        let t = Instant::now();
        fs::remove_file(&b).expect("unlink");
        ops.unlink.push(t.elapsed().as_nanos() as u64);

        let t = Instant::now();
        let _ = data.read_at(&mut rbuf, 0).expect("read");
        ops.read.push(t.elapsed().as_nanos() as u64);

        let t = Instant::now();
        data.write_all_at(&PAYLOAD, 0).expect("write");
        ops.write.push(t.elapsed().as_nanos() as u64);
    }

    drop(data);
    let _ = fs::remove_file(&data_path);
}

// ---------------------------------------------------------------------------
// The court
// ---------------------------------------------------------------------------

/// A bounded scale: `iters` create/stat/rename/unlink cycles plus `iters`
/// read/write ops, so `iters × 6` measured syscalls.
#[derive(Clone, Copy)]
struct Scale {
    iters: usize,
}

impl Scale {
    const fn smoke() -> Scale {
        Scale { iters: 300 }
    }
    const fn sweep() -> Scale {
        Scale { iters: 2_500 }
    }
}

fn run_court(scale: Scale, write_receipt: bool, label: &str) {
    if !fuse_test_required() {
        eprintln!(
            "hotpath_counters: skipped ({label}, ORFS_FUSE_TEST unset); \
             run under scripts/container-hotpath-counters.sh"
        );
        return;
    }

    let scratch = unique_scratch("hotpath");
    let backing = scratch.join("backing");
    let mnt = scratch.join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    if let Err(e) = init_volume(&backing) {
        if write_receipt {
            record_ran_false(
                format!("volume init failed: {e}"),
                serde_json::json!({ "scale": label }),
            );
        }
        panic!("volume init failed under ORFS_FUSE_TEST=1: {e}");
    }

    let opts = MountOptions::default();
    let mount = match fuse::spawn(&backing, &mnt, &opts) {
        Ok(m) => m,
        Err(e) => {
            if write_receipt {
                record_ran_false(
                    format!("mount failed: {e}"),
                    serde_json::json!({ "scale": label }),
                );
            }
            let _ = fs::remove_dir_all(&scratch);
            panic!("mount failed under ORFS_FUSE_TEST=1: {e}");
        }
    };
    let transport = format!("{:?}", mount.transport_used());
    let backing_io = format!("{:?}", mount.backing_io_used);

    // Discover the daemon threads (waiting for the workers to spawn) before the
    // counters are attached.
    let tids = discover_daemon_tids("fuser");
    eprintln!("hotpath_counters: {label}: transport={transport} daemon_tids={tids:?}");

    // The client (calling-thread) group and one group per daemon thread.
    let mut client = PmuGroup::open().ok();
    let pmu_available = client.is_some();
    let pmu_error = if client.is_none() {
        PmuGroup::open().err()
    } else {
        None
    };
    let mut daemon: Vec<(i32, PmuGroup)> = Vec::new();
    let mut daemon_failed: Vec<i32> = Vec::new();
    let mut daemon_reason: Option<String> = None;
    if pmu_available {
        for &tid in &tids {
            match PmuGroup::open_pid(tid) {
                Ok(g) => daemon.push((tid, g)),
                Err(e) => {
                    daemon_failed.push(tid);
                    if daemon_reason.is_none() {
                        daemon_reason = Some(e);
                    }
                }
            }
        }
    }
    let counters = client
        .as_ref()
        .map(|g| g.counters().iter().map(|c| c.name()).collect::<Vec<_>>())
        .unwrap_or_default();
    let missing: serde_json::Value = client
        .as_ref()
        .map(|g| {
            let mut m = serde_json::Map::new();
            for (c, reason) in g.missing_reasons() {
                m.insert(c.name().to_string(), serde_json::json!(reason));
            }
            serde_json::Value::Object(m)
        })
        .unwrap_or_else(|| serde_json::json!({}));

    // Warm the mount (counters disabled) so the first cold misses are not charged.
    {
        let mut warm = Ops::with_capacity(64);
        drive_workload(&mnt, 64, &mut warm);
    }

    // Measured window: reset + enable every group, drive the bounded workload,
    // disable, then read every counter once.
    if let Some(g) = client.as_mut() {
        let _ = g.reset();
        let _ = g.enable();
    }
    for (_, g) in daemon.iter_mut() {
        let _ = g.reset();
        let _ = g.enable();
    }
    let (a0, b0) = alloc_snapshot();
    let mut ops = Ops::with_capacity(scale.iters);
    let wall = Instant::now();
    drive_workload(&mnt, scale.iters, &mut ops);
    let wall = wall.elapsed();
    let (a1, b1) = alloc_snapshot();
    if let Some(g) = client.as_mut() {
        let _ = g.disable();
    }
    for (_, g) in daemon.iter_mut() {
        let _ = g.disable();
    }

    let total_ops = ops.total().max(1);
    let client_tot = client.as_ref().map(|g| sum_groups(&[g]));
    let daemon_tot = {
        let refs: Vec<&PmuGroup> = daemon.iter().map(|(_, g)| g).collect();
        sum_groups(&refs)
    };
    let allocs = a1.saturating_sub(a0);
    let bytes = b1.saturating_sub(b0);

    // The daemon flamegraph: sample only the daemon threads over a second bounded
    // window, so the leaves are the daemon's, not the caller's.
    let evidence_dir = manifest_dir().join("evidence/performance");
    let flame = run_daemon_flamegraph(&evidence_dir, &mnt, scale.iters, &tids);

    if write_receipt {
        let doc = build_receipt(
            label,
            &transport,
            &backing_io,
            scale,
            &ops,
            wall,
            total_ops,
            allocs,
            bytes,
            pmu_available,
            &pmu_error,
            &counters,
            &missing,
            client_tot,
            daemon_tot,
            &daemon,
            &daemon_failed,
            &daemon_reason,
            flame,
        );
        write_json(&doc);
        println!("hotpath_counters: wrote evidence/performance/hotpath-counters.json");
    } else {
        eprintln!(
            "hotpath_counters: {label}: {} ops in {:?}, allocs/op={:.3}{}",
            total_ops,
            wall,
            allocs as f64 / total_ops as f64,
            if pmu_available {
                String::new()
            } else {
                format!(
                    " (PMU unavailable: {})",
                    pmu_error.as_deref().unwrap_or("?")
                )
            }
        );
    }

    let _ = mount.unmount();
    let _ = fs::remove_dir_all(&scratch);
}

/// Sample the daemon threads over a second bounded workload window.
fn run_daemon_flamegraph(
    evidence_dir: &Path,
    mnt: &Path,
    iters: usize,
    tids: &[i32],
) -> flamegraph::FlameOutcome {
    const STEM: &str = "flamegraph-hotpath";
    let mut samplers: Vec<pmu::Sampler> = Vec::new();
    let mut failures: Vec<i32> = Vec::new();
    for &tid in tids {
        // A 2 kHz software CPU-clock period per thread: with a handful of daemon
        // threads the 8-page ring is drained well within its capacity between
        // collections (a faster period would overflow the ring).
        match pmu::Sampler::open_pid(500_000, tid) {
            Ok(mut s) => match s.enable() {
                Ok(()) => samplers.push(s),
                Err(_) => failures.push(tid),
            },
            Err(_) => failures.push(tid),
        }
    }
    if samplers.is_empty() {
        return flamegraph::emit(
            evidence_dir,
            STEM,
            flamegraph::failure(
                "no sampling ring could attach to a daemon thread \
                 (perf_event_open denied or no fuser* thread found)"
                    .to_string(),
            ),
        );
    }
    let mut ops = Ops::with_capacity(160);
    let bounded = iters.clamp(64, 120);
    let started = Instant::now();
    let mut ips: Vec<u64> = Vec::new();
    while started.elapsed() < std::time::Duration::from_millis(1200) {
        drive_workload(mnt, bounded, &mut ops);
        ops.clear();
        for s in samplers.iter_mut() {
            ips.extend(s.collect().into_iter().map(|x| x.ip));
        }
    }
    for s in samplers.iter_mut() {
        let _ = s.disable();
        ips.extend(s.collect().into_iter().map(|x| x.ip));
    }
    flamegraph::render(evidence_dir, STEM, &ips)
}

#[allow(clippy::too_many_arguments)]
fn build_receipt(
    label: &str,
    transport: &str,
    backing_io: &str,
    scale: Scale,
    ops: &Ops,
    wall: std::time::Duration,
    total_ops: u64,
    allocs: u64,
    bytes: u64,
    pmu_available: bool,
    pmu_error: &Option<String>,
    counters: &[&str],
    missing: &serde_json::Value,
    client_tot: Option<Totals>,
    daemon_tot: Totals,
    daemon: &[(i32, PmuGroup)],
    daemon_failed: &[i32],
    daemon_reason: &Option<String>,
    flame: flamegraph::FlameOutcome,
) -> serde_json::Value {
    let per_op = |tot: &Totals, denom: u64| {
        let d = denom.max(1) as f64;
        serde_json::json!({
            "cycles_per_op": tot.cycles as f64 / d,
            "instructions_per_op": tot.instructions as f64 / d,
            "cache_references_per_op": tot.cache_references as f64 / d,
                "cache_misses_per_op": tot.cache_misses as f64 / d,
            "branch_misses_per_op": tot.branch_misses as f64 / d,
            "dtlb_read_misses_per_op": tot.dtlb_read_misses as f64 / d,
            "ipc": if tot.cycles > 0 { tot.instructions as f64 / tot.cycles as f64 } else { 0.0 },
        })
    };
    let per_thread: Vec<serde_json::Value> = daemon
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

    let env = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());

    serde_json::json!({
        "schema": "orfs.performance.hotpath-counters.v1",
        "generated_by": "tests/hotpath_counters.rs",
        "ran": true,
        "scale": label,
        "note": "Phase 83 counter-guided forensics of the MOUNTED metadata/read hot path. \
                 A real OrFS volume is mounted with fuse::spawn (the same code path as \
                 `orfs mount`, classical /dev/fuse transport) and a bounded \
                 create/stat/rename/unlink + small read/write workload is driven through \
                 it while per-thread user-space hardware counters (exclude_kernel=1) are \
                 attached to the calling thread and to every live fuser* daemon thread, \
                 and a counting global allocator records allocations. The counters see \
                 user-space dispatch + engine work on the daemon threads; the kernel \
                 FUSE/VFS time is excluded and is visible only in the client wall-clock \
                 percentiles. No number is fabricated: when perf_event_open is denied the \
                 court records available:false with the exact errno.",
        "mount": {
            "options": "MountOptions::default() (classical FUSE transport, synchronous \
                        backing I/O, page cache on, durability Ordered)",
            "transport_used": transport,
            "backing_io_used": backing_io,
            "container_image": std::env::var("ORFS_IMAGE").ok(),
            "image_digest": image_digest(),
        },
        "workload": {
            "iters": scale.iters,
            "measured_syscalls": total_ops,
            "ops": "create (+96 B payload) | stat | rename | unlink | read 96 B | write 96 B",
            "wall_ns": wall.as_nanos() as u64,
            "wall_ns_per_op": wall.as_nanos() as f64 / total_ops as f64,
        },
        "allocations": {
            "calls": allocs,
            "bytes": bytes,
            "allocs_per_op": allocs as f64 / total_ops as f64,
            "bytes_per_op": bytes as f64 / total_ops as f64,
            "note": "counting #[global_allocator]; the client and the daemon run in the \
                     same process, so this counts both.",
        },
        "pmu": {
            "available": pmu_available,
            "error": pmu_error,
            "counters": counters,
            "missing_counters": missing,
            "client_thread": client_tot.map(|t| per_op(&t, total_ops)),
            "daemon_threads": {
                "attached_tids": daemon.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
                "failed_tids": daemon_failed,
                "reason": daemon_reason,
                "per_op": per_op(&daemon_tot, total_ops),
                "per_thread": per_thread,
                "method_note": "sums every live fuser* thread of the test process, divided \
                                by the client's measured syscall count; the classical /dev/fuse \
                                daemon runs on fuser-bg + fuser-0..N. Client-side counters are \
                                user-space only (exclude_kernel=1), so the kernel FUSE syscall \
                                time is not counted on either side.",
            },
        },
        "latency_ns": {
            "create": latency_json(&summarize(ops.create.clone())),
            "stat": latency_json(&summarize(ops.stat.clone())),
            "rename": latency_json(&summarize(ops.rename.clone())),
            "unlink": latency_json(&summarize(ops.unlink.clone())),
            "read": latency_json(&summarize(ops.read.clone())),
            "write": latency_json(&summarize(ops.write.clone())),
        },
        "flamegraph": flame,
        "environment": env,
        "build": if cfg!(debug_assertions) { "debug" } else { "release" },
    })
}

fn write_json(doc: &serde_json::Value) {
    let path = manifest_dir().join("evidence/performance/hotpath-counters.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(doc).expect("serialize");
    s.push('\n');
    fs::write(&path, s).expect("write evidence");
}

/// Record `ran:false` with the exact reason, never fabricating counters.
fn record_ran_false(blocker: String, extra: serde_json::Value) {
    let doc = serde_json::json!({
        "schema": "orfs.performance.hotpath-counters.v1",
        "generated_by": "tests/hotpath_counters.rs",
        "ran": false,
        "blocker": blocker,
        "detail": extra,
    });
    write_json(&doc);
}

#[test]
fn hotpath_counters_smoke() {
    run_court(Scale::smoke(), false, "smoke");
}

#[test]
fn hotpath_counters_sweep() {
    if std::env::var("ORFS_HOTPATH").as_deref() != Ok("1") {
        eprintln!("hotpath_counters_sweep: skipped (ORFS_HOTPATH unset)");
        return;
    }
    run_court(Scale::sweep(), true, "sweep");
}
