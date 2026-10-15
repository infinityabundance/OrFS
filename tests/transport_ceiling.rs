//! **Phase 84 — the metadata/transport ceiling, measured.**
//!
//! Phase 83 (`docs/PERFORMANCE.md` §34) attributed the mounted metadata/read hot
//! path with real counters, but only for one transport (F0) and without a
//! same-device reference: it could say the daemon costs ~43.8 k cycles/op, but not
//! **how much of the gap to a plain filesystem is irreducible FUSE dispatch** and
//! how much is OrFS's own work, nor whether the transport changes the answer.
//!
//! This court answers both with measurements:
//!
//! * it drives the **same bounded** `create`/`stat`/`rename`/`unlink` + small
//!   `read`/`write` workload through a real mount on each transport the host
//!   actually permits — **F0** (`fuser`), **F2** with `F2Servicing::Single` and
//!   `F2Servicing::pool_default()` (only when F2 genuinely negotiates; a fallback
//!   is recorded concretely), and a **read-only immutable snapshot** arm for the
//!   read path;
//! * it drives the **identical** workload against a plain directory on the same
//!   device with **no FUSE** (the same-device baseline) and — for allocation
//!   attribution — directly through the in-process [`Namespace`] engine (no
//!   mount at all);
//! * for every mounted arm it records p50/p95/p99/p99.9 per op, real per-thread
//!   hardware counters on the calling thread **and every live daemon thread**, the
//!   counting-allocator `allocs/op`, which transport **actually served** the
//!   request (`transport_used()`), and the daemon request counts.
//!
//! ## The decomposition (honest)
//!
//! For each mounted transport the *overhead* over the same-device baseline,
//! `overhead = mounted_wall − raw_wall` (ns/op), is split into three measured
//! parts:
//!
//! ```text
//! overhead ≈ client_cpu + daemon_cpu + kernel
//!   client_cpu = client cycles/op ÷ cycles_per_ns        (calling thread)
//!   daemon_cpu = Σ daemon-thread cycles/op ÷ cycles_per_ns
//!   kernel     = overhead − client_cpu − daemon_cpu       (irreducible FUSE dispatch,
//!                                                          syscall, scheduling)
//! ```
//!
//! `cycles_per_ns` is **measured** on the calling thread with a hardware cycle
//! counter over a CPU-bound loop (no fabricated frequency). The daemon counter is
//! **summed across every daemon thread** and divided by the client's measured
//! syscall count: because the workload is serial, each op is served by exactly one
//! daemon thread, so `Σ cycles ÷ ops` is the average per-op fuel — its limits are
//! stated in the receipt.
//!
//! User-space counters use `exclude_kernel=1`, so the kernel FUSE/VFS time is
//! visible only as the residual. Every number comes from a real container run; when
//! `perf_event_open` is denied the court records `available:false` with the exact
//! errno and still reports the wall-clock percentiles and allocation counts.
//!
//! Evidence: `evidence/performance/transport-ceiling.json`
//! (schema `orfs.performance.transport-ceiling.v1`).

use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use orfs::commit::DurabilityMode;
use orfs::fuse::{self, BackingIo, F2Servicing, MountOptions, Transport};
use orfs::fuse_uring::TransportProfile;
use orfs::index::ROOT_INODE;
use orfs::log::DEFAULT_SEGMENT_SIZE;
use orfs::namespace::{Namespace, RenameMode, SetAttr};

#[path = "support/pmu.rs"]
mod pmu;

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

fn receipt_requested() -> bool {
    std::env::var("ORFS_TRANSPORT_CEILING").as_deref() == Ok("1")
}

fn image_digest() -> String {
    std::env::var("ORFS_IMAGE_DIGEST").unwrap_or_else(|_| "unknown".into())
}

fn unique_scratch(prefix: &str) -> PathBuf {
    let base = manifest_dir().join("target").join("transport-ceiling-it");
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

fn init_namespace(backing: &Path) -> Result<Namespace, String> {
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
    ns.sync().map_err(|e| e.to_string())?;
    Ok(ns)
}

fn init_volume(backing: &Path) -> Result<(), String> {
    init_namespace(backing).map(|_| ())
}

/// The thread ids of this process whose `comm` starts with any of `prefixes`.
fn tids_matching(prefixes: &[&str]) -> Vec<i32> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir("/proc/self/task") {
        for e in rd.flatten() {
            let Some(tid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            let comm =
                fs::read_to_string(format!("/proc/self/task/{tid}/comm")).unwrap_or_default();
            if prefixes.iter().any(|p| comm.trim_start().starts_with(p)) {
                out.push(tid);
            }
        }
    }
    out.sort_unstable();
    out
}

/// Discover the daemon threads, waiting (bounded) for the session's workers to
/// appear, then requiring the set to stop growing.
fn discover_tids(prefixes: &[&str]) -> Vec<i32> {
    let started = Instant::now();
    let mut best = tids_matching(prefixes);
    let mut stable = 0u32;
    while started.elapsed() < Duration::from_millis(2000) {
        std::thread::sleep(Duration::from_millis(40));
        let now = tids_matching(prefixes);
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
                _ => {}
            }
        }
    }
    t
}

/// Latency summary in nanoseconds (incl. p99.9 for the tail decision).
struct Latency {
    n: u64,
    mean: f64,
    p50: u64,
    p95: u64,
    p99: u64,
    p999: u64,
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
            p999: 0,
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
        p999: pick(99.9),
    }
}

fn latency_json(l: &Latency) -> serde_json::Value {
    serde_json::json!({
        "n": l.n,
        "mean_ns": l.mean,
        "p50_ns": l.p50,
        "p95_ns": l.p95,
        "p99_ns": l.p99,
        "p99_9_ns": l.p999,
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

    fn total(&self) -> u64 {
        (self.create.len()
            + self.stat.len()
            + self.rename.len()
            + self.unlink.len()
            + self.read.len()
            + self.write.len()) as u64
    }

    fn latency_json(&self) -> serde_json::Value {
        serde_json::json!({
            "create": latency_json(&summarize(self.create.clone())),
            "stat": latency_json(&summarize(self.stat.clone())),
            "rename": latency_json(&summarize(self.rename.clone())),
            "unlink": latency_json(&summarize(self.unlink.clone())),
            "read": latency_json(&summarize(self.read.clone())),
            "write": latency_json(&summarize(self.write.clone())),
        })
    }
}

const PAYLOAD: [u8; 96] = [0x5a; 96];

/// Drive one bounded `create`/`stat`/`rename`/`unlink` + small `read`/`write`
/// cycle against the mount/directory at `root`, timing each syscall. This is the
/// **same** workload as the Phase-83 hot-path court (`tests/hotpath_counters.rs`),
/// so its F0 numbers are directly comparable.
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

/// Read `iters` times a 96-byte block from `root/.__readonly-f` through the mount,
/// timing each read. Used for the read-only immutable snapshot arm, where the
/// workload **cannot** mutate and the label says so.
fn drive_read_only(root: &Path, iters: usize, ops: &mut Ops) {
    let path = root.join(".__readonly-f");
    let data = OpenOptions::new()
        .read(true)
        .open(&path)
        .expect("open readonly file");
    let mut rbuf = [0u8; 96];
    for _ in 0..iters {
        let t = Instant::now();
        let _ = data.read_at(&mut rbuf, 0).expect("read");
        ops.read.push(t.elapsed().as_nanos() as u64);
    }
}

/// Per-op allocation counts, indexed by op, for the engine arm (deterministic:
/// single thread, no daemon).
#[derive(Default, Clone, Copy)]
struct AllocAttrib {
    create: u64,
    stat: u64,
    rename: u64,
    unlink: u64,
    read: u64,
    write: u64,
}

impl AllocAttrib {
    fn json(&self, iters: u64) -> serde_json::Value {
        let per = |v: u64| v as f64 / iters.max(1) as f64;
        serde_json::json!({
            "create_calls": self.create, "create_allocs_per_op": per(self.create),
            "stat_calls": self.stat, "stat_allocs_per_op": per(self.stat),
            "rename_calls": self.rename, "rename_allocs_per_op": per(self.rename),
            "unlink_calls": self.unlink, "unlink_allocs_per_op": per(self.unlink),
            "read_calls": self.read, "read_allocs_per_op": per(self.read),
            "write_calls": self.write, "write_allocs_per_op": per(self.write),
        })
    }
}

/// Drive the **identical logical sequence** directly through the engine, with no
/// mount and no FUSE at all. This isolates OrFS's own allocation and CPU work from
/// the FUSE dispatch, so the mounted-vs-engine delta is the dispatch/framing cost.
///
/// When `attrib` is given, the allocation delta of each op is recorded, so the
/// top allocation sources are named with numbers rather than guessed.
fn drive_engine_workload(
    ns: &mut Namespace,
    iters: usize,
    ops: &mut Ops,
    mut attrib: Option<&mut AllocAttrib>,
) {
    // `create`/`rename`/`unlink` take the parent's **inode id** (the root is inode
    // 1); `getattr`/`read_at` take the committed **root offset** that selects the
    // view. They are two different things and must not be conflated.
    let root_ino = ns.root_inode();
    // SAFETY: pure queries.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    // Idempotent across the warm-up and measured passes: drop any data file the
    // previous pass left behind before recreating it.
    let _ = ns.unlink(root_ino, b".__engdata");
    let ino = ns
        .create(root_ino, b".__engdata", 0o644, uid, gid)
        .expect("engine create data");
    ns.write_at(ino, 0, &PAYLOAD).expect("engine seed data");

    for i in 0..iters {
        let a = format!(".__eng-{i}-a");
        let b = format!(".__eng-{i}-b");

        let t = Instant::now();
        let a0 = alloc_snapshot().0;
        let created = ns
            .create(root_ino, a.as_bytes(), 0o644, uid, gid)
            .expect("engine create");
        ns.write_at(created, 0, &PAYLOAD)
            .expect("engine write payload");
        ops.create.push(t.elapsed().as_nanos() as u64);
        if let Some(at) = attrib.as_deref_mut() {
            at.create += alloc_snapshot().0 - a0;
        }

        let t = Instant::now();
        let a0 = alloc_snapshot().0;
        let meta = ns.getattr(created, ns.root()).expect("engine stat");
        ops.stat.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(meta.size);
        if let Some(at) = attrib.as_deref_mut() {
            at.stat += alloc_snapshot().0 - a0;
        }

        let t = Instant::now();
        let a0 = alloc_snapshot().0;
        ns.rename(
            root_ino,
            a.as_bytes(),
            root_ino,
            b.as_bytes(),
            RenameMode::Ordinary,
        )
        .expect("engine rename");
        ops.rename.push(t.elapsed().as_nanos() as u64);
        if let Some(at) = attrib.as_deref_mut() {
            at.rename += alloc_snapshot().0 - a0;
        }

        let t = Instant::now();
        let a0 = alloc_snapshot().0;
        ns.unlink(root_ino, b.as_bytes()).expect("engine unlink");
        ops.unlink.push(t.elapsed().as_nanos() as u64);
        if let Some(at) = attrib.as_deref_mut() {
            at.unlink += alloc_snapshot().0 - a0;
        }

        let t = Instant::now();
        let a0 = alloc_snapshot().0;
        let got = ns.read_at(ino, ns.root(), 0, 96).expect("engine read");
        ops.read.push(t.elapsed().as_nanos() as u64);
        debug_assert_eq!(got.len(), 96);
        if let Some(at) = attrib.as_deref_mut() {
            at.read += alloc_snapshot().0 - a0;
        }

        let t = Instant::now();
        let a0 = alloc_snapshot().0;
        ns.write_at(ino, 0, &PAYLOAD).expect("engine write");
        ops.write.push(t.elapsed().as_nanos() as u64);
        if let Some(at) = attrib.as_deref_mut() {
            at.write += alloc_snapshot().0 - a0;
        }
    }
}

/// Measure the effective clock in cycles per nanosecond on the calling thread
/// with a real hardware cycle counter over a CPU-bound loop. Returns
/// `(cycles, nanos, cycles_per_ns)` or `None` when the cycle counter is refused.
fn calibrate_cycles_per_ns() -> Option<(u64, u64, f64)> {
    let mut group = PmuGroup::open().ok()?;
    if !group.has(Counter::Cycles) {
        return None;
    }
    let mut buf = vec![0u8; 1 << 16];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = i as u8;
    }
    // Warm the loop so the measured window is steady-state.
    let warm = Instant::now();
    let mut acc = 0u64;
    while warm.elapsed() < Duration::from_millis(5) {
        for &b in &buf {
            acc = acc.wrapping_mul(31).wrapping_add(b as u64);
        }
    }
    std::hint::black_box(acc);

    let _ = group.reset();
    let _ = group.enable();
    let t = Instant::now();
    let start = Instant::now();
    let mut acc = 0u64;
    while t.elapsed() < Duration::from_millis(40) {
        for &b in &buf {
            acc = acc.wrapping_mul(31).wrapping_add(b as u64);
        }
    }
    std::hint::black_box(acc);
    let nanos = start.elapsed().as_nanos() as u64;
    let _ = group.disable();
    let cycles = sum_groups(&[&group]).cycles;
    if cycles == 0 || nanos == 0 {
        return None;
    }
    Some((cycles, nanos, cycles as f64 / nanos as f64))
}

// ---------------------------------------------------------------------------
// Arms
// ---------------------------------------------------------------------------

/// What kind of arm this is, which selects the mount path and the driver.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ArmKind {
    /// A read-write mount driven with the full metadata + read/write workload.
    Mount,
    /// A read-only immutable snapshot mount (F2 native), driven with reads only.
    ReadOnlySnapshot,
}

struct MountSpec {
    label: &'static str,
    kind: ArmKind,
    transport: Transport,
    backing: BackingIo,
    f2: F2Servicing,
    passthrough: bool,
}

/// One measured arm, ready to serialize.
struct Arm {
    label: String,
    kind: &'static str,
    requested: String,
    transport_used: String,
    fallback: bool,
    fallback_reason: Option<String>,
    backing_io_used: String,
    servicing: Option<String>,
    iters: usize,
    total_ops: u64,
    wall_ns: u64,
    wall_ns_per_op: f64,
    allocs: u64,
    bytes: u64,
    pmu_available: bool,
    pmu_error: Option<String>,
    counters: Vec<&'static str>,
    client_tot: Option<Totals>,
    daemon_tot: Totals,
    daemon_tids: Vec<i32>,
    daemon_failed: Vec<i32>,
    daemon_reason: Option<String>,
    latency: serde_json::Value,
    daemon_metrics: Option<serde_json::Value>,
    f2_stats: Option<serde_json::Value>,
    alloc_attrib: Option<AllocAttrib>,
}

fn measure_mount_arm(
    spec: &MountSpec,
    iters: usize,
    drive: &dyn Fn(&Path, usize, &mut Ops),
) -> Result<Arm, String> {
    let scratch = unique_scratch(spec.label);
    let backing = scratch.join("backing");
    let mnt = scratch.join("mnt");
    fs::create_dir_all(&mnt).map_err(|e| e.to_string())?;

    let opts = MountOptions {
        transport: spec.transport,
        backing_io: spec.backing,
        f2_servicing: spec.f2,
        passthrough: spec.passthrough,
        // The read-only arm reads the SAME 96-byte block every iteration: without
        // direct I/O the kernel page cache would serve every read after the first
        // and the arm would measure the cache, not the transport. Direct I/O makes
        // each read a real round trip (and is why the mutation arms keep the
        // default profile: their cost is the metadata round trip, not the read).
        direct_io: spec.kind == ArmKind::ReadOnlySnapshot,
        ..Default::default()
    };

    // Build the volume, and (for the read-only arm) seed the file the reads hit.
    let mount = if spec.kind == ArmKind::ReadOnlySnapshot {
        let mut ns = init_namespace(&backing)?;
        // SAFETY: pure queries.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let f = ns
            .create(ROOT_INODE, b".__readonly-f", 0o644, uid, gid)
            .map_err(|e| e.to_string())?;
        ns.write_at(f, 0, &PAYLOAD).map_err(|e| e.to_string())?;
        ns.sync().map_err(|e| e.to_string())?;
        let root = ns.root();
        // Prefer the native F2 session (the only transport that can register a
        // kernel backing). If it cannot engage, still measure the read path on the
        // classical read-only transport and record the fallback honestly rather
        // than skipping the arm.
        match fuse::spawn_snapshot_native(&backing, &mnt, root, &opts) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "transport_ceiling: read-only arm: native F2 snapshot did not engage \
                     ({e}); falling back to the classical read-only transport"
                );
                fuse::spawn_snapshot(&backing, &mnt, root, &opts).map_err(|e| e.to_string())?
            }
        }
    } else {
        init_volume(&backing)?;
        fuse::spawn(&backing, &mnt, &opts).map_err(|e| e.to_string())?
    };

    let used = mount.transport_used();
    let transport_used = used.name().to_string();
    let fallback = spec.transport.requests_uring_fuse() && used != TransportProfile::F2;
    let fallback_reason = if fallback {
        Some(format!(
            "F2 requested but the transport in force is {transport_used}: {}",
            mount.transport_description()
        ))
    } else {
        None
    };
    let servicing = mount.f2_environment().map(|e| e.servicing);

    let prefixes: &[&str] = if used == TransportProfile::F2 {
        &["orfs-f2"]
    } else {
        &["fuser"]
    };
    let tids = discover_tids(prefixes);

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

    // Warm (counters disabled) so cold misses are not charged.
    {
        let mut warm = Ops::with_capacity(64);
        drive(&mnt, 64, &mut warm);
    }

    let metrics_before = mount.daemon_metrics();
    let f2_before = mount.f2_stats();

    if let Some(g) = client.as_mut() {
        let _ = g.reset();
        let _ = g.enable();
    }
    for (_, g) in daemon.iter_mut() {
        let _ = g.reset();
        let _ = g.enable();
    }
    let (a0, b0) = alloc_snapshot();
    let mut ops = Ops::with_capacity(iters);
    let wall = Instant::now();
    drive(&mnt, iters, &mut ops);
    let wall = wall.elapsed();
    let (a1, b1) = alloc_snapshot();
    if let Some(g) = client.as_mut() {
        let _ = g.disable();
    }
    for (_, g) in daemon.iter_mut() {
        let _ = g.disable();
    }

    let metrics_after = mount.daemon_metrics();
    let f2_after = mount.f2_stats();

    let total_ops = ops.total().max(1);
    let client_tot = client.as_ref().map(|g| sum_groups(&[g]));
    let daemon_tot = {
        let refs: Vec<&PmuGroup> = daemon.iter().map(|(_, g)| g).collect();
        sum_groups(&refs)
    };

    let arm = Arm {
        label: spec.label.to_string(),
        kind: match spec.kind {
            ArmKind::Mount => "mount",
            ArmKind::ReadOnlySnapshot => "read-only-snapshot",
        },
        requested: spec.transport.requested_name().to_string(),
        transport_used,
        fallback,
        fallback_reason,
        backing_io_used: format!("{:?}", mount.backing_io_used),
        servicing,
        iters,
        total_ops,
        wall_ns: wall.as_nanos() as u64,
        wall_ns_per_op: wall.as_nanos() as f64 / total_ops as f64,
        allocs: a1.saturating_sub(a0),
        bytes: b1.saturating_sub(b0),
        pmu_available,
        pmu_error,
        counters,
        client_tot,
        daemon_tot,
        daemon_tids: tids,
        daemon_failed,
        daemon_reason,
        latency: ops.latency_json(),
        daemon_metrics: Some(metrics_diff(&metrics_before, &metrics_after)),
        f2_stats: match (f2_before, f2_after) {
            (Some(b), Some(a)) => Some(f2_stats_diff(&b, &a)),
            _ => None,
        },
        alloc_attrib: None,
    };

    let _ = mount.unmount();
    let _ = fs::remove_dir_all(&scratch);
    Ok(arm)
}

fn measure_raw_arm(iters: usize) -> Result<Arm, String> {
    let scratch = unique_scratch("raw");
    let dir = scratch.join("plain");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let mut client = PmuGroup::open().ok();
    let pmu_available = client.is_some();
    let pmu_error = if client.is_none() {
        PmuGroup::open().err()
    } else {
        None
    };
    let counters = client
        .as_ref()
        .map(|g| g.counters().iter().map(|c| c.name()).collect::<Vec<_>>())
        .unwrap_or_default();

    {
        let mut warm = Ops::with_capacity(64);
        drive_workload(&dir, 64, &mut warm);
    }
    if let Some(g) = client.as_mut() {
        let _ = g.reset();
        let _ = g.enable();
    }
    let (a0, b0) = alloc_snapshot();
    let mut ops = Ops::with_capacity(iters);
    let wall = Instant::now();
    drive_workload(&dir, iters, &mut ops);
    let wall = wall.elapsed();
    let (a1, b1) = alloc_snapshot();
    if let Some(g) = client.as_mut() {
        let _ = g.disable();
    }
    let total_ops = ops.total().max(1);
    let client_tot = client.as_ref().map(|g| sum_groups(&[g]));

    let arm = Arm {
        label: "same-device (no FUSE)".to_string(),
        kind: "same-device-baseline",
        requested: "none".to_string(),
        transport_used: "direct".to_string(),
        fallback: false,
        fallback_reason: None,
        backing_io_used: "direct".to_string(),
        servicing: None,
        iters,
        total_ops,
        wall_ns: wall.as_nanos() as u64,
        wall_ns_per_op: wall.as_nanos() as f64 / total_ops as f64,
        allocs: a1.saturating_sub(a0),
        bytes: b1.saturating_sub(b0),
        pmu_available,
        pmu_error,
        counters,
        client_tot,
        daemon_tot: Totals::default(),
        daemon_tids: Vec::new(),
        daemon_failed: Vec::new(),
        daemon_reason: None,
        latency: ops.latency_json(),
        daemon_metrics: None,
        f2_stats: None,
        alloc_attrib: None,
    };
    let _ = fs::remove_dir_all(&scratch);
    Ok(arm)
}

fn measure_engine_arm(iters: usize) -> Result<Arm, String> {
    let scratch = unique_scratch("engine");
    let backing = scratch.join("backing");
    let mut ns = init_namespace(&backing)?;

    let mut client = PmuGroup::open().ok();
    let pmu_available = client.is_some();
    let pmu_error = if client.is_none() {
        PmuGroup::open().err()
    } else {
        None
    };
    let counters = client
        .as_ref()
        .map(|g| g.counters().iter().map(|c| c.name()).collect::<Vec<_>>())
        .unwrap_or_default();

    {
        let mut warm = Ops::with_capacity(64);
        drive_engine_workload(&mut ns, 64, &mut warm, None);
    }
    if let Some(g) = client.as_mut() {
        let _ = g.reset();
        let _ = g.enable();
    }
    let (a0, b0) = alloc_snapshot();
    let mut ops = Ops::with_capacity(iters);
    let mut attrib = AllocAttrib::default();
    let wall = Instant::now();
    drive_engine_workload(&mut ns, iters, &mut ops, Some(&mut attrib));
    let wall = wall.elapsed();
    let (a1, b1) = alloc_snapshot();
    if let Some(g) = client.as_mut() {
        let _ = g.disable();
    }
    let total_ops = ops.total().max(1);
    let client_tot = client.as_ref().map(|g| sum_groups(&[g]));

    let arm = Arm {
        label: "engine (no mount)".to_string(),
        kind: "engine-direct",
        requested: "engine".to_string(),
        transport_used: "engine".to_string(),
        fallback: false,
        fallback_reason: None,
        backing_io_used: "Sync".to_string(),
        servicing: None,
        iters,
        total_ops,
        wall_ns: wall.as_nanos() as u64,
        wall_ns_per_op: wall.as_nanos() as f64 / total_ops as f64,
        allocs: a1.saturating_sub(a0),
        bytes: b1.saturating_sub(b0),
        pmu_available,
        pmu_error,
        counters,
        client_tot,
        daemon_tot: Totals::default(),
        daemon_tids: Vec::new(),
        daemon_failed: Vec::new(),
        daemon_reason: None,
        latency: ops.latency_json(),
        daemon_metrics: None,
        f2_stats: None,
        alloc_attrib: Some(attrib),
    };
    let _ = fs::remove_dir_all(&scratch);
    Ok(arm)
}

fn metrics_diff(before: &fuse::Metrics, after: &fuse::Metrics) -> serde_json::Value {
    let d = |a: u64, b: u64| b.saturating_sub(a);
    serde_json::json!({
        "lookups": d(before.lookups, after.lookups),
        "forgets": d(before.forgets, after.forgets),
        "opens": d(before.opens, after.opens),
        "releases": d(before.releases, after.releases),
        "opendirs": d(before.opendirs, after.opendirs),
        "releasedirs": d(before.releasedirs, after.releasedirs),
        "reads": d(before.reads, after.reads),
        "writes": d(before.writes, after.writes),
        "byte_reads": d(before.byte_reads, after.byte_reads),
        "byte_writes": d(before.byte_writes, after.byte_writes),
        "fsyncs": d(before.fsyncs, after.fsyncs),
        "create": d(before.create, after.create),
        "mkdir": d(before.mkdir, after.mkdir),
        "unlink": d(before.unlink, after.unlink),
        "rmdir": d(before.rmdir, after.rmdir),
        "rename": d(before.rename, after.rename),
        "link": d(before.link, after.link),
        "symlink": d(before.symlink, after.symlink),
        "setattr": d(before.setattr, after.setattr),
    })
}

fn f2_stats_diff(
    before: &orfs::fuse_native::NativeStats,
    after: &orfs::fuse_native::NativeStats,
) -> serde_json::Value {
    let d = |a: u64, b: u64| b.saturating_sub(a);
    serde_json::json!({
        "requests_served": d(before.requests_served, after.requests_served),
        "ring_submits": d(before.ring_submits, after.ring_submits),
        "ring_completions": d(before.ring_completions, after.ring_completions),
        "sq_full_events": d(before.sq_full_events, after.sq_full_events),
        "cq_max_len": after.cq_max_len,
        "fast_routed": d(before.fast_routed, after.fast_routed),
        "bulk_routed": d(before.bulk_routed, after.bulk_routed),
        "handoffs": d(before.handoffs, after.handoffs),
        "passthrough_requested": after.passthrough_requested,
        "passthrough_negotiated": after.passthrough_negotiated,
        "passthrough_opens": d(before.passthrough_opens, after.passthrough_opens),
        "passthrough_registered": after.passthrough_registered,
        "passthrough_reused": d(before.passthrough_reused, after.passthrough_reused),
        "passthrough_fallbacks": d(before.passthrough_fallbacks, after.passthrough_fallbacks),
        "passthrough_releases": d(before.passthrough_releases, after.passthrough_releases),
        "passthrough_bytes": d(before.passthrough_bytes, after.passthrough_bytes),
        "passthrough_last_error": after.passthrough_last_error,
    })
}

// ---------------------------------------------------------------------------
// The court
// ---------------------------------------------------------------------------

/// A bounded scale: `iters` cycles of the 6-op workload per arm.
#[derive(Clone, Copy)]
struct Scale {
    iters: usize,
}

impl Scale {
    const fn smoke() -> Scale {
        Scale { iters: 200 }
    }
    const fn receipt() -> Scale {
        Scale { iters: 2000 }
    }
}

fn collect_arms(scale: Scale) -> Vec<Arm> {
    let mut arms: Vec<Arm> = Vec::new();

    // The same-device baseline first, then the engine, then every mount transport.
    match measure_raw_arm(scale.iters) {
        Ok(a) => arms.push(a),
        Err(e) => eprintln!("transport_ceiling: same-device arm failed: {e}"),
    }
    match measure_engine_arm(scale.iters) {
        Ok(a) => arms.push(a),
        Err(e) => eprintln!("transport_ceiling: engine arm failed: {e}"),
    }

    let specs = [
        MountSpec {
            label: "F0",
            kind: ArmKind::Mount,
            transport: Transport::Fuse,
            backing: BackingIo::Sync,
            f2: F2Servicing::Single,
            passthrough: false,
        },
        MountSpec {
            label: "F2-single",
            kind: ArmKind::Mount,
            transport: Transport::FuseUring,
            backing: BackingIo::Uring,
            f2: F2Servicing::Single,
            passthrough: false,
        },
        MountSpec {
            label: "F2-pool",
            kind: ArmKind::Mount,
            transport: Transport::FuseUring,
            backing: BackingIo::Uring,
            f2: F2Servicing::pool_default(),
            passthrough: false,
        },
        MountSpec {
            label: "F2-immutable-read",
            kind: ArmKind::ReadOnlySnapshot,
            transport: Transport::FuseUring,
            backing: BackingIo::Sync,
            f2: F2Servicing::Single,
            passthrough: true,
        },
    ];

    for spec in &specs {
        let drive: &dyn Fn(&Path, usize, &mut Ops) = if spec.kind == ArmKind::ReadOnlySnapshot {
            &drive_read_only
        } else {
            &drive_workload
        };
        match measure_mount_arm(spec, scale.iters, drive) {
            Ok(a) => {
                eprintln!(
                    "transport_ceiling: arm {}: requested={} used={} fallback={} ops={} \
                     wall_ns_per_op={:.1} allocs_per_op={:.3}",
                    a.label,
                    a.requested,
                    a.transport_used,
                    a.fallback,
                    a.total_ops,
                    a.wall_ns_per_op,
                    a.allocs as f64 / a.total_ops as f64,
                );
                arms.push(a);
            }
            Err(e) => {
                if fuse_test_required() {
                    panic!(
                        "transport_ceiling: arm {} could not be measured: {e}",
                        spec.label
                    );
                }
                eprintln!(
                    "transport_ceiling: arm {} skipped (ORFS_FUSE_TEST unset): {e}",
                    spec.label
                );
            }
        }
    }
    arms
}

fn run_court(scale: Scale, write_receipt: bool) {
    if !fuse_test_required() {
        eprintln!(
            "transport_ceiling: skipped (ORFS_FUSE_TEST unset); \
             run under scripts/container-transport-ceiling.sh"
        );
        return;
    }

    let calibration = calibrate_cycles_per_ns();
    let arms = collect_arms(scale);
    if arms.is_empty() {
        panic!("transport_ceiling: no arm could be measured under ORFS_FUSE_TEST=1");
    }

    if write_receipt {
        let doc = build_receipt(scale, &arms, calibration);
        write_json(&doc);
        println!("transport_ceiling: wrote evidence/performance/transport-ceiling.json");
    } else {
        for a in &arms {
            eprintln!(
                "transport_ceiling: {:<22} used={:<6} fallback={} wall_ns_per_op={:.1} \
                 allocs_per_op={:.2}",
                a.label,
                a.transport_used,
                a.fallback,
                a.wall_ns_per_op,
                a.allocs as f64 / a.total_ops as f64,
            );
        }
    }
}

fn per_op(tot: &Totals, total: u64) -> serde_json::Value {
    let d = total.max(1) as f64;
    serde_json::json!({
        "cycles_per_op": tot.cycles as f64 / d,
        "instructions_per_op": tot.instructions as f64 / d,
        "cache_references_per_op": tot.cache_references as f64 / d,
        "cache_misses_per_op": tot.cache_misses as f64 / d,
        "branch_misses_per_op": tot.branch_misses as f64 / d,
        "ipc": if tot.cycles > 0 { tot.instructions as f64 / tot.cycles as f64 } else { 0.0 },
    })
}

/// The measured decomposition of one mounted arm against the same-device baseline.
#[allow(clippy::too_many_arguments)]
fn decompose(
    arm: &Arm,
    raw_wall_ns_per_op: f64,
    cycles_per_ns: Option<f64>,
    engine_allocs_per_op: Option<f64>,
) -> serde_json::Value {
    let mounted = arm.wall_ns_per_op;
    let overhead = (mounted - raw_wall_ns_per_op).max(0.0);
    let d = arm.total_ops.max(1) as f64;
    let daemon_cycles_per_op = arm.daemon_tot.cycles as f64 / d;
    let client_cycles_per_op = arm.client_tot.map(|t| t.cycles as f64 / d).unwrap_or(0.0);

    let mut obj = serde_json::Map::new();
    obj.insert("mounted_wall_ns_per_op".into(), serde_json::json!(mounted));
    obj.insert(
        "same_device_wall_ns_per_op".into(),
        serde_json::json!(raw_wall_ns_per_op),
    );
    obj.insert("overhead_ns_per_op".into(), serde_json::json!(overhead));
    obj.insert(
        "daemon_cycles_per_op".into(),
        serde_json::json!(daemon_cycles_per_op),
    );
    obj.insert(
        "client_cycles_per_op".into(),
        serde_json::json!(client_cycles_per_op),
    );

    match cycles_per_ns {
        Some(f) if f > 0.0 => {
            let client_cpu = client_cycles_per_op / f;
            let daemon_cpu = daemon_cycles_per_op / f;
            let kernel = (overhead - client_cpu - daemon_cpu).max(0.0);
            obj.insert("cycles_per_ns".into(), serde_json::json!(f));
            obj.insert("client_cpu_ns_per_op".into(), serde_json::json!(client_cpu));
            obj.insert("daemon_cpu_ns_per_op".into(), serde_json::json!(daemon_cpu));
            obj.insert("kernel_ns_per_op".into(), serde_json::json!(kernel));
            obj.insert(
                "irreducible_dispatch_ns_per_op".into(),
                serde_json::json!(kernel),
            );
            obj.insert(
                "irreducible_fraction_of_overhead".into(),
                serde_json::json!(if overhead > 0.0 {
                    kernel / overhead
                } else {
                    0.0
                }),
            );
            obj.insert(
                "daemon_fraction_of_overhead".into(),
                serde_json::json!(if overhead > 0.0 {
                    daemon_cpu / overhead
                } else {
                    0.0
                }),
            );
            obj.insert(
                "irreducible_fraction_of_mounted".into(),
                serde_json::json!(if mounted > 0.0 { kernel / mounted } else { 0.0 }),
            );
        }
        _ => {
            obj.insert(
                "note".into(),
                serde_json::json!(
                    "cycle counter unavailable: the ns decomposition is not computed; \
                     the raw cycles_per_op above are still real"
                ),
            );
        }
    }

    if let Some(ea) = engine_allocs_per_op {
        let mounted_allocs = arm.allocs as f64 / d;
        obj.insert("engine_allocs_per_op".into(), serde_json::json!(ea));
        obj.insert(
            "mounted_allocs_per_op".into(),
            serde_json::json!(mounted_allocs),
        );
        obj.insert(
            "dispatch_allocs_per_op".into(),
            serde_json::json!((mounted_allocs - ea).max(0.0)),
        );
    }
    serde_json::Value::Object(obj)
}

fn build_receipt(
    scale: Scale,
    arms: &[Arm],
    calibration: Option<(u64, u64, f64)>,
) -> serde_json::Value {
    let raw_wall = arms
        .iter()
        .find(|a| a.kind == "same-device-baseline")
        .map(|a| a.wall_ns_per_op)
        .unwrap_or(0.0);
    let engine_allocs = arms
        .iter()
        .find(|a| a.kind == "engine-direct")
        .map(|a| a.allocs as f64 / a.total_ops.max(1) as f64);
    let cpn = calibration.map(|(_, _, f)| f);

    let env = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());

    let arm_json: Vec<serde_json::Value> = arms
        .iter()
        .map(|a| {
            let is_mount = a.kind == "mount";
            let decomposition = if is_mount {
                serde_json::Value::Object(
                    decompose(a, raw_wall, cpn, engine_allocs)
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                )
            } else {
                let mut m = serde_json::Map::new();
                m.insert(
                    "mounted_wall_ns_per_op".into(),
                    serde_json::json!(a.wall_ns_per_op),
                );
                if let Some(f) = cpn {
                    let cc = a
                        .client_tot
                        .map(|t| t.cycles as f64 / a.total_ops as f64)
                        .unwrap_or(0.0);
                    m.insert("cycles_per_ns".into(), serde_json::json!(f));
                    m.insert("client_cpu_ns_per_op".into(), serde_json::json!(cc / f));
                }
                m.insert(
                    "allocs_per_op".into(),
                    serde_json::json!(a.allocs as f64 / a.total_ops.max(1) as f64),
                );
                serde_json::Value::Object(m)
            };
            serde_json::json!({
                "label": a.label,
                "kind": a.kind,
                "requested_transport": a.requested,
                "transport_used": a.transport_used,
                "transport_description": if a.fallback {
                    a.fallback_reason.clone().unwrap_or_default()
                } else {
                    describe_transport(&a.transport_used)
                },
                "fallback": a.fallback,
                "fallback_reason": a.fallback_reason,
                "backing_io_used": a.backing_io_used,
                "servicing": a.servicing,
                "workload": {
                    "iters": a.iters,
                    "measured_syscalls": a.total_ops,
                    "wall_ns": a.wall_ns,
                    "wall_ns_per_op": a.wall_ns_per_op,
                },
                "allocations": {
                    "calls": a.allocs,
                    "bytes": a.bytes,
                    "allocs_per_op": a.allocs as f64 / a.total_ops.max(1) as f64,
                    "bytes_per_op": a.bytes as f64 / a.total_ops.max(1) as f64,
                },
                "latency_ns": a.latency,
                "pmu": {
                    "available": a.pmu_available,
                    "error": a.pmu_error,
                    "counters": a.counters,
                    "client_thread": a.client_tot.map(|t| per_op(&t, a.total_ops)),
                    "daemon_threads": {
                        "attached_tids": a.daemon_tids,
                        "failed_tids": a.daemon_failed,
                        "reason": a.daemon_reason,
                        "per_op": per_op(&a.daemon_tot, a.total_ops),
                    },
                },
                "daemon_requests": a.daemon_metrics,
                "f2_stats": a.f2_stats,
                "engine_allocation_attribution": a.alloc_attrib.map(|at| at.json(a.iters as u64)),
                "decomposition": decomposition,
            })
        })
        .collect();

    let calibration_json = calibration.map(|(cycles, nanos, f)| {
        serde_json::json!({
            "cycles": cycles,
            "nanos": nanos,
            "cycles_per_ns": f,
            "method": "hardware PERF_COUNT_HW_CPU_CYCLES on the calling thread over a \
                       40 ms CPU-bound rolling-hash loop, timed with Instant",
        })
    });

    serde_json::json!({
        "schema": "orfs.performance.transport-ceiling.v1",
        "generated_by": "tests/transport_ceiling.rs",
        "ran": true,
        "note": "Phase 84 — the metadata/transport ceiling, measured. The SAME bounded \
                 create/stat/rename/unlink + small read/write workload is driven through a \
                 real mount on every transport the host permits (F0, F2 single-loop, F2 pool, \
                 and a read-only immutable F2 snapshot read arm), through a plain directory \
                 on the same device with no FUSE (the baseline), and directly through the \
                 in-process engine (no mount). Per-arm latencies p50/p95/p99/p99.9, real \
                 per-thread user-space counters (exclude_kernel=1) on the calling thread and \
                 every live daemon thread, a counting allocator's allocs/op, the truth of \
                 which transport actually served (transport_used()), and the daemon request \
                 counts are all recorded. The overhead over the same-device baseline is split \
                 (measured) into client_cpu + daemon_cpu + kernel, where kernel is the \
                 irreducible FUSE dispatch/syscall/scheduling residual. No number is fabricated.",
        "workload": {
            "iters": scale.iters,
            "ops": "create (+96 B payload) | stat | rename | unlink | read 96 B | write 96 B",
            "read_only_arm_ops": "read 96 B only (immutable snapshot; not comparable to the \
                                  read-write metadata arms)",
        },
        "calibration": calibration_json,
        "comparability": {
            "F0_F2": "identical MountOptions (default TTLs, Ordered durability) differing only \
                      in transport/backing-I/O; directly comparable.",
            "same_device_baseline": "the identical workload on a plain directory on the same \
                                     device with no FUSE; the delta is the FUSE overhead.",
            "engine_direct": "the identical logical sequence through the engine with no mount; \
                              the mounted-minus-engine delta is dispatch + framing.",
            "read_only_snapshot": "a read-only immutable F2 snapshot, reads only; mutation ops \
                                   do not apply and the arm is labelled, not compared.",
        },
        "arms": arm_json,
        "reductions": reduction_evidence(arms),
        "build": if cfg!(debug_assertions) { "debug" } else { "release" },
        "environment": env,
        "image_digest": image_digest(),
    })
}

/// A machine-generated, in-run paired measurement of the one applied reduction
/// whose two code paths both remain expressible: the `DATA_EXTENT` payload
/// encoder. The "legacy" arm builds the struct (which owns a copy of the data)
/// and encodes it; the "current" arm encodes directly from the borrowed slice
/// (the form the hot append path now uses). Both are real code paths, measured
/// back to back in the same process, so this pair cannot be a run-to-run artefact.
fn encoder_pair() -> serde_json::Value {
    use orfs::extent::DataExtentPayload;
    const N: u64 = 100_000;
    let data = [0x5au8; 96];

    let (a0, _) = alloc_snapshot();
    for _ in 0..N {
        let encoded = DataExtentPayload {
            offset: 0,
            data: data.to_vec(),
        }
        .encode();
        std::hint::black_box(encoded.len());
    }
    let (a1, _) = alloc_snapshot();

    let (b0, _) = alloc_snapshot();
    for _ in 0..N {
        let encoded = DataExtentPayload::encode_slice(0, &data);
        std::hint::black_box(encoded.len());
    }
    let (b1, _) = alloc_snapshot();

    let legacy = a1.saturating_sub(a0);
    let current = b1.saturating_sub(b0);
    serde_json::json!({
        "what": "DATA_EXTENT payload encoding: struct-with-copy (`DataExtentPayload { data: data.to_vec() }.encode()`) vs direct slice (`DataExtentPayload::encode_slice(offset, data)`)",
        "op": "encode one 96-byte DATA_EXTENT payload",
        "iterations": N,
        "legacy": { "allocs": legacy, "allocs_per_op": legacy as f64 / N as f64 },
        "current": { "allocs": current, "allocs_per_op": current as f64 / N as f64 },
        "saved_allocs_per_op": (legacy as f64 - current as f64).max(0.0) / N as f64,
        "note": "the legacy form allocates the throwaway owned Vec and then the encoded Vec; the current form allocates only the encoded Vec. Same bytes are produced (checked by the round-trip tests).",
    })
}

/// The applied hot-path reductions and their measured effect. The `before`
/// numbers are the real Phase-83/Phase-84 pre-change measurements of the
/// **identical** court workload (see `evidence/performance/hotpath-counters.json`,
/// whose pre-change `allocs_per_op` was 101.8874, and the pre-change run of this
/// court at commit `6c46229`); `after` is the current arm's own measurement in
/// `arms`. Allocation counts are deterministic (a counting `#[global_allocator]`
/// over a fixed workload), so this delta is not a run-to-run artefact.
fn reduction_evidence(arms: &[Arm]) -> serde_json::Value {
    let find = |label: &str| arms.iter().find(|a| a.label == label);
    let engine = find("engine (no mount)");
    let f0 = find("F0");
    let attr = engine.and_then(|a| a.alloc_attrib);
    let per = |a: &Arm| a.allocs as f64 / a.total_ops.max(1) as f64;
    serde_json::json!({
        "applied": [
            {
                "id": "commit-projection-arithmetic",
                "files": ["src/commit.rs"],
                "what": "`CommitSequencer::projected_transaction_bytes` rebuilt and re-encoded the whole transaction (a clone + an encode per record, two payload to_vecs) only to sum framed lengths. It is now arithmetic: `tx.bracket_byte_length() + HEADER_LEN + FOOTER_LEN + TX_COMMIT_PAYLOAD_LEN`, which `TransactionBuilder::build` had already computed exactly.",
            },
            {
                "id": "single-record-encode",
                "files": ["src/commit.rs"],
                "what": "`publish_one` encoded each TX_BEGIN/data record once for the bracket and again inside `write_record`. It now encodes once and writes the same bytes (`write_record_bytes`), and pre-sizes the bracket from the already-known bracket length (no growth reallocs).",
            },
            {
                "id": "lazy-commit-bookkeeping",
                "files": ["src/namespace.rs"],
                "what": "`commit_plan` collected the touched-inode `Vec` and deep-cloned the changed-range `HashMap` on every commit even though only the (default-off) manifestation/trigram engines consume them. Both are now built only when such an engine is present (empty `Vec`/`HashMap` allocate nothing).",
            },
            {
                "id": "extent-encode-slice",
                "files": ["src/extent.rs", "src/namespace.rs"],
                "what": "`write_at_inner` built `DataExtentPayload { data: data.to_vec() }` and then encoded it, copying the payload twice; it now calls `DataExtentPayload::encode_slice(offset, data)`, which copies once. The in-run paired measurement below is this change.",
            },
        ],
        "in_run_paired": encoder_pair(),
        "end_to_end": {
            "method": "the identical court workload (2 000 iters; create/stat/rename/unlink/read/write) measured before and after the change; allocs/op is deterministic",
            "before": {
                "source": "tests/hotpath_counters.rs at commit 6c46229 (evidence/performance/hotpath-counters.json, allocs_per_op 101.8874) and the pre-change run of this court",
                "f0_allocs_per_op": 101.728,
                "f2_single_allocs_per_op": 115.615,
                "f2_pool_allocs_per_op": 116.483,
                "engine_allocs_per_op": 86.880,
                "engine_create_allocs_per_op": 206.061,
                "engine_rename_allocs_per_op": 101.291,
                "engine_unlink_allocs_per_op": 110.635,
                "engine_write_allocs_per_op": 98.144,
            },
            "after": {
                "source": "this run",
                "f0_allocs_per_op": f0.map(per),
                "engine_allocs_per_op": engine.map(per),
                "engine_create_allocs_per_op": attr.map(|a| a.create as f64 / engine.map(|e| e.iters).unwrap_or(1) as f64),
                "engine_rename_allocs_per_op": attr.map(|a| a.rename as f64 / engine.map(|e| e.iters).unwrap_or(1) as f64),
                "engine_unlink_allocs_per_op": attr.map(|a| a.unlink as f64 / engine.map(|e| e.iters).unwrap_or(1) as f64),
                "engine_write_allocs_per_op": attr.map(|a| a.write as f64 / engine.map(|e| e.iters).unwrap_or(1) as f64),
            },
        },
        "rejected": [
            {
                "id": "conditional-write-getattr",
                "what": "dropping the per-write `core.getattr(ino, root)` (Phase-83 §4 candidate): still rejected — the adapter needs `st.size` (O_APPEND) and `st.uid`/`st.mode` (non-owner killpriv) in the common case, so the condition cannot be expressed without the lookup.",
                "measured": "no material request/instruction reduction: the mounted daemon keeps one in-memory `Index::inode` lookup per write, below the resolution of the counter ratios here.",
            }
        ],
    })
}

fn describe_transport(used: &str) -> String {
    match used {
        "F0" => "classical /dev/fuse, synchronous backing I/O".to_string(),
        "F1" => "classical /dev/fuse, io_uring backing I/O".to_string(),
        "F2" => "native FUSE-over-io_uring".to_string(),
        "direct" => "plain directory, no FUSE".to_string(),
        "engine" => "in-process engine, no mount".to_string(),
        other => other.to_string(),
    }
}

fn write_json(doc: &serde_json::Value) {
    let path = manifest_dir().join("evidence/performance/transport-ceiling.json");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(doc).expect("serialize");
    s.push('\n');
    fs::write(&path, s).expect("write evidence");
}

#[test]
fn transport_ceiling_smoke() {
    run_court(Scale::smoke(), false);
}

#[test]
fn transport_ceiling_receipt() {
    if !receipt_requested() {
        eprintln!("transport_ceiling_receipt: skipped (ORFS_TRANSPORT_CEILING unset)");
        return;
    }
    run_court(Scale::receipt(), true);
}
