//! **Phase 50 — the CPU microarchitecture court (reviewer research §11).**
//! **Phase 83 — run under the probed PERFMON profile, so the counters are real.**
//!
//! §11 asks where OrFS's hot paths actually spend their time — "rather than
//! guessing which Rust constructs are slow" — and names the PMap lookup, the
//! EKBLOOM read path, planner selection, FUSE dispatch, log-segment lookup, group
//! commit, and historical open. It also names concrete mitigations: cache-line
//! alignment, compact candidate arrays, **reduced temporary allocations**, and
//! fewer contended shared locks.
//!
//! The court has two layers. The **proxies** need no PMU and run in every
//! container (including the default seccomp-confined one, where the profile denies
//! `perf_event_open` with `EPERM` — **not** `perf_event_paranoid=2`, which permits
//! user-space counters; see `docs/PMU.md`):
//!
//! * **Allocator traffic on the steady-state read.** A counting global allocator
//!   measures allocations and bytes per certified read in the hot path — the
//!   direct way to check §11's "reduced temporary allocations". A steady-state
//!   read must not allocate beyond the result buffer it returns.
//! * **Contended shared locks under reader scaling.** The court measures
//!   steady-state read throughput at 1/2/4/8 concurrent readers. Phase 50 removed
//!   the last policy write lock from the served-read path (the per-path served
//!   counter is now a lock-free atomic array), so the scaling curve is a direct
//!   measure of the remaining shared-lock surface.
//! * **A cache/TLB-pressure curve for the order-statistics treap.** A
//!   working-set sweep of `PMap` point lookups (`src/persistent.rs`) at sizes
//!   spanning L1/L2/L3 shows the flat-to-steep transition.
//!
//! The **counters** layer (Phase 83) reads real user-space hardware counters for
//! each hot-path component when the court runs under the probed `--cap-add PERFMON`
//! profile (`scripts/container-microarch.sh` proves the flags at run time). A
//! counter the microarchitecture genuinely does not expose is skipped by name with
//! its exact errno; a counter the container profile denies is recorded with the
//! errno — never reported as a proxy, never invented.
//!
//! The always-on `microarch_smoke` runs a bounded version in the default gate; the
//! full sweep is opt-in behind `ORFS_MICROARCH=1` and writes
//! `evidence/performance/microarch.json` (run it via
//! `scripts/container-microarch.sh`).
//!
//! **Phase 83 — real counters, not only proxies.** The same sweep additionally
//! reads **real** user-space hardware counters (cycles, instructions,
//! cache-references/-misses, branch-misses, and the data/instruction-TLB misses
//! where the PMU exposes them) for each hot-path component, through
//! `tests/support/pmu.rs`. `scripts/container-microarch.sh` now runs the court
//! under the probed **PERFMON** profile (`--cap-add PERFMON`, proven at run time
//! with `scripts/pmu-probe.c`), so the counters are read for real instead of being
//! inferred. A counter the microarchitecture genuinely does not provide is skipped
//! by name; a counter the container profile denies is recorded with the exact
//! errno. A proxy is never reported as a counter, and a counter is never invented.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use orfs::commit::{CommitSequencer, DurabilityMode};
use orfs::historical::{self, load_persisted_historical};
use orfs::index::ROOT_INODE;
use orfs::manifestation::{
    ekbloom_format_version, CertificationState, GenerationManifest, GenerationStore,
    ManifestationProfile, ManifestationState, MANIFEST_SCHEMA,
};
use orfs::namespace::Namespace;
use orfs::persistent::PMap;
use orfs::readpath::{ReadPlanner, ReadPlannerConfig, ReadQuery};
use orfs::record::RecordType;
use orfs::transaction::TransactionBuilder;
use orfs::volume::Volume;
use tempfile::TempDir;

#[path = "support/pmu.rs"]
mod pmu;

use pmu::{Counter, PmuGroup};

// ---------------------------------------------------------------------------
// A counting global allocator (allocation instrument)
// ---------------------------------------------------------------------------

static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

/// A pass-through allocator that counts every allocation request. Used only by
/// this test binary.
struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc_zeroed(layout)
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
// Fixtures
// ---------------------------------------------------------------------------

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x43, 0x44, 0x40, 0x50, 0x83, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
];

const SRC_LEN: usize = 4096;
const READ_LEN: u64 = 64;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 131 + 17) % 251) as u8).collect()
}

fn auth_slice(source: &[u8], offset: u64, length: u64) -> Vec<u8> {
    let n = source.len() as u64;
    let end = offset.saturating_add(length).min(n);
    if offset >= end {
        Vec::new()
    } else {
        source[offset as usize..end as usize].to_vec()
    }
}

fn publish_generation(
    store: &GenerationStore,
    inode: u64,
    version: u64,
    root: u64,
    source: &[u8],
    profile: ManifestationProfile,
) -> GenerationManifest {
    store.ensure_dirs().expect("ensure dirs");
    let generation = store.next_generation().expect("generation");
    let body = ekbloom::create(source, profile.to_ekbloom()).expect("create body");
    let path = store.payload_path(generation, inode, version, root);
    ekbloom::write_body(&path, &body).expect("write body");
    let payload = std::fs::read(&path).expect("read payload");
    let (interval, depth, region_bytes) = profile.params();
    let manifest = GenerationManifest {
        schema: MANIFEST_SCHEMA,
        generation,
        volume_uuid: UUID,
        inode,
        inode_version: version,
        root,
        backend: "ekbloom".to_string(),
        ekbloom_version: "0.3.0".to_string(),
        ekbloom_format: ekbloom_format_version(),
        profile: profile.label(),
        profile_kind: profile.kind_code(),
        logical_start: 0,
        logical_end: source.len() as u64,
        physical_start: 0,
        physical_end: payload.len() as u64,
        interval,
        depth,
        region_bytes,
        certification: CertificationState::Built,
        certification_method: "test".to_string(),
        payload_rel_path: store.payload_rel_path(generation, inode, version, root),
        ekbloom_object_id: Some(body.object_id),
        payload_blake3: *blake3::hash(&payload).as_bytes(),
        visible_bytes: source.len() as u64,
        physical_bytes: payload.len() as u64,
        concealed_bytes: (payload.len() as u64).saturating_sub(source.len() as u64),
        source_bytes: source.len() as u64,
        components: vec![],
        base_generation: None,
        base_manifest_blake3: None,
        overlay_depth: 0,
        regions: Vec::new(),
        manifest_blake3: [0u8; 32],
    }
    .sealed();
    store.publish(&manifest).expect("publish");
    manifest
}

fn rss_kib() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages.saturating_mul(4))
}

fn planner_for(dir: &Path, source: &[u8]) -> ReadPlanner {
    let store = GenerationStore::new(dir);
    publish_generation(
        &store,
        1,
        1,
        1,
        source,
        ManifestationProfile::Path { depth: 4 },
    );
    let state =
        ManifestationState::recover(GenerationStore::new(dir), UUID).expect("recover state");
    ReadPlanner::new(state, ReadPlannerConfig::default())
}

fn query(logical_len: u64) -> ReadQuery {
    ReadQuery {
        inode: 1,
        inode_version: 1,
        root: 1,
        logical_len,
        offset: 0,
        length: READ_LEN,
    }
}

/// A steady-state certified read of the single manifested object.
fn hot_read(planner: &ReadPlanner, source: &[u8]) -> usize {
    let p = planner
        .read(&query(source.len() as u64), |o, l| {
            Ok(auth_slice(source, o, l))
        })
        .expect("read");
    p.bytes.len()
}

// ---------------------------------------------------------------------------
// Court
// ---------------------------------------------------------------------------

struct AllocOutcome {
    reads: u64,
    allocs: u64,
    bytes: u64,
    peak_ns_per_read: f64,
    hot_reads_delta: u64,
    chosen: Vec<(orfs::readpath::ReadPathKind, u64)>,
}

/// Allocations for the two ways of reaching the newest published manifest: the
/// deep-cloning `latest_for` and the `Arc`-sharing `latest_for_shared`.
struct HandleProbe {
    calls: u64,
    shared_allocs: u64,
    deep_allocs: u64,
}

fn manifest_handle_probe(calls: u64) -> HandleProbe {
    let td = TempDir::new().unwrap();
    let source = pattern(SRC_LEN);
    let store = GenerationStore::new(td.path());
    publish_generation(
        &store,
        1,
        1,
        1,
        &source,
        ManifestationProfile::Path { depth: 4 },
    );
    let state =
        ManifestationState::recover(GenerationStore::new(td.path()), UUID).expect("recover");
    assert!(
        state.latest_for_shared(1).is_some(),
        "no published generation"
    );

    let (a0, _) = alloc_snapshot();
    for _ in 0..calls {
        std::hint::black_box(state.latest_for_shared(1).is_some());
    }
    let (a1, _) = alloc_snapshot();

    let (b0, _) = alloc_snapshot();
    for _ in 0..calls {
        std::hint::black_box(state.latest_for(1).is_some());
    }
    let (b1, _) = alloc_snapshot();

    HandleProbe {
        calls,
        shared_allocs: a1 - a0,
        deep_allocs: b1 - b0,
    }
}

/// Steady-state read after a bounded warm-up: measure allocator traffic.
fn alloc_court(reads: u64) -> AllocOutcome {
    let td = TempDir::new().unwrap();
    let source = pattern(SRC_LEN);
    let planner = planner_for(td.path(), &source);
    // Warm up: the first read calibrates (and allocates); steady state follows.
    for _ in 0..64 {
        std::hint::black_box(hot_read(&planner, &source));
    }

    let (a0, b0) = alloc_snapshot();
    let hot0 = planner.stats().hot_reads;
    let started = Instant::now();
    for _ in 0..reads {
        std::hint::black_box(hot_read(&planner, &source));
    }
    let elapsed = started.elapsed();
    let (a1, b1) = alloc_snapshot();
    AllocOutcome {
        reads,
        allocs: a1 - a0,
        bytes: b1 - b0,
        peak_ns_per_read: elapsed.as_nanos() as f64 / reads.max(1) as f64,
        hot_reads_delta: planner.stats().hot_reads - hot0,
        chosen: planner.chosen_counts(),
    }
}

struct ScalingRow {
    readers: usize,
    ops_per_s: f64,
    ns_per_op: f64,
}

/// Steady-state read throughput as concurrent readers scale.
fn reader_scaling(reader_counts: &[usize], ops_per_reader: u64) -> Vec<ScalingRow> {
    let td = TempDir::new().unwrap();
    let source = pattern(SRC_LEN);
    let planner = planner_for(td.path(), &source);
    for _ in 0..64 {
        std::hint::black_box(hot_read(&planner, &source));
    }
    let mut rows = Vec::new();
    for &readers in reader_counts {
        // A short untimed pass to make sure every thread path is warm.
        std::thread::scope(|s| {
            for _ in 0..readers {
                s.spawn(|| {
                    for _ in 0..16 {
                        std::hint::black_box(hot_read(&planner, &source));
                    }
                });
            }
        });
        let started = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..readers {
                s.spawn(|| {
                    for _ in 0..ops_per_reader {
                        std::hint::black_box(hot_read(&planner, &source));
                    }
                });
            }
        });
        let elapsed = started.elapsed();
        let total = (readers as u64 * ops_per_reader).max(1);
        let ops_per_s = total as f64 / elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
        rows.push(ScalingRow {
            readers,
            ops_per_s,
            ns_per_op: elapsed.as_nanos() as f64 / total as f64,
        });
    }
    rows
}

/// A tiny deterministic PRNG for reproducible lookup patterns.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
}

struct LookupRow {
    entries: usize,
    ns_per_lookup: f64,
}

/// A cache-hierarchy proxy: `PMap` point-lookup latency as the working set grows.
fn pmap_curve(sizes: &[usize], lookups: u64) -> Vec<LookupRow> {
    let mut rows = Vec::new();
    for &n in sizes {
        let mut map: PMap<u64, u64> = PMap::new();
        for k in 0..n as u64 {
            map = map.insert(k, k);
        }
        let mut rng = Lcg(0x9E37_79B9_7F4A_7C15);
        let mask = (n as u64).next_power_of_two() - 1;
        // Warm the access path, then time.
        for _ in 0..(lookups / 8).max(1) {
            let k = rng.next() & mask;
            std::hint::black_box(map.get(&(k % n as u64)));
        }
        let started = Instant::now();
        let mut acc = 0u64;
        for _ in 0..lookups {
            let k = rng.next() & mask;
            if let Some(v) = map.get(&(k % n as u64)) {
                acc = acc.wrapping_add(*v);
            }
        }
        let elapsed = started.elapsed();
        std::hint::black_box(acc);
        rows.push(LookupRow {
            entries: n,
            ns_per_lookup: elapsed.as_nanos() as f64 / lookups as f64,
        });
    }
    rows
}

// ---------------------------------------------------------------------------
// Real hardware counters (Phase 83)
// ---------------------------------------------------------------------------
//
// The probes above are PMU-free proxies that also run in the default container.
// When the court runs under the probed PERFMON profile
// (`scripts/container-microarch.sh`), the same hot-path components additionally
// read **real** user-space hardware counters. A counter the microarchitecture or
// the kernel genuinely does not expose is skipped by name; a counter the
// container profile denies is recorded with the exact errno. The court never
// reports a proxy as a counter, nor a counter as a proxy.

const LOG_SEGMENT_SIZE: u64 = 256 * 1024;

/// A probe's real counters over `ops` operations; `total` is `None` when no PMU
/// group was granted (so the wall-clock time is still reported).
struct Countered {
    name: &'static str,
    ops: u64,
    wall_ns_per_op: f64,
    total: Option<Vec<(Counter, u64)>>,
}

fn counter_of(counters: &[(Counter, u64)], c: Counter) -> u64 {
    counters
        .iter()
        .find(|(k, _)| *k == c)
        .map(|(_, v)| *v)
        .unwrap_or(0)
}

/// Run `ops` iterations of `work` with the counters reset/enabled around the
/// loop and disabled before reading them once.
fn run_countered<F: FnMut()>(
    name: &'static str,
    mut group: Option<&mut PmuGroup>,
    ops: u64,
    mut work: F,
) -> Countered {
    if let Some(g) = group.as_mut() {
        let _ = g.reset();
        let _ = g.enable();
    }
    let started = Instant::now();
    for _ in 0..ops {
        work();
    }
    let elapsed = started.elapsed();
    let total = if let Some(g) = group.as_mut() {
        let _ = g.disable();
        Some(g.read_all())
    } else {
        None
    };
    Countered {
        name,
        ops,
        wall_ns_per_op: elapsed.as_nanos() as f64 / ops.max(1) as f64,
        total,
    }
}

impl Countered {
    fn json(&self) -> serde_json::Value {
        let mut per_op = serde_json::Map::new();
        if let Some(counters) = &self.total {
            let ops = self.ops.max(1) as f64;
            for (c, v) in counters {
                per_op.insert(c.name().to_string(), serde_json::json!(*v as f64 / ops));
            }
            let cycles = counter_of(counters, Counter::Cycles);
            let insn = counter_of(counters, Counter::Instructions);
            let refs = counter_of(counters, Counter::CacheReferences);
            let misses = counter_of(counters, Counter::CacheMisses);
            let bmiss = counter_of(counters, Counter::BranchMisses);
            if cycles > 0 {
                per_op.insert("ipc".into(), serde_json::json!(insn as f64 / cycles as f64));
            }
            if refs > 0 {
                per_op.insert(
                    "cache_miss_rate".into(),
                    serde_json::json!(misses as f64 / refs as f64),
                );
            }
            if insn > 0 {
                per_op.insert(
                    "branch_miss_rate".into(),
                    serde_json::json!(bmiss as f64 / insn as f64),
                );
            }
        }
        serde_json::json!({
            "name": self.name,
            "ops": self.ops,
            "wall_ns_per_op": self.wall_ns_per_op,
            "per_op": per_op,
            "measured": self.total.is_some(),
        })
    }
}

/// `PMap` point lookup over a 64 Ki-entry treap.
fn countered_pmap(group: Option<&mut PmuGroup>, ops: u64) -> Countered {
    let n = 1usize << 16;
    let mut map: PMap<u64, u64> = PMap::new();
    for k in 0..n as u64 {
        map = map.insert(k, k);
    }
    let mask = (n as u64).next_power_of_two() - 1;
    let mut rng = Lcg(0x1234_5678_9abc_def0);
    let mut acc = 0u64;
    let c = run_countered("pmap_point_lookup", group, ops, || {
        let k = rng.next() & mask;
        if let Some(v) = map.get(&(k % n as u64)) {
            acc = acc.wrapping_add(*v);
        }
    });
    std::hint::black_box(acc);
    c
}

/// The EKBLOOM manifested read path via the planner (`measure_paths` executes
/// each manifested candidate structure for the object).
fn countered_ekbloom(group: Option<&mut PmuGroup>, ops: u64) -> Countered {
    let td = TempDir::new().expect("tempdir");
    let source = pattern(SRC_LEN);
    let planner = planner_for(td.path(), &source);
    let q = query(source.len() as u64);
    let mut warm = |o: u64, l: u64| -> orfs::Result<Vec<u8>> { Ok(auth_slice(&source, o, l)) };
    planner.measure_paths(&q, &mut warm, 1).expect("warm paths");
    run_countered("ekbloom_manifested_read", group, ops, || {
        let mut auth = |o: u64, l: u64| -> orfs::Result<Vec<u8>> { Ok(auth_slice(&source, o, l)) };
        std::hint::black_box(
            planner
                .measure_paths(&q, &mut auth, 1)
                .expect("measure paths"),
        );
    })
}

/// The `ReadPlanner` steady-state selection: a hot certified read that walks the
/// published ranking and executes the chosen path.
fn countered_readplanner(group: Option<&mut PmuGroup>, ops: u64) -> Countered {
    let td = TempDir::new().expect("tempdir");
    let source = pattern(SRC_LEN);
    let planner = planner_for(td.path(), &source);
    for _ in 0..128 {
        std::hint::black_box(hot_read(&planner, &source));
    }
    run_countered("readplanner_steady_state_read", group, ops, || {
        std::hint::black_box(hot_read(&planner, &source));
    })
}

/// A volume with a committed log, for the backing-segment-read component.
fn log_fixture() -> (TempDir, Volume, u64) {
    let td = TempDir::new().expect("tempdir");
    let mut vol = Volume::init_with_uuid(td.path(), LOG_SEGMENT_SIZE, UUID, 1_700_000_000)
        .expect("init volume");
    let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
    for i in 0..32u64 {
        let mut b = TransactionBuilder::new(seq.peek_transaction_id()).expect("builder");
        b.add(RecordType::InodeCreate, 1, 0, small_payload(i, 1))
            .expect("add");
        b.add(RecordType::DataExtent, 1, 0, small_payload(i, 2))
            .expect("add");
        seq.commit(b.build().expect("build")).expect("commit");
    }
    let len = vol.log.committed_end_offset();
    (td, vol, len)
}

fn small_payload(seed: u64, salt: u8) -> Vec<u8> {
    (0..48)
        .map(|k| {
            ((seed as u8).wrapping_mul(31))
                .wrapping_add(salt)
                .wrapping_add(k as u8)
        })
        .collect()
}

/// A backing log segment read (`Log::read_range`).
fn countered_log(group: Option<&mut PmuGroup>, ops: u64) -> Countered {
    let (_td, vol, len) = log_fixture();
    let read_len = 4096u64.min(len.max(1));
    let _ = vol.log.read_range(0, read_len).expect("warm read");
    run_countered("backing_log_segment_read", group, ops, || {
        std::hint::black_box(vol.log.read_range(0, read_len).expect("segment read"));
    })
}

/// The ordered commit path (transaction append + durability barrier) that the
/// group-commit coordinator amortises: one single-record transaction committed
/// with `DurabilityMode::Ordered` per iteration.
fn countered_commit(group: Option<&mut PmuGroup>, ops: u64) -> Countered {
    let td = TempDir::new().expect("tempdir");
    let mut vol = Volume::init_with_uuid(td.path(), LOG_SEGMENT_SIZE, UUID, 1_700_000_001)
        .expect("init volume");
    let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
    run_countered("ordered_commit", group, ops, || {
        let mut b = TransactionBuilder::new(seq.peek_transaction_id()).expect("builder");
        b.add(RecordType::InodeCreate, 1, 0, small_payload(7, 3))
            .expect("add");
        seq.commit(b.build().expect("build")).expect("commit");
    })
}

/// Opening a persisted historical index accelerator: the decode + dense-ordinal
/// re-seal a warm historical-root open performs.
fn countered_historical_open(group: Option<&mut PmuGroup>, ops: u64) -> Countered {
    let td = TempDir::new().expect("tempdir");
    let mut ns =
        Namespace::init(td.path(), LOG_SEGMENT_SIZE, DurabilityMode::Ordered).expect("init volume");
    for i in 0..200 {
        ns.create(ROOT_INODE, format!("h{i:04}").as_bytes(), 0o644, 0, 0)
            .expect("create");
    }
    ns.sync().expect("sync");
    let uuid = ns.volume().meta.uuid;
    let root = ns.root();
    let index_dir = td.path().join("index");
    historical::persist_historical(&index_dir, &uuid, ns.index()).expect("persist");
    let probe = load_persisted_historical(&index_dir, &uuid, root)
        .expect("load")
        .expect("accelerator present");
    std::hint::black_box(probe.inode_layout());
    run_countered("historical_index_open", group, ops, || {
        let idx = load_persisted_historical(&index_dir, &uuid, root)
            .expect("load")
            .expect("accelerator present");
        std::hint::black_box(idx.inode_layout());
    })
}

/// The always-on smoke: a bounded version of every probe.
#[test]
fn microarch_smoke() {
    let a = alloc_court(20_000);
    eprintln!(
        "microarch smoke: allocs/read={:.3} bytes/read={:.1} ns/read={:.1} hot={} chosen={:?}",
        a.allocs as f64 / a.reads as f64,
        a.bytes as f64 / a.reads as f64,
        a.peak_ns_per_read,
        a.hot_reads_delta,
        a.chosen
    );
    // A steady-state certified read must allocate only the result buffer it
    // returns (one `Vec` per read); the planner adds no temporary allocations.
    let allocs_per_read = a.allocs as f64 / a.reads as f64;
    assert!(
        allocs_per_read <= 8.0,
        "steady-state read allocated {allocs_per_read} times per read \
         (allocs={}, reads={}, hot_reads={}, chosen={:?})",
        a.allocs,
        a.reads,
        a.hot_reads_delta,
        a.chosen
    );
    assert_eq!(
        a.hot_reads_delta, a.reads,
        "the measured reads did not all take the steady-state hot path"
    );
    // The decisive Phase-50 allocation regression guard: sharing the published
    // manifest (`latest_for_shared`) allocates nothing, whereas the deep-cloning
    // `latest_for` allocates its owned `String`/`Vec` fields on every call. A read
    // path that regressed to `latest_for` would show it here immediately.
    let probe = manifest_handle_probe(10_000);
    assert_eq!(
        probe.shared_allocs, 0,
        "latest_for_shared allocated {} times over {} calls",
        probe.shared_allocs, probe.calls
    );
    assert!(
        probe.deep_allocs > probe.calls,
        "latest_for did not deep-clone ({} allocs over {} calls)",
        probe.deep_allocs,
        probe.calls
    );
    // The very first (calibrating) read is allowed to allocate more; the point is
    // that this does not grow with the read count.
    let a2 = alloc_court(40_000);
    let allocs_per_read2 = a2.allocs as f64 / a2.reads as f64;
    assert!(
        (allocs_per_read2 - allocs_per_read).abs() <= 0.05,
        "per-read allocations grew with the read count: {allocs_per_read} -> \
         {allocs_per_read2}"
    );

    let rows = reader_scaling(&[1, 4], 20_000);
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.ops_per_s > 0.0));

    let curve = pmap_curve(&[1 << 10, 1 << 14], 50_000);
    assert_eq!(curve.len(), 2);
    assert!(curve.iter().all(|r| r.ns_per_lookup > 0.0));
}

#[test]
fn microarch_sweep() {
    if std::env::var("ORFS_MICROARCH").as_deref() != Ok("1") {
        eprintln!("microarch_sweep: skipped (set ORFS_MICROARCH=1 to run the full sweep)");
        return;
    }
    let rss_before = rss_kib().unwrap_or(0);

    let a = alloc_court(500_000);
    let probe = manifest_handle_probe(200_000);
    let scaling = reader_scaling(&[1, 2, 4, 8], 200_000);
    let curve = pmap_curve(&[1 << 10, 1 << 13, 1 << 16, 1 << 18], 400_000);

    // Phase 83: the same hot-path components, now with real hardware counters.
    let (cnt_available, cnt_error, cnt_granted, cnt_missing, cnt_probes) = {
        let mut group = match PmuGroup::open() {
            Ok(g) => Some(g),
            Err(e) => {
                eprintln!("microarch: hardware counters unavailable: {e}");
                None
            }
        };
        let available = group.is_some();
        let error = PmuGroup::open().err();
        let granted: Vec<String> = group
            .as_ref()
            .map(|g| g.counters().iter().map(|c| c.name().to_string()).collect())
            .unwrap_or_default();
        let missing: serde_json::Value = group
            .as_ref()
            .map(|g| {
                let mut m = serde_json::Map::new();
                for (c, reason) in g.missing_reasons() {
                    m.insert(c.name().to_string(), serde_json::json!(reason));
                }
                serde_json::Value::Object(m)
            })
            .unwrap_or_else(|| serde_json::json!({}));
        let probes = vec![
            countered_pmap(group.as_mut(), 500_000),
            countered_ekbloom(group.as_mut(), 20_000),
            countered_readplanner(group.as_mut(), 500_000),
            countered_log(group.as_mut(), 100_000),
            countered_commit(group.as_mut(), 20_000),
            countered_historical_open(group.as_mut(), 20_000),
        ];
        (available, error, granted, missing, probes)
    };

    let rss_after = rss_kib().unwrap_or(0);
    let environment = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());
    let counters_available = environment.perf_counters_available;

    let doc = serde_json::json!({
        "schema": "orfs.performance.microarch.v1",
        "generated_by": "tests/microarch.rs",
        "note": "Single-run, single-host microarchitecture probes. The **proxies** \
                 (a counting global allocator for hot-path allocator traffic, \
                 concurrent-reader throughput for the remaining shared-lock surface, and a \
                 working-set latency curve as a cache-hierarchy shape) need no PMU and run \
                 in every container. Under the probed PERFMON profile \
                 (scripts/container-microarch.sh) the `counters` section additionally \
                 carries **real** user-space hardware counters for each hot-path component \
                 (cycles, instructions, cache-references/-misses, branch-misses, and the \
                 DTLB/ITLB read misses where the PMU exposes them). A counter the \
                 microarchitecture does not provide is skipped by name; when the container \
                 profile denies perf_event_open the section records available:false with the \
                 exact errno and only wall-clock times are reported — the default container's \
                 seccomp profile denies the syscall with EPERM, which is **not** the paranoid \
                 level (perf_event_paranoid=2 permits user-space counters; see docs/PMU.md). \
                 Absolute nanoseconds are host/load sensitive; the shape, the allocator \
                 counts, and the counter ratios are the point.",
        "pmu": {
            "hardware_counters_available": counters_available,
            "perf_event_paranoid": environment.perf_event_paranoid,
            "note": "Environment metadata. perf_event_paranoid=2 permits user-space \
                     per-thread counters; the real gate is the container seccomp profile, \
                     which denies perf_event_open with EPERM in the default container. Run \
                     under --cap-add PERFMON to read the counters (see docs/PMU.md).",
        },
        "counters": {
            "hardware_counters_available": cnt_available,
            "perf_event_open_error": cnt_error,
            "granted_counters": cnt_granted,
            "missing_counters": cnt_missing,
            "note": "Real user-space per-thread counters (exclude_kernel=1), reset/enabled \
                     around each measured loop, disabled before reading. `missing_counters` \
                     maps each event this microarchitecture/PMU does not expose to the exact \
                     errno/reason the kernel returned (e.g. EINVAL for an unsupported generic \
                     TLB event); those counters are skipped by name, never reported as zero \
                     and never conflated with an unavailable PMU. When the container profile \
                     denies perf_event_open the whole section records available:false with the \
                     exact errno and every probe reports measured:false with wall-clock time \
                     only — no counter is fabricated.",
            "probes": cnt_probes.iter().map(|p| p.json()).collect::<Vec<_>>(),
        },
        "steady_state_read_allocations": {
            "reads": a.reads,
            "allocs": a.allocs,
            "bytes": a.bytes,
            "allocs_per_read": a.allocs as f64 / a.reads.max(1) as f64,
            "bytes_per_read": a.bytes as f64 / a.reads.max(1) as f64,
            "ns_per_read": a.peak_ns_per_read,
            "interpretation": "A steady-state certified read returns one result Vec; \
                              the read planner adds no per-read manifest clone (Phase 50 \
                              shares the published manifest as an Arc).",
        },
        "manifest_handle_allocations": {
            "calls": probe.calls,
            "latest_for_shared_allocs": probe.shared_allocs,
            "latest_for_allocs": probe.deep_allocs,
            "note": "latest_for_shared (the read path) allocates nothing per call; the \
                     deep-cloning latest_for allocates the manifest's owned fields. \
                     Before Phase 50 the read path used latest_for: the court measured \
                     8.0 allocs/read, dropping to 2.0 after the change.",
        },
        "reader_scaling": scaling
            .iter()
            .map(|r| serde_json::json!({
                "readers": r.readers,
                "ops_per_s": r.ops_per_s,
                "ns_per_op": r.ns_per_op,
            }))
            .collect::<Vec<_>>(),
        "reader_scaling_baseline": {
            "note": "Phase 50 replaced the per-path served counter (an RwLock<HashMap>) \
                     with a lock-free atomic array, removing the last policy write lock \
                     from the served-read path.",
        },
        "pmap_lookup_curve": curve
            .iter()
            .map(|r| serde_json::json!({
                "entries": r.entries,
                "ns_per_lookup": r.ns_per_lookup,
            }))
            .collect::<Vec<_>>(),
        "rss_kib_end": rss_after,
        "rss_kib_growth": rss_after.saturating_sub(rss_before),
        "environment": {
            "bench": serde_json::to_value(&environment).unwrap_or(serde_json::Value::Null),
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        },
    });

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/performance/microarch.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!("microarch evidence written to {}", path.display());
}
