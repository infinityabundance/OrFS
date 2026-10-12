//! Benchmark harness for the certified read path (reviewer task, Priority 2).
//!
//! Two things live here:
//!
//! 1. The Phase-0 EKBLOOM machine round-trip (kept unchanged).
//! 2. A **paired** read-planner benchmark over a heterogeneous workload (hot and
//!    cold objects, different fragmentation, varying request sizes), measured
//!    single-threaded and with 16 concurrent readers. It reports per-request
//!    p50/p99 latency and allocations per request, and appends its run to
//!    `evidence/performance/read-planner.json` under the label named by
//!    `ORFS_READ_PLANNER_LABEL` (default `after`). Running the same bench once on
//!    the pre-Phase-43 tree (label `before`) and once on the Phase-43 tree (label
//!    `after`) produces the paired comparison in one machine-generated file.
//!
//! It uses only the planner's public API, so the identical bench compiles and runs
//! against both trees. Absolute nanoseconds are single-run, single-host and
//! load-sensitive; the *comparison* between labels, measured back to back, is the
//! point.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ekbloom::{OrMachine, NL2};

use orfs::manifestation::{
    ekbloom_format_version, CertificationState, GenerationManifest, GenerationStore,
    ManifestationProfile, ManifestationState, MANIFEST_SCHEMA,
};
use orfs::readpath::{ReadPlanner, ReadPlannerConfig, ReadQuery};

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x43, 0x22, 0x40, 0x33, 0x81, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
];

// ---------------------------------------------------------------------------
// A process-wide allocation counter (single- and multi-threaded workloads).
// ---------------------------------------------------------------------------

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

// SAFETY: a thin wrapper over `System` that increments a non-allocating atomic
// before delegating. All pointer/layout arguments are forwarded unchanged.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

// ---------------------------------------------------------------------------
// EKBLOOM machine round-trip (unchanged)
// ---------------------------------------------------------------------------

fn bench_roundtrip(len: usize, iters: u32) {
    let src: Vec<u8> = (0..len).map(|i| (i * 131 + 7) as u8).collect();
    let start = Instant::now();
    let mut acc = 0u64;
    for _ in 0..iters {
        let core = NL2.encode(&src).expect("encode");
        let out = NL2.decode(&core, src.len() as u64).expect("decode");
        acc = acc.wrapping_add(out.len() as u64);
    }
    let elapsed = start.elapsed();
    let bytes = (len as u64) * (iters as u64) * 2; // encode + decode
    let secs = elapsed.as_secs_f64();
    let mbps = (bytes as f64) / secs / 1e6;
    println!(
        "ekbloom roundtrip len={len:>8} iters={iters:>6} acc={acc} {:.1} MB/s ({secs:.3}s)",
        mbps
    );
}

// ---------------------------------------------------------------------------
// The read-planner workload
// ---------------------------------------------------------------------------

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 131 + 17) % 251) as u8).collect()
}

fn slice(source: &[u8], offset: u64, length: u64) -> Vec<u8> {
    let n = source.len() as u64;
    let end = offset.saturating_add(length).min(n);
    if offset >= end {
        Vec::new()
    } else {
        source[offset as usize..end as usize].to_vec()
    }
}

fn publish(
    store: &GenerationStore,
    inode: u64,
    version: u64,
    root: u64,
    source: &[u8],
    profile: ManifestationProfile,
) {
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
        certification_method: "bench".to_string(),
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
}

/// One heterogeneous request: a distinct object, a fragmented offset and a
/// varied length.
#[derive(Clone, Copy)]
struct Req {
    inode: u64,
    root: u64,
    logical_len: u64,
    offset: u64,
    length: u64,
}

/// A deterministic PRNG so runs are byte-comparable.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

struct Fixture {
    objects: HashMap<u64, Vec<u8>>,
    requests: Vec<Req>,
}

fn build_fixture(dir: &Path) -> Fixture {
    let store = GenerationStore::new(dir);
    // Hot objects: two small files; cold objects: three larger files. Profiles
    // differ (path / max-speed / sparse / full), so different manifested paths are
    // exercised.
    let specs: [(u64, usize, ManifestationProfile); 5] = [
        (1, 4096, ManifestationProfile::Path { depth: 4 }),
        (2, 8192, ManifestationProfile::MaxSpeed),
        (3, 65536, ManifestationProfile::Sparse { interval: 64 }),
        (4, 262_144, ManifestationProfile::Full),
        (5, 131_072, ManifestationProfile::Path { depth: 4 }),
    ];
    let mut objects = HashMap::new();
    for (inode, len, profile) in specs {
        let source = pattern(len);
        publish(&store, inode, 1, 1, &source, profile);
        objects.insert(inode, source);
    }

    // A deterministic heterogeneous request mix: hot inodes dominate, request
    // sizes span byte/small/medium/large, and offsets fragment the objects.
    let mut rng = Lcg(0x1234_5678);
    let mut requests = Vec::new();
    for _ in 0..4096 {
        let inode = match rng.below(10) {
            0..=5 => {
                if rng.below(2) == 0 {
                    1
                } else {
                    2
                }
            }
            6..=7 => 3,
            8 => 4,
            _ => 5,
        };
        let source_len = objects[&inode].len() as u64;
        let length = match rng.below(4) {
            0 => 1,
            1 => 512,
            2 => 4096,
            _ => 65_536.min(source_len),
        };
        // Offset strictly inside the object, so the effective length is the
        // requested length (never clamped to zero by the authoritative read).
        let offset = rng.below(source_len);
        let avail = source_len - offset;
        requests.push(Req {
            inode,
            root: 1,
            logical_len: source_len,
            offset,
            length: length.min(avail),
        });
    }
    Fixture { objects, requests }
}

/// The authoritative read for a request (the same bytes the planner must return).
fn auth(objects: &HashMap<u64, Vec<u8>>, r: &Req) -> Vec<u8> {
    slice(&objects[&r.inode], r.offset, r.length)
}

fn query(r: &Req) -> ReadQuery {
    ReadQuery {
        inode: r.inode,
        inode_version: 1,
        root: r.root,
        logical_len: r.logical_len,
        offset: r.offset,
        length: r.length,
    }
}

fn percentiles(mut ns: Vec<u64>) -> (u64, u64, f64) {
    ns.sort_unstable();
    let n = ns.len();
    let p50 = ns[n / 2];
    let p99 = ns[(n * 99 / 100).min(n - 1)];
    let mean = ns.iter().sum::<u64>() as f64 / n as f64;
    (p50, p99, mean)
}

struct Phase {
    p50_ns: u64,
    p99_ns: u64,
    mean_ns: f64,
    requests: u64,
    allocs_per_request: f64,
    wall_seconds: f64,
}

/// Warm the planner to its steady state, then measure `repeats` passes over the
/// request list single-threaded.
fn single_threaded(fixture: &Fixture, planner: &Arc<ReadPlanner>, repeats: usize) -> Phase {
    let read_once = |planner: &ReadPlanner, r: &Req| {
        planner
            .read(&query(r), |off, len| {
                Ok(slice(fixture.objects.get(&r.inode).unwrap(), off, len))
            })
            .expect("read")
    };
    for r in &fixture.requests {
        let planned = read_once(planner, r);
        assert_eq!(planned.bytes, auth(&fixture.objects, r), "byte mismatch");
    }

    let start = Instant::now();
    ALLOCS.store(0, Ordering::Relaxed);
    let mut latencies: Vec<u64> = Vec::with_capacity(fixture.requests.len() * repeats);
    for _ in 0..repeats {
        for r in &fixture.requests {
            let t = Instant::now();
            let planned = read_once(planner, r);
            latencies.push(t.elapsed().as_nanos() as u64);
            debug_assert_eq!(planned.bytes.len() as u64, r.length);
        }
    }
    let wall = start.elapsed().as_secs_f64();
    let requests = (fixture.requests.len() * repeats) as u64;
    let allocs = ALLOCS.load(Ordering::Relaxed);
    let (p50_ns, p99_ns, mean_ns) = percentiles(latencies);
    Phase {
        p50_ns,
        p99_ns,
        mean_ns,
        requests,
        allocs_per_request: allocs as f64 / requests as f64,
        wall_seconds: wall,
    }
}

/// `threads` concurrent readers, `repeats` passes each. Exposes the contention
/// cost of a per-request shared-state write lock.
fn multi_threaded(
    fixture: &Fixture,
    planner: &Arc<ReadPlanner>,
    threads: usize,
    repeats: usize,
) -> Phase {
    let start = Instant::now();
    ALLOCS.store(0, Ordering::Relaxed);
    let mut handles = Vec::new();
    for id in 0..threads {
        let planner = planner.clone();
        let objects = fixture.objects.clone();
        let requests = fixture.requests.clone();
        handles.push(std::thread::spawn(move || {
            let mut latencies: Vec<u64> = Vec::with_capacity(requests.len() * repeats);
            for _ in 0..repeats {
                for r in &requests {
                    let t = Instant::now();
                    let planned = planner
                        .read(&query(r), |off, len| {
                            Ok(slice(objects.get(&r.inode).unwrap(), off, len))
                        })
                        .expect("read");
                    latencies.push(t.elapsed().as_nanos() as u64);
                    debug_assert_eq!(planned.bytes.len() as u64, r.length);
                }
            }
            let _ = id;
            latencies
        }));
    }
    let mut all = Vec::new();
    for h in handles {
        all.extend(h.join().expect("join"));
    }
    let wall = start.elapsed().as_secs_f64();
    let requests = all.len() as u64;
    let allocs = ALLOCS.load(Ordering::Relaxed);
    let (p50_ns, p99_ns, mean_ns) = percentiles(all);
    Phase {
        p50_ns,
        p99_ns,
        mean_ns,
        requests,
        allocs_per_request: allocs as f64 / requests as f64,
        wall_seconds: wall,
    }
}

fn phase_json(label: &str, phase: &Phase, threads: usize) -> serde_json::Value {
    serde_json::json!({
        "label": label,
        "threads": threads,
        "requests": phase.requests,
        "p50_ns": phase.p50_ns,
        "p99_ns": phase.p99_ns,
        "mean_ns": phase.mean_ns,
        "allocations_per_request": phase.allocs_per_request,
        "wall_seconds": phase.wall_seconds,
        "requests_per_second": phase.requests as f64 / phase.wall_seconds,
    })
}

fn write_evidence(label: &str, single: &Phase, multi: &Phase, threads: usize, repeats: usize) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/performance/read-planner.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut doc: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| {
            serde_json::json!({
                "schema": "orfs.readpath-planner.v1",
                "generated_by": "benches/read_path.rs",
                "note": "Paired read-planner benchmark: the same bench binary run once on the pre-Phase-43 tree (label 'before') and once on the Phase-43 tree (label 'after'), appended by label. Absolute nanoseconds are single-run, single-host and load-sensitive; the comparison between labels, measured back to back, is the point.",
                "workload": {
                    "hot_objects": [1, 2],
                    "cold_objects": [3, 4, 5],
                    "request_sizes_bytes": [1, 512, 4096, 65536],
                    "objects": [
                        {"inode": 1, "bytes": 4096, "profile": "path"},
                        {"inode": 2, "bytes": 8192, "profile": "max-speed"},
                        {"inode": 3, "bytes": 65536, "profile": "sparse"},
                        {"inode": 4, "bytes": 262144, "profile": "full"},
                        {"inode": 5, "bytes": 131072, "profile": "path"}
                    ]
                },
                "runs": {},
            })
        });
    let runs = doc
        .get_mut("runs")
        .and_then(|v| v.as_object_mut())
        .expect("runs object");
    runs.insert(
        label.to_string(),
        serde_json::json!({
            "single_threaded": phase_json(label, single, 1),
            "concurrent": phase_json(label, multi, threads),
            "repeats_per_thread": repeats,
            "note": "allocations_per_request counts every allocation on the process allocator, including the returned byte buffer and the authoritative slice; the planning-only overhead is the excess over the after run.",
        }),
    );
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    println!(
        "read-planner[{label}] single: p50={} ns p99={} ns alloc/req={:.3} | concurrent({threads}): p50={} ns p99={} ns alloc/req={:.3} req/s={:.0}",
        single.p50_ns,
        single.p99_ns,
        single.allocs_per_request,
        multi.p50_ns,
        multi.p99_ns,
        multi.allocs_per_request,
        multi.requests as f64 / multi.wall_seconds,
    );
}

fn bench_read_planner() {
    let td = tempfile::TempDir::new().expect("tempdir");
    let fixture = build_fixture(td.path());
    let state =
        ManifestationState::recover(GenerationStore::new(td.path()), UUID).expect("recover");
    let planner = Arc::new(ReadPlanner::new(state, ReadPlannerConfig::default()));

    const THREADS: usize = 16;
    const REPEATS: usize = 32;
    let single = single_threaded(&fixture, &planner, REPEATS);
    let multi = multi_threaded(&fixture, &planner, THREADS, REPEATS);

    let label = std::env::var("ORFS_READ_PLANNER_LABEL").unwrap_or_else(|_| "after".to_string());
    write_evidence(&label, &single, &multi, THREADS, REPEATS);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--planner-only") {
        bench_read_planner();
        return;
    }
    bench_roundtrip(1024, 20_000);
    bench_roundtrip(64 * 1024, 2_000);
    bench_roundtrip(1024 * 1024, 256);
    bench_read_planner();
}
