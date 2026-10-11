//! Phase 18 — reproducible latency anatomy of the authoritative (and planned)
//! read path. Writes `evidence/performance/latency-anatomy.json`.
//!
//! The measurement is library-level and deterministic in *shape*: it times a
//! mixed single-byte / 4 KiB read workload over a genuinely fragmented object and
//! reports the per-request phase breakdown (dispatch, extent resolve, segment
//! read, assembly, reply) with p50/p95/p99 and allocation counts, plus the
//! marginal cost a manifested read planner adds over the authoritative read.
//! Absolute figures depend on the host/build; the breakdown and the bounds do not.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::time::Instant;

use orfs::commit::DurabilityMode;
use orfs::manifestation::{ManifestationConfig, ManifestationProfile};
use orfs::namespace::{Namespace, ReadPhases};
use orfs::readpath::{ReadPathKind, ReadQuery};
use tempfile::TempDir;

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x18, 0x22, 0x40, 0x33, 0x81, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
];
const CREATED: u64 = 1_700_000_000;

// A per-thread allocation counter (this test binary only).
thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

// SAFETY: thin wrapper over `System`; it only bumps a thread-local counter (a
// `Cell` with a `const` initialiser, which cannot allocate) and forwards every
// pointer/layout argument unchanged.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.with(|c| c.set(c.get() + 1));
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.with(|c| c.set(c.get() + 1));
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.with(|c| c.set(c.get() + 1));
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn count_allocs<T>(f: impl FnOnce() -> T) -> (T, usize) {
    COUNTING.with(|c| c.set(true));
    ALLOCS.with(|c| c.set(0));
    let out = f();
    let n = ALLOCS.with(|c| c.get());
    COUNTING.with(|c| c.set(false));
    (out, n)
}

/// A tiny deterministic PRNG (evidence reproducibility).
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

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

fn dist(mut xs: Vec<u64>) -> serde_json::Value {
    xs.sort_unstable();
    let sum: u64 = xs.iter().sum();
    serde_json::json!({
        "samples": xs.len(),
        "min": xs.first().copied().unwrap_or(0),
        "p50": percentile(&xs, 50.0),
        "p95": percentile(&xs, 95.0),
        "p99": percentile(&xs, 99.0),
        "mean": if xs.is_empty() { 0.0 } else { sum as f64 / xs.len() as f64 },
        "max": xs.last().copied().unwrap_or(0),
    })
}

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create evidence dir");
    }
    let mut s = serde_json::to_string_pretty(value).expect("serialize json");
    s.push('\n');
    std::fs::write(path, s).expect("write evidence");
}

fn evidence_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("evidence/performance")
}

/// A 512 KiB object assembled from `chunks` small scattered writes, so its extent
/// map is genuinely fragmented (the authoritative resolution must not scan it).
fn build_fragmented(dir: &Path) -> (Namespace, u64, u64, usize) {
    let mut ns = Namespace::init_with_uuid(dir, 1 << 20, UUID, CREATED, DurabilityMode::Ordered)
        .expect("init");
    let root = ns.root_inode();
    let ino = ns.create(root, b"frag", 0o644, 0, 0).expect("create");
    let stride = 512u64;
    let chunk = 64usize;
    let chunks = 1024u64;
    let byte = [0x5Au8; 64];
    for i in 0..chunks {
        ns.write_at(ino, i * stride, &byte[..chunk]).expect("write");
    }
    ns.sync().expect("sync");
    let root = ns.root();
    let extents = ns.extent_count(ino, root).expect("extent count");
    (ns, ino, root, extents)
}

#[test]
fn emit_latency_anatomy_evidence() {
    let td = TempDir::new().unwrap();
    let (mut ns, ino, root, extents) = build_fragmented(td.path());

    // Manifest a Path structure so the planner has a real (bounded) candidate to
    // time against; the anatomy is about the authoritative path, but the marginal
    // planner cost is part of the picture.
    ns.enable_manifestation(ManifestationConfig {
        workers: 1,
        queue_capacity: 8,
        synchronous: true,
        profile: ManifestationProfile::Path { depth: 4 },
        max_source_bytes: 64 << 20,
    })
    .expect("enable manifestation");
    let outcomes = ns
        .manifest_eligible(Some(ino), ManifestationProfile::Path { depth: 4 })
        .expect("manifest");
    assert!(
        outcomes
            .iter()
            .any(|o| o.status == orfs::manifestation::ManifestationStatus::Published),
        "the Path generation was not published"
    );

    let size = ns.getattr(ino, root).expect("stat").size;
    let mut rng = Lcg(0x1A7E_0C0D);
    let iterations = 2000usize;

    let mut dispatch = Vec::with_capacity(iterations);
    let mut resolve = Vec::with_capacity(iterations);
    let mut segment = Vec::with_capacity(iterations);
    let mut assembly = Vec::with_capacity(iterations);
    let mut reply = Vec::with_capacity(iterations);
    let mut total = Vec::with_capacity(iterations);
    let mut auth_allocs = Vec::with_capacity(iterations);
    let mut planned_total = Vec::with_capacity(iterations);
    let mut planner_added = Vec::with_capacity(iterations);
    let mut planned_allocs = Vec::with_capacity(iterations);
    let mut accelerated = 0u64;
    let mut equivalent = 0u64;

    // Warm up: load/verify the manifest body once, prime allocator state.
    let _ = ns.planned_read(ino, root, 0, 4096).expect("warm");

    let planner = ns.read_planner().expect("planner").clone();

    for _ in 0..iterations {
        let off = rng.below(size);
        let len = if rng.below(2) == 0 { 1 } else { 4096 };

        let ((bytes, phases), allocs): ((Vec<u8>, ReadPhases), usize) =
            count_allocs(|| ns.read_extent_traced(ino, root, off, len).expect("auth"));
        assert_eq!(bytes.len(), len.min(size - off) as usize);

        let query = ReadQuery {
            inode: ino,
            inode_version: ns.getattr(ino, root).expect("stat").version,
            root,
            logical_len: size,
            offset: off,
            length: len,
        };
        let ((planned, planned_ns), p_allocs) = count_allocs(|| {
            let t = Instant::now();
            let r = planner.read(&query, |o, l| ns.read_extent(ino, root, o, l));
            (r.expect("planned"), t.elapsed().as_nanos() as u64)
        });
        if planned.bytes == bytes {
            equivalent += 1;
        }
        if planned.path != ReadPathKind::LogicalExtent {
            accelerated += 1;
        }

        let reply_ns = phases.total_ns.saturating_sub(
            phases.dispatch_ns
                + phases.extent_resolve_ns
                + phases.segment_read_ns
                + phases.assembly_ns,
        );
        dispatch.push(phases.dispatch_ns);
        resolve.push(phases.extent_resolve_ns);
        segment.push(phases.segment_read_ns);
        assembly.push(phases.assembly_ns);
        reply.push(reply_ns);
        total.push(phases.total_ns);
        auth_allocs.push(allocs as u64);

        planned_total.push(planned_ns);
        // The planner's marginal cost is its own wall time minus the authoritative
        // read it would otherwise perform for the same request.
        planner_added.push(planned_ns.saturating_sub(phases.total_ns));
        planned_allocs.push(p_allocs as u64);
    }

    assert_eq!(equivalent as usize, iterations, "a planned read disagreed");

    let doc = serde_json::json!({
        "schema": "orfs.performance.latency-anatomy.v1",
        "generated_by": "tests/latency_anatomy.rs",
        "note": "Library-level per-request anatomy over a fragmented object. Phases: dispatch (view+inode), extent resolve (ExtentMap::plan_read), segment read (log read_range_into), assembly (destination placement), reply (residual). `planned_*` reflects the read planner; `planner_added_ns` is the authoritative-read time the planner adds on top for the same request. Absolute nanoseconds depend on the host/build; the breakdown and the O(log E + k) work bound do not.",
        "environment": orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok()),
        "workload": {
            "object_bytes": size,
            "logical_extents": extents,
            "iterations": iterations,
            "lengths": [1, 4096],
            "manifested_profile": "path(D=4)",
        },
        "authoritative": {
            "dispatch_ns": dist(dispatch),
            "extent_resolve_ns": dist(resolve),
            "segment_read_ns": dist(segment),
            "assembly_ns": dist(assembly),
            "reply_ns": dist(reply),
            "total_ns": dist(total),
            "allocations_per_request": dist(auth_allocs),
        },
        "planned": {
            "total_ns": dist(planned_total),
            "planner_added_ns": dist(planner_added),
            "allocations_per_request": dist(planned_allocs),
            "accelerated_requests": accelerated,
        },
        "equivalence": {
            "requests": iterations,
            "equivalent": equivalent,
            "mismatches": iterations as u64 - equivalent,
        },
    });
    write_json(&evidence_dir().join("latency-anatomy.json"), &doc);
}
