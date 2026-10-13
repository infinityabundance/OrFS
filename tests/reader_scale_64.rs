//! **Reviewer item — concurrent read-path p99/p99.9 under 64 threads, and a
//! bounded planner lifecycle under concurrency.**
//!
//! This court extends the Phase-43 read-planner court (`tests/read_path_planner.rs`)
//! and the Phase-19 reader-scaling court (`tests/concurrency_stress.rs`) to the
//! concurrency the reviewer asked for: a single manifested object served by one
//! shared [`ReadPlanner`], read by **1/2/4/8/16/32/64** concurrent threads.
//!
//! What is proved here:
//!
//! * **The steady-state read is concurrency-safe and byte-exact.** Every read, at
//!   every reader count, returns bytes identical to the authoritative extent read.
//! * **Latency percentiles exist under contention.** For each reader count the court
//!   records aggregate ops/s and the pooled per-op p50/p95/p99/p99.9 (nanoseconds).
//! * **The planner lifecycle stays bounded under concurrency.** After the sweep
//!   `ReadPlanner::resident()` remains within its configured capacities, and the
//!   cumulative `selection_sorts` / `model_write_locks` / `calibrations` /
//!   `plan_builds` counters do not advance during the steady-state phase: no reader
//!   re-plans, sorts, calibrates, or takes the cost-model write lock.
//!
//! ## Running it
//!
//! * `cargo test --test reader_scale_64` runs a small always-on smoke
//!   (`reader_scale_64_smoke`) in the default gate.
//! * The full 64-thread sweep is opt-in behind `ORFS_READER_SCALE64=1` and writes
//!   `evidence/performance/reader-scaling-64.json`. Run it (release, the
//!   representative build for performance evidence) via
//!   `scripts/container-reader-scale64.sh`.
//!
//! ## Honest caveat
//!
//! The container is capped at 8 CPUs (`ORFS_CPUS`, a CFS quota) and the host is
//! under external load, so reader counts above 8 cannot add real parallelism — they
//! add contention. The curve is reported as measured rather than smoothed.

use std::path::Path;
use std::time::Instant;

use orfs::manifestation::{
    ekbloom_format_version, CertificationState, GenerationManifest, GenerationStore,
    ManifestationProfile, ManifestationState, MANIFEST_SCHEMA,
};
use orfs::readpath::{
    PlannerResidency, ReadPathKind, ReadPlanner, ReadPlannerConfig, ReadPlannerStats, ReadQuery,
};
use tempfile::TempDir;

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x43, 0x22, 0x40, 0x33, 0x81, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
];

/// The manifested object's identity (matches the Phase-43 fixture).
const INODE: u64 = 7;
const VERSION: u64 = 1;
const ROOT: u64 = 100;

/// A 64 KiB logical object; 4 KiB reads land in the `Small` size class.
const SRC_LEN: usize = 64 * 1024;
const READ_LEN: u64 = 4096;

/// The reader counts the reviewer asked for, and a bounded always-on prefix.
const SWEEP_READERS: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];
const SMOKE_READERS: [usize; 4] = [1, 2, 4, 8];

/// Total timed reads per row (spread across the readers) and a floor per reader so
/// high reader counts still produce a usable tail.
const SWEEP_TOTAL_READS: u64 = 24_000;
const SMOKE_TOTAL_READS: u64 = 4_000;
const MIN_OPS_PER_READER: u64 = 128;

/// Untimed per-thread priming reads before each timed row.
const WARM_PASS_READS: u64 = 16;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 131 + 17) % 251) as u8).collect()
}

/// The authoritative semantics of an extent read.
fn auth_slice(source: &[u8], offset: u64, length: u64) -> Vec<u8> {
    let n = source.len() as u64;
    let end = offset.saturating_add(length).min(n);
    if offset >= end {
        Vec::new()
    } else {
        source[offset as usize..end as usize].to_vec()
    }
}

/// Publish a synthetic generation over `source` (exactly as the production
/// builder does), mirroring the `tests/read_path_planner.rs` helper.
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

/// Build a manifested object and the planner over it. The returned `TempDir` must
/// be kept alive for the payload to remain on disk.
fn manifested_planner(source: &[u8]) -> (TempDir, ReadPlanner) {
    let td = TempDir::new().unwrap();
    let store = GenerationStore::new(td.path());
    publish_generation(
        &store,
        INODE,
        VERSION,
        ROOT,
        source,
        ManifestationProfile::MaxSpeed,
    );
    let state =
        ManifestationState::recover(GenerationStore::new(td.path()), UUID).expect("recover state");
    let planner = ReadPlanner::new(state, ReadPlannerConfig::default());
    (td, planner)
}

/// A deterministic, spread set of read offsets within the object (so a single timed
/// row covers several logical positions, and a single reader count is not just one
/// cache-hot address).
fn read_offsets(logical_len: u64, read_len: u64) -> Vec<u64> {
    let span = logical_len.saturating_sub(read_len).max(1);
    (0..=8).map(|i| span * i as u64 / 8).collect()
}

/// Nearest-rank percentile over an ascending slice (nanoseconds).
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

/// One steady-state read of the manifested object through the shared planner.
fn do_read(planner: &ReadPlanner, source: &[u8], offset: u64, read_len: u64) -> Vec<u8> {
    let q = ReadQuery {
        inode: INODE,
        inode_version: VERSION,
        root: ROOT,
        logical_len: source.len() as u64,
        offset,
        length: read_len,
    };
    planner
        .read(&q, |o, l| Ok(auth_slice(source, o, l)))
        .expect("planned read")
        .bytes
}

/// Drive the planner to its steady state: keep probing until a batch of reads
/// advances only `hot_reads` (no sort, no model write lock, no calibration, no plan
/// rebuild). Bounded, so a planner that never converges fails loudly.
fn warm_to_steady(planner: &ReadPlanner, source: &[u8], offsets: &[u64], read_len: u64) {
    const PROBE: u64 = 64;
    let mut attempts = 0u32;
    loop {
        // A warm batch, allowed to calibrate.
        for i in 0..PROBE {
            let off = offsets[(i as usize) % offsets.len()];
            let bytes = do_read(planner, source, off, read_len);
            assert_eq!(
                bytes,
                auth_slice(source, off, read_len),
                "warm read mismatch at offset {off}"
            );
        }
        // A probe batch: in steady state this must add no planning work.
        let before = planner.stats();
        for i in 0..PROBE {
            let off = offsets[(i as usize) % offsets.len()];
            let _ = do_read(planner, source, off, read_len);
        }
        let after = planner.stats();
        let steady = after.selection_sorts == before.selection_sorts
            && after.model_write_locks == before.model_write_locks
            && after.calibrations == before.calibrations
            && after.plan_builds == before.plan_builds
            && after.hot_reads == before.hot_reads + PROBE;
        if steady {
            return;
        }
        attempts += 1;
        assert!(
            attempts < 512,
            "planner did not reach steady state after {attempts} probe batches: before={before:?} after={after:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

struct Row {
    readers: usize,
    reads: u64,
    ops_per_s: f64,
    ns_per_op: f64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    p999_ns: u64,
    p9999_ns: u64,
}

impl Row {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "readers": self.readers,
            "reads": self.reads,
            "ops_per_s": self.ops_per_s,
            "ns_per_op": self.ns_per_op,
            "p50_ns": self.p50_ns,
            "p95_ns": self.p95_ns,
            "p99_ns": self.p99_ns,
            "p999_ns": self.p999_ns,
            "p9999_ns": self.p9999_ns,
        })
    }
}

/// Measure one reader count: an untimed priming pass, then the timed steady-state
/// sweep. Every read is asserted byte-exact against the authoritative extent.
fn measure_row(
    planner: &ReadPlanner,
    source: &[u8],
    offsets: &[u64],
    read_len: u64,
    readers: usize,
    total_reads: u64,
) -> Row {
    let ops_per_reader = (total_reads / readers as u64).max(MIN_OPS_PER_READER);

    // Untimed priming pass so every thread's path is warm (still steady-state).
    std::thread::scope(|s| {
        for _ in 0..readers {
            s.spawn(|| {
                for i in 0..WARM_PASS_READS {
                    let off = offsets[(i as usize) % offsets.len()];
                    let bytes = do_read(planner, source, off, read_len);
                    assert_eq!(
                        bytes,
                        auth_slice(source, off, read_len),
                        "warm read mismatch at offset {off} with {readers} readers"
                    );
                }
            });
        }
    });

    let pre = planner.stats();
    let mut samples: Vec<u64> = Vec::with_capacity((readers as u64 * ops_per_reader) as usize);
    let started = Instant::now();
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(readers);
        for t in 0..readers {
            handles.push(s.spawn(move || {
                let mut local: Vec<u64> = Vec::with_capacity(ops_per_reader as usize);
                for i in 0..ops_per_reader {
                    let off = offsets[(t + i as usize) % offsets.len()];
                    let t0 = Instant::now();
                    let bytes = do_read(planner, source, off, read_len);
                    local.push(t0.elapsed().as_nanos() as u64);
                    assert_eq!(
                        bytes,
                        auth_slice(source, off, read_len),
                        "read mismatch at offset {off} with {readers} readers"
                    );
                }
                local
            }));
        }
        for h in handles {
            samples.extend(h.join().expect("reader thread"));
        }
    });
    let elapsed = started.elapsed();
    let post = planner.stats();

    let total = readers as u64 * ops_per_reader;
    // The timed reads must all be steady-state hot reads that neither re-plan nor
    // take the cost-model write lock (bounded planner lifecycle under concurrency).
    assert_eq!(
        post.hot_reads - pre.hot_reads,
        total,
        "readers={readers}: not every timed read was a steady-state hot read ({pre:?} -> {post:?})"
    );
    assert_eq!(
        post.selection_sorts, pre.selection_sorts,
        "readers={readers}: a steady-state read sorted candidates ({pre:?} -> {post:?})"
    );
    assert_eq!(
        post.model_write_locks, pre.model_write_locks,
        "readers={readers}: a steady-state read took the cost-model write lock ({pre:?} -> {post:?})"
    );
    assert_eq!(
        post.calibrations, pre.calibrations,
        "readers={readers}: a steady-state read calibrated ({pre:?} -> {post:?})"
    );
    assert_eq!(
        post.plan_builds, pre.plan_builds,
        "readers={readers}: a steady-state read rebuilt a plan ({pre:?} -> {post:?})"
    );

    samples.sort_unstable();
    Row {
        readers,
        reads: total,
        ops_per_s: total as f64 / elapsed.as_secs_f64().max(f64::MIN_POSITIVE),
        ns_per_op: elapsed.as_nanos() as f64 / total as f64,
        p50_ns: percentile(&samples, 50.0),
        p95_ns: percentile(&samples, 95.0),
        p99_ns: percentile(&samples, 99.0),
        p999_ns: percentile(&samples, 99.9),
        p9999_ns: percentile(&samples, 99.99),
    }
}

struct Sweep {
    rows: Vec<Row>,
    residency: PlannerResidency,
    stats_before: ReadPlannerStats,
    stats_after: ReadPlannerStats,
    chosen: Vec<(ReadPathKind, u64)>,
}

/// Run the full court: build the object, warm the planner, sweep the reader counts,
/// and assert the bounded planner lifecycle and byte-exactness.
fn run_sweep(counts: &[usize], total_reads: u64) -> Sweep {
    let source = pattern(SRC_LEN);
    let (_td, planner) = manifested_planner(&source);
    let offsets = read_offsets(source.len() as u64, READ_LEN);

    warm_to_steady(&planner, &source, &offsets, READ_LEN);
    let stats_before = planner.stats();

    let mut rows = Vec::with_capacity(counts.len());
    for &readers in counts {
        let row = measure_row(&planner, &source, &offsets, READ_LEN, readers, total_reads);
        eprintln!(
            "reader-scale64: readers={:>2} ops/s={:>10.0} p50={:>6}ns p95={:>6}ns p99={:>6}ns p99.9={:>7}ns p99.99={:>8}ns",
            row.readers,
            row.ops_per_s,
            row.p50_ns,
            row.p95_ns,
            row.p99_ns,
            row.p999_ns,
            row.p9999_ns,
        );
        rows.push(row);
    }

    let stats_after = planner.stats();
    let residency = planner.resident();
    let chosen = planner.chosen_counts();

    // No planning work anywhere in the steady-state phase.
    assert_eq!(
        stats_after.selection_sorts, stats_before.selection_sorts,
        "the steady-state sweep sorted candidates: {stats_before:?} -> {stats_after:?}"
    );
    assert_eq!(
        stats_after.model_write_locks, stats_before.model_write_locks,
        "the steady-state sweep took the cost-model write lock: {stats_before:?} -> {stats_after:?}"
    );
    assert_eq!(
        stats_after.calibrations, stats_before.calibrations,
        "the steady-state sweep calibrated: {stats_before:?} -> {stats_after:?}"
    );
    assert_eq!(
        stats_after.plan_builds, stats_before.plan_builds,
        "the steady-state sweep rebuilt a plan: {stats_before:?} -> {stats_after:?}"
    );

    // Bounded planner lifecycle: every identity-keyed table is within its capacity.
    assert!(
        residency.body_plans <= residency.body_capacity,
        "body plans {} exceed capacity {}",
        residency.body_plans,
        residency.body_capacity
    );
    assert!(
        residency.object_models <= residency.object_capacity,
        "object models {} exceed capacity {}",
        residency.object_models,
        residency.object_capacity
    );
    assert!(
        residency.overlay_verified <= residency.identity_capacity,
        "verified overlays {} exceed capacity {}",
        residency.overlay_verified,
        residency.identity_capacity
    );
    assert!(
        residency.overlay_failed <= residency.identity_capacity,
        "failed overlays {} exceed capacity {}",
        residency.overlay_failed,
        residency.identity_capacity
    );

    Sweep {
        rows,
        residency,
        stats_before,
        stats_after,
        chosen,
    }
}

// ---------------------------------------------------------------------------
// Courts
// ---------------------------------------------------------------------------

/// The always-on smoke: a bounded reader sweep over the manifested object that
/// asserts byte-exactness, the steady-state counters, and the residency bound.
#[test]
fn reader_scale_64_smoke() {
    let sweep = run_sweep(&SMOKE_READERS, SMOKE_TOTAL_READS);
    assert_eq!(sweep.rows.len(), SMOKE_READERS.len());
    assert!(
        sweep.rows.iter().all(|r| r.reads > 0 && r.ops_per_s > 0.0),
        "every reader count must have measured reads: {:?}",
        sweep
            .rows
            .iter()
            .map(|r| (r.readers, r.reads, r.ops_per_s))
            .collect::<Vec<_>>()
    );
    eprintln!(
        "reader-scale64 smoke: counts={:?} residency_total={} sorts={}->{} locks={}->{}",
        SMOKE_READERS,
        sweep.residency.total(),
        sweep.stats_before.selection_sorts,
        sweep.stats_after.selection_sorts,
        sweep.stats_before.model_write_locks,
        sweep.stats_after.model_write_locks,
    );
}

/// The full 64-thread sweep (opt-in). Writes
/// `evidence/performance/reader-scaling-64.json`.
#[test]
fn reader_scale_64_sweep() {
    if std::env::var("ORFS_READER_SCALE64").as_deref() != Ok("1") {
        eprintln!(
            "reader_scale_64_sweep: skipped (set ORFS_READER_SCALE64=1 to run the full sweep)"
        );
        return;
    }

    let sweep = run_sweep(&SWEEP_READERS, SWEEP_TOTAL_READS);
    let environment = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());

    let doc = serde_json::json!({
        "schema": "orfs.performance.reader-scaling-64.v1",
        "generated_by": "tests/reader_scale_64.rs",
        "note": "Single-run, single-host, single-container measurements. One manifested \
                 object (profile max-speed) is served by one shared ReadPlanner and read \
                 by 1/2/4/8/16/32/64 concurrent threads; every read is asserted byte-exact \
                 against the authoritative extent read, and the steady-state counters prove \
                 no thread re-plans. Latency percentiles are over the pooled per-op samples \
                 of all readers for that row.",
        "caveat": "The container is CFS-capped at ORFS_CPUS CPUs (8) and the host is under \
                   external load, so reader counts above the effective core count contend \
                   rather than add parallelism. The curve is reported as measured, not smoothed.",
        "environment": {
            "bench": serde_json::to_value(&environment).unwrap_or(serde_json::Value::Null),
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        },
        "workload": {
            "logical_bytes": SRC_LEN,
            "read_bytes": READ_LEN,
            "offsets": read_offsets(SRC_LEN as u64, READ_LEN),
            "reader_counts": SWEEP_READERS,
            "profile": "max-speed",
            "object": { "inode": INODE, "inode_version": VERSION, "root": ROOT },
        },
        "results": sweep.rows.iter().map(Row::to_json).collect::<Vec<_>>(),
        "served_paths": sweep
            .chosen
            .iter()
            .map(|(k, c)| serde_json::json!({ "path": k.name(), "reads": c }))
            .collect::<Vec<_>>(),
        "planner_residency": {
            "body_plans": sweep.residency.body_plans,
            "object_models": sweep.residency.object_models,
            "overlay_verified": sweep.residency.overlay_verified,
            "overlay_failed": sweep.residency.overlay_failed,
            "body_capacity": sweep.residency.body_capacity,
            "object_capacity": sweep.residency.object_capacity,
            "identity_capacity": sweep.residency.identity_capacity,
            "total": sweep.residency.total(),
        },
        "steady_state_counters": {
            "before": {
                "plan_builds": sweep.stats_before.plan_builds,
                "calibrations": sweep.stats_before.calibrations,
                "selection_sorts": sweep.stats_before.selection_sorts,
                "model_write_locks": sweep.stats_before.model_write_locks,
                "hot_reads": sweep.stats_before.hot_reads,
            },
            "after": {
                "plan_builds": sweep.stats_after.plan_builds,
                "calibrations": sweep.stats_after.calibrations,
                "selection_sorts": sweep.stats_after.selection_sorts,
                "model_write_locks": sweep.stats_after.model_write_locks,
                "hot_reads": sweep.stats_after.hot_reads,
            },
            "selection_sorts_delta": sweep.stats_after.selection_sorts - sweep.stats_before.selection_sorts,
            "model_write_locks_delta": sweep.stats_after.model_write_locks - sweep.stats_before.model_write_locks,
            "calibrations_delta": sweep.stats_after.calibrations - sweep.stats_before.calibrations,
            "plan_builds_delta": sweep.stats_after.plan_builds - sweep.stats_before.plan_builds,
        },
        "bytes_exact": true,
    });

    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/performance/reader-scaling-64.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!("reader-scale64 evidence written to {}", path.display());
}
