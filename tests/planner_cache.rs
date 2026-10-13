//! **Phase 49 — the volatile-cache court (reviewer §10).**
//!
//! The planner's volatile caches hold *re-derivable* structures: parsed,
//! verified EKBLOOM bodies (each carrying one precompiled [`ObjectPlan`]),
//! resolved region payload bodies, and coverage tables. Evicting one forgets a
//! cached parse only — the committed manifestation it came from is untouched
//! (non-withdrawal) and is re-parsed on next use. That makes the caches pure
//! performance state, but it does **not** make their eviction policy arbitrary:
//! a plain insertion-ordered FIFO is destroyed by a single one-pass scan over
//! more distinct objects than the cache holds, because every scan insert evicts
//! the front — including a hot working set.
//!
//! Phase 49 replaces that FIFO with a scan-resistant admission policy
//! ([`AdmissionCache`], an S3-FIFO analogue: a small probationary segment, a
//! protected main segment, and a keys-only ghost queue). This court proves the
//! observable consequence through the planner's public API:
//!
//! * **Hot reads stay resident across a scan.** During a one-pass cold scan far
//!   larger than the cache, the only body-plan rebuilds are the cold objects
//!   themselves — every interleaved hot read is a cache hit (a rebuild would
//!   re-parse and re-verify the body). The same key trace replayed through an
//!   analytic FIFO model rebuilds strictly more, quantifying the improvement.
//! * **Correctness is unchanged.** Every read returns byte-exact authoritative
//!   bytes regardless of which cache path served it.
//! * **The caches stay bounded.** Resident bodies never exceed the configured
//!   capacity, and the process's resident set does not grow with the number of
//!   objects ever seen.
//!
//! The always-on `planner_cache_smoke` runs a bounded version in the default gate;
//! the full sweep is opt-in behind `ORFS_CACHE_COURT=1` and writes
//! `evidence/performance/planner-cache.json` (run it via
//! `scripts/container-planner-cache.sh`).

use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::time::Instant;

use orfs::manifestation::{
    ekbloom_format_version, CertificationState, GenerationManifest, GenerationStore,
    ManifestationProfile, ManifestationState, MANIFEST_SCHEMA,
};
use orfs::readpath::{
    AdmissionStats, PlannerCacheStats, ReadPlanner, ReadPlannerConfig, ReadQuery,
};
use tempfile::TempDir;

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x43, 0x33, 0x40, 0x49, 0x82, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
];

/// Logical object size and the read length used throughout the court.
const SRC_LEN: usize = 1024;
const READ_LEN: u64 = 64;

// ---------------------------------------------------------------------------
// Fixtures (mirroring `tests/read_path_planner.rs`)
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

/// Publish a synthetic generation over `source`, exactly as the production
/// builder does (mirroring the `tests/read_path_planner.rs` helper).
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

/// The process's resident set size in kibibytes, on Linux; `None` elsewhere.
fn rss_kib() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages.saturating_mul(4))
}

// ---------------------------------------------------------------------------
// Court
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Params {
    /// Body-cache capacity.
    capacity: usize,
    /// Number of hot objects forming the protected working set.
    hot: usize,
    /// Number of distinct cold objects in the one-pass scan.
    scan: usize,
    /// Warm-up rounds over the hot set before measurement.
    warmup: usize,
    /// Rounds over the hot set after the scan (steady state).
    hot_only_rounds: usize,
}

struct Outcome {
    scan_plan_builds: u64,
    scan_stats: AdmissionStats,
    hot_only_plan_builds: u64,
    hot_only_reads: u64,
    hot_only_hits: u64,
    hot_only_ns_per_read: f64,
    resident_body_plans: usize,
    resident_bound: usize,
    cache_stats: PlannerCacheStats,
    rss_kib_end: Option<u64>,
    fifo_scan_builds: u64,
    fifo_hot_only_builds: u64,
}

/// A plain insertion-ordered FIFO of `capacity` keys — the pre-Phase-49 policy —
/// replayed over the *identical* key trace to quantify the admission change. It is
/// an analytic model of the old policy, not a second run of the filesystem.
struct FifoModel {
    capacity: usize,
    order: VecDeque<u64>,
    resident: HashSet<u64>,
    misses: u64,
}

impl FifoModel {
    fn new(capacity: usize) -> FifoModel {
        FifoModel {
            capacity,
            order: VecDeque::new(),
            resident: HashSet::new(),
            misses: 0,
        }
    }

    fn touch(&mut self, key: u64) {
        if self.resident.contains(&key) {
            return;
        }
        self.misses += 1;
        if self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.resident.remove(&old);
            }
        }
        self.order.push_back(key);
        self.resident.insert(key);
    }
}

fn run_court(dir: &Path, p: &Params) -> Outcome {
    let source = pattern(SRC_LEN);
    let store = GenerationStore::new(dir);
    let hot: Vec<u64> = (0..p.hot as u64).map(|i| 10 + i).collect();
    let cold: Vec<u64> = (0..p.scan as u64).map(|i| 1_000_000 + i).collect();
    for &inode in hot.iter().chain(cold.iter()) {
        publish_generation(
            &store,
            inode,
            1,
            1,
            &source,
            ManifestationProfile::Path { depth: 4 },
        );
    }
    let state =
        ManifestationState::recover(GenerationStore::new(dir), UUID).expect("recover state");
    let planner = ReadPlanner::new(
        state,
        ReadPlannerConfig {
            cache_capacity: p.capacity,
            ..Default::default()
        },
    );

    let read = |inode: u64| -> Vec<u8> {
        let q = ReadQuery {
            inode,
            inode_version: 1,
            root: 1,
            logical_len: source.len() as u64,
            offset: 0,
            length: READ_LEN,
        };
        planner
            .read(&q, |off, len| Ok(auth_slice(&source, off, len)))
            .expect("read")
            .bytes
    };
    let expect = auth_slice(&source, 0, READ_LEN);

    let mut fifo = FifoModel::new(p.capacity);

    // Warm up the hot set so it settles into the protected segment.
    for _ in 0..p.warmup {
        for &k in &hot {
            assert_eq!(read(k), expect, "warm-up read of inode {k}");
            fifo.touch(k);
        }
    }

    // The scan phase: one pass over the cold objects, each interleaved with reads
    // of the whole hot set.
    let before = planner.stats().plan_builds;
    let fifo_before = fifo.misses;
    for &c in &cold {
        assert_eq!(read(c), expect, "scan read of inode {c}");
        fifo.touch(c);
        for &k in &hot {
            assert_eq!(read(k), expect, "hot read of inode {k} during the scan");
            fifo.touch(k);
        }
    }
    let scan_plan_builds = planner.stats().plan_builds - before;
    let fifo_scan_builds = fifo.misses - fifo_before;
    let scan_stats = planner.cache_stats().body;

    // The hot-only phase: the steady state, which must be all hits.
    let before = planner.stats().plan_builds;
    let fifo_before = fifo.misses;
    let hits_before = planner.cache_stats().body.hits;
    let hot_only_reads = (p.hot_only_rounds * p.hot) as u64;
    let started = Instant::now();
    for _ in 0..p.hot_only_rounds {
        for &k in &hot {
            assert_eq!(read(k), expect, "hot-only read of inode {k}");
            fifo.touch(k);
        }
    }
    let elapsed = started.elapsed();
    let hot_only_plan_builds = planner.stats().plan_builds - before;
    let hot_only_hits = planner.cache_stats().body.hits - hits_before;
    let fifo_hot_only_builds = fifo.misses - fifo_before;

    let resident = planner.resident();
    Outcome {
        scan_plan_builds,
        scan_stats,
        hot_only_plan_builds,
        hot_only_reads,
        hot_only_hits,
        hot_only_ns_per_read: elapsed.as_nanos() as f64 / hot_only_reads.max(1) as f64,
        resident_body_plans: resident.body_plans,
        resident_bound: resident.body_capacity.max(1),
        cache_stats: planner.cache_stats(),
        rss_kib_end: rss_kib(),
        fifo_scan_builds,
        fifo_hot_only_builds,
    }
}

/// The always-on smoke: a bounded version of the court in the default gate.
#[test]
fn planner_cache_smoke() {
    let td = TempDir::new().unwrap();
    let p = Params {
        capacity: 16,
        hot: 6,
        scan: 32,
        warmup: 4,
        hot_only_rounds: 8,
    };
    let o = run_court(td.path(), &p);

    assert!(
        o.resident_body_plans <= o.resident_bound,
        "resident bodies {} exceed the bound {}",
        o.resident_body_plans,
        o.resident_bound
    );
    // The only body rebuilds during the scan are the cold objects themselves:
    // every interleaved hot read was a cache hit.
    assert_eq!(
        o.scan_plan_builds, p.scan as u64,
        "hot reads during the scan rebuilt bodies: {:?}",
        o.scan_stats
    );
    // A steady hot read never rebuilds a body.
    assert_eq!(
        o.hot_only_plan_builds, 0,
        "a steady hot read rebuilt a body: {:?}",
        o.cache_stats.body
    );
    assert_eq!(
        o.hot_only_hits, o.hot_only_reads,
        "every hot-only read must be a body-cache hit"
    );
    // The scan-resistance property is exactly that the hot set survives: the
    // analytic FIFO over the same trace rebuilds strictly more.
    assert!(
        o.fifo_scan_builds > o.scan_plan_builds,
        "the FIFO model did not lose the hot set here (fifo={}, admission={}); \
         the court needs a larger hot set relative to capacity",
        o.fifo_scan_builds,
        o.scan_plan_builds
    );
    assert_eq!(o.fifo_hot_only_builds, 0);
}

#[test]
fn planner_cache_sweep() {
    if std::env::var("ORFS_CACHE_COURT").as_deref() != Ok("1") {
        eprintln!("planner_cache_sweep: skipped (set ORFS_CACHE_COURT=1 to run the full sweep)");
        return;
    }
    let td = TempDir::new().unwrap();
    let p = Params {
        capacity: 32,
        hot: 20,
        scan: 512,
        warmup: 4,
        hot_only_rounds: 64,
    };
    let rss_before = rss_kib().unwrap_or(0);
    let o = run_court(td.path(), &p);

    assert!(
        o.resident_body_plans <= o.resident_bound,
        "resident bodies {} exceed the bound {}",
        o.resident_body_plans,
        o.resident_bound
    );
    assert_eq!(o.scan_plan_builds, p.scan as u64, "scan rebuilt a hot body");
    assert_eq!(o.hot_only_plan_builds, 0, "steady hot read rebuilt a body");
    assert!(
        o.fifo_scan_builds > o.scan_plan_builds,
        "expected the admission policy to beat the FIFO model (fifo={}, admission={})",
        o.fifo_scan_builds,
        o.scan_plan_builds
    );
    let rss_after = o.rss_kib_end.unwrap_or(0);
    assert!(
        rss_after.saturating_sub(rss_before) < 64 * 1024,
        "resident set grew by {} KiB over the court",
        rss_after.saturating_sub(rss_before)
    );

    let ratio = o.fifo_scan_builds as f64 / o.scan_plan_builds.max(1) as f64;
    let environment = serde_json::json!({
        "bench": serde_json::to_value(orfs::bench::Environment::capture(
            std::env::var("ORFS_IMAGE").ok()
        ))
        .unwrap_or(serde_json::Value::Null),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
    });
    let doc = serde_json::json!({
        "schema": "orfs.performance.planner-cache.v1",
        "generated_by": "tests/planner_cache.rs",
        "note": "Single-run, single-host measurement. The planner's volatile caches \
                 hold re-derivable structures (parsed EKBLOOM bodies + their \
                 precompiled read plans, region payload bodies, coverage tables); \
                 evicting one forgets only a cached parse, never the committed \
                 manifestation. This court measures the *observable* effect of the \
                 Phase 49 scan-resistant admission policy through the planner's \
                 public API: during a one-pass cold scan far larger than the cache, \
                 every interleaved hot read is a body-cache hit, so the only body-plan \
                 rebuilds are the cold objects themselves. The 'fifo_model' figures \
                 are an analytic replay of the pre-Phase-49 insertion-ordered FIFO \
                 over the identical key trace (a model of the old policy, not a second \
                 filesystem run).",
        "policy": {
            "name": "s3-fifo-admission",
            "probationary_small_segment_ratio": 0.1,
            "ghost_queue_capacity_factor": 1,
            "promote_min_references": 1,
            "max_reference_count": 3,
            "retires_volatile_only": true,
        },
        "workload": {
            "capacity": p.capacity,
            "hot_objects": p.hot,
            "scan_objects": p.scan,
            "warmup_rounds": p.warmup,
            "hot_reads_per_scan_step": p.hot,
            "hot_only_rounds": p.hot_only_rounds,
            "read_len": READ_LEN,
            "object_len": SRC_LEN,
        },
        "measured": {
            "scan_plan_builds": o.scan_plan_builds,
            "scan_object_count": p.scan,
            "hot_reads_during_scan": (p.scan * p.hot) as u64,
            "scan_body_stats": admission_json(&o.scan_stats),
            "hot_only_plan_builds": o.hot_only_plan_builds,
            "hot_only_reads": o.hot_only_reads,
            "hot_only_hits": o.hot_only_hits,
            "hot_only_hit_rate": if o.hot_only_reads == 0 { 0.0 } else {
                o.hot_only_hits as f64 / o.hot_only_reads as f64
            },
            "hot_only_ns_per_read": o.hot_only_ns_per_read,
            "resident_body_plans_end": o.resident_body_plans,
            "resident_bound": o.resident_bound,
            "cache_stats_end": {
                "body": admission_json(&o.cache_stats.body),
                "region": admission_json(&o.cache_stats.region),
                "coverage": admission_json(&o.cache_stats.coverage),
            },
            "rss_kib_end": o.rss_kib_end,
        },
        "fifo_model": {
            "note": "analytic replay of the pre-Phase-49 insertion-ordered FIFO over \
                     the identical key trace",
            "scan_plan_builds": o.fifo_scan_builds,
            "hot_only_plan_builds": o.fifo_hot_only_builds,
        },
        "comparison": {
            "admission_vs_fifo_scan_build_ratio": ratio,
            "admission_scan_builds": o.scan_plan_builds,
            "fifo_scan_builds": o.fifo_scan_builds,
            "cold_builds_are_unavoidable": p.scan,
            "explanation": "The admission policy rebuilds only the cold objects \
                            (one per scan step); the FIFO model rebuilds those plus \
                            hot bodies its eviction displaced.",
        },
        "environment": environment,
    });

    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/performance/planner-cache.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!("planner-cache evidence written to {}", path.display());
}

fn admission_json(s: &AdmissionStats) -> serde_json::Value {
    serde_json::json!({
        "hits": s.hits,
        "misses": s.misses,
        "ghost_hits": s.ghost_hits,
        "promotions": s.promotions,
        "evictions": s.evictions,
    })
}
