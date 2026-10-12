//! **Reviewer item 4 — the history-scaling court.**
//!
//! The governing laws are non-withdrawal (committed authoritative history is
//! never overwritten/reused) and concealed expansion (derived manifestation
//! structures accelerate reads but are never authoritative). This court measures
//! what happens to the time spent answering *the same* historical workload as
//! additional certified manifestations accumulate over a growing committed
//! history, and compares that against OrFS itself with the manifested plane
//! disabled over the *same* history.
//!
//! ## What grows, what is fixed
//!
//! * A deterministic committed history is built from **epochs**. Each epoch
//!   performs small *misaligned* writes of the exact bytes already present, so the
//!   live logical content is **byte-identical at every checkpoint** while the
//!   authoritative log grows (non-withdrawal) and each object's extent map
//!   fragments further.
//! * Checkpoints are taken at epochs `{0, E, 3E, 9E}` (genesis and geometric
//!   depth). At each checkpoint the *same fixed read workload* is run over the
//!   checkpoint's **pinned committed root** (a committed snapshot).
//! * The **manifested arm** publishes manifestations over the live objects (the
//!   plane auto-manifests every committed write; a full generation is published at
//!   each checkpoint so every object is qualified at the pinned root). The
//!   **authoritative arm** runs the identical history with the manifested plane
//!   disabled.
//!
//! ## Comparison contract (explicit and honest)
//!
//! A different filesystem implementing OrFS's historical + correctness guarantees
//! does not exist in this repository, so the defensible baseline is **OrFS with
//! manifestation disabled over the same history**. It shares the committed
//! history, snapshot/pinned-root semantics, storage engine and read API, and it
//! answers every read through the authoritative logical-extent path. It differs
//! only in that the concealed manifested plane is absent. A conventional-directory
//! reference is *not* used here: it is a different storage interface without
//! snapshots or committed history, and comparing against it would not isolate the
//! manifested plane.
//!
//! ## Hypothesis (tested, not assumed)
//!
//! Answering a fixed historical read should **not degrade** as history grows, and
//! should **improve when manifestations are reused**; construction work and
//! persistent bytes grow. A flat or negative result is reported as such.
//!
//! ## Running it
//!
//! * `cargo test --test history_scaling` runs a small always-on smoke that asserts
//!   the pinned-root reads are byte-exact between the two arms.
//! * The full sweep is opt-in behind `ORFS_HISTORY_SCALING=1` and writes
//!   `evidence/performance/history-scaling.json`. Run it (release, representative)
//!   via `scripts/container-history-scaling.sh`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use orfs::commit::DurabilityMode;
use orfs::index::Index;
use orfs::log::OpenMode;
use orfs::manifestation::{
    GenerationStore, ManifestationConfig, ManifestationProfile, ManifestationStatus,
    FLATTEN_AFTER_OVERLAYS, MAX_OVERLAY_DEPTH,
};
use orfs::namespace::Namespace;
use orfs::readpath::ReadPathKind;
use orfs::stats;
use orfs::volume::Volume;
use tempfile::TempDir;

/// A fixed volume identity makes the authoritative history byte-reproducible, so
/// the two arms build the *same* history and their pinned roots must agree.
const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x44, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const CREATED: u64 = 1_700_000_000;
const SEGMENT: u64 = 1 << 20;
/// Length of each content-neutral misaligned epoch write.
const WRITE_LEN: u64 = 16;

#[derive(Clone, Copy)]
struct CourtParams {
    objects: usize,
    object_bytes: u64,
    initial_chunk: u64,
    epoch_writes: u64,
    read_len: u64,
    rounds: u64,
}

struct CourtPlan {
    params: CourtParams,
    checkpoints: Vec<u64>,
}

fn sweep_plan() -> CourtPlan {
    CourtPlan {
        params: CourtParams {
            objects: 4,
            object_bytes: 32 * 1024,
            initial_chunk: 1024,
            epoch_writes: 16,
            read_len: 4096,
            rounds: 64,
        },
        checkpoints: vec![0, 4, 12, 36],
    }
}

fn smoke_plan() -> CourtPlan {
    CourtPlan {
        params: CourtParams {
            objects: 2,
            object_bytes: 8 * 1024,
            initial_chunk: 1024,
            epoch_writes: 4,
            read_len: 2048,
            rounds: 3,
        },
        checkpoints: vec![0, 2],
    }
}

/// The deterministic logical content of every object. Every write in the court
/// writes a slice of exactly these bytes, so logical content never changes.
fn content_at(offset: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|j| (((offset + j as u64) * 131 + 17) % 251) as u8)
        .collect()
}

/// A tiny deterministic PRNG so the epoch write offsets are reproducible.
struct Lcg(u64);

impl Lcg {
    fn new(epoch: u64, object: u64) -> Lcg {
        Lcg(0x9E37_79B9_7F4A_7C15 ^ epoch.wrapping_mul(0x1000_0001) ^ object)
    }
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

fn resident_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

// ---------------------------------------------------------------------------
// The fixed workload (identical at every checkpoint and in both arms)
// ---------------------------------------------------------------------------

struct Workload {
    samples_ns: Vec<u64>,
    round_totals_ns: Vec<u64>,
    digest_hex: String,
    paths: BTreeMap<String, u64>,
    manifested_served: u64,
    avoided_bytes: u64,
}

impl Workload {
    fn summary(&self) -> serde_json::Value {
        let mut sorted = self.samples_ns.clone();
        sorted.sort_unstable();
        let total_ns: u64 = self.samples_ns.iter().sum();
        let mean_ns = if self.samples_ns.is_empty() {
            0.0
        } else {
            total_ns as f64 / self.samples_ns.len() as f64
        };
        let throughput = if total_ns == 0 {
            0.0
        } else {
            self.samples_ns.len() as f64 / (total_ns as f64 / 1e9)
        };
        let round_means: Vec<f64> = self
            .round_totals_ns
            .iter()
            .map(|t| {
                let per_round = (self.samples_ns.len() / self.round_totals_ns.len().max(1)).max(1);
                *t as f64 / per_round as f64
            })
            .collect();
        serde_json::json!({
            "samples": self.samples_ns.len(),
            "p50_ns": percentile(&sorted, 50.0),
            "p99_ns": percentile(&sorted, 99.0),
            "p999_ns": percentile(&sorted, 99.9),
            "mean_ns": mean_ns,
            "min_ns": sorted.first().copied().unwrap_or(0),
            "max_ns": sorted.last().copied().unwrap_or(0),
            "throughput_reads_per_s": throughput,
            "round_mean_ns": round_means,
            "paths": self.paths,
            "manifested_served_reads": self.manifested_served,
            "avoided_authoritative_bytes": self.avoided_bytes,
            "digest_blake3": self.digest_hex,
        })
    }
}

/// Run the fixed workload: every object read at the same fixed offsets, `rounds`
/// times, through the (possibly manifested) planned read path.
fn run_workload(
    ns: &Namespace,
    root: u64,
    inodes: &[u64],
    read_len: u64,
    object_bytes: u64,
    rounds: u64,
) -> Workload {
    let offsets: Vec<u64> = (0..object_bytes / read_len).map(|i| i * read_len).collect();
    let mut samples_ns = Vec::new();
    let mut round_totals_ns = Vec::new();
    let mut hasher = blake3::Hasher::new();
    let mut paths: BTreeMap<String, u64> = BTreeMap::new();
    let mut manifested_served = 0u64;
    let mut avoided_bytes = 0u64;

    for _ in 0..rounds {
        let round_start = Instant::now();
        for &ino in inodes {
            for &off in &offsets {
                let t = Instant::now();
                let planned = ns
                    .planned_read(ino, root, off, read_len as u32)
                    .expect("planned read");
                samples_ns.push(t.elapsed().as_nanos() as u64);
                *paths.entry(planned.path.name().to_string()).or_insert(0) += 1;
                if planned.path != ReadPathKind::LogicalExtent {
                    // The manifested path produced these bytes without the
                    // authoritative logical-extent read that would otherwise have
                    // been performed for this request. `History`/`PathBloom` are
                    // certified, so no verify-on-use authoritative read happens.
                    manifested_served += 1;
                    avoided_bytes += planned.bytes.len() as u64;
                }
                hasher.update(&planned.bytes);
            }
        }
        round_totals_ns.push(round_start.elapsed().as_nanos() as u64);
    }

    Workload {
        samples_ns,
        round_totals_ns,
        digest_hex: hex32(hasher.finalize().as_bytes()),
        paths,
        manifested_served,
        avoided_bytes,
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/// Recovery at the current history depth: authoritative index reconstruction
/// (best of `reps`), the accelerated checkpoint mount, and the manifested-plane
/// generation recovery. All best-effort measured; read-only opens never mutate
/// authority.
fn recovery_json(dir: &Path, reps: usize) -> serde_json::Value {
    let mut auth_best = u128::MAX;
    let mut cp_best = u128::MAX;
    let mut cp_used = false;
    let mut cp_root: Option<u64> = None;
    for _ in 0..reps {
        let t = Instant::now();
        let vol = Volume::open(dir, OpenMode::ReadOnly).expect("open ro");
        let idx = Index::from_log(&vol.log, vol.log.committed_end_offset()).expect("replay");
        auth_best = auth_best.min(t.elapsed().as_micros());
        std::hint::black_box(idx);
        let t = Instant::now();
        if let Ok((idx, report)) = orfs::checkpoint::mount_index(&vol.log) {
            cp_best = cp_best.min(t.elapsed().as_micros());
            cp_used = report.used_checkpoint;
            cp_root = report.checkpoint_root;
            std::hint::black_box(idx);
        }
    }
    let mut man_best = u128::MAX;
    let mut man_generations = 0usize;
    let mut man_rejected = 0usize;
    for _ in 0..reps {
        let t = Instant::now();
        let rec = GenerationStore::new(dir)
            .recover()
            .expect("recover manifests");
        man_best = man_best.min(t.elapsed().as_micros());
        man_generations = rec.generations.len();
        man_rejected = rec.rejected;
    }
    serde_json::json!({
        "authoritative_index_rebuild_micros": if auth_best == u128::MAX { 0 } else { auth_best as u64 },
        "checkpoint_mount_micros": if cp_best == u128::MAX { 0 } else { cp_best as u64 },
        "checkpoint_used": cp_used,
        "checkpoint_root": cp_root,
        "manifest_recovery_micros": if man_best == u128::MAX { 0 } else { man_best as u64 },
        "manifest_generations_recovered": man_generations,
        "manifest_generations_rejected": man_rejected,
    })
}

// ---------------------------------------------------------------------------
// One arm
// ---------------------------------------------------------------------------

struct Arm {
    checkpoints: Vec<serde_json::Value>,
    roots: Vec<u64>,
    digests: Vec<String>,
    history_build_wall_micros: u128,
    resident_kib: Option<u64>,
}

/// Build the deterministic growing history and take the checkpoint measurements.
/// `manifested` selects the manifested arm (plane enabled, auto-manifesting on
/// every commit) or the authoritative baseline (plane disabled).
fn run_arm(dir: &Path, plan: &CourtPlan, manifested: bool) -> Arm {
    let p = plan.params;
    let mut ns = Namespace::init_with_uuid(dir, SEGMENT, UUID, CREATED, DurabilityMode::Ordered)
        .expect("init namespace");

    let root_ino = ns.root_inode();
    let mut inodes = Vec::with_capacity(p.objects);
    for i in 0..p.objects {
        let name = format!("obj{i}");
        let ino = ns
            .create(root_ino, name.as_bytes(), 0o644, 0, 0)
            .expect("create object");
        let mut off = 0;
        while off < p.object_bytes {
            let n = p.initial_chunk.min(p.object_bytes - off);
            ns.write_at(ino, off, &content_at(off, n as usize))
                .expect("initial write");
            off += n;
        }
        inodes.push(ino);
    }
    ns.sync().expect("sync initial content");

    if manifested {
        ns.enable_manifestation(ManifestationConfig {
            workers: 1,
            queue_capacity: 32,
            synchronous: true,
            profile: ManifestationProfile::Full,
            max_source_bytes: 64 << 20,
        })
        .expect("enable manifestation");
    }

    let max_epoch = *plan.checkpoints.last().expect("at least one checkpoint");
    let mut checkpoints = Vec::new();
    let mut roots = Vec::new();
    let mut digests = Vec::new();
    let mut history_build_wall_micros: u128 = 0;
    let mut cumulative_epoch_build_micros: u128 = 0;

    for epoch in 0..=max_epoch {
        if plan.checkpoints.contains(&epoch) {
            let committed_root = ns.root();

            // Manifested arm: publish a full generation for every object at the
            // pinned root, so each object is exactly qualified for a read at it.
            let construction = if manifested {
                let t = Instant::now();
                let outcomes = ns
                    .manifest_eligible(None, ManifestationProfile::Full)
                    .expect("manifest at checkpoint");
                let explicit_build_micros = t.elapsed().as_micros();
                let explicit_build_nanos: u64 = outcomes.iter().map(|o| o.build_nanos).sum();
                let explicit_physical_bytes: u64 = outcomes.iter().map(|o| o.physical_bytes).sum();
                let explicit_logical_bytes: u64 = outcomes
                    .iter()
                    .map(|o| o.changed_bytes + o.reused_bytes)
                    .sum();
                let published = outcomes
                    .iter()
                    .filter(|o| o.status == ManifestationStatus::Published)
                    .count();
                let generation_count = ns
                    .manifestation_state()
                    .map(|s| s.generation_count())
                    .unwrap_or(0);
                serde_json::json!({
                    "explicit_objects": outcomes.len(),
                    "explicit_published": published,
                    "explicit_build_nanos": explicit_build_nanos,
                    "explicit_build_micros": explicit_build_micros,
                    "explicit_physical_bytes": explicit_physical_bytes,
                    "explicit_logical_bytes": explicit_logical_bytes,
                    "generation_count_after": generation_count,
                    "cumulative_epoch_build_micros": cumulative_epoch_build_micros as u64,
                    "max_overlay_depth_cap": MAX_OVERLAY_DEPTH,
                    "flatten_after_overlays": FLATTEN_AFTER_OVERLAYS,
                })
            } else {
                serde_json::Value::Null
            };

            let workload = run_workload(
                &ns,
                committed_root,
                &inodes,
                p.read_len,
                p.object_bytes,
                p.rounds,
            );
            let workload_digest = workload.digest_hex.clone();

            let acc = stats::account_volume(dir).expect("account volume");
            let total_extents: usize = inodes
                .iter()
                .map(|&i| ns.extent_count(i, committed_root).unwrap_or(0))
                .sum();
            let recovery = recovery_json(dir, 3);

            checkpoints.push(serde_json::json!({
                "epoch": epoch,
                "committed_root": committed_root,
                "total_extents": total_extents,
                "logical_object_bytes": p.object_bytes,
                "objects": p.objects,
                "workload": workload.summary(),
                "physical": {
                    "m_log": acc.m_log,
                    "m_ekbloom": acc.m_ekbloom,
                    "m_indexes": acc.m_indexes,
                    "m_other": acc.m_other,
                    "m_total": acc.m_total,
                    "authoritative_canonical_bytes": acc.authoritative_canonical_bytes,
                    "logical_live_bytes": acc.logical_live_bytes,
                    "physical_overhead_bytes": acc.physical_overhead_bytes,
                    "manifested_generations": acc.manifested_generations,
                    "manifested_inodes": acc.manifested_inodes,
                    "manifested_bytes": acc.manifested_bytes,
                },
                "resident_kib": resident_kib(),
                "recovery": recovery,
                "construction": construction,
            }));
            roots.push(committed_root);
            digests.push(workload_digest);
        }

        if epoch < max_epoch {
            let t = Instant::now();
            for w in 0..p.epoch_writes {
                for (oi, &ino) in inodes.iter().enumerate() {
                    let mut rng = Lcg::new(epoch, oi as u64);
                    // Advance the deterministic stream by `w` draws.
                    for _ in 0..w {
                        let _ = rng.next();
                    }
                    let off = rng.below(p.object_bytes - WRITE_LEN);
                    ns.write_at(ino, off, &content_at(off, WRITE_LEN as usize))
                        .expect("epoch write");
                }
            }
            let dt = t.elapsed().as_micros();
            history_build_wall_micros += dt;
            cumulative_epoch_build_micros += dt;
        }
    }
    ns.sync().ok();

    Arm {
        checkpoints,
        roots,
        digests,
        history_build_wall_micros,
        resident_kib: resident_kib(),
    }
}

// ---------------------------------------------------------------------------
// The court
// ---------------------------------------------------------------------------

struct CourtOutcome {
    authoritative: Arm,
    manifested: Arm,
}

fn run_court(dir: &Path, plan: &CourtPlan) -> CourtOutcome {
    // Two sibling volumes so the two arms never share a backing directory; the
    // fixed UUID + deterministic writes make the built histories identical.
    let auth_dir = dir.join("authoritative");
    let man_dir = dir.join("manifested");
    std::fs::create_dir_all(&auth_dir).expect("auth dir");
    std::fs::create_dir_all(&man_dir).expect("man dir");

    let authoritative = run_arm(&auth_dir, plan, false);
    let manifested = run_arm(&man_dir, plan, true);

    // Correctness: identical committed history, byte-exact pinned-root reads.
    assert_eq!(
        authoritative.roots, manifested.roots,
        "the two arms must build the identical committed history"
    );
    assert_eq!(
        authoritative.digests, manifested.digests,
        "every pinned-root read must be byte-identical between the arms"
    );

    CourtOutcome {
        authoritative,
        manifested,
    }
}

fn cp_u64(cp: &serde_json::Value, path: &[&str]) -> u64 {
    let mut v = cp;
    for k in path {
        v = &v[*k];
    }
    v.as_u64().unwrap_or(0)
}

fn ratio(num: u64, den: u64) -> Option<f64> {
    if den == 0 {
        None
    } else {
        Some(num as f64 / den as f64)
    }
}

/// A machine-computed reading of the hypothesis from this run's own numbers.
fn assess(outcome: &CourtOutcome) -> serde_json::Value {
    let a = &outcome.authoritative.checkpoints;
    let m = &outcome.manifested.checkpoints;
    let (a_first, a_last) = (&a[0], a.last().expect("authoritative checkpoints"));
    let (m_first, m_last) = (&m[0], m.last().expect("manifested checkpoints"));

    let a_first_p50 = cp_u64(a_first, &["workload", "p50_ns"]);
    let a_last_p50 = cp_u64(a_last, &["workload", "p50_ns"]);
    let m_first_p50 = cp_u64(m_first, &["workload", "p50_ns"]);
    let m_last_p50 = cp_u64(m_last, &["workload", "p50_ns"]);
    let served_last = cp_u64(m_last, &["workload", "manifested_served_reads"]);
    let samples_last = cp_u64(m_last, &["workload", "samples"]);
    let a_first_phys = cp_u64(a_first, &["physical", "m_total"]);
    let a_last_phys = cp_u64(a_last, &["physical", "m_total"]);
    let m_first_phys = cp_u64(m_first, &["physical", "m_total"]);
    let m_last_phys = cp_u64(m_last, &["physical", "m_total"]);
    let m_last_gens = cp_u64(m_last, &["physical", "manifested_generations"]);
    let a_first_rec = cp_u64(a_first, &["recovery", "authoritative_index_rebuild_micros"]);
    let a_last_rec = cp_u64(a_last, &["recovery", "authoritative_index_rebuild_micros"]);
    let m_first_rec = cp_u64(m_first, &["recovery", "manifest_recovery_micros"]);
    let m_last_rec = cp_u64(m_last, &["recovery", "manifest_recovery_micros"]);

    // Steady-state manifested reads: checkpoints where at least half of the reads
    // were served by a manifested path. The p50 *between* onset and the deepest
    // checkpoint is the honest measure of "does it degrade once manifestations are
    // actually reused?".
    let mut selected: Vec<(u64, u64)> = Vec::new();
    for cp in m {
        let served = cp_u64(cp, &["workload", "manifested_served_reads"]);
        let samples = cp_u64(cp, &["workload", "samples"]);
        if samples > 0 && (served as f64) >= 0.5 * (samples as f64) {
            selected.push((cp_u64(cp, &["epoch"]), cp_u64(cp, &["workload", "p50_ns"])));
        }
    }
    let (onset_epoch, onset_p50) = selected.first().copied().unwrap_or((0, 0));
    let steady_p50 = selected.last().copied().unwrap_or((0, 0));
    let steady_ratio = if selected.len() >= 2 {
        ratio(steady_p50.1, onset_p50)
    } else {
        None
    };

    serde_json::json!({
        "statement": "answering the same fixed historical read workload should not \
                      degrade as history grows, and should improve when manifestations \
                      are reused; construction work and persistent bytes grow",
        "authoritative_p50_growth_first_to_last": ratio(a_last_p50, a_first_p50),
        "manifested_p50_cold_first": m_first_p50,
        "manifested_p50_deepest": m_last_p50,
        "manifested_selection_onset_epoch": onset_epoch,
        "manifested_p50_at_selection_onset": onset_p50,
        "manifested_p50_growth_onset_to_deepest": steady_ratio,
        "manifested_over_authoritative_p50_at_deepest": ratio(m_last_p50, a_last_p50),
        "manifested_served_fraction_at_deepest": ratio(served_last, samples_last),
        "authoritative_physical_bytes_growth": ratio(a_last_phys, a_first_phys),
        "manifested_physical_bytes_growth": ratio(m_last_phys, m_first_phys),
        "manifested_generations_at_deepest": m_last_gens,
        "authoritative_recovery_growth": ratio(a_last_rec, a_first_rec),
        "manifested_recovery_growth": ratio(m_last_rec, m_first_rec),
        "manifestation_history_build_overhead_ratio": ratio(
            outcome.manifested.history_build_wall_micros as u64,
            outcome.authoritative.history_build_wall_micros as u64,
        ),
        "assessments": {
            "authoritative_degrades_as_history_grows": a_last_p50 > a_first_p50,
            "manifested_flat_once_selected": steady_ratio.map(|r| r <= 1.25).unwrap_or(false),
            "manifested_faster_than_authoritative_at_deepest": m_last_p50 < a_last_p50,
            "persistent_bytes_grow": m_last_phys > m_first_phys
                && a_last_phys > a_first_phys
        },
        "note": "Ratios and booleans are computed from this single run only; the \
                 nanos are host/build dependent. 'manifested_p50_cold_first' is the \
                 genesis checkpoint, before the planner had selected a manifested \
                 path; 'manifested_flat_once_selected' compares the p50 at the \
                 selection onset to the deepest checkpoint, so intermediate planner \
                 choices are reported exactly as measured rather than hidden.",
    })
}

/// The always-on smoke (bounded; runs in the default `cargo test` gate). It builds
/// a small growing history in both arms and asserts the pinned-root reads are
/// byte-exact, then checks the manifested plane actually engaged.
#[test]
fn history_scaling_smoke() {
    let td = TempDir::new().unwrap();
    let plan = smoke_plan();
    let outcome = run_court(td.path(), &plan);

    assert_eq!(
        outcome.authoritative.checkpoints.len(),
        plan.checkpoints.len(),
        "every checkpoint must be measured in the authoritative arm"
    );
    assert_eq!(
        outcome.manifested.checkpoints.len(),
        plan.checkpoints.len(),
        "every checkpoint must be measured in the manifested arm"
    );

    for (i, cp) in outcome.manifested.checkpoints.iter().enumerate() {
        let samples = cp["workload"]["samples"].as_u64().unwrap_or(0);
        assert!(samples > 0, "checkpoint {i} measured no reads");
        // A byte-exact answer is the correctness contract; the cross-arm digest
        // equality is asserted inside `run_court`.
        assert_eq!(
            cp["workload"]["digest_blake3"].as_str(),
            outcome.authoritative.checkpoints[i]["workload"]["digest_blake3"].as_str(),
            "checkpoint {i}: manifested read digest must equal the authoritative one"
        );
    }

    // The manifested plane must actually have engaged and published generations.
    let published: u64 = outcome
        .manifested
        .checkpoints
        .iter()
        .map(|c| {
            c["construction"]["explicit_published"]
                .as_u64()
                .unwrap_or(0)
        })
        .sum();
    assert!(
        published > 0,
        "the manifested arm published no generations at any checkpoint"
    );
}

#[test]
fn history_scaling_sweep() {
    if std::env::var("ORFS_HISTORY_SCALING").as_deref() != Ok("1") {
        eprintln!(
            "history_scaling_sweep: skipped (set ORFS_HISTORY_SCALING=1 to run the full sweep)"
        );
        return;
    }
    let td = TempDir::new().unwrap();
    let plan = sweep_plan();
    let outcome = run_court(td.path(), &plan);

    let environment = serde_json::json!({
        "bench": serde_json::to_value(orfs::bench::Environment::capture(
            std::env::var("ORFS_IMAGE").ok()
        ))
        .unwrap_or(serde_json::Value::Null),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "resident_kib_end": resident_kib(),
    });

    let hypothesis = assess(&outcome);

    let doc = serde_json::json!({
        "schema": "orfs.performance.history-scaling.v1",
        "generated_by": "tests/history_scaling.rs",
        "note": "Single-run, single-host measurements. Absolute nanoseconds are \
                 indicative and depend on the host/build; the *shape* (does the \
                 fixed historical workload degrade as history and manifestations \
                 grow?) and the byte counts are the point. Both arms run the \
                 identical deterministic committed history (pinned roots and \
                 per-checkpoint read digests are asserted equal); only the \
                 concealed manifested plane differs.",
        "comparison_contract": {
            "baseline": "OrFS with manifestation disabled over the same history",
            "baseline_shares": [
                "the same committed, non-withdrawable history",
                "the same pinned-root (snapshot) semantics and read API",
                "the same storage engine, index, and recovery path",
                "the same deterministic workload and byte-exact answers"
            ],
            "baseline_does_not_share": [
                "the concealed manifested plane (EKBLOOM bodies) and its bytes",
                "the measured, certified read planner and its path selection"
            ],
            "manifested_arm": "OrFS with manifestation enabled (profile full); the \
                               plane auto-manifests every committed write and a full \
                               generation is published per object at each checkpoint",
            "conventional_directory_reference": "not used: a plain directory is a \
                                                 different storage interface without \
                                                 committed history or snapshots, so it \
                                                 would not isolate the manifested plane"
        },
        "design": {
            "objects": plan.params.objects,
            "object_bytes": plan.params.object_bytes,
            "epoch_writes_per_object": plan.params.epoch_writes,
            "epoch_write_len": WRITE_LEN,
            "content_neutral": "each epoch writes the exact bytes already present at \
                                misaligned offsets, so live logical content is \
                                byte-identical at every checkpoint while the \
                                authoritative log grows and extents fragment",
            "checkpoints_epochs": plan.checkpoints,
            "read_len": plan.params.read_len,
            "rounds": plan.params.rounds,
            "reads_per_checkpoint": (plan.params.objects as u64)
                * (plan.params.object_bytes / plan.params.read_len)
                * plan.params.rounds,
        },
        "environment": environment,
        "hypothesis": hypothesis,
        "history_build_wall_micros": {
            "authoritative": outcome.authoritative.history_build_wall_micros as u64,
            "manifested": outcome.manifested.history_build_wall_micros as u64,
            "difference_manifestation_overhead":
                outcome
                    .manifested
                    .history_build_wall_micros
                    .saturating_sub(outcome.authoritative.history_build_wall_micros)
                    as u64,
        },
        "arms": {
            "authoritative": {
                "manifestation": "disabled",
                "resident_kib_end": outcome.authoritative.resident_kib,
                "checkpoints": outcome.authoritative.checkpoints,
            },
            "manifested": {
                "manifestation": "enabled (profile full)",
                "resident_kib_end": outcome.manifested.resident_kib,
                "checkpoints": outcome.manifested.checkpoints,
            },
        },
    });

    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("evidence/performance/history-scaling.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!("history-scaling evidence written to {}", path.display());
}
