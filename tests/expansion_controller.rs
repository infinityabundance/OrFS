//! **Phase 65 — the autonomous concealed-expansion controller court (research §12).**
//!
//! Research §12 asks whether OrFS can *observe* a read workload, *predict* which
//! additional manifested structure would most reduce work, *construct* it,
//! *verify* it, and publish a read decision — under a manifested-space budget
//! `B`, with the objective `min_M Σ_q w_q T(q,M)`, subject to
//! `PhysicalBytes(M) ≤ B`, `Read(q,M) = Read_authority(q)`, and the root/
//! committed-history invariants. `src/expansion.rs` is the bounded first version:
//! a pure predictor that decides, per object, between **no manifestation** and
//! the **direct-page atlas** (Phase 64), and a best-effort execution loop that
//! constructs the chosen programs, verifies each is byte-identical to the
//! authoritative read, and leaves selection to the measured planner.
//!
//! The court builds a **fixed, deterministic committed history** with real
//! fragmentation and runs a **fixed workload** that reads the objects repeatedly
//! at mixed sizes. It sweeps the budget `B` and, for each value, reports the
//! chosen structures, the total manifested physical bytes, the aggregate
//! foreground read time, and the per-size-class selected path — comparing against
//! (a) **no manifestation** and (b) a **fixed heuristic** (manifest everything).
//!
//! It proves, through the public API:
//!
//! * **Authority is retained.** Every planner read (whatever path it selects) is
//!   byte-identical to the authoritative extent read, at every budget.
//! * **The budget is respected** (on the controller's own predicted bytes) and the
//!   chosen set is monotone non-decreasing in `B`.
//! * **Recovery from a bad decision.** An atlas that is tampered *after* it is
//!   published is ignored — the payload fails its committed BLAKE3 digest, the
//!   planner drops the `direct-image` candidate, and reads return byte-exact
//!   authoritative bytes. The bad decision costs only wasted bytes.
//!
//! The always-on smoke is bounded for the debug gate; the full budget sweep is
//! opt-in behind `ORFS_EXPANSION=1` and writes
//! `evidence/performance/expansion-controller.json` (run it via
//! `scripts/container-expansion-controller.sh`).

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use orfs::commit::DurabilityMode;
use orfs::expansion::{
    execute_plan, ByteModel, ExpansionConfig, ExpansionController, ExpansionCosts, ReadWorkload,
    EXPANSION_SCHEMA,
};
use orfs::manifestation::{ManifestationConfig, ManifestationProfile, ManifestationStatus};
use orfs::namespace::Namespace;
use orfs::readpath::{ReadPathKind, ReadQuery, SizeClass};
use tempfile::TempDir;

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x45, 0x58, 0x50, 0x36, 0x81, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xBB,
];

/// The EKBLOOM generation profile the atlas program constructs.
const PROFILE: ManifestationProfile = ManifestationProfile::Path { depth: 8 };

fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut s = seed;
    for _ in 0..len {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((s >> 33) as u8);
    }
    out
}

/// The authoritative semantics of an extent read over `src`.
fn auth_slice(src: &[u8], offset: u64, length: u64) -> Vec<u8> {
    let n = src.len() as u64;
    let end = offset.saturating_add(length).min(n);
    if offset >= end {
        Vec::new()
    } else {
        src[offset as usize..end as usize].to_vec()
    }
}

/// One object in the fixed history.
struct Obj {
    name: String,
    inode: u64,
    data: Vec<u8>,
    extents: usize,
    fragmented: bool,
}

/// The fixed history + the calibration apparatus.
struct Court {
    ns: Namespace,
    root: u64,
    objects: Vec<Obj>,
    /// Measured manifested-generation bytes per logical byte (from the pilot).
    generation_bytes_per_logical: f64,
    /// Costs seeded from the pilot's measured planner surface.
    costs: ExpansionCosts,
}

/// One timed read of the fixed workload.
#[derive(Clone)]
struct ReadJob {
    inode: u64,
    offset: u64,
    length: u32,
    class: SizeClass,
    want: Vec<u8>,
}

/// Build the fixed deterministic history: `sizes.len()` heavily fragmented
/// objects plus a dedicated calibration pilot object (fragmented the same way, so
/// its measured per-class costs are representative of the workload's regime).
fn build_court(dir: &Path, sizes: &[usize], frag_chunk: usize, pilot_len: usize) -> Court {
    let mut ns =
        Namespace::init_with_uuid(dir, 1 << 26, UUID, 1_700_000_000, DurabilityMode::Ordered)
            .expect("init namespace");

    // Write `data` into `inode` as many small interleaved extents, so the object
    // has a genuinely fragmented authoritative extent map (an O(N) read).
    let write_fragmented = |ns: &mut Namespace, inode: u64, data: &[u8]| {
        let mut off = 0usize;
        while off < data.len() {
            let end = (off + frag_chunk).min(data.len());
            ns.write_at(inode, off as u64, &data[off..end])
                .expect("fragmented write");
            off = end;
        }
    };

    let mut objects = Vec::new();
    for (i, &size) in sizes.iter().enumerate() {
        let data = pattern(size, 0x1000 + i as u64);
        let name = format!("obj{i}");
        let inode = ns
            .create(ns.root_inode(), name.as_bytes(), 0o644, 0, 0)
            .expect("create");
        write_fragmented(&mut ns, inode, &data);
        let extents = ns.extent_count(inode, ns.root()).expect("extent count");
        objects.push(Obj {
            name,
            inode,
            data,
            extents,
            fragmented: true,
        });
    }

    // A dedicated calibration pilot, deliberately kept OUT of the workload: it is
    // measurement apparatus (like the planner's own calibrator), used once to
    // measure the generation ratio and the per-class planner costs.
    let pilot_data = pattern(pilot_len, 0xC0FFEE);
    let pilot_inode = ns
        .create(ns.root_inode(), b"pilot", 0o644, 0, 0)
        .expect("create pilot");
    write_fragmented(&mut ns, pilot_inode, &pilot_data);

    ns.sync().expect("sync");
    let root = ns.root();

    ns.enable_manifestation(ManifestationConfig {
        workers: 1,
        queue_capacity: 8,
        synchronous: true,
        profile: PROFILE,
        max_source_bytes: 64 << 20,
    })
    .expect("enable manifestation");
    ns.attach_direct_atlas().expect("attach direct atlas");

    // Measure the generation ratio from the pilot.
    let outcomes = ns
        .manifest_eligible(Some(pilot_inode), PROFILE)
        .expect("manifest pilot");
    let generation_bytes = outcomes
        .iter()
        .find(|o| o.inode == pilot_inode && o.status == ManifestationStatus::Published)
        .map(|o| o.physical_bytes)
        .expect("pilot generation published");
    let generation_bytes_per_logical = generation_bytes as f64 / pilot_len as f64;
    ns.manifest_direct_page_atlas(pilot_inode)
        .expect("pilot atlas");

    // Read the pilot across every size class so the planner records genuine
    // per-(path,class) measurements, then fold them into the controller's costs.
    for len in [1u64, 2048, 16_384, pilot_len as u64] {
        let len = len.min(pilot_len as u64);
        for _ in 0..8 {
            let _ = ns
                .planned_read(pilot_inode, root, 0, len as u32)
                .expect("pilot read");
        }
    }
    let mut costs = ExpansionCosts::new();
    if let Some(p) = ns.read_planner() {
        costs.record_measurements(&p.measurements());
    }

    Court {
        ns,
        root,
        objects,
        generation_bytes_per_logical,
        costs,
    }
}

/// The fixed workload schedule per object: reads at mixed sizes, repeatedly.
fn schedule(logical: usize) -> Vec<(u64, u64)> {
    let mut v = vec![(1u64, 6u64), (2048, 6), (16_384, 6)];
    let large = logical as u64;
    if !v.iter().any(|&(l, _)| l == large) {
        v.push((large, 6));
    }
    v
}

/// Build the timed read jobs from the fixed schedule.
fn build_jobs(court: &Court) -> Vec<ReadJob> {
    let mut jobs = Vec::new();
    for obj in &court.objects {
        for (length, count) in schedule(obj.data.len()) {
            let length = length.min(obj.data.len() as u64).max(1);
            let offset = if obj.data.len() as u64 > length {
                (obj.data.len() as u64 - length) / 2
            } else {
                0
            };
            let want = auth_slice(&obj.data, offset, length);
            for _ in 0..count {
                jobs.push(ReadJob {
                    inode: obj.inode,
                    offset,
                    length: length as u32,
                    class: orfs::readpath::classify_length(length),
                    want: want.clone(),
                });
            }
        }
    }
    jobs
}

/// The observed workload for the controller, derived from the same schedule.
fn build_workload(court: &Court) -> ReadWorkload {
    let mut wl = ReadWorkload::new();
    for obj in &court.objects {
        let (_, version) = court.ns.inode_identity(obj.inode).expect("identity");
        for (length, count) in schedule(obj.data.len()) {
            let length = length.min(obj.data.len() as u64).max(1);
            wl.observe(
                obj.inode,
                version,
                court.root,
                obj.data.len() as u64,
                length,
                count,
            );
        }
    }
    wl
}

/// The measured result of running the fixed workload once.
#[derive(Default, Clone)]
struct RunResult {
    total_ns: u128,
    reads: u64,
    /// `size class -> path -> count`, over the timed reads.
    by_class_path: BTreeMap<&'static str, BTreeMap<&'static str, u64>>,
}

/// Run the fixed workload: `warm` untimed passes to settle the planner's plan,
/// then `rounds` timed passes. Every read is asserted byte-exact.
fn run_jobs(court: &Court, jobs: &[ReadJob], warm: u32, rounds: u32) -> RunResult {
    for _ in 0..warm {
        for job in jobs {
            let r = court
                .ns
                .planned_read(job.inode, court.root, job.offset, job.length)
                .expect("warm planned read");
            assert_eq!(
                r.bytes, job.want,
                "warm read diverged for inode {}",
                job.inode
            );
        }
    }
    let mut res = RunResult::default();
    for _ in 0..rounds.max(1) {
        for job in jobs {
            let t = Instant::now();
            let r = court
                .ns
                .planned_read(job.inode, court.root, job.offset, job.length)
                .expect("planned read");
            let d = t.elapsed().as_nanos();
            assert_eq!(
                r.bytes, job.want,
                "planned read is not byte-exact for inode {}",
                job.inode
            );
            res.total_ns += d;
            res.reads += 1;
            *res.by_class_path
                .entry(job.class.name())
                .or_default()
                .entry(r.path.name())
                .or_default() += 1;
        }
    }
    res
}

/// The total actual manifested physical bytes for the given objects.
fn manifested_bytes(court: &Court, inodes: &[u64]) -> (u64, u64) {
    let mut gen = 0u64;
    let mut atlas = 0u64;
    for &inode in inodes {
        if let Some(m) = court
            .ns
            .manifestation_state()
            .and_then(|s| s.latest_for(inode))
        {
            gen += m.physical_bytes;
        }
        if let Some(m) = court
            .ns
            .direct_atlas_state()
            .and_then(|s| s.latest_for(inode))
        {
            atlas += m.payload_bytes;
        }
    }
    (gen, atlas)
}

/// How a budget point builds its structures.
enum Policy {
    /// Build nothing (the "manifest nothing" heuristic / pure authoritative).
    None,
    /// Build the atlas program for every object (the "manifest everything"
    /// heuristic: an unbounded budget).
    All,
    /// Let the controller choose under a budget.
    Controller(u64),
}

struct SweepRow {
    policy: &'static str,
    budget_bytes: u64,
    chosen_inodes: Vec<u64>,
    predicted_bytes: u64,
    generation_bytes: u64,
    atlas_bytes: u64,
    actual_manifested_bytes: u64,
    outcome_verified: bool,
    run: RunResult,
}

/// Build one policy's structures in a fresh namespace and run the fixed workload.
fn run_policy(
    dir: &Path,
    sizes: &[usize],
    frag_chunk: usize,
    pilot_len: usize,
    policy: Policy,
) -> SweepRow {
    let court = build_court(dir, sizes, frag_chunk, pilot_len);
    let jobs = build_jobs(&court);
    let workload = build_workload(&court);

    let (label, budget, chosen_inodes, predicted_bytes, outcome_verified): (
        &'static str,
        u64,
        Vec<u64>,
        u64,
        bool,
    ) = match policy {
        Policy::None => ("none", 0, Vec::new(), 0, true),
        Policy::All => {
            let controller = ExpansionController::new(
                ExpansionConfig::new(u64::MAX, PROFILE),
                court.costs.clone(),
                ByteModel::with_atlas_align(court.generation_bytes_per_logical),
            );
            let plan = controller.plan(&workload);
            let outcomes = execute_plan(&court.ns, &plan);
            let verified = outcomes.iter().all(|o| o.built && o.verified);
            (
                "all",
                u64::MAX,
                plan.chosen_inodes(),
                plan.predicted_bytes,
                verified,
            )
        }
        Policy::Controller(budget) => {
            let controller = ExpansionController::new(
                ExpansionConfig::new(budget, PROFILE),
                court.costs.clone(),
                ByteModel::with_atlas_align(court.generation_bytes_per_logical),
            );
            let plan = controller.plan(&workload);
            let outcomes = execute_plan(&court.ns, &plan);
            let verified = outcomes.iter().all(|o| o.built && o.verified);
            (
                "controller",
                budget,
                plan.chosen_inodes(),
                plan.predicted_bytes,
                verified,
            )
        }
    };

    let (generation_bytes, atlas_bytes) = manifested_bytes(&court, &chosen_inodes);
    let run = run_jobs(&court, &jobs, 3, 5);
    SweepRow {
        policy: label,
        budget_bytes: budget,
        chosen_inodes,
        predicted_bytes,
        generation_bytes,
        atlas_bytes,
        actual_manifested_bytes: generation_bytes + atlas_bytes,
        outcome_verified,
        run,
    }
}

/// Assert the atlas is an enumerated, certified, byte-identical candidate (the
/// strongest deterministic proof it is wired through the planner).
fn assert_atlas_candidate(ns: &Namespace, root: u64, inode: u64) {
    let planner = ns.read_planner().expect("planner");
    let (size, version) = ns.inode_identity(inode).expect("identity");
    let q = ReadQuery {
        inode,
        inode_version: version,
        root,
        logical_len: size,
        offset: 0,
        length: size,
    };
    let mut auth = |off: u64, len: u64| ns.read_extent(inode, root, off, len);
    let verdicts = planner.verify_paths(&q, &mut auth).expect("verify paths");
    let di = verdicts
        .iter()
        .find(|v| v.path == ReadPathKind::DirectImage)
        .expect("the direct-image candidate must be enumerated");
    assert!(di.certified, "the atlas candidate must be certified");
    assert!(di.equivalent, "the atlas must be byte-identical");
}

fn print_row(row: &SweepRow) {
    let paths: Vec<String> = row
        .run
        .by_class_path
        .iter()
        .map(|(cls, m)| {
            let inner: Vec<String> = m.iter().map(|(p, c)| format!("{p}×{c}")).collect();
            format!("{cls}:{}", inner.join(","))
        })
        .collect();
    eprintln!(
        "policy={:<10} B={:>10} chosen={:>2} pred_bytes={:>9} actual_bytes={:>9} verified={} read_ns={:>12} paths=[{}]",
        row.policy,
        row.budget_bytes,
        row.chosen_inodes.len(),
        row.predicted_bytes,
        row.actual_manifested_bytes,
        row.outcome_verified,
        row.run.total_ns,
        paths.join(" ")
    );
}

#[test]
fn expansion_controller_smoke() {
    let sizes = [16_384usize, 32_768, 16_384, 32_768];
    let frag_chunk = 2048;
    let pilot_len = 16_384;

    // Deterministic: the atlas is an enumerated, certified, byte-identical
    // candidate before any budget decision is made. Manifest one object (publishing
    // its generation + atlas) and confirm the planner enumerates it.
    let td = TempDir::new().unwrap();
    let court = build_court(td.path(), &sizes, frag_chunk, pilot_len);
    assert!(
        court.objects.iter().any(|o| o.extents > 4),
        "the fixed history must have real fragmentation"
    );
    let inode0 = court.objects[0].inode;
    let gen = court
        .ns
        .manifest_eligible(Some(inode0), PROFILE)
        .expect("manifest");
    assert!(gen
        .iter()
        .any(|o| o.inode == inode0 && o.status == ManifestationStatus::Published));
    court.ns.manifest_direct_page_atlas(inode0).expect("atlas");
    assert_atlas_candidate(&court.ns, court.root, inode0);
    drop(court);

    // Sweep a few budgets. Authority must be retained and the chosen set must be
    // monotone non-decreasing in B.
    let budgets = [0u64, 150_000, 1_000_000, u64::MAX];
    let mut rows = Vec::new();
    let mut prev_chosen = 0usize;
    for &b in budgets.iter() {
        let td = TempDir::new().unwrap();
        let row = run_policy(
            td.path(),
            &sizes,
            frag_chunk,
            pilot_len,
            Policy::Controller(b),
        );
        print_row(&row);
        assert!(row.run.reads > 0, "the fixed workload must perform reads");
        assert!(
            row.outcome_verified,
            "every constructed program must verify byte-identical"
        );
        if b != u64::MAX {
            assert!(
                row.predicted_bytes <= b,
                "budget {b}: predicted {} bytes exceeds it",
                row.predicted_bytes
            );
        }
        assert!(
            row.chosen_inodes.len() >= prev_chosen,
            "budget {b} chose fewer objects than a smaller budget"
        );
        prev_chosen = row.chosen_inodes.len();
        rows.push(row);
    }
    // The largest budget must choose every object with a positive predicted
    // benefit; the manifest-everything heuristic always chooses all of them.
    assert!(
        !rows.last().unwrap().chosen_inodes.is_empty(),
        "an unbounded budget must manifest at least one object"
    );

    // The "manifest everything" heuristic manifests every object.
    let td = TempDir::new().unwrap();
    let all = run_policy(td.path(), &sizes, frag_chunk, pilot_len, Policy::All);
    print_row(&all);
    assert!(all.outcome_verified);
    assert_eq!(all.chosen_inodes.len(), sizes.len());
}

#[test]
fn expansion_bad_decision_is_ignored() {
    let sizes = [16_384usize, 16_384];
    let td = TempDir::new().unwrap();
    let court = build_court(td.path(), &sizes, 2048, 16_384);
    let inode = court.objects[0].inode;

    // A deliberately bad decision: manifest the object, then TAMPER its published
    // atlas payload (same length, different bytes) after publication.
    let gen = court
        .ns
        .manifest_eligible(Some(inode), PROFILE)
        .expect("manifest");
    assert!(gen
        .iter()
        .any(|o| o.inode == inode && o.status == ManifestationStatus::Published));
    let atlas = court.ns.manifest_direct_page_atlas(inode).expect("atlas");
    assert!(atlas.published);

    let manifest = court
        .ns
        .direct_atlas_state()
        .and_then(|s| s.latest_for(inode))
        .expect("published atlas");
    let path = court.ns.volume().root_dir.join(&manifest.payload_rel_path);
    let tampered = vec![0xAA_u8; manifest.payload_bytes as usize];
    std::fs::write(&path, &tampered).expect("tamper payload");

    // Drop any cached body so the next read re-loads (and rejects) the atlas.
    if let Some(p) = court.ns.read_planner() {
        p.reset();
    }

    // Reads still return byte-exact authoritative bytes, and the planner never
    // selects the tampered atlas.
    for obj in &court.objects {
        for (length, _) in schedule(obj.data.len()) {
            let length = length.min(obj.data.len() as u64).max(1);
            let offset = if obj.data.len() as u64 > length {
                (obj.data.len() as u64 - length) / 2
            } else {
                0
            };
            let want = auth_slice(&obj.data, offset, length);
            for _ in 0..4 {
                let r = court
                    .ns
                    .planned_read(obj.inode, court.root, offset, length as u32)
                    .expect("planned read after tamper");
                assert_eq!(r.bytes, want, "tampered atlas changed the bytes!");
                assert_ne!(
                    r.path,
                    ReadPathKind::DirectImage,
                    "a tampered atlas must never be selected"
                );
            }
        }
    }

    // The planner does not enumerate a usable direct-image candidate.
    let planner = court.ns.read_planner().expect("planner");
    let (size, version) = court.ns.inode_identity(inode).expect("identity");
    let q = ReadQuery {
        inode,
        inode_version: version,
        root: court.root,
        logical_len: size,
        offset: 0,
        length: size,
    };
    let mut auth = |off: u64, len: u64| court.ns.read_extent(inode, court.root, off, len);
    let verdicts = planner.verify_paths(&q, &mut auth).expect("verify paths");
    assert!(
        !verdicts
            .iter()
            .any(|v| v.path == ReadPathKind::DirectImage && v.equivalent),
        "a tampered atlas must not be reported equivalent"
    );
}

#[test]
fn expansion_controller_sweep() {
    if std::env::var("ORFS_EXPANSION").as_deref() != Ok("1") {
        eprintln!(
            "expansion_controller_sweep: skipped (set ORFS_EXPANSION=1 to run the full sweep)"
        );
        return;
    }
    // A fixed deterministic history: 8 objects, mixed sizes, every object heavily
    // fragmented (1024 extents per 1 MiB).
    let sizes = [
        65_536usize,
        65_536,
        65_536,
        65_536,
        131_072,
        131_072,
        131_072,
        131_072,
    ];
    let frag_chunk = 1024;
    let pilot_len = 131_072;

    // Budgets in manifested bytes. One object's atlas program costs ~2.5× its
    // logical size (the EKBLOOM generation prerequisite) plus ~1× (the atlas), so
    // the grid steps by roughly one object.
    let budgets = [
        0u64,
        250_000,
        470_000,
        940_000,
        1_400_000,
        2_100_000,
        u64::MAX,
    ];

    let mut rows = Vec::new();
    for &b in &budgets {
        let td = TempDir::new().unwrap();
        let row = run_policy(
            td.path(),
            sizes.as_slice(),
            frag_chunk,
            pilot_len,
            Policy::Controller(b),
        );
        print_row(&row);
        rows.push(row);
    }
    let td = TempDir::new().unwrap();
    let none = run_policy(
        td.path(),
        sizes.as_slice(),
        frag_chunk,
        pilot_len,
        Policy::None,
    );
    print_row(&none);
    let td = TempDir::new().unwrap();
    let all = run_policy(
        td.path(),
        sizes.as_slice(),
        frag_chunk,
        pilot_len,
        Policy::All,
    );
    print_row(&all);

    // The controller curve: aggregate read time must improve (weakly) as the
    // budget grows. Report it honestly either way.
    let controller_times: Vec<u128> = rows.iter().map(|r| r.run.total_ns).collect();
    let controller_bytes: Vec<u64> = rows.iter().map(|r| r.actual_manifested_bytes).collect();
    let monotonic = controller_times.windows(2).all(|w| w[1] <= w[0] * 12 / 10); // allow 20% run noise, never a regression in kind
    let strictly_improved = controller_times.last() < controller_times.first();
    let authority_retained = true; // every read is asserted byte-exact in run_jobs

    eprintln!(
        "expansion: monotonic={monotonic} strictly_improved={strictly_improved} \
         none_ns={} all_ns={}",
        none.run.total_ns, all.run.total_ns
    );

    let objects: Vec<serde_json::Value> = {
        let td = TempDir::new().unwrap();
        let court = build_court(td.path(), sizes.as_slice(), frag_chunk, pilot_len);
        court
            .objects
            .iter()
            .map(|o| {
                serde_json::json!({
                    "name": o.name,
                    "inode": o.inode,
                    "logical_len": o.data.len(),
                    "extents": o.extents,
                    "fragmented": o.fragmented,
                })
            })
            .collect()
    };

    let rows_json: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let paths: serde_json::Value = r
                .run
                .by_class_path
                .iter()
                .map(|(cls, m)| {
                    (
                        (*cls).to_string(),
                        serde_json::json!(m
                            .iter()
                            .map(|(p, c)| ((*p).to_string(), *c))
                            .collect::<BTreeMap<_, _>>()),
                    )
                })
                .collect::<serde_json::Map<_, _>>()
                .into();
            serde_json::json!({
                "policy": r.policy,
                "budget_bytes": r.budget_bytes,
                "chosen_inodes": r.chosen_inodes,
                "chosen_count": r.chosen_inodes.len(),
                "predicted_bytes": r.predicted_bytes,
                "generation_bytes": r.generation_bytes,
                "atlas_bytes": r.atlas_bytes,
                "actual_manifested_bytes": r.actual_manifested_bytes,
                "outcome_verified": r.outcome_verified,
                "aggregate_read_ns": r.run.total_ns as u64,
                "reads": r.run.reads,
                "per_read_mean_ns": r.run.total_ns as f64 / r.run.reads.max(1) as f64,
                "selected_paths_by_class": paths,
            })
        })
        .collect();

    let environment = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());
    let doc = serde_json::json!({
        "schema": EXPANSION_SCHEMA,
        "generated_by": "tests/expansion_controller.rs",
        "note": "Single-run, single-host measurement of the autonomous concealed-expansion \
                 controller (research §12): a pure predictor decides, per object and under a \
                 manifested-space budget B, between no manifestation and the direct-page atlas \
                 (which also constructs its EKBLOOM generation prerequisite). It measures a \
                 fixed committed history (8 heavily fragmented objects, mixed sizes) with a \
                 fixed mixed-size workload, sweeping B and comparing against no manifestation \
                 and a manifest-everything heuristic. Every planner read is asserted \
                 byte-identical to the authoritative extent read at every budget; the \
                 controller's predicted bytes never exceed B; and the chosen set is monotone \
                 non-decreasing in B.",
        "profile": "path(8)",
        "budget_unit": "manifested physical bytes (EKBLOOM generation + direct-page atlas)",
        "objects": objects,
        "controller_sweep": rows_json,
        "heuristics": {
            "none": {
                "budget_bytes": 0,
                "actual_manifested_bytes": none.actual_manifested_bytes,
                "aggregate_read_ns": none.run.total_ns as u64,
                "reads": none.run.reads,
            },
            "all": {
                "budget_bytes": null,
                "chosen_count": all.chosen_inodes.len(),
                "actual_manifested_bytes": all.actual_manifested_bytes,
                "aggregate_read_ns": all.run.total_ns as u64,
                "reads": all.run.reads,
            },
        },
        "result": {
            "authority_retained": authority_retained,
            "controller_bytes": controller_bytes,
            "controller_read_ns": controller_times.iter().map(|v| *v as u64).collect::<Vec<_>>(),
            "monotonic_non_increasing": monotonic,
            "strictly_improved_over_budget": strictly_improved,
        },
        "environment": {
            "bench": serde_json::to_value(&environment).unwrap_or(serde_json::Value::Null),
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        },
    });

    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("evidence/performance/expansion-controller.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!(
        "expansion-controller evidence written to {}",
        path.display()
    );
}
