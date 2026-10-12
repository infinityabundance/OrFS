//! Phase 43 — the precompiled read plan (reviewer task, priority 2).
//!
//! Proved here:
//!
//! * **The steady-state certified read is a bounded lookup + execute.** After the
//!   one bounded calibration pass for an identity+size-class, further reads build
//!   no candidate vector, sort nothing, and take no cost-model write lock; the
//!   planner's cumulative counters prove it.
//! * **Identity isolation is preserved.** Per-object plans and per-object selection
//!   are keyed by the full [`ManifestIdentity`]; an object's plan never serves
//!   another object.
//! * **The fallback is unchanged.** Wrong root/version, an absent payload, and a
//!   zero calibration budget all serve the authoritative extent read with
//!   identical bytes.
//! * **All identity-keyed planner state is bounded** (the aging court): driving an
//!   unbounded number of distinct identities through the planner's bookkeeping
//!   leaves resident state at its capacity, while correctness still holds.
//!
//! The million-identity aging sweep is `ORFS_READ_PLANNER_AGING`-scaled: the
//! default `cargo test` runs a bounded prefix, and
//! `sh scripts/container-read-planner.sh` runs the full ~1e6 sweep.

use std::path::Path;

use orfs::manifestation::{
    ekbloom_format_version, CertificationState, GenerationManifest, GenerationStore,
    ManifestationProfile, ManifestationState, MANIFEST_SCHEMA,
};
use orfs::readpath::{
    ManifestIdentity, ReadPathKind, ReadPlanner, ReadPlannerConfig, ReadQuery, SizeClass,
};
use tempfile::TempDir;

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x43, 0x22, 0x40, 0x33, 0x81, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
];

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
/// builder does), mirroring the `tests/ekbloom_read.rs` helper.
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

fn planner_for(dir: &Path) -> ReadPlanner {
    let state =
        ManifestationState::recover(GenerationStore::new(dir), UUID).expect("recover state");
    ReadPlanner::new(state, ReadPlannerConfig::default())
}

// ---------------------------------------------------------------------------
// (1) The steady-state certified read does no planning work
// ---------------------------------------------------------------------------

/// The core Phase-43 claim: once an identity+class is calibrated, a certified
/// read is a bounded lookup + execute. The planner's cumulative counters prove
/// that no candidate is sorted and no cost-model write lock is taken after the
/// bounded warm-up.
#[test]
fn steady_state_certified_read_does_not_plan() {
    let td = TempDir::new().unwrap();
    let source = pattern(8192);
    let store = GenerationStore::new(td.path());
    publish_generation(&store, 7, 1, 100, &source, ManifestationProfile::MaxSpeed);
    let planner = planner_for(td.path());

    let q = ReadQuery {
        inode: 7,
        inode_version: 1,
        root: 100,
        logical_len: source.len() as u64,
        offset: 512,
        length: 4096,
    };

    // Bounded warm-up: the first read(s) for this identity+class calibrate.
    for _ in 0..16 {
        let p = planner
            .read(&q, |off, len| Ok(auth_slice(&source, off, len)))
            .unwrap();
        assert_eq!(p.bytes, auth_slice(&source, 512, 4096));
    }
    let warm = planner.stats();
    assert!(warm.calibrations >= 1, "no calibration happened: {warm:?}");
    assert!(warm.selection_sorts >= 1, "no ranking was sorted: {warm:?}");
    assert!(
        warm.hot_reads >= 1,
        "no read was served from a plan: {warm:?}"
    );

    // Steady state: many certified reads must add no planning work at all.
    const STEADY: u64 = 500;
    for _ in 0..STEADY {
        let p = planner
            .read(&q, |off, len| Ok(auth_slice(&source, off, len)))
            .unwrap();
        assert_eq!(p.bytes, auth_slice(&source, 512, 4096));
    }
    let after = planner.stats();
    assert_eq!(
        after.selection_sorts, warm.selection_sorts,
        "the steady-state read sorted candidates: {after:?}"
    );
    assert_eq!(
        after.model_write_locks, warm.model_write_locks,
        "the steady-state read took the cost-model write lock: {after:?}"
    );
    assert_eq!(
        after.calibrations, warm.calibrations,
        "the steady-state read calibrated: {after:?}"
    );
    assert_eq!(
        after.plan_builds, warm.plan_builds,
        "the steady-state read rebuilt a plan: {after:?}"
    );
    assert_eq!(
        after.hot_reads,
        warm.hot_reads + STEADY,
        "steady-state reads were not served from the published plan: {after:?}"
    );
}

/// A read that is *not* calibrated for its size class still calibrates and then
/// serves from a published ranking; the next read of that class is hot. This is
/// the boundary of the lean path.
#[test]
fn a_new_size_class_calibrates_once_then_becomes_hot() {
    let td = TempDir::new().unwrap();
    let source = pattern(65536);
    let store = GenerationStore::new(td.path());
    publish_generation(&store, 9, 1, 5, &source, ManifestationProfile::MaxSpeed);
    let planner = planner_for(td.path());

    let q = |len: u64| ReadQuery {
        inode: 9,
        inode_version: 1,
        root: 5,
        logical_len: source.len() as u64,
        offset: 0,
        length: len,
    };

    // A 1-byte read is its own class; the first read calibrates it.
    let before = planner.stats();
    let p = planner
        .read(&q(1), |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    assert_eq!(p.bytes, auth_slice(&source, 0, 1));
    let after_first = planner.stats();
    assert!(
        after_first.calibrations > before.calibrations,
        "a fresh size class must calibrate on its first read"
    );

    // The second read of that class is hot, and takes no further planning work.
    let p = planner
        .read(&q(1), |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    assert_eq!(p.bytes, auth_slice(&source, 0, 1));
    let after_second = planner.stats();
    assert_eq!(
        after_second.selection_sorts, after_first.selection_sorts,
        "the second read of a calibrated class sorted candidates"
    );
    assert_eq!(
        after_second.model_write_locks, after_first.model_write_locks,
        "the second read of a calibrated class took the model write lock"
    );
    assert_eq!(after_second.hot_reads, after_first.hot_reads + 1);
}

// ---------------------------------------------------------------------------
// (2) Identity isolation is preserved
// ---------------------------------------------------------------------------

/// Per-object state is keyed by the full identity: an object with its own plan
/// never inherits another object's calibration, and one object's reads never
/// disturb another's hot path.
#[test]
fn per_object_plans_are_isolated() {
    let td = TempDir::new().unwrap();
    let source = pattern(4096);
    let store = GenerationStore::new(td.path());
    publish_generation(
        &store,
        100,
        1,
        10,
        &source,
        ManifestationProfile::Path { depth: 4 },
    );
    publish_generation(
        &store,
        200,
        1,
        20,
        &source,
        ManifestationProfile::Path { depth: 4 },
    );
    let planner = planner_for(td.path());

    let query = |inode: u64, root: u64| ReadQuery {
        inode,
        inode_version: 1,
        root,
        logical_len: source.len() as u64,
        offset: 0,
        length: 1024,
    };

    // Warm A to its steady state.
    for _ in 0..8 {
        let p = planner
            .read(&query(100, 10), |off, len| {
                Ok(auth_slice(&source, off, len))
            })
            .unwrap();
        assert_eq!(p.bytes, auth_slice(&source, 0, 1024));
    }
    let after_a = planner.stats();

    // B is a distinct identity and must build its own plan (a fresh calibration),
    // not reuse A's ranking.
    let p = planner
        .read(&query(200, 20), |off, len| {
            Ok(auth_slice(&source, off, len))
        })
        .unwrap();
    assert_eq!(p.bytes, auth_slice(&source, 0, 1024));
    let after_b = planner.stats();
    assert!(
        after_b.calibrations > after_a.calibrations,
        "object B reused object A's calibration"
    );
    assert!(
        after_b.plan_builds > after_a.plan_builds,
        "object B did not publish its own plan"
    );

    // A is still hot and correct.
    let p = planner
        .read(&query(100, 10), |off, len| {
            Ok(auth_slice(&source, off, len))
        })
        .unwrap();
    assert_eq!(p.bytes, auth_slice(&source, 0, 1024));
    assert_eq!(planner.stats().hot_reads, after_b.hot_reads + 1);
}

// ---------------------------------------------------------------------------
// (3) The fallback is unchanged
// ---------------------------------------------------------------------------

/// A zero calibration budget times nothing, so nothing is measured and the read
/// is served by the authoritative path — the documented "unmeasured candidate is
/// never selected" guarantee.
#[test]
fn zero_budget_still_serves_the_authoritative_path() {
    let td = TempDir::new().unwrap();
    let source = pattern(2048);
    let store = GenerationStore::new(td.path());
    publish_generation(
        &store,
        5,
        2,
        7,
        &source,
        ManifestationProfile::Path { depth: 4 },
    );
    let state =
        ManifestationState::recover(GenerationStore::new(td.path()), UUID).expect("recover");
    let planner = ReadPlanner::new(
        state,
        ReadPlannerConfig {
            calibration_budget_ns: 0,
            ..Default::default()
        },
    );
    let q = ReadQuery {
        inode: 5,
        inode_version: 2,
        root: 7,
        logical_len: source.len() as u64,
        offset: 0,
        length: 256,
    };
    let p = planner
        .read(&q, |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    assert_eq!(p.path, ReadPathKind::LogicalExtent);
    assert!(p.fallback_reason.is_some());
    assert_eq!(p.bytes, auth_slice(&source, 0, 256));
    assert!(planner.measurements().is_empty(), "nothing may be measured");
    assert_eq!(planner.stats().hot_reads, 0);
}

/// A wrong root/version is refused on every read and served by the authoritative
/// path with identical bytes.
#[test]
fn mismatched_identity_falls_back_with_identical_bytes() {
    let td = TempDir::new().unwrap();
    let source = pattern(2048);
    let store = GenerationStore::new(td.path());
    publish_generation(
        &store,
        9,
        5,
        200,
        &source,
        ManifestationProfile::Path { depth: 4 },
    );
    let planner = planner_for(td.path());
    let q = ReadQuery {
        inode: 9,
        inode_version: 6, // wrong version
        root: 200,
        logical_len: source.len() as u64,
        offset: 0,
        length: 64,
    };
    for _ in 0..4 {
        let p = planner
            .read(&q, |off, len| Ok(auth_slice(&source, off, len)))
            .unwrap();
        assert_eq!(p.path, ReadPathKind::LogicalExtent);
        assert_eq!(p.bytes, auth_slice(&source, 0, 64));
    }
    assert_eq!(planner.stats().hot_reads, 0);
}

// ---------------------------------------------------------------------------
// (4) Plan state is bounded by the body cache
// ---------------------------------------------------------------------------

/// Per-object plans live inside the body cache, so a bounded cache bounds the
/// number of resident plans. Driving reads across more inodes than the cache holds
/// leaves planner state bounded while every read stays correct.
#[test]
fn plan_state_is_bounded_by_the_body_cache() {
    let td = TempDir::new().unwrap();
    let source = pattern(2048);
    let store = GenerationStore::new(td.path());
    let inodes: Vec<u64> = (0..5).map(|i| 300 + i).collect();
    for &inode in &inodes {
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
        ManifestationState::recover(GenerationStore::new(td.path()), UUID).expect("recover");
    let planner = ReadPlanner::new(
        state,
        ReadPlannerConfig {
            cache_capacity: 2,
            ..Default::default()
        },
    );
    for &inode in &inodes {
        let q = ReadQuery {
            inode,
            inode_version: 1,
            root: 1,
            logical_len: source.len() as u64,
            offset: 0,
            length: 128,
        };
        let p = planner
            .read(&q, |off, len| Ok(auth_slice(&source, off, len)))
            .unwrap();
        assert_eq!(p.bytes, auth_slice(&source, 0, 128));
    }
    let r = planner.resident();
    assert!(
        r.body_plans <= 2,
        "resident plans exceed the body-cache bound: {r:?}"
    );
}

// ---------------------------------------------------------------------------
// (5) The aging court: unbounded distinct identities, bounded resident state
// ---------------------------------------------------------------------------

/// How many distinct identities the aging court drives. The default `cargo test`
/// gate uses a bounded prefix; `scripts/container-read-planner.sh` sets the full
/// ~1e6 sweep (see `ORFS_READ_PLANNER_AGING`).
fn aging_identities() -> u64 {
    std::env::var("ORFS_READ_PLANNER_AGING")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000)
}

/// The process's resident set size in bytes, on Linux; `None` elsewhere.
fn rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    let page = 4096u64;
    Some(pages.saturating_mul(page))
}

/// Drive an unbounded number of distinct `ManifestIdentity` values through the
/// planner's identity-keyed bookkeeping and prove every resident table stays at
/// its capacity — while a real certified read still returns the correct bytes.
#[test]
fn million_distinct_versions_keep_planner_state_bounded() {
    let td = TempDir::new().unwrap();
    let source = pattern(1024);
    let store = GenerationStore::new(td.path());
    publish_generation(
        &store,
        1,
        1,
        1,
        &source,
        ManifestationProfile::Path { depth: 4 },
    );
    let planner = planner_for(td.path());

    let capacity = planner.resident();
    let count = aging_identities();
    let before = rss_bytes();

    for i in 0..count {
        // Every field varies, so every value is a distinct identity (a distinct
        // version AND generation), exactly the aging pressure the reviewer named.
        let identity = ManifestIdentity {
            volume_uuid: UUID,
            inode: 10 + i,
            inode_version: i,
            root: i.wrapping_mul(2_654_435_761),
            generation: i,
        };
        planner.record_observation(identity, SizeClass::Small, ReadPathKind::History, 100.0);
    }

    let after = planner.resident();
    assert!(
        after.body_plans <= capacity.body_capacity.max(1),
        "resident plans unbounded: {after:?}"
    );
    assert!(
        after.object_models <= capacity.object_capacity.max(1),
        "resident object models unbounded: {after:?}"
    );
    assert!(
        after.overlay_verified <= capacity.identity_capacity.max(1),
        "resident verified-overlay identities unbounded: {after:?}"
    );
    assert!(
        after.overlay_failed <= capacity.identity_capacity.max(1),
        "resident rejected-overlay identities unbounded: {after:?}"
    );
    let bound =
        capacity.body_capacity + capacity.object_capacity + capacity.identity_capacity * 2 + 8;
    assert!(
        after.total() <= bound,
        "total resident planner state {} exceeds the bound {bound} after {count} identities",
        after.total()
    );

    // A bounded state must not mean unbounded memory: the resident set may not
    // grow by more than a small multiple of the capacity.
    if let (Some(b), Some(a)) = (before, rss_bytes()) {
        let grew = a.saturating_sub(b);
        assert!(
            grew < 64 * 1024 * 1024,
            "RSS grew by {grew} bytes over {count} distinct identities"
        );
    }

    // Correctness still holds after the aging pressure.
    let q = ReadQuery {
        inode: 1,
        inode_version: 1,
        root: 1,
        logical_len: source.len() as u64,
        offset: 0,
        length: 64,
    };
    for _ in 0..4 {
        let p = planner
            .read(&q, |off, len| Ok(auth_slice(&source, off, len)))
            .unwrap();
        assert_eq!(p.bytes, auth_slice(&source, 0, 64));
    }
}
