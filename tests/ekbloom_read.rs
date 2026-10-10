//! Phase 8 tests: EKBLOOM accelerated, certified read paths (research §10.2,
//! §16, §20 Ring R).
//!
//! The governing laws proved here:
//!
//! * **Equivalence** — for many inodes, versions, roots, and randomized
//!   `(offset, length)` (single bytes, random 4K, and spans), the planned read
//!   equals the authoritative extent read byte-for-byte — including historical
//!   versions read through a [`Snapshot`].
//! * **Compatibility** — a structure built for one inode version/root is refused
//!   for another, on every read; the read still returns the correct bytes.
//! * **Fallback** — absent, corrupt, or wrong-version structures fall back to the
//!   authoritative path with identical bytes.
//! * **Certification** — an exact (certified) structure is used directly; an
//!   uncertified `D`-step bloom is verified-on-use and rejected on disagreement.
//!
//! It also emits machine-generated evidence
//! `evidence/correctness/ekbloom-read-equivalence.json` and
//! `evidence/performance/ekbloom-read-paths.json`.

use std::path::Path;

use orfs::commit::DurabilityMode;
use orfs::manifestation::{
    ekbloom_format_version, CertificationState, GenerationManifest, GenerationStore,
    ManifestationConfig, ManifestationProfile, ManifestationState, ManifestationStatus,
    MANIFEST_SCHEMA,
};
use orfs::namespace::Namespace;
use orfs::readpath::{ReadPathKind, ReadPlanner, ReadPlannerConfig, ReadQuery};
use orfs::snapshot::Snapshot;
use proptest::prelude::*;
use tempfile::TempDir;

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x08, 0x22, 0x40, 0x33, 0x81, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create evidence dir");
    }
    let mut s = serde_json::to_string_pretty(value).expect("serialize json");
    s.push('\n');
    std::fs::write(path, s).expect("write evidence");
}

/// The authoritative semantics of an extent read: `min(length, size - offset)`
/// bytes, empty when the offset is at or beyond the size.
fn auth_slice(source: &[u8], offset: u64, length: u64) -> Vec<u8> {
    let n = source.len() as u64;
    let end = offset.saturating_add(length).min(n);
    if offset >= end {
        Vec::new()
    } else {
        source[offset as usize..end as usize].to_vec()
    }
}

/// A tiny deterministic PRNG, so evidence is byte-reproducible.
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

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 131 + 17) % 251) as u8).collect()
}

/// Publish a synthetic generation over `source`, writing the EKBLOOM payload
/// with `ekbloom::write_body` (exactly as the production builder does).
#[allow(clippy::too_many_arguments)]
fn publish_generation(
    store: &GenerationStore,
    inode: u64,
    version: u64,
    root: u64,
    source: &[u8],
    profile: ManifestationProfile,
    ekbloom_version: &str,
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
        ekbloom_version: ekbloom_version.to_string(),
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
// (1) Planner-level compatibility, certification, and fallback
// ---------------------------------------------------------------------------

#[test]
fn compatible_certified_path_serves_an_exact_read() {
    let td = TempDir::new().unwrap();
    let source = pattern(4096);
    let store = GenerationStore::new(td.path());
    let m = publish_generation(
        &store,
        7,
        3,
        100,
        &source,
        ManifestationProfile::Path { depth: 4 },
        "0.3.0",
    );
    let planner = planner_for(td.path());
    let q = ReadQuery {
        inode: 7,
        inode_version: 3,
        root: 100,
        logical_len: source.len() as u64,
        offset: 1000,
        length: 200,
    };
    let planned = planner
        .read(&q, |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    assert_eq!(planned.bytes, auth_slice(&source, 1000, 200));
    // Explicit per-path equivalence: the certified path bloom is a candidate and
    // reveals exactly the authoritative bytes, as does the extent path.
    let verdicts = planner
        .verify_paths(&q, &mut |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    assert!(
        verdicts
            .iter()
            .any(|v| v.path == ReadPathKind::PathBloom && v.certified && v.equivalent),
        "the certified path bloom was not an equivalent candidate: {verdicts:?}"
    );
    assert!(verdicts
        .iter()
        .any(|v| v.path == ReadPathKind::LogicalExtent && v.equivalent));
    let _ = m.generation;
}

#[test]
fn mismatched_version_or_root_is_rejected_every_read() {
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
        "0.3.0",
    );
    let planner = planner_for(td.path());

    // Wrong inode version.
    let wrong_version = ReadQuery {
        inode: 9,
        inode_version: 6,
        root: 200,
        logical_len: source.len() as u64,
        offset: 0,
        length: 64,
    };
    let planned = planner
        .read(&wrong_version, |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    assert_eq!(planned.path, ReadPathKind::LogicalExtent);
    assert_eq!(planned.bytes, auth_slice(&source, 0, 64));
    assert!(planned.fallback_reason.is_some());

    // Wrong committed root.
    let wrong_root = ReadQuery {
        root: 201,
        ..wrong_version
    };
    let planned = planner
        .read(&wrong_root, |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    assert_eq!(planned.path, ReadPathKind::LogicalExtent);
    assert_eq!(planned.bytes, auth_slice(&source, 0, 64));
}

#[test]
fn wrong_ekbloom_engine_version_is_rejected() {
    let td = TempDir::new().unwrap();
    let source = pattern(1024);
    let store = GenerationStore::new(td.path());
    publish_generation(
        &store,
        11,
        1,
        7,
        &source,
        ManifestationProfile::Full,
        "9.9.9",
    );
    let planner = planner_for(td.path());
    let q = ReadQuery {
        inode: 11,
        inode_version: 1,
        root: 7,
        logical_len: source.len() as u64,
        offset: 10,
        length: 100,
    };
    let planned = planner
        .read(&q, |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    assert_eq!(planned.path, ReadPathKind::LogicalExtent);
    assert_eq!(planned.bytes, auth_slice(&source, 10, 100));
    assert!(planned
        .fallback_reason
        .as_deref()
        .unwrap_or_default()
        .contains("ekbloom engine"));
}

#[test]
fn absent_and_corrupt_payloads_fall_back() {
    let td = TempDir::new().unwrap();
    let source = pattern(1024);
    let store = GenerationStore::new(td.path());
    let m = publish_generation(
        &store,
        13,
        2,
        8,
        &source,
        ManifestationProfile::Path { depth: 4 },
        "0.3.0",
    );
    let payload = store.volume_root().join(&m.payload_rel_path);
    let original = std::fs::read(&payload).unwrap();
    let planner = planner_for(td.path());
    let q = ReadQuery {
        inode: 13,
        inode_version: 2,
        root: 8,
        logical_len: source.len() as u64,
        offset: 5,
        length: 900,
    };

    // Corrupt: flip a payload byte; the committed digest no longer matches.
    let mut corrupted = original.clone();
    let mid = corrupted.len() / 2;
    corrupted[mid] ^= 0xFF;
    std::fs::write(&payload, &corrupted).unwrap();
    let planned = planner
        .read(&q, |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    assert_eq!(planned.path, ReadPathKind::LogicalExtent);
    assert_eq!(planned.bytes, auth_slice(&source, 5, 900));

    // Absent: remove the payload; the state still references the generation.
    std::fs::write(&payload, &original).unwrap();
    std::fs::remove_file(&payload).unwrap();
    let planned = planner
        .read(&q, |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    assert_eq!(planned.path, ReadPathKind::LogicalExtent);
    assert_eq!(planned.bytes, auth_slice(&source, 5, 900));
}

#[test]
fn uncertified_transition_bloom_is_verified_on_use_and_rejected_when_wrong() {
    // A source that repeats a state key with a differing 4-symbol outcome: the
    // universal 16-bit key is insufficient, so the (Unverified) bloom must be
    // verified against the authoritative read and rejected on disagreement.
    //
    // Window start 2 uses key (s0,s1) = (0x11,0x22) with symbols [1,2,0x11,0x22];
    // window start 6 reuses the same key with symbols [9,8,7,6].
    let td = TempDir::new().unwrap();
    let source: Vec<u8> = vec![0x11, 0x22, 1, 2, 0x11, 0x22, 9, 8, 7, 6];
    let store = GenerationStore::new(td.path());
    publish_generation(
        &store,
        17,
        1,
        3,
        &source,
        ManifestationProfile::Bloom { depth: 4 },
        "0.3.0",
    );
    let planner = planner_for(td.path());
    // Start at the second, conflicting occurrence (position 6).
    let q = ReadQuery {
        inode: 17,
        inode_version: 1,
        root: 3,
        logical_len: source.len() as u64,
        offset: 6,
        length: 4,
    };
    let planned = planner
        .read(&q, |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    assert_eq!(planned.bytes, auth_slice(&source, 6, 4));
    assert_eq!(planned.bytes, vec![9, 8, 7, 6]);
    // The uncertified bloom disagrees with the authoritative read and must be
    // rejected; the read still returns the correct bytes.
    let verdicts = planner
        .verify_paths(&q, &mut |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    let tbloom = verdicts
        .iter()
        .find(|v| v.path == ReadPathKind::TransitionBloom)
        .expect("a transition-bloom candidate should be enumerated");
    assert!(!tbloom.certified);
    assert!(
        !tbloom.equivalent,
        "the insufficient 16-bit-key bloom should disagree with the authoritative read"
    );
    assert_ne!(planned.path, ReadPathKind::TransitionBloom);
}

// ---------------------------------------------------------------------------
// (2) Namespace-level equivalence across inodes, versions, and roots
// ---------------------------------------------------------------------------

struct Harness {
    ns: Namespace,
    backing: std::path::PathBuf,
    files: Vec<(u64, Vec<u8>)>,
}

fn build_harness(dir: &Path) -> Harness {
    let mut ns =
        Namespace::init_with_uuid(dir, 1 << 20, UUID, 1_700_000_000, DurabilityMode::Ordered)
            .expect("init");
    let root = ns.root_inode();
    let sizes = [("f0", 300usize), ("f1", 4096), ("f2", 8192), ("f3", 65536)];
    let mut files = Vec::new();
    for (name, len) in sizes {
        let ino = ns
            .create(root, name.as_bytes(), 0o644, 0, 0)
            .expect("create");
        let data = pattern(len);
        ns.write_at(ino, 0, &data).expect("write");
        files.push((ino, data));
    }
    ns.sync().expect("sync");
    Harness {
        ns,
        backing: dir.to_path_buf(),
        files,
    }
}

fn enable(ns: &mut Namespace) {
    let cfg = ManifestationConfig {
        workers: 1,
        queue_capacity: 8,
        synchronous: true,
        profile: ManifestationProfile::Full,
        max_source_bytes: 64 << 20,
    };
    ns.enable_manifestation(cfg).expect("enable manifestation");
}

fn manifest_one(ns: &Namespace, inode: u64, profile: ManifestationProfile) {
    let outcomes = ns
        .manifest_eligible(Some(inode), profile)
        .expect("manifest");
    for o in &outcomes {
        assert_eq!(
            o.status,
            ManifestationStatus::Published,
            "manifestation of inode {inode} did not publish: {:?}",
            o.detail
        );
    }
}

#[test]
fn planned_reads_match_authoritative_across_inodes_and_snapshots() {
    let td = TempDir::new().unwrap();
    let mut h = build_harness(td.path());
    enable(&mut h.ns);
    let root = h.ns.root();

    // Distinct profiles per file, so several candidate kinds are exercised.
    manifest_one(&h.ns, h.files[0].0, ManifestationProfile::Full);
    manifest_one(
        &h.ns,
        h.files[1].0,
        ManifestationProfile::Sparse { interval: 64 },
    );
    manifest_one(&h.ns, h.files[2].0, ManifestationProfile::Path { depth: 4 });
    manifest_one(&h.ns, h.files[3].0, ManifestationProfile::MaxSpeed);

    let planner = h.ns.read_planner().expect("planner").clone();
    planner.reset();

    // (a) In-version equivalence, many randomized ranges per file.
    let mut accelerated = 0usize;
    let mut total = 0usize;
    let mut rng = Lcg(0xC0FFEE);
    for (inode, data) in &h.files {
        let size = data.len() as u64;
        for _ in 0..400 {
            let offset = rng.below(size + 8);
            let length = match rng.below(4) {
                0 => 1,
                1 => 4096,
                2 => rng.below(512),
                _ => rng.below(size.max(1)),
            };
            let planned =
                h.ns.planned_read(*inode, root, offset, length as u32)
                    .expect("planned");
            let auth =
                h.ns.read_extent(*inode, root, offset, length)
                    .expect("auth");
            assert_eq!(
                planned.bytes, auth,
                "mismatch inode={inode} off={offset} len={length}"
            );
            assert_eq!(planned.bytes, auth_slice(data, offset, length));
            total += 1;
            if planned.path != ReadPathKind::LogicalExtent {
                accelerated += 1;
            }
        }
    }
    assert!(accelerated > 0, "no read used a manifested structure");
    assert!(
        accelerated < total,
        "every read was accelerated; fallback not exercised"
    );

    // (b) Historical versions via snapshots. Every historical read must be
    // byte-correct and agree with the snapshot; a structure is used where it is
    // compatible with the historical (root, version), and refused otherwise.
    let historical_root = root;
    let first_inode = h.files[0].0;
    h.ns.write_at(first_inode, 0, b"rewritten")
        .expect("rewrite");
    h.ns.sync().expect("sync");
    let new_root = h.ns.root();
    assert!(new_root > historical_root);

    let snap = Snapshot::open_dir(&h.backing, historical_root).expect("snapshot");
    let mut historical_accelerated = 0usize;
    for (inode, data) in &h.files {
        for (offset, length) in [(0u64, 32u32), (7, 1), (100, 4096)] {
            let planned =
                h.ns.planned_read(*inode, historical_root, offset, length)
                    .expect("historical planned");
            let auth =
                h.ns.read_extent(*inode, historical_root, offset, length as u64)
                    .unwrap();
            let via_snapshot = snap.read_at(*inode, offset, length).unwrap();
            assert_eq!(planned.bytes, auth, "historical planned != authoritative");
            assert_eq!(
                planned.bytes, via_snapshot,
                "historical planned != snapshot"
            );
            assert_eq!(planned.bytes, auth_slice(data, offset, length as u64));
            if planned.path != ReadPathKind::LogicalExtent {
                historical_accelerated += 1;
            }
        }
    }
    assert!(
        historical_accelerated > 0,
        "no historical read used a compatible manifested structure"
    );

    // After the commit the root advanced. An untouched file's generation is now
    // root-stale and is refused; the read is still byte-correct.
    let planned =
        h.ns.planned_read(h.files[1].0, new_root, 0, 128)
            .expect("planned");
    assert_eq!(
        planned.bytes,
        h.ns.read_extent(h.files[1].0, new_root, 0, 128).unwrap()
    );
    assert_eq!(planned.path, ReadPathKind::LogicalExtent);

    // The rewritten file is read correctly at the new root (its structure was
    // rebuilt for the new version, or it falls back; either way bytes match).
    let planned =
        h.ns.planned_read(first_inode, new_root, 0, 16)
            .expect("planned");
    assert_eq!(
        planned.bytes,
        h.ns.read_extent(first_inode, new_root, 0, 16).unwrap()
    );
}

// ---------------------------------------------------------------------------
// (3) Property test over the offset/length space
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn proptest_planned_equals_authoritative(offset in 0u64..8192, length in 0u64..8192) {
        let td = TempDir::new().unwrap();
        let mut ns = Namespace::init_with_uuid(td.path(), 1 << 20, UUID, 1_700_000_000, DurabilityMode::Ordered).unwrap();
        let root_inode = ns.root_inode();
        let inode = ns.create(root_inode, b"f", 0o644, 0, 0).unwrap();
        let data = pattern(4096);
        ns.write_at(inode, 0, &data).unwrap();
        ns.sync().unwrap();
        let cfg = ManifestationConfig { workers: 1, queue_capacity: 4, synchronous: true, profile: ManifestationProfile::MaxSpeed, max_source_bytes: 64 << 20 };
        ns.enable_manifestation(cfg).unwrap();
        manifest_one(&ns, inode, ManifestationProfile::MaxSpeed);
        let root = ns.root();
        let planned = ns.planned_read(inode, root, offset, length as u32).unwrap();
        let auth = ns.read_extent(inode, root, offset, length).unwrap();
        prop_assert_eq!(planned.bytes, auth);
    }
}

// ---------------------------------------------------------------------------
// (4) Evidence
// ---------------------------------------------------------------------------

#[test]
fn emit_ekbloom_read_evidence() {
    let td = TempDir::new().unwrap();
    let mut h = build_harness(td.path());
    enable(&mut h.ns);
    let root = h.ns.root();
    manifest_one(&h.ns, h.files[0].0, ManifestationProfile::Full);
    manifest_one(
        &h.ns,
        h.files[1].0,
        ManifestationProfile::Sparse { interval: 64 },
    );
    manifest_one(&h.ns, h.files[2].0, ManifestationProfile::Path { depth: 4 });
    manifest_one(&h.ns, h.files[3].0, ManifestationProfile::MaxSpeed);

    let mut cases: Vec<serde_json::Value> = Vec::new();
    let mut by_path: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut rng = Lcg(0xD1CE);
    let mut total = 0u64;
    let mut equivalent = 0u64;
    let mut historical_cases = 0u64;
    let mut accelerated = 0u64;

    // Current-version cases.
    for (inode, data) in &h.files {
        let size = data.len() as u64;
        for _ in 0..120 {
            let offset = rng.below(size + 8);
            let length = match rng.below(4) {
                0 => 1,
                1 => 4096,
                2 => rng.below(512),
                _ => rng.below(size.max(1)),
            };
            let planned =
                h.ns.planned_read(*inode, root, offset, length as u32)
                    .unwrap();
            let auth = h.ns.read_extent(*inode, root, offset, length).unwrap();
            let eq = planned.bytes == auth;
            total += 1;
            if eq {
                equivalent += 1;
            }
            if planned.path != ReadPathKind::LogicalExtent {
                accelerated += 1;
            }
            *by_path.entry(planned.path.name().to_string()).or_insert(0) += 1;
            if cases.len() < 200 {
                cases.push(serde_json::json!({
                    "file": format!("f{}", inode),
                    "inode": inode,
                    "root": root,
                    "historical": false,
                    "offset": offset,
                    "length": length,
                    "path": planned.path.name(),
                    "certified": planned.certified,
                    "generation": planned.generation,
                    "profile": planned.profile,
                    "bytes": planned.bytes.len(),
                    "equivalent": eq,
                }));
            }
        }
    }

    // ---- performance evidence (measured before any further commit) ----
    let performance = build_performance_evidence(&h, root);
    write_json(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("evidence/performance/ekbloom-read-paths.json"),
        &performance,
    );

    // Historical cases through a snapshot.
    let historical_root = root;
    let first = h.files[0].0;
    h.ns.write_at(first, 0, b"rewritten").unwrap();
    h.ns.sync().unwrap();
    let snap = Snapshot::open_dir(&h.backing, historical_root).unwrap();
    for (inode, data) in &h.files {
        for (offset, length) in [(0u64, 1u64), (10, 4096), (3, 777)] {
            let planned =
                h.ns.planned_read(*inode, historical_root, offset, length as u32)
                    .unwrap();
            let via_snapshot = snap.read_at(*inode, offset, length as u32).unwrap();
            let eq =
                planned.bytes == via_snapshot && planned.bytes == auth_slice(data, offset, length);
            total += 1;
            historical_cases += 1;
            if eq {
                equivalent += 1;
            }
            *by_path.entry(planned.path.name().to_string()).or_insert(0) += 1;
            if cases.len() < 260 {
                cases.push(serde_json::json!({
                    "file": format!("f{}", inode),
                    "inode": inode,
                    "root": historical_root,
                    "historical": true,
                    "offset": offset,
                    "length": length,
                    "path": planned.path.name(),
                    "certified": planned.certified,
                    "generation": planned.generation,
                    "bytes": planned.bytes.len(),
                    "equivalent": eq,
                }));
            }
        }
    }

    // Explicit rejection cases.
    let rejection = build_rejection_evidence(td.path());

    let correctness = serde_json::json!({
        "schema": orfs::readpath::READPATH_SCHEMA,
        "generated_by": "tests/ekbloom_read.rs",
        "authoritative": "Namespace::read_extent (ordinary logical extent read)",
        "ekbloom_version": "0.3.0",
        "cases": cases,
        "rejection_cases": rejection,
        "summary": {
            "total": total,
            "equivalent": equivalent,
            "mismatches": total - equivalent,
            "historical_cases": historical_cases,
            "accelerated_cases": accelerated,
            "by_path": by_path,
        },
    });
    write_json(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("evidence/correctness/ekbloom-read-equivalence.json"),
        &correctness,
    );
    assert_eq!(equivalent, total, "some read was not byte-equivalent");
    assert!(accelerated > 0, "no accelerated read was recorded");
}

/// Build and exercise the explicit rejection cases, returning their verdicts.
fn build_rejection_evidence(dir: &Path) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let sub = dir.join("reject");
    std::fs::create_dir_all(&sub).unwrap();
    let source = pattern(1024);

    let store = GenerationStore::new(&sub);
    let m = publish_generation(
        &store,
        5,
        2,
        50,
        &source,
        ManifestationProfile::Path { depth: 4 },
        "0.3.0",
    );
    let payload = sub.join(&m.payload_rel_path);
    let planner = planner_for(&sub);

    let q = |version, root| ReadQuery {
        inode: 5,
        inode_version: version,
        root,
        logical_len: source.len() as u64,
        offset: 0,
        length: 512,
    };

    // A compatible read first (control).
    let control = planner
        .read(&q(2, 50), |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    out.push(serde_json::json!({
        "kind": "compatible-control",
        "rejected": control.path == ReadPathKind::LogicalExtent,
        "path": control.path.name(),
        "bytes_equivalent": control.bytes == auth_slice(&source, 0, 512),
    }));

    // Wrong inode version.
    let v = planner
        .read(&q(3, 50), |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    out.push(serde_json::json!({
        "kind": "wrong-inode-version",
        "rejected": v.path == ReadPathKind::LogicalExtent,
        "path": v.path.name(),
        "bytes_equivalent": v.bytes == auth_slice(&source, 0, 512),
    }));

    // Wrong root.
    let r = planner
        .read(&q(2, 51), |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    out.push(serde_json::json!({
        "kind": "wrong-root",
        "rejected": r.path == ReadPathKind::LogicalExtent,
        "path": r.path.name(),
        "bytes_equivalent": r.bytes == auth_slice(&source, 0, 512),
    }));

    // Absent payload: reset the (immutable-body) cache so the load path observes
    // the absence rather than a previously validated in-memory copy.
    let original = std::fs::read(&payload).unwrap();
    std::fs::remove_file(&payload).unwrap();
    planner.reset();
    let a = planner
        .read(&q(2, 50), |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    out.push(serde_json::json!({
        "kind": "absent-payload",
        "rejected": a.path == ReadPathKind::LogicalExtent,
        "path": a.path.name(),
        "bytes_equivalent": a.bytes == auth_slice(&source, 0, 512),
    }));

    // Corrupt payload.
    std::fs::write(&payload, &original).unwrap();
    let mut corrupted = original.clone();
    let mid = corrupted.len() / 2;
    corrupted[mid] ^= 0xFF;
    std::fs::write(&payload, &corrupted).unwrap();
    planner.reset();
    let c = planner
        .read(&q(2, 50), |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    out.push(serde_json::json!({
        "kind": "corrupt-payload",
        "rejected": c.path == ReadPathKind::LogicalExtent,
        "path": c.path.name(),
        "bytes_equivalent": c.bytes == auth_slice(&source, 0, 512),
    }));

    // Wrong EKBLOOM engine version (a fresh store so it is the newest).
    let sub2 = dir.join("reject-ver");
    std::fs::create_dir_all(&sub2).unwrap();
    let store2 = GenerationStore::new(&sub2);
    publish_generation(
        &store2,
        5,
        2,
        50,
        &source,
        ManifestationProfile::Full,
        "9.9.9",
    );
    let planner2 = planner_for(&sub2);
    let wv = planner2
        .read(&q(2, 50), |off, len| Ok(auth_slice(&source, off, len)))
        .unwrap();
    out.push(serde_json::json!({
        "kind": "wrong-ekbloom-version",
        "rejected": wv.path == ReadPathKind::LogicalExtent,
        "path": wv.path.name(),
        "bytes_equivalent": wv.bytes == auth_slice(&source, 0, 512),
    }));

    out
}

/// Time each candidate path (and the authoritative path) for two workloads.
fn build_performance_evidence(h: &Harness, root: u64) -> serde_json::Value {
    let planner = h.ns.read_planner().expect("planner").clone();
    // A MaxSpeed object has history + checkpoint + path bloom, so every
    // certified candidate kind is measurable against it.
    let target = h.files[3].0; // 65536 bytes

    let mut workloads: Vec<serde_json::Value> = Vec::new();

    for (name, inode, length) in [("random-1B", target, 1u64), ("random-4K", target, 4096u64)] {
        let st = h.ns.getattr(inode, root).unwrap();
        let size = st.size;
        let version = st.version;
        let offsets = [0u64, size / 4, size / 2, size.saturating_sub(length)];

        // Aggregate per path across offsets: min over all samples, mean of means.
        let mut agg: std::collections::BTreeMap<String, (u128, f64, u64, bool)> =
            std::collections::BTreeMap::new();
        for &off in &offsets {
            let q = ReadQuery {
                inode,
                inode_version: version,
                root,
                logical_len: size,
                offset: off,
                length,
            };
            let mut auth = |o: u64, l: u64| h.ns.read_extent(inode, root, o, l);
            for l in planner
                .measure_paths(&q, &mut auth, 200)
                .unwrap_or_default()
            {
                let key = if l.certified {
                    l.path.name().to_string()
                } else {
                    format!("{} (verified-on-use)", l.path.name())
                };
                let e = agg.entry(key).or_insert((u128::MAX, 0.0, 0, l.certified));
                e.0 = e.0.min(l.min_ns);
                e.1 += l.mean_ns;
                e.2 += 1;
                e.3 = l.certified;
            }
        }

        // The authoritative path is itself a measured candidate now.
        let (auth_min, auth_mean) = agg
            .get("logical-extent")
            .map(|(min, sum, n, _)| (*min, sum / (*n as f64)))
            .unwrap_or((0, 0.0));

        // Which path does the *planner* select for these requests, under the
        // measured model warmed by the equivalence sweep?
        let mut selected: std::collections::BTreeMap<String, u64> =
            std::collections::BTreeMap::new();
        for &off in &offsets {
            let p = h.ns.planned_read(inode, root, off, length as u32).unwrap();
            *selected.entry(p.path.name().to_string()).or_insert(0) += 1;
        }

        let paths: Vec<serde_json::Value> = agg
            .iter()
            .map(|(path, (min, sum, n, certified))| {
                serde_json::json!({
                    "path": path,
                    "certified": certified,
                    "min_ns": min,
                    "mean_ns": sum / (*n as f64),
                    "iterations": n,
                })
            })
            .collect();
        let best_manifested_mean = agg
            .iter()
            .filter(|(k, _)| k.as_str() != "logical-extent")
            .map(|(_, (_, sum, n, _))| sum / (*n as f64))
            .fold(f64::INFINITY, f64::min);
        workloads.push(serde_json::json!({
            "name": name,
            "inode": inode,
            "inode_version": version,
            "length": length,
            "offsets": offsets,
            "iterations_per_offset": 200,
            "paths": paths,
            "authoritative": { "min_ns": auth_min, "mean_ns": auth_mean },
            "best_manifested_mean_ns": if best_manifested_mean.is_finite() { serde_json::json!(best_manifested_mean) } else { serde_json::Value::Null },
            "speedup_vs_authoritative": if best_manifested_mean.is_finite() && best_manifested_mean > 0.0 && auth_mean > 0.0 { serde_json::json!(auth_mean / best_manifested_mean) } else { serde_json::Value::Null },
            "selected_paths": selected,
        }));
    }

    let model: Vec<serde_json::Value> = planner
        .measurements()
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "path": m.path.name(),
                "class": m.class.name(),
                "ewma_ns": m.ewma_ns,
                "samples": m.samples,
            })
        })
        .collect();
    let chosen: Vec<serde_json::Value> = planner
        .chosen_counts()
        .into_iter()
        .map(|(p, c)| serde_json::json!({ "path": p.name(), "reads": c }))
        .collect();

    serde_json::json!({
        "schema": orfs::readpath::READPATH_SCHEMA,
        "generated_by": "tests/ekbloom_read.rs",
        "note": "Each path is timed directly (min/mean over offsets x iterations). Selection uses the measured EWMA model (see src/readpath.rs); the ordinary logical extent read is itself a measured candidate, so the planner never picks a manifested path that is slower than the authoritative one. Absolute latencies are from an unoptimized test build, so per-symbol loops dominate; selection, not the absolute figure, is the point.",
        "workloads": workloads,
        "measured_selection_model": model,
        "paths_chosen_by_the_planner": chosen,
    })
}
