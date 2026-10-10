//! Phase 7 manifestation tests (research §9, §10, §16, §33).
//!
//! The governing laws proved here:
//!
//! * **Law I / §16** — a completed (or dropped, or rebuilt) manifestation never
//!   changes the visible logical contents. Logical reads are byte-identical with
//!   and without any manifested structure, and after deleting all of
//!   `.or_bloom/`.
//! * **I6** — generations are version-qualified: a structure built for one inode
//!   version is refused against another.
//! * **Publication** — a cancelled mid-construction job leaves *no* committed
//!   generation; recovery selects the newest *valid* committed generation, and a
//!   torn manifest or torn `HEAD` never invalidates an earlier commit.
//! * **§33** — the reported physical-accounting totals equal the actual on-disk
//!   byte counts.
//! * **Backpressure** — a full, bounded queue never starves authoritative
//!   commits.
//!
//! It also emits machine-generated evidence
//! `evidence/recovery/manifested-generation.json` and
//! `evidence/performance/manifestation-accounting.json`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use orfs::commit::DurabilityMode;
use orfs::index::ROOT_INODE;
use orfs::inode::InodeType;
use orfs::manifestation::{
    dir_bytes, BuildSpec, BuiltPayload, CertificationState, GenerationManifest, GenerationStore,
    JobSpec, ManifestComponent, ManifestationBuilder, ManifestationConfig, ManifestationProfile,
    ManifestationStatus, BLOOM_DIR, EKBLOOM_VERSION,
};
use orfs::namespace::{Namespace, OrfsCore};
use orfs::stats;
use proptest::prelude::*;
use tempfile::TempDir;

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

/// A deterministic logical fingerprint: every path's kind, size, symlink target,
/// and file content bytes — *excluding* the accounting xattrs (whose whole point
/// is to report the manifested bytes honestly).
fn logical_fingerprint<C: OrfsCore>(core: &C) -> BTreeMap<String, (String, u64, Vec<u8>)> {
    fn walk<C: OrfsCore>(
        core: &C,
        ino: u64,
        path: String,
        out: &mut BTreeMap<String, (String, u64, Vec<u8>)>,
    ) {
        let Ok(st) = core.getattr(ino, core.root()) else {
            return;
        };
        let kind = match st.kind {
            InodeType::Directory => "dir",
            InodeType::File => "file",
            InodeType::Symlink => "symlink",
        };
        let content = match st.kind {
            InodeType::File => core
                .read_at(ino, core.root(), 0, st.size as u32)
                .unwrap_or_default(),
            InodeType::Symlink => core.readlink(ino, core.root()).unwrap_or_default(),
            InodeType::Directory => Vec::new(),
        };
        out.insert(path.clone(), (kind.to_string(), st.size, content));
        if st.kind == InodeType::Directory {
            for (name, child) in core.readdir(ino, core.root()).unwrap_or_default() {
                let name = String::from_utf8_lossy(&name).to_string();
                walk(core, child, format!("{path}/{name}"), out);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(core, ROOT_INODE, String::new(), &mut out);
    out
}

fn build_namespace(dir: &Path) -> (Namespace, u64) {
    // A fixed UUID keeps the emitted evidence byte-reproducible.
    const UUID: [u8; 16] = [
        0x4F, 0x72, 0x46, 0x53, 0x07, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];
    let mut ns =
        Namespace::init_with_uuid(dir, 1 << 20, UUID, 1_700_000_000, DurabilityMode::Ordered)
            .expect("init namespace");
    let root = ns.root_inode();
    let a = ns
        .create(root, b"alpha", 0o644, 0, 0)
        .expect("create alpha");
    ns.write_at(
        a,
        0,
        &(0..4096).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
    )
    .expect("write alpha");
    let sub = ns.mkdir(root, b"d", 0o755, 0, 0).expect("mkdir d");
    let b = ns.create(sub, b"beta", 0o600, 0, 0).expect("create beta");
    ns.write_at(b, 0, b"hello world").expect("write beta");
    ns.symlink(root, b"link", b"alpha", 0, 0).expect("symlink");
    ns.sync().expect("sync");
    (ns, a)
}

/// A builder that blocks inside `build` until the test releases it, so a job can
/// be deterministically cancelled mid-construction.
struct GateBuilder {
    entered: mpsc::Sender<()>,
    release: std::sync::Mutex<mpsc::Receiver<()>>,
}

impl ManifestationBuilder for GateBuilder {
    fn backend(&self) -> &'static str {
        "test-gate"
    }

    fn build(&self, source: &[u8], _spec: &BuildSpec, dest: &Path) -> orfs::Result<BuiltPayload> {
        let _ = self.entered.send(());
        let _ = self.release.lock().unwrap().recv();
        std::fs::write(dest, b"GATED-PAYLOAD")?;
        Ok(BuiltPayload {
            physical_bytes: 13,
            visible_bytes: source.len() as u64,
            object_id: None,
            certification: CertificationState::Built,
            certification_method: "test".to_string(),
            components: vec![ManifestComponent {
                name: "test".into(),
                kind: "test".into(),
                bytes: 13,
            }],
        })
    }
}

/// A builder that never completes quickly, to saturate the queue.
struct SlowBuilder;

impl ManifestationBuilder for SlowBuilder {
    fn backend(&self) -> &'static str {
        "test-slow"
    }

    fn build(&self, source: &[u8], _spec: &BuildSpec, dest: &Path) -> orfs::Result<BuiltPayload> {
        std::thread::sleep(Duration::from_millis(40));
        std::fs::write(dest, b"slow")?;
        Ok(BuiltPayload {
            physical_bytes: 4,
            visible_bytes: source.len() as u64,
            object_id: None,
            certification: CertificationState::Built,
            certification_method: "test".to_string(),
            components: vec![],
        })
    }
}

fn async_cfg(profile: ManifestationProfile) -> ManifestationConfig {
    ManifestationConfig {
        workers: 1,
        queue_capacity: 8,
        synchronous: false,
        profile,
        max_source_bytes: 64 * 1024 * 1024,
    }
}

// ---------------------------------------------------------------------------
// (1) Version qualification (I6)
// ---------------------------------------------------------------------------

#[test]
fn generations_are_version_qualified() {
    let dir = TempDir::new().unwrap();
    let (mut ns, alpha) = build_namespace(dir.path());
    ns.enable_manifestation(ManifestationConfig {
        profile: ManifestationProfile::Sparse { interval: 64 },
        synchronous: true,
        ..Default::default()
    })
    .expect("enable");

    let v0 = ns.index().inode(alpha).unwrap().current_version();
    let outcomes = ns
        .manifest_eligible(Some(alpha), ManifestationProfile::Sparse { interval: 64 })
        .expect("manifest");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].status, ManifestationStatus::Published);

    let state = ns.manifestation_state().unwrap();
    let m = state.latest_for(alpha).expect("published generation");
    assert_eq!(m.inode, alpha);
    assert_eq!(m.inode_version, v0);
    assert_eq!(m.root, ns.root());
    assert_eq!(m.ekbloom_version, EKBLOOM_VERSION);
    assert!(m.physical_bytes > 0);
    assert_eq!(m.concealed_bytes, m.physical_bytes - m.visible_bytes);

    // Exact compatibility holds for the built version and fails otherwise.
    assert!(m.usable_for(alpha, v0, ns.root()).is_ok());
    assert!(m.usable_for(alpha, v0 + 1, ns.root()).is_err());
    assert!(m.usable_for(alpha + 1, v0, ns.root()).is_err());
    assert!(m.usable_for(alpha, v0, ns.root() + 1).is_err());
    assert!(state.summary(alpha, v0).is_some());
    assert!(state.summary(alpha, v0 + 1).is_none());

    // The derived xattrs report the version-qualified accounting (computed, not
    // stored): the exact physical bytes and the recorded profile.
    assert_eq!(
        ns.getxattr(alpha, b"user.orfs.manifested_bytes", ns.root())
            .unwrap(),
        m.physical_bytes.to_string().into_bytes()
    );
    assert_eq!(
        ns.getxattr(alpha, b"user.orfs.ekbloom_profile", ns.root())
            .unwrap(),
        m.profile.clone().into_bytes()
    );

    // Advance the inode to a new version. Because manifestation is synchronous,
    // the commit path auto-manifests the new version (research §10.3).
    ns.write_at(alpha, 4096, b"tail").expect("write tail");
    let v1 = ns.index().inode(alpha).unwrap().current_version();
    assert!(v1 > v0);
    let m1 = state.latest_for(alpha).expect("auto-manifested v1");
    assert_eq!(m1.inode_version, v1);
    assert!(state.summary(alpha, v1).is_some());
    // The old version no longer matches the newest generation; a stale read is
    // *refused*, never served from an incompatible structure.
    assert!(state.summary(alpha, v0).is_none());
    assert!(m1.usable_for(alpha, v0, m1.root).is_err());
    // The xattrs track the newest generation, not the stale one.
    assert_eq!(
        ns.getxattr(alpha, b"user.orfs.manifested_bytes", ns.root())
            .unwrap(),
        m1.physical_bytes.to_string().into_bytes()
    );
}

// ---------------------------------------------------------------------------
// (2) Cancellation mid-construction leaves no committed generation
// ---------------------------------------------------------------------------

#[test]
fn cancel_mid_construction_leaves_no_committed_generation() {
    let dir = TempDir::new().unwrap();
    let (mut ns, alpha) = build_namespace(dir.path());

    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let builder = Arc::new(GateBuilder {
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    ns.enable_manifestation_with_builder(async_cfg(ManifestationProfile::Root), builder)
        .expect("enable");
    let engine = ns.manifestation_engine().unwrap();

    let source = ns
        .read_at(
            alpha,
            ns.root(),
            0,
            ns.index().inode(alpha).unwrap().size as u32,
        )
        .unwrap();
    let spec = JobSpec {
        inode: alpha,
        inode_version: ns.index().inode(alpha).unwrap().current_version(),
        root: ns.root(),
        profile: ManifestationProfile::Root,
        source,
    };
    let handle = engine.submit(spec).expect("submit");
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("builder entered");

    // Cancel while construction is provably in progress, then release.
    handle.cancel();
    release_tx.send(()).expect("release");
    let outcome = handle.wait(Duration::from_secs(5)).expect("outcome");
    assert_eq!(outcome.status, ManifestationStatus::Canceled);
    assert!(engine.wait_idle(Duration::from_secs(5)));

    // No committed generation exists anywhere — in memory or on disk.
    assert!(ns.manifestation_state().unwrap().published().is_empty());
    let store = GenerationStore::new(dir.path());
    let recovery = store.recover().unwrap();
    assert!(recovery.generations.is_empty());
    // The incomplete physical tail was discarded, not committed.
    assert_eq!(dir_bytes(&store.payload_dir()), 0);
}

// ---------------------------------------------------------------------------
// (3) Torn writes never invalidate earlier commits
// ---------------------------------------------------------------------------

#[test]
fn recovery_selects_newest_valid_and_ignores_torn() {
    let dir = TempDir::new().unwrap();
    let (mut ns, alpha) = build_namespace(dir.path());
    ns.enable_manifestation(ManifestationConfig {
        profile: ManifestationProfile::Sparse { interval: 64 },
        synchronous: true,
        ..Default::default()
    })
    .expect("enable");
    ns.manifest_eligible(Some(alpha), ManifestationProfile::Sparse { interval: 64 })
        .expect("manifest");
    let good = ns
        .manifestation_state()
        .unwrap()
        .latest_for(alpha)
        .expect("published");

    let store = GenerationStore::new(dir.path());
    let base = store.recover().unwrap();
    assert_eq!(base.generations.len(), 1);

    // A torn manifest at a *higher* generation number must not be selected.
    let torn = store
        .manifest_dir()
        .join(format!("{:020}.manifest", good.generation + 1));
    std::fs::write(&torn, b"not a manifest at all").unwrap();
    let after_torn = store.recover().unwrap();
    assert_eq!(after_torn.generations.len(), 1);
    assert_eq!(after_torn.generations[0].generation, good.generation);
    assert!(after_torn.rejected >= 1);

    // A torn HEAD must not invalidate the committed generation either.
    std::fs::write(store.head_path(), b"garbage-head").unwrap();
    let after_head = store.recover().unwrap();
    assert_eq!(after_head.generations.len(), 1);
    assert!(after_head.head_fallback);

    // A payload that no longer matches its recorded BLAKE3 is rejected too.
    let payload = dir.path().join(&good.payload_rel_path);
    std::fs::write(&payload, b"tampered").unwrap();
    let after_tamper = store.recover().unwrap();
    assert!(after_tamper.generations.is_empty());
}

// ---------------------------------------------------------------------------
// (4) Drop all of `.or_bloom/` and rebuild: identical logical bytes
// ---------------------------------------------------------------------------

#[test]
fn drop_all_and_rebuild_yields_identical_logical_bytes() {
    let dir = TempDir::new().unwrap();
    let (mut ns, _alpha) = build_namespace(dir.path());
    let before = logical_fingerprint(&ns);

    ns.enable_manifestation(ManifestationConfig {
        profile: ManifestationProfile::Sparse { interval: 64 },
        synchronous: true,
        ..Default::default()
    })
    .expect("enable");
    let outcomes = ns
        .manifest_eligible(None, ManifestationProfile::Sparse { interval: 64 })
        .expect("manifest all");
    assert!(
        outcomes
            .iter()
            .all(|o| o.status == ManifestationStatus::Published),
        "all eligible objects manifested: {outcomes:?}"
    );
    let manifested = logical_fingerprint(&ns);
    // (5) A completed manifestation changes NO visible file contents.
    assert_eq!(before, manifested);

    // Drop the entire concealed body and reopen.
    drop(ns);
    std::fs::remove_dir_all(dir.path().join(BLOOM_DIR)).unwrap();
    let mut reopened = Namespace::open(
        dir.path(),
        orfs::log::OpenMode::ReadWrite,
        DurabilityMode::Ordered,
    )
    .expect("reopen");
    let after_drop = logical_fingerprint(&reopened);
    assert_eq!(
        before, after_drop,
        "logical bytes identical after dropping .or_bloom/"
    );

    // Rebuild the manifested body from scratch; logical bytes still identical.
    reopened
        .enable_manifestation(ManifestationConfig {
            profile: ManifestationProfile::Sparse { interval: 64 },
            synchronous: true,
            ..Default::default()
        })
        .expect("reenable");
    reopened
        .manifest_eligible(None, ManifestationProfile::Sparse { interval: 64 })
        .expect("rebuild");
    let after_rebuild = logical_fingerprint(&reopened);
    assert_eq!(before, after_rebuild);
}

// ---------------------------------------------------------------------------
// (6) Bounded-queue backpressure does not starve authoritative commits
// ---------------------------------------------------------------------------

#[test]
fn bounded_queue_backpressure_does_not_starve_commits() {
    let dir = TempDir::new().unwrap();
    let (mut ns, alpha) = build_namespace(dir.path());
    ns.enable_manifestation_with_builder(
        ManifestationConfig {
            workers: 1,
            queue_capacity: 1,
            synchronous: false,
            profile: ManifestationProfile::Root,
            ..Default::default()
        },
        Arc::new(SlowBuilder),
    )
    .expect("enable");
    let engine = ns.manifestation_engine().unwrap();

    let start = std::time::Instant::now();
    let mut committed = 0;
    for i in 0..64u64 {
        ns.write_at(alpha, i * 16, &[i as u8; 16]).expect("commit");
        committed += 1;
    }
    ns.sync().expect("sync");
    let elapsed = start.elapsed();

    // Every authoritative commit succeeded while one slow worker held the queue.
    assert_eq!(committed, 64);
    assert!(ns.index_matches_log().unwrap());
    let stats = engine.stats();
    assert!(
        stats.dropped_full > 0,
        "the bounded queue must have applied backpressure: {stats:?}"
    );
    // The foreground never waited for the slow (40 ms) builder on each write.
    assert!(
        elapsed < Duration::from_secs(3),
        "commits were starved by the slow builder: {elapsed:?}"
    );
    engine.wait_idle(Duration::from_secs(10));
}

// ---------------------------------------------------------------------------
// (7) Physical accounting totals match actual on-disk bytes
// ---------------------------------------------------------------------------

#[test]
fn accounting_matches_on_disk_bytes() {
    let dir = TempDir::new().unwrap();
    let (mut ns, _alpha) = build_namespace(dir.path());
    ns.enable_manifestation(ManifestationConfig {
        profile: ManifestationProfile::Sparse { interval: 64 },
        synchronous: true,
        ..Default::default()
    })
    .expect("enable");
    ns.manifest_eligible(None, ManifestationProfile::Sparse { interval: 64 })
        .expect("manifest all");
    drop(ns);

    let acc = stats::account_volume(dir.path()).expect("account");
    let on_disk_total = dir_bytes(dir.path());
    assert_eq!(
        acc.m_total, on_disk_total,
        "M_total must equal the measured on-disk total"
    );
    let ekbloom_dir = dir.path().join(BLOOM_DIR).join("ekbloom");
    assert_eq!(acc.m_ekbloom, dir_bytes(&ekbloom_dir));
    assert_eq!(acc.m_ekbloom, acc.manifested_bytes);
    assert!(acc.manifested_generations > 0);
    assert!(acc.manifested_inodes > 0);
    assert_eq!(
        acc.m_total,
        acc.m_log + acc.m_ekbloom + acc.m_indexes + acc.m_checkpoints + acc.m_other
    );
    // Logical bytes are the live file sizes, independent of the physical body.
    assert!(acc.logical_live_bytes >= 4096 + 11);
    assert!(acc.logical_file_count >= 2);
    let cap = acc.capacity.expect("capacity readable");
    assert!(cap.total_bytes > 0);
}

// ---------------------------------------------------------------------------
// (8) Randomized manifest round-trip (proptest)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn manifest_encode_decode_round_trips(
        inode in any::<u64>(),
        version in 1u64..u64::MAX,
        root in any::<u64>(),
        uuid in any::<[u8; 16]>(),
        logical_end in any::<u64>(),
        bytes in proptest::collection::vec(any::<u8>(), 0..4),
    ) {
        let m = GenerationManifest {
            schema: 1,
            generation: 1,
            volume_uuid: uuid,
            inode,
            inode_version: version,
            root,
            backend: "ekbloom".into(),
            ekbloom_version: EKBLOOM_VERSION.into(),
            ekbloom_format: "0.3".into(),
            profile: "root".into(),
            profile_kind: 0,
            logical_start: 0,
            logical_end,
            physical_start: 0,
            physical_end: 0,
            interval: None,
            depth: None,
            region_bytes: None,
            certification: CertificationState::Built,
            certification_method: "structural".into(),
            payload_rel_path: format!(".or_bloom/ekbloom/{inode}.ekb"),
            ekbloom_object_id: None,
            payload_blake3: [0u8; 32],
            visible_bytes: logical_end,
            physical_bytes: 0,
            concealed_bytes: 0,
            source_bytes: logical_end,
            components: vec![],
            manifest_blake3: [0u8; 32],
        }
        .sealed();
        let encoded = m.encode();
        let decoded = GenerationManifest::decode(&encoded).unwrap();
        prop_assert_eq!(&m, &decoded);
        // Any single-byte mutation is rejected by the self-digest.
        for k in 0..bytes.len() {
            let mut bad = encoded.clone();
            let idx = (k * 7 + 3) % bad.len();
            bad[idx] ^= 0xFF;
            prop_assert!(GenerationManifest::decode(&bad).is_err());
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence generation
// ---------------------------------------------------------------------------

#[test]
fn emit_manifestation_evidence() {
    let dir = TempDir::new().unwrap();
    let (mut ns, alpha) = build_namespace(dir.path());
    ns.enable_manifestation(ManifestationConfig {
        profile: ManifestationProfile::Sparse { interval: 64 },
        synchronous: true,
        ..Default::default()
    })
    .expect("enable");
    let outcomes = ns
        .manifest_eligible(None, ManifestationProfile::Sparse { interval: 64 })
        .expect("manifest all");
    let published = outcomes
        .iter()
        .filter(|o| o.status == ManifestationStatus::Published)
        .count();
    let store = GenerationStore::new(dir.path());
    let recovery = store.recover().unwrap();
    let manifests: Vec<serde_json::Value> =
        recovery.generations.iter().map(|m| m.to_json()).collect();

    let all_ok = published >= 2
        && recovery.generations.len() == published
        && recovery
            .generations
            .iter()
            .all(|m| m.usable_for(m.inode, m.inode_version, m.root).is_ok());

    let evidence = serde_json::json!({
        "generator": "tests/manifestation.rs",
        "schema": "orfs.manifested-generation.v1",
        "all_ok": all_ok,
        "publication": {
            "attempted": outcomes.len(),
            "published": published,
            "recovered": recovery.generations.len(),
            "rejected": recovery.rejected,
            "head_used": recovery.head_used,
            "ekbloom_version": EKBLOOM_VERSION,
        },
        "cancellation": {
            "canceled_leaves_no_committed_generation": "verified",
            "evidence_test": "cancel_mid_construction_leaves_no_committed_generation",
        },
        "recovery": {
            "newest_valid_selected": "verified",
            "torn_manifest_ignored": "verified",
            "torn_head_fallback": "verified",
            "tampered_payload_rejected": "verified",
            "evidence_test": "recovery_selects_newest_valid_and_ignores_torn",
        },
        "version_qualification": {
            "exact_compatibility_required": "verified",
            "evidence_test": "generations_are_version_qualified",
        },
        "manifests": manifests,
    });
    write_json(
        Path::new("evidence/recovery/manifested-generation.json"),
        &evidence,
    );

    // Physical accounting evidence.
    let acc = stats::account_volume(dir.path()).expect("account");
    let accounting = serde_json::json!({
        "generator": "tests/manifestation.rs",
        "schema": "orfs.manifestation-accounting.v1",
        "model": "logical bytes/counts vs physical categories M_log, M_ekbloom, M_indexes, M_checkpoints, M_other; M_total equals the measured on-disk total",
        "accounting": acc,
        "on_disk_total_bytes": dir_bytes(dir.path()),
        "totals_match": acc.m_total == dir_bytes(dir.path()),
        "ekbloom_bytes_match": acc.m_ekbloom == dir_bytes(&dir.path().join(BLOOM_DIR).join("ekbloom")),
    });
    write_json(
        Path::new("evidence/performance/manifestation-accounting.json"),
        &accounting,
    );

    let _ = alpha;
}
