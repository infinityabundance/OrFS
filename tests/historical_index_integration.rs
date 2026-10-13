//! **Phase 58 — integrating a non-treap index for the sealed historical role.**
//!
//! Phase 48 (research §6) held a layout-competition court and concluded — under
//! the decisive rule *"a faster point lookup is insufficient if snapshot
//! publication or namespace mutation regresses"* — that the production
//! namespace index must keep the Phase-27 path-copying treap: a byte-radix and a
//! page tree both regress namespace mutation (2.4–4.3×). Its productive finding
//! was that for the **sealed, immutable historical** role a **direct-ordinal**
//! layout (an id-indexed array, legal because inode ids are dense and monotonic)
//! is near-`O(1)` and far more compact. That finding was not integrated.
//!
//! This court integrates it and proves it. A decoded historical index
//! ([`Index::decode_packed`], i.e. the `.v2.bin` accelerator and the legacy JSON
//! accelerator) now stores its inode-id spine as a **sealed dense-ordinal** array
//! ([`Index::inode_layout`] returns `"sealed-dense-ordinal"`); the live writer
//! spine is untouched and stays `"persistent-treap"`.
//!
//! The always-on smoke asserts, for the same committed root:
//!
//! * the sealed layout answers **identical** point lookups, ordered id
//!   enumeration, `readdir`, dentry `lookup`, `parent_of`, `is_live_dir`, and
//!   `latest_offset` to the treap, and has the same canonical digest and
//!   structural equality;
//! * it is **more compact** (a smaller inode-id spine);
//! * the real accelerator round-trip (`persist_historical` →
//!   `load_persisted_historical`) yields the sealed layout;
//! * the **live** index's spine stays the treap through further commits, so its
//!   mutation/publication are unchanged by construction, and old roots stay
//!   readable.
//!
//! A larger, opt-in sweep (`ORFS_HIST_INTEG=1`) measures point lookup, spine
//! bytes, publication, and live commit cost per retained scale and writes
//! `evidence/performance/historical-index-integrated.json`
//! (schema `orfs.performance.historical-index-integrated.v1`).

use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::Instant;

use orfs::commit::DurabilityMode;
use orfs::historical::{self, load_persisted_historical};
use orfs::index::{Index, ROOT_INODE};
use orfs::namespace::Namespace;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// history building
// ---------------------------------------------------------------------------

/// A small but representative history: two populated directories, a nested
/// directory, root-level files, a symlink, and an xattr.
fn build_small(dir: &Path) -> Namespace {
    let mut ns = Namespace::init(dir, 1 << 22, DurabilityMode::Ordered).expect("init volume");
    let a = ns.mkdir(ROOT_INODE, b"alpha", 0o755, 0, 0).expect("mkdir");
    let b = ns.mkdir(ROOT_INODE, b"beta", 0o755, 0, 0).expect("mkdir");
    for i in 0..24 {
        ns.create(a, format!("a{i:03}").as_bytes(), 0o644, 0, 0)
            .expect("create");
    }
    for i in 0..16 {
        ns.create(b, format!("b{i:03}").as_bytes(), 0o644, 0, 0)
            .expect("create");
    }
    for i in 0..8 {
        ns.create(ROOT_INODE, format!("r{i:03}").as_bytes(), 0o644, 0, 0)
            .expect("create");
    }
    let c = ns.mkdir(a, b"sub", 0o755, 0, 0).expect("mkdir");
    ns.create(c, b"deep", 0o644, 0, 0).expect("create");
    let link = ns
        .symlink(ROOT_INODE, b"link", b"alpha/a000", 0, 0)
        .expect("symlink");
    ns.setxattr(link, b"user.k", b"v", false).expect("xattr");
    ns.sync().expect("sync");
    ns
}

/// A large, write-heavy history of `n` inodes. Files are created directly under
/// the root so `require_live_dir` short-circuits (the root is always live) and
/// the build stays linear; the inode-id spine this court measures is independent
/// of the directory shape.
fn build_large(dir: &Path, n: u64) -> Namespace {
    let mut ns = Namespace::init(dir, 1 << 27, DurabilityMode::Ordered).expect("init volume");
    for i in 0..n {
        ns.create(ROOT_INODE, format!("f{i:010}").as_bytes(), 0o644, 0, 0)
            .expect("create");
    }
    ns.sync().expect("sync");
    ns
}

/// The authoritative (treap) index at `root` and its sealed decode.
fn two_forms(log: &orfs::log::Log, root: u64) -> (Index, Index) {
    let treap = Index::from_log(log, root).expect("from_log");
    let sealed = Index::decode_packed(&treap.encode_packed()).expect("decode_packed");
    (treap, sealed)
}

// ---------------------------------------------------------------------------
// equivalence: the sealed layout answers every read identically
// ---------------------------------------------------------------------------

fn assert_same_reads(treap: &Index, sealed: &Index) {
    assert_eq!(sealed, treap, "sealed and treap must be structurally equal");
    assert_eq!(sealed.root(), treap.root());
    assert_eq!(sealed.next_inode_id(), treap.next_inode_id());
    assert_eq!(sealed.inode_count(), treap.inode_count());
    assert_eq!(sealed.dentry_count(), treap.dentry_count());
    assert_eq!(sealed.canonical_digest(), treap.canonical_digest());
    assert_eq!(
        sealed.inode_layout(),
        "sealed-dense-ordinal",
        "the sealed index must use the dense-ordinal inode spine"
    );
    assert_eq!(treap.inode_layout(), "persistent-treap");

    // Ordered id enumeration (the inode-id "range").
    let a: Vec<u64> = treap.inode_ids().collect();
    let b: Vec<u64> = sealed.inode_ids().collect();
    assert_eq!(a, b, "ordered inode-id enumeration differs");
    assert!(
        a.windows(2).all(|w| w[0] < w[1]),
        "ids must be enumerated in ascending order"
    );

    // Point lookups over every present id plus absent ids around the domain.
    let mut probes = a.clone();
    probes.push(0);
    probes.push(treap.next_inode_id());
    probes.push(treap.next_inode_id() + 1);
    probes.push(u64::MAX);
    for &id in &probes {
        assert_eq!(sealed.inode(id), treap.inode(id), "inode({id}) differs");
        assert_eq!(
            sealed.latest_offset(id),
            treap.latest_offset(id),
            "latest_offset({id}) differs"
        );
        assert_eq!(
            sealed.is_live_dir(id),
            treap.is_live_dir(id),
            "is_live_dir({id}) differs"
        );
        assert_eq!(
            sealed.parent_of(id),
            treap.parent_of(id),
            "parent_of({id}) differs"
        );
        assert_eq!(
            sealed.readdir(id),
            treap.readdir(id),
            "readdir({id}) differs"
        );
        // An absent name under every id.
        assert_eq!(
            sealed.lookup(id, b"\xffabsent"),
            treap.lookup(id, b"\xffabsent"),
            "absent lookup under {id} differs"
        );
    }

    // Dentry lookups over every name the treap knows.
    for &id in &a {
        if let Some(entries) = treap.readdir(id) {
            for (name, child) in entries {
                assert_eq!(
                    sealed.lookup(id, &name),
                    Some(child),
                    "lookup({id}, {:?}) differs",
                    String::from_utf8_lossy(&name)
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// measurement helpers
// ---------------------------------------------------------------------------

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

/// `(p50_ns, best_bulk_mean_ns)` for `index.inode(q)` over `queries`. The bulk
/// pass has no per-op timer, so its mean is not dominated by the `Instant::now`
/// floor (the Phase-48 convention); the reported `best` is the minimum over
/// `reps` passes.
fn measure_lookup(index: &Index, queries: &[u64], reps: usize) -> (u64, u64) {
    let mut samples = Vec::with_capacity(queries.len());
    for &q in queries {
        let t = Instant::now();
        let r = index.inode(q);
        samples.push(t.elapsed().as_nanos() as u64);
        black_box(r);
    }
    samples.sort_unstable();
    let p50 = percentile(&samples, 50.0);
    let mut best = u64::MAX;
    for _ in 0..reps.max(1) {
        let t = Instant::now();
        let mut acc = 0u64;
        for &q in queries {
            acc = acc.wrapping_add(index.inode(q).map(|i| i.id).unwrap_or(0));
        }
        black_box(acc);
        best = best.min(t.elapsed().as_nanos() as u64);
    }
    (p50, best / queries.len() as u64)
}

/// The minimum cost of cloning `index` — publication is a handful of `Arc`
/// pointer copies for both layouts.
fn min_clone_ns(index: &Index) -> u64 {
    let mut best = u64::MAX;
    for _ in 0..64 {
        let t = Instant::now();
        black_box(index.clone());
        best = best.min(t.elapsed().as_nanos() as u64);
    }
    best
}

fn min_ns<F: FnMut()>(mut f: F, reps: usize) -> u64 {
    let mut best = u64::MAX;
    for _ in 0..reps.max(1) {
        let t = Instant::now();
        f();
        best = best.min(t.elapsed().as_nanos() as u64);
    }
    best
}

/// A deterministic present/absent query mix over `[1, next_id]`.
fn query_plan(next_id: u64, n: usize) -> Vec<u64> {
    let mut state = 0x2545_F491_4F6C_DD1Du64 ^ next_id;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let r = state >> 17;
        out.push(if i % 2 == 0 {
            1 + r % next_id.max(1)
        } else {
            next_id + 1 + r % next_id.max(1)
        });
    }
    out
}

// ---------------------------------------------------------------------------
// always-on smoke
// ---------------------------------------------------------------------------

#[test]
fn sealed_dense_ordinal_answers_identically_and_is_more_compact() {
    let td = TempDir::new().unwrap();
    let ns = build_small(td.path());
    let root = ns.root();
    let uuid = ns.volume().meta.uuid;
    let log = &ns.volume().log;

    let (treap, sealed) = two_forms(log, root);
    assert!(treap.inode_count() >= 50, "history must be non-trivial");
    assert!(treap.dentry_count() >= 48);

    // (1) Identical reads + structural equality + same digest.
    assert_same_reads(&treap, &sealed);

    // (2) More compact inode-id spine.
    let t_bytes = treap.inode_spine_bytes();
    let s_bytes = sealed.inode_spine_bytes();
    assert!(
        s_bytes < t_bytes,
        "the sealed spine ({s_bytes} B) must be smaller than the treap ({t_bytes} B)"
    );

    // (3) The real persisted accelerator path yields the sealed layout.
    let index_dir = td.path().join("index");
    historical::persist_historical(&index_dir, &uuid, &treap).expect("persist");
    let loaded = load_persisted_historical(&index_dir, &uuid, root)
        .expect("load")
        .expect("accelerator present");
    assert_eq!(
        loaded.inode_layout(),
        "sealed-dense-ordinal",
        "a loaded historical accelerator must be sealed"
    );
    assert_eq!(loaded, treap, "the loaded accelerator equals the audit");
    assert_same_reads(&treap, &loaded);

    // (4) Publication is a pointer copy for both layouts, orders of magnitude
    //     below a rebuild.
    let rebuild = min_ns(
        || {
            black_box(Index::from_log(log, root).unwrap());
        },
        4,
    );
    let t_clone = min_clone_ns(&treap);
    let s_clone = min_clone_ns(&sealed);
    assert!(
        t_clone < rebuild / 10 + 1,
        "treap publication ({t_clone} ns) should be far below a rebuild ({rebuild} ns)"
    );
    assert!(
        s_clone < rebuild / 10 + 1,
        "sealed publication ({s_clone} ns) should be far below a rebuild ({rebuild} ns)"
    );
}

#[test]
fn the_live_writer_spine_is_never_sealed_and_old_roots_stay_readable() {
    let td = TempDir::new().unwrap();
    let mut ns = build_small(td.path());
    let root = ns.root();
    let log_dir = td.path().to_path_buf();

    // The live writer spine is the treap.
    assert_eq!(ns.index().inode_layout(), "persistent-treap");

    let captured = {
        let log = &ns.volume().log;
        let (treap, sealed) = two_forms(log, root);
        assert_same_reads(&treap, &sealed);
        sealed
    };

    // Further live commits leave the live spine the treap at every step.
    let extra = ns.mkdir(ROOT_INODE, b"gamma", 0o755, 0, 0).unwrap();
    for i in 0..32 {
        ns.create(extra, format!("g{i:03}").as_bytes(), 0o644, 0, 0)
            .unwrap();
        assert_eq!(ns.index().inode_layout(), "persistent-treap");
    }
    ns.sync().unwrap();
    assert_eq!(ns.index().inode_layout(), "persistent-treap");

    // The captured sealed root is immutable and still equals the treap at the
    // same committed root.
    drop(ns);
    let vol = orfs::volume::Volume::open(&log_dir, orfs::log::OpenMode::ReadOnly).unwrap();
    let treap_at_root = Index::from_log(&vol.log, root).unwrap();
    assert_eq!(captured, treap_at_root, "old roots must stay readable");
    assert_eq!(
        captured.canonical_digest(),
        treap_at_root.canonical_digest()
    );
}

// ---------------------------------------------------------------------------
// opt-in measurement sweep (writes evidence)
// ---------------------------------------------------------------------------

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

fn sweep_scales() -> Vec<u64> {
    if let Ok(s) = std::env::var("ORFS_HIST_INTEG_SCALES") {
        let parsed: Vec<u64> = s
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .filter(|&v| v > 0)
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    vec![10_000, 100_000, 1_000_000]
}

fn evidence_environment() -> serde_json::Value {
    serde_json::json!({
        "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "image_digest": std::env::var("ORFS_IMAGE_DIGEST").unwrap_or_else(|_| "unknown".into()),
    })
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn ratio(num: u64, den: u64) -> Option<f64> {
    if den == 0 {
        None
    } else {
        Some(num as f64 / den as f64)
    }
}

#[test]
fn historical_index_integration_sweep() {
    if std::env::var("ORFS_HIST_INTEG").as_deref() != Ok("1") {
        eprintln!(
            "historical_index_integration_sweep: skipped (set ORFS_HIST_INTEG=1 to run the sweep)"
        );
        return;
    }
    let scales = sweep_scales();
    let lookups = env_u64("ORFS_HIST_INTEG_LOOKUPS", 100_000) as usize;

    let mut rows = Vec::new();
    let mut all_more_compact = true;
    let mut lookup_never_slower = true;
    let mut live_always_treap = true;

    for &n in &scales {
        eprintln!("historical-index-integration: scale {n} ...");
        let td = TempDir::new().unwrap();
        let ns = build_large(td.path(), n);
        let root = ns.root();
        let log = &ns.volume().log;

        let (treap, sealed) = two_forms(log, root);
        assert_same_reads(&treap, &sealed);

        let queries = query_plan(treap.next_inode_id(), lookups);
        let (t_p50, t_mean) = measure_lookup(&treap, &queries, 5);
        let (s_p50, s_mean) = measure_lookup(&sealed, &queries, 5);

        let t_bytes = treap.inode_spine_bytes();
        let s_bytes = sealed.inode_spine_bytes();
        let t_clone = min_clone_ns(&treap);
        let s_clone = min_clone_ns(&sealed);

        // Re-seal cost: the price of building the dense array from the treap.
        let seal_ns = min_ns(
            || {
                black_box(treap.to_sealed());
            },
            4,
        );

        // Live spine + live commit cost, unchanged by this integration.
        assert_eq!(ns.index().inode_layout(), "persistent-treap");
        live_always_treap &= ns.index().inode_layout() == "persistent-treap";
        let live_clone = min_clone_ns(ns.index());

        let more_compact = s_bytes < t_bytes;
        let not_slower = s_mean <= t_mean.saturating_mul(105) / 100 + 2;
        all_more_compact &= more_compact;
        lookup_never_slower &= not_slower;

        rows.push(serde_json::json!({
            "retained_inodes": n,
            "next_inode_id": treap.next_inode_id(),
            "dentry_count": treap.dentry_count(),
            "equivalence": "identical lookups, ordered id enumeration, readdir, dentry \
                            lookup, parent_of, is_live_dir, latest_offset, canonical digest, \
                            and structural equality (asserted)",
            "treap": {
                "layout": treap.inode_layout(),
                "lookup_p50_ns": t_p50,
                "lookup_bulk_mean_ns": t_mean,
                "inode_spine_bytes": t_bytes,
                "clone_ns": t_clone,
            },
            "sealed": {
                "layout": sealed.inode_layout(),
                "lookup_p50_ns": s_p50,
                "lookup_bulk_mean_ns": s_mean,
                "inode_spine_bytes": s_bytes,
                "clone_ns": s_clone,
                "seal_rebuild_ns": seal_ns,
            },
            "ratios": {
                "spine_sealed_over_treap": ratio(s_bytes as u64, t_bytes as u64),
                "lookup_bulk_mean_treap_over_sealed": ratio(t_mean, s_mean),
                "lookup_p50_treap_over_sealed": ratio(t_p50, s_p50),
                "clone_sealed_over_treap": ratio(s_clone, t_clone),
            },
            "live": {
                "layout": ns.index().inode_layout(),
                "clone_ns": live_clone,
                "note": "the live writer spine is the treap; this integration adds no \
                         code to `from_log`/`apply_record`/commit, so live mutation and \
                         publication are unchanged by construction",
            },
        }));
    }

    let integrate = all_more_compact && lookup_never_slower && live_always_treap;

    let doc = serde_json::json!({
        "schema": "orfs.performance.historical-index-integrated.v1",
        "generated_by": "tests/historical_index_integration.rs",
        "claim": "for the sealed, immutable historical role a direct-ordinal (dense) \
                  inode-id spine answers identical lookups/ranges/readdir, is more \
                  compact, and cannot regress publication or mutation because the live \
                  writer spine stays the persistent treap",
        "note": "Single run, single host. Absolute nanoseconds are host/build dependent; \
                 the *shape* (a direct-ordinal array vs a pointer-heavy treap) and the \
                 spine-bytes ratio are the point. `inode_spine_bytes` is a structural \
                 lower bound (node/entry capacities, no allocator slop, no inode \
                 payloads, which are shared in both layouts). `seal_rebuild_ns` is the \
                 one-time cost of building the dense array from the treap, paid only \
                 when an accelerator is decoded. The live column records the writer \
                 spine's layout and publication cost: it is the treap, so mutation and \
                 publication are the pre-existing Phase-27 behaviour.",
        "environment": evidence_environment(),
        "design": {
            "scales": scales,
            "lookup_queries": lookups,
            "note": "files are created directly under the root so the build is linear; \
                     the inode-id spine measured is independent of the directory shape",
        },
        "scales": rows,
        "decision": {
            "rule": "integrate only where it wins and cannot regress publication or \
                     mutation: the sealed layout must be more compact and not slower on \
                     the point lookup, and the live spine must remain the treap",
            "more_compact_at_every_scale": all_more_compact,
            "lookup_not_slower_at_every_scale": lookup_never_slower,
            "live_spine_is_treap": live_always_treap,
            "integrate": integrate,
        },
    });

    let path = manifest_dir().join("evidence/performance/historical-index-integrated.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!(
        "historical-index-integrated evidence written to {} (integrate={integrate})",
        path.display()
    );
}
