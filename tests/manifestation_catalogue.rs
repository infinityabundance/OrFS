//! Reviewer task — manifested-generation **catalogue** scaling court.
//!
//! The manifested-generation catalogue (`manifests/catalogue/`) is an immutable,
//! append-only record log that replaces the old whole-`HEAD`-list rewrite. This
//! court proves the decisive property and the safety properties:
//!
//! * **Growth-independence (the decisive property).** Per-publication work does
//!   not grow linearly with the number of accumulated generations `G`: the
//!   publication p50/p99 and the metadata bytes rewritten per publication are flat
//!   across the `1 000 / 10 000 / 100 000 / 1 000 000` checkpoints.
//! * **Recovery equals a full scan.** The catalogue-accelerated
//!   `latest_published()` returns exactly `recover().newest_per_inode()` on the
//!   recoverable set, at every checkpoint.
//! * **Torn-safety.** A torn catalogue record (segment tail or a truncated
//!   record), a corrupt summary, and a missing derived file (manifest or payload)
//!   never change the recoverable set and never invalidate an earlier commit; the
//!   existing legacy-`HEAD`/full-`*.manifest`-scan fallback remains.
//!
//! The always-on smoke is bounded (small checkpoints); the full sweep is opt-in
//! behind `ORFS_CATALOGUE_SCALING=1` and writes
//! `evidence/performance/manifestation-catalogue.json`. Run it with
//! `sh scripts/container-manifestation-catalogue.sh` (release build).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use orfs::manifestation::{
    ekbloom_format_version, CertificationState, GenerationManifest, GenerationStore,
    ManifestRegion, EKBLOOM_VERSION, MANIFEST_SCHEMA,
};
use tempfile::TempDir;

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0xCA, 0x7A, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const SHARED_REL: &str = ".or_bloom/ekbloom/scale-shared.ekb";
const SHARED_BYTES: &[u8] = b"scale";

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

/// Create the single shared payload every fixture generation references and
/// return its digest.
fn shared_payload(dir: &Path) -> [u8; 32] {
    let path = dir.join(SHARED_REL);
    std::fs::create_dir_all(path.parent().unwrap()).expect("payload dir");
    std::fs::write(&path, SHARED_BYTES).expect("shared payload");
    *blake3::hash(SHARED_BYTES).as_bytes()
}

/// A minimal flattened-table manifest referencing the shared payload (only the
/// identity fields the catalogue and recovery care about are meaningful).
fn mk_manifest(
    g: u64,
    inode: u64,
    version: u64,
    root: u64,
    digest: [u8; 32],
) -> GenerationManifest {
    let region = ManifestRegion {
        logical_start: 0,
        logical_end: 1,
        owner_generation: g,
        payload_offset: 0,
        payload_rel_path: SHARED_REL.to_string(),
        payload_blake3: digest,
        visible_bytes: 1,
        physical_bytes: 1,
        profile_kind: 3,
        certification: 3,
        ekbloom_object_id: None,
    };
    GenerationManifest {
        schema: MANIFEST_SCHEMA,
        generation: g,
        volume_uuid: UUID,
        inode,
        inode_version: version,
        root,
        backend: "scale-fixture".to_string(),
        ekbloom_version: EKBLOOM_VERSION.to_string(),
        ekbloom_format: ekbloom_format_version(),
        profile: "full".to_string(),
        profile_kind: 3,
        logical_start: 0,
        logical_end: 1,
        physical_start: 0,
        physical_end: 1,
        interval: None,
        depth: None,
        region_bytes: None,
        certification: CertificationState::Built,
        certification_method: "scale-fixture".to_string(),
        payload_rel_path: String::new(),
        ekbloom_object_id: None,
        payload_blake3: [0u8; 32],
        visible_bytes: 1,
        physical_bytes: 1,
        concealed_bytes: 0,
        source_bytes: 1,
        components: Vec::new(),
        base_generation: None,
        base_manifest_blake3: None,
        overlay_depth: 0,
        regions: vec![region],
        manifest_blake3: [0u8; 32],
    }
    .sealed()
}

type Map = BTreeMap<u64, (u64, u64, [u8; 32])>;

/// Newest-per-inode `(inode_version, generation, manifest_blake3)` from a full
/// validated recovery.
fn full_map(store: &GenerationStore) -> Map {
    store
        .recover()
        .expect("full recover")
        .generations
        .iter()
        .fold(BTreeMap::new(), |mut acc, m| {
            let e = acc.entry(m.inode).or_insert((0, 0, [0u8; 32]));
            if (m.inode_version, m.generation) > (e.0, e.1) {
                *e = (m.inode_version, m.generation, m.manifest_blake3);
            }
            acc
        })
}

/// Newest-per-inode from the catalogue-accelerated path.
fn fast_map(store: &GenerationStore) -> (Map, bool) {
    let latest = store.latest_published().expect("latest recover");
    let map = latest
        .published
        .iter()
        .map(|(inode, m)| (*inode, (m.inode_version, m.generation, m.manifest_blake3)))
        .collect();
    (map, latest.catalogue_used)
}

fn assert_recovery_agrees(store: &GenerationStore) {
    let (fast, _) = fast_map(store);
    assert_eq!(
        full_map(store),
        fast,
        "catalogue recovery must equal the full-scan recovery on the recoverable set"
    );
}

fn greatest_file(dir: &Path, prefix: &str, suffix: &str) -> Option<PathBuf> {
    let mut best: Option<u64> = None;
    for ent in std::fs::read_dir(dir).ok()?.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name
            .strip_prefix(prefix)
            .and_then(|s| s.strip_suffix(suffix))
        {
            if let Ok(i) = stem.parse::<u64>() {
                best = Some(best.map_or(i, |b| b.max(i)));
            }
        }
    }
    best.map(|i| dir.join(format!("{prefix}{i:010}{suffix}")))
}

fn count_files(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|rd| rd.flatten().filter(|e| e.path().is_file()).count() as u64)
        .unwrap_or(0)
}

fn percentile(samples: &[u64], p: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut s = samples.to_vec();
    s.sort_unstable();
    let rank = ((p / 100.0) * s.len() as f64).ceil() as usize;
    s[rank.saturating_sub(1).min(s.len() - 1)]
}

fn resident_kib() -> u64 {
    let Ok(s) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

// ---------------------------------------------------------------------------
// (1) Correctness + torn/corrupt/missing damage (always on, bounded)
// ---------------------------------------------------------------------------

#[test]
fn catalogue_equals_full_scan_and_survives_damage() {
    let td = TempDir::new().unwrap();
    let dir = td.path();
    let digest = shared_payload(dir);
    let store = GenerationStore::new(dir);
    store.ensure_dirs().unwrap();

    // 40 real publications across 6 inodes.
    for g in 1..=40u64 {
        let inode = 1 + (g % 6);
        store
            .publish(&mk_manifest(g, inode, 1, 100, digest))
            .unwrap();
    }
    let (_, used) = fast_map(&store);
    assert!(used, "a healthy catalogue should serve the fast path");
    assert_recovery_agrees(&store);

    // --- legacy HEAD union (backward-compatible read) ---
    store.write_head(&[1, 7, 13]).unwrap();
    assert_recovery_agrees(&store);
    assert!(store.read_head().is_some());

    // --- torn record: append garbage to the populated segment's tail ---
    let seg = greatest_file(&store.catalogue_dir(), "seg-", ".cat").expect("a segment");
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(&[0xAB; 37]).unwrap(); // not a framed record
    }
    assert_recovery_agrees(&store);

    // --- a corrupt summary must be skipped (a smaller summary is still usable) ---
    let seeded = dir.join("seeded");
    let seed = GenerationStore::new(&seeded);
    let seeded_digest = shared_payload(&seeded);
    seed.seed_scale(1, 2500, 6, 1, 100, UUID, SHARED_REL, seeded_digest)
        .unwrap();
    assert_recovery_agrees(&seed);
    let sum = greatest_file(&seed.catalogue_dir(), "sum-", ".sum").expect("a summary");
    std::fs::write(&sum, b"corrupt summary bytes").unwrap();
    assert_recovery_agrees(&seed);

    // --- missing derived file: delete the newest manifest for one inode ---
    let (newest, _) = fast_map(&seed);
    let (&victim, entry) = newest.iter().next().expect("an inode");
    std::fs::remove_file(
        seed.manifest_dir()
            .join(format!("{:020}.manifest", entry.1)),
    )
    .unwrap();
    let (fast_after, _) = fast_map(&seed);
    assert_eq!(
        full_map(&seed),
        fast_after,
        "missing manifest must not diverge"
    );
    assert!(
        fast_after.get(&victim).map(|e| e.1) < Some(entry.1),
        "the deleted newest generation must not be selected"
    );

    // --- missing payload: every generation is invalid; both paths agree (empty) ---
    std::fs::remove_file(seed.volume_root().join(SHARED_REL)).unwrap();
    assert!(
        full_map(&seed).is_empty(),
        "with no payload nothing is recoverable"
    );
    assert_eq!(full_map(&seed), fast_map(&seed).0);
}

#[test]
fn legacy_volume_migrates_catalogue() {
    let td = TempDir::new().unwrap();
    let dir = td.path();
    let digest = shared_payload(dir);
    let store = GenerationStore::new(dir);
    store.ensure_dirs().unwrap();
    for g in 1..=20u64 {
        let inode = 1 + (g % 4);
        store
            .publish(&mk_manifest(g, inode, 1, 100, digest))
            .unwrap();
    }

    // Simulate a pre-catalogue volume: remove the catalogue, keep a legacy HEAD.
    std::fs::remove_dir_all(store.catalogue_dir()).unwrap();
    store.write_head(&(1..=20).collect::<Vec<_>>()).unwrap();

    // With no catalogue the fast path must fall back, and still equal the scan.
    let (map, used) = fast_map(&store);
    assert!(!used, "with no catalogue the fast path must fall back");
    assert_eq!(full_map(&store), map);

    // A publication performs the one-time migration; the fast path is then
    // complete (no older generation is silently lost).
    store.publish(&mk_manifest(21, 2, 1, 100, digest)).unwrap();
    let (map2, used2) = fast_map(&store);
    assert!(used2, "the migrated catalogue must serve the fast path");
    assert_eq!(full_map(&store), map2);
    assert_eq!(map2.get(&1).map(|e| e.1), Some(20));
    assert_eq!(map2.get(&2).map(|e| e.1), Some(21));
}

// ---------------------------------------------------------------------------
// (2) Bounded smoke: per-publication work must not scale with G
// ---------------------------------------------------------------------------

struct Checkpoint {
    generations: u64,
    inodes: u64,
    publish: PublishStat,
    recovery: RecoveryStat,
    resident_kib: u64,
    catalogue_bytes: u64,
}

struct PublishStat {
    p50_ns: u64,
    p99_ns: u64,
    bytes_rewritten: u64,
    dir_ops: u64,
    samples: usize,
}

struct RecoveryStat {
    fast_micros: u64,
    full_micros: u64,
    fast_catalogue_used: bool,
    full_generations: u64,
    rejected: usize,
    agrees: bool,
}

fn measure(
    dir: &Path,
    generations: u64,
    inodes: u64,
    publishes: u64,
    do_full_scan: bool,
) -> Checkpoint {
    let digest = shared_payload(dir);
    let store = GenerationStore::new(dir);
    store
        .seed_scale(1, generations, inodes, 1, 100, UUID, SHARED_REL, digest)
        .expect("seed scale");

    // Measure real publications on top of the seeded (G-sized) catalogue.
    let cat_before = store.catalogue_bytes();
    let manifest_dir_before = count_files(&store.manifest_dir());
    let mut samples = Vec::with_capacity(publishes as usize);
    for k in 0..publishes {
        let g = generations + 1 + k;
        let inode = 1 + (g % inodes);
        let m = mk_manifest(g, inode, 1, 100, digest);
        let t = Instant::now();
        store.publish(&m).expect("publish");
        samples.push(t.elapsed().as_nanos() as u64);
    }
    let cat_after = store.catalogue_bytes();
    let manifest_dir_after = count_files(&store.manifest_dir());

    let t = Instant::now();
    let (fast, used) = fast_map(&store);
    let fast_micros = t.elapsed().as_micros() as u64;

    let (full_micros, full_generations, rejected, agrees) = if do_full_scan {
        let t = Instant::now();
        let rec = store.recover().expect("full recover");
        let micros = t.elapsed().as_micros() as u64;
        let map = rec.generations.iter().fold(BTreeMap::new(), |mut acc, m| {
            let e = acc.entry(m.inode).or_insert((0, 0, [0u8; 32]));
            if (m.inode_version, m.generation) > (e.0, e.1) {
                *e = (m.inode_version, m.generation, m.manifest_blake3);
            }
            acc
        });
        (
            micros,
            rec.generations.len() as u64,
            rec.rejected,
            map == fast,
        )
    } else {
        (0, 0, 0, true)
    };

    Checkpoint {
        generations,
        inodes,
        publish: PublishStat {
            p50_ns: percentile(&samples, 50.0),
            p99_ns: percentile(&samples, 99.0),
            bytes_rewritten: cat_after.saturating_sub(cat_before) / publishes.max(1),
            dir_ops: manifest_dir_after.saturating_sub(manifest_dir_before) / publishes.max(1),
            samples: samples.len(),
        },
        recovery: RecoveryStat {
            fast_micros,
            full_micros,
            fast_catalogue_used: used,
            full_generations,
            rejected,
            agrees,
        },
        resident_kib: resident_kib(),
        catalogue_bytes: cat_after,
    }
}

#[test]
fn publication_cost_is_growth_independent_smoke() {
    let td = TempDir::new().unwrap();
    let small = measure(&td.path().join("small"), 200, 8, 64, true);
    let large = measure(&td.path().join("large"), 2_000, 8, 64, true);

    assert!(
        small.recovery.agrees,
        "smoke: catalogue must equal full scan"
    );
    assert!(
        large.recovery.agrees,
        "smoke: catalogue must equal full scan"
    );
    assert!(
        small.recovery.fast_catalogue_used && large.recovery.fast_catalogue_used,
        "smoke: the fast catalogue path must be used"
    );

    // A 10× growth in G must not make publication grow linearly (≈10×); allow a
    // generous 4× for noise/build variance.
    let ratio = large.publish.p50_ns as f64 / small.publish.p50_ns.max(1) as f64;
    assert!(
        ratio < 4.0,
        "publication p50 grew {ratio:.2}× over a 10× growth in G \
         ({} ns -> {} ns); it must not be linear",
        small.publish.p50_ns,
        large.publish.p50_ns
    );
    assert!(
        large.publish.bytes_rewritten <= 512,
        "record must stay small"
    );
}

// ---------------------------------------------------------------------------
// (3) The full sweep (opt-in; writes evidence)
// ---------------------------------------------------------------------------

fn sweep_checkpoints() -> Vec<u64> {
    std::env::var("ORFS_CATALOGUE_CHECKPOINTS")
        .ok()
        .and_then(|s| {
            let v: Vec<u64> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
            (!v.is_empty()).then_some(v)
        })
        .unwrap_or_else(|| vec![1_000, 10_000, 100_000, 1_000_000])
}

#[test]
fn catalogue_scaling_sweep() {
    if std::env::var("ORFS_CATALOGUE_SCALING").as_deref() != Ok("1") {
        eprintln!(
            "catalogue_scaling_sweep: skipped (set ORFS_CATALOGUE_SCALING=1 to run the full sweep)"
        );
        return;
    }
    let td = TempDir::new().unwrap();
    let inodes: u64 = std::env::var("ORFS_CATALOGUE_INODES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64);
    let publishes: u64 = std::env::var("ORFS_CATALOGUE_PUBLISHES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256);

    let mut checkpoints = Vec::new();
    for g in sweep_checkpoints() {
        let dir = td.path().join(format!("g{g}"));
        let cp = measure(&dir, g, inodes, publishes, true);
        eprintln!(
            "catalogue sweep: G={g} inodes={inodes} p50={}ns p99={}ns bytes/pub={} \
             fast_rec={}us full_rec={}us",
            cp.publish.p50_ns,
            cp.publish.p99_ns,
            cp.publish.bytes_rewritten,
            cp.recovery.fast_micros,
            cp.recovery.full_micros
        );
        checkpoints.push(cp);
    }

    // The decisive property: publication p50/p99 do not grow linearly with G.
    let first = &checkpoints[0];
    let last = checkpoints.last().unwrap();
    let g_ratio = last.generations as f64 / first.generations as f64;
    let p50_ratio = last.publish.p50_ns as f64 / first.publish.p50_ns.max(1) as f64;
    let p99_ratio = last.publish.p99_ns as f64 / first.publish.p99_ns.max(1) as f64;
    let all_agree = checkpoints.iter().all(|c| c.recovery.agrees);
    let all_fast = checkpoints.iter().all(|c| c.recovery.fast_catalogue_used);

    assert!(
        all_agree,
        "recovery must equal a full scan at every checkpoint"
    );
    assert!(
        all_fast,
        "the fast catalogue path must be used at every checkpoint"
    );
    assert!(
        p50_ratio < 5.0 && p99_ratio < 5.0,
        "publication cost grew with G ({g_ratio:.0}× more generations): p50 ×{p50_ratio:.2}, \
         p99 ×{p99_ratio:.2}; it must be growth-independent"
    );

    let environment = serde_json::json!({
        "bench": serde_json::to_value(orfs::bench::Environment::capture(
            std::env::var("ORFS_IMAGE").ok()
        ))
        .unwrap_or(serde_json::Value::Null),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "resident_kib_end": resident_kib(),
    });

    let rows: Vec<serde_json::Value> = checkpoints
        .iter()
        .map(|c| {
            serde_json::json!({
                "generations": c.generations,
                "inodes": c.inodes,
                "publication": {
                    "samples": c.publish.samples,
                    "p50_ns": c.publish.p50_ns,
                    "p99_ns": c.publish.p99_ns,
                    "metadata_bytes_rewritten_per_publication": c.publish.bytes_rewritten,
                    "directory_operations_per_publication": c.publish.dir_ops,
                    "legacy_head_bytes_rewritten_counterfactual": (c.generations + 1) * 8 + 12,
                },
                "recovery": {
                    "fast_micros": c.recovery.fast_micros,
                    "full_scan_micros": c.recovery.full_micros,
                    "fast_path_catalogue_used": c.recovery.fast_catalogue_used,
                    "full_scan_generations": c.recovery.full_generations,
                    "full_scan_rejected": c.recovery.rejected,
                    "equals_full_scan": c.recovery.agrees,
                },
                "resident_kib": c.resident_kib,
                "catalogue_bytes": c.catalogue_bytes,
            })
        })
        .collect();

    let doc = serde_json::json!({
        "schema": "orfs.performance.manifestation-catalogue.v1",
        "generated_by": "tests/manifestation_catalogue.rs",
        "note": "Single-run, single-host measurements; absolute nanoseconds are host/build \
                 sensitive and the shape is the point. Checkpoints are seeded with a bulk \
                 fixture (`GenerationStore::seed_scale`) so a volume with up to 1e6 \
                 generations can be materialised without ~1e6*3 fsyncs; the *publication* \
                 cost is then measured with real `GenerationStore::publish` calls on top of \
                 the G-sized catalogue. `legacy_head_bytes_rewritten_counterfactual` is the \
                 old protocol's per-publication HEAD rewrite size (8*(G+1)+12 bytes) \
                 computed analytically, not measured.",
        "design": {
            "catalogue_dir": "manifests/catalogue/",
            "segments": "seg-<index:010>.cat, append-only, immutable once sealed (128 KiB)",
            "record": "fixed 128 bytes: body_len + family + schema + generation + uuid + \
                       inode + inode_version + root + manifest_blake3 + payload_blake3 + crc32c",
            "pointer": "CURRENT, rewritten only when a segment is sealed",
            "summary": "sum-<through:010>.sum, immutable folded newest-per-inode, crc32c",
            "publication": "O(1) amortized append + fsync (no whole-list rewrite)",
            "recovery_fast": "newest usable summary + only the segments after it (suffix)",
            "recovery_full": "legacy HEAD union full *.manifest scan, validated (equals a scan)",
        },
        "environment": environment,
        "checkpoints": rows,
        "assertions": {
            "publication_growth_ratio_G": g_ratio,
            "publication_p50_ratio_first_to_last": p50_ratio,
            "publication_p99_ratio_first_to_last": p99_ratio,
            "publication_is_growth_independent": p50_ratio < 5.0 && p99_ratio < 5.0,
            "recovery_equals_full_scan_at_every_checkpoint": all_agree,
            "fast_catalogue_path_used_at_every_checkpoint": all_fast,
            "inodes": inodes,
            "publishes_measured_per_checkpoint": publishes,
        },
    });

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("evidence/performance/manifestation-catalogue.json");
    write_json(&path, &doc);
    eprintln!(
        "manifestation-catalogue evidence written to {}",
        path.display()
    );
}
