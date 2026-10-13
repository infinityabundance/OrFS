//! **Phase 64 — the manifested direct-page atlas court (reviewer research §5).**
//!
//! The measured EKBLOOM frontier (§5) shows EKBLOOM wins for tiny random reads
//! but **not** for 4–64 KiB reads: a `path` bloom costs one symbol lookup per
//! byte, while the authoritative extent read is already `O(1)` when the object is
//! unfragmented. §5 names the missing physical form: a contiguous image that
//! serves a different request shape. This court exercises the **direct-page atlas**
//! — a page-aligned, contiguous copy of the object's committed logical bytes,
//! served by direct slicing — on an unfragmented object and a heavily fragmented
//! one, across read sizes 1 B / 64 B / 512 B / 4 KiB / 16 KiB / 64 KiB / 1 MiB.
//!
//! It proves, through the public API:
//!
//! * **Parity.** Every planner read (whatever path it selects) is byte-identical
//!   to the authoritative extent read; `verify_paths` reports the `direct-image`
//!   candidate equivalent to the authoritative bytes.
//! * **It is a measured candidate.** The atlas is wired into the same candidate
//!   enumeration and ranking as every other kind, so an unmeasured atlas is never
//!   selected and the planner only prefers it when it measured cheaper.
//! * **Honest shape.** The selection and measured latency per size class are
//!   reported as measured; the court does not force the atlas to win. The expected
//!   (and observed) shape is that the atlas loses on 1 B and wins on medium/large
//!   reads of the *fragmented* object, where one contiguous copy beats many small
//!   authoritative reads.
//!
//! The always-on smoke runs a bounded 1 MiB object in the debug gate; the full
//! sweep is opt-in behind `ORFS_ATLAS=1` and writes
//! `evidence/performance/direct-page-atlas.json` (run it via
//! `scripts/container-direct-page-atlas.sh`).

use std::path::Path;
use std::time::Instant;

use orfs::commit::DurabilityMode;
use orfs::manifestation::{ManifestationConfig, ManifestationProfile, ManifestationStatus};
use orfs::namespace::Namespace;
use orfs::readpath::{ReadPathKind, ReadQuery};
use tempfile::TempDir;

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x44, 0x50, 0x41, 0x36, 0x81, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xBB,
];

/// The read sizes the acceptance court sweeps (research §5).
const SIZES: [u64; 7] = [1, 64, 512, 4096, 16_384, 65_536, 1_048_576];

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

struct Obj {
    name: &'static str,
    inode: u64,
    data: Vec<u8>,
    extents: usize,
    fragmented: bool,
}

struct Court {
    ns: Namespace,
    root: u64,
    objects: Vec<Obj>,
}

/// Build the court: an unfragmented object (one write) and a heavily fragmented
/// object (many small interleaved writes) with identical logical content, both
/// EKBLOOM-manifested (`path(4)`) with a direct-page atlas built for each.
fn build_court(dir: &Path, logical_len: usize, frag_chunk: usize) -> Court {
    let mut ns =
        Namespace::init_with_uuid(dir, 1 << 26, UUID, 1_700_000_000, DurabilityMode::Ordered)
            .expect("init namespace");
    let data = pattern(logical_len, 0x1234_5678);

    let build_object = |ns: &mut Namespace, name: &'static str, chunk: usize| -> Obj {
        let ino = ns
            .create(ns.root_inode(), name.as_bytes(), 0o644, 0, 0)
            .expect("create");
        if chunk == 0 {
            ns.write_at(ino, 0, &data).expect("write");
        } else {
            let mut off = 0usize;
            while off < data.len() {
                let end = (off + chunk).min(data.len());
                ns.write_at(ino, off as u64, &data[off..end])
                    .expect("write");
                off = end;
            }
        }
        Obj {
            name,
            inode: ino,
            data: data.clone(),
            extents: ns.extent_count(ino, ns.root()).expect("extent count"),
            fragmented: chunk != 0,
        }
    };

    let unfrag = build_object(&mut ns, "unfragmented", 0);
    let frag = build_object(&mut ns, "fragmented", frag_chunk);
    ns.sync().expect("sync");
    let root = ns.root();

    // EKBLOOM manifestation with a certified exact-path bloom — the fast structure
    // the frontier reports for small reads, so the atlas is compared against a
    // genuine manifested contender, not only the authoritative path.
    let profile = ManifestationProfile::Path { depth: 4 };
    ns.enable_manifestation(ManifestationConfig {
        workers: 1,
        queue_capacity: 8,
        synchronous: true,
        profile,
        max_source_bytes: 64 << 20,
    })
    .expect("enable manifestation");
    for obj in [&unfrag, &frag] {
        let outcomes = ns
            .manifest_eligible(Some(obj.inode), profile)
            .expect("manifest eligible");
        for o in &outcomes {
            assert_eq!(
                o.status,
                ManifestationStatus::Published,
                "manifestation of inode {} did not publish: {:?}",
                obj.inode,
                o.detail
            );
        }
    }

    // Attach the atlas plane and build an atlas for each selected object.
    ns.attach_direct_atlas().expect("attach direct atlas");
    for obj in [&unfrag, &frag] {
        let outcome = ns
            .manifest_direct_page_atlas(obj.inode)
            .expect("manifest direct-page atlas");
        assert!(outcome.published);
    }

    Court {
        ns,
        root,
        objects: vec![unfrag, frag],
    }
}

fn atlas_bytes(ns: &Namespace, inode: u64) -> u64 {
    ns.direct_atlas_state()
        .and_then(|s| s.latest_for(inode))
        .map(|m| m.payload_bytes)
        .unwrap_or(0)
}

/// Assert the atlas is an enumerated, certified, byte-identical candidate for the
/// exact identity: the strongest deterministic proof that it is wired through
/// `candidates`/`direct_bytes` and can never change the bytes.
fn verify_atlas_candidate(ns: &Namespace, root: u64, inode: u64, length: u64) {
    let planner = ns.read_planner().expect("read planner present");
    let (size, version) = ns.inode_identity(inode).expect("identity");
    let q = ReadQuery {
        inode,
        inode_version: version,
        root,
        logical_len: size,
        offset: 0,
        length,
    };
    let mut auth = |off: u64, len: u64| ns.read_extent(inode, root, off, len);
    let verdicts = planner.verify_paths(&q, &mut auth).expect("verify paths");
    eprintln!(
        "verify_paths inode {inode} len {length}: {:?}",
        verdicts
            .iter()
            .map(|v| (v.path.name(), v.certified, v.equivalent))
            .collect::<Vec<_>>()
    );
    let di = verdicts
        .iter()
        .find(|v| v.path == ReadPathKind::DirectImage)
        .expect("the direct-image candidate must be enumerated");
    assert!(di.certified, "the atlas candidate must be certified");
    assert!(
        di.equivalent,
        "the atlas must be byte-identical to the authoritative read"
    );
}

#[derive(Debug, Clone)]
struct Row {
    object: &'static str,
    size: u64,
    selected_path: &'static str,
    planner_mean_ns: f64,
    planner_min_ns: u128,
    auth_mean_ns: f64,
    auth_min_ns: u128,
    atlas_bytes: u64,
    rounds: u32,
}

fn row_json(r: &Row) -> serde_json::Value {
    serde_json::json!({
        "object": r.object,
        "size": r.size,
        "selected_path": r.selected_path,
        "planner_mean_ns": r.planner_mean_ns,
        "planner_min_ns": r.planner_min_ns,
        "authoritative_mean_ns": r.auth_mean_ns,
        "authoritative_min_ns": r.auth_min_ns,
        "atlas_bytes": r.atlas_bytes,
        "rounds": r.rounds,
    })
}

/// Read `size` bytes (clamped to the object) from the middle, warm the plan, then
/// measure both the planner's selected path and the raw authoritative read.
fn measure(
    ns: &Namespace,
    root: u64,
    obj: &Obj,
    name: &'static str,
    size: u64,
    warm: u32,
    rounds: u32,
) -> Row {
    let logical = obj.data.len() as u64;
    let len = size.min(logical).max(1);
    let offset = if logical > len {
        (logical - len) / 2
    } else {
        0
    };
    let want = auth_slice(&obj.data, offset, len);

    // Warm-up: calibrate the identity+class and let the ranking settle.
    for _ in 0..warm {
        let r = ns
            .planned_read(obj.inode, root, offset, len as u32)
            .expect("planned read");
        assert_eq!(r.bytes, want, "{name} warm planner read diverged");
    }

    let rounds = rounds.max(1);
    let mut best = u128::MAX;
    let mut sum = 0u128;
    let mut last_path = ReadPathKind::LogicalExtent;
    for _ in 0..rounds {
        let t = Instant::now();
        let r = ns
            .planned_read(obj.inode, root, offset, len as u32)
            .expect("planned read");
        let d = t.elapsed().as_nanos();
        assert_eq!(
            r.bytes, want,
            "{name} size {size}: planner bytes are not byte-exact"
        );
        sum += d;
        best = best.min(d);
        last_path = r.path;
    }

    let mut abest = u128::MAX;
    let mut asum = 0u128;
    for _ in 0..rounds {
        let t = Instant::now();
        let b = ns
            .read_extent(obj.inode, root, offset, len)
            .expect("auth read");
        let d = t.elapsed().as_nanos();
        assert_eq!(b, want, "{name} size {size}: authoritative read diverged");
        asum += d;
        abest = abest.min(d);
    }

    Row {
        object: name,
        size,
        selected_path: last_path.name(),
        planner_mean_ns: sum as f64 / rounds as f64,
        planner_min_ns: best,
        auth_mean_ns: asum as f64 / rounds as f64,
        auth_min_ns: abest,
        atlas_bytes: atlas_bytes(ns, obj.inode),
        rounds,
    }
}

fn sweep_rows(c: &Court, warm: u32, rounds: u32) -> Vec<Row> {
    let mut rows = Vec::new();
    for obj in &c.objects {
        for &size in &SIZES {
            rows.push(measure(&c.ns, c.root, obj, obj.name, size, warm, rounds));
        }
    }
    rows
}

fn print_table(rows: &[Row]) {
    eprintln!(
        "{:<13} {:>9} {:>14} {:>14} {:>14} {:>14}",
        "object", "size", "path", "planner_mean", "auth_mean", "atlas_bytes"
    );
    for r in rows {
        eprintln!(
            "{:<13} {:>9} {:>14} {:>14.1} {:>14.1} {:>14}",
            r.object, r.size, r.selected_path, r.planner_mean_ns, r.auth_mean_ns, r.atlas_bytes
        );
    }
}

#[test]
fn direct_page_atlas_smoke() {
    let td = TempDir::new().unwrap();
    // A 1 MiB object, lightly fragmented (256 extents) — bounded for the debug gate.
    let c = build_court(td.path(), 1 << 20, 4096);

    assert_eq!(
        c.ns.direct_atlas_state().unwrap().generation_count(),
        2,
        "both objects must have a published atlas"
    );
    assert_eq!(
        c.objects[0].extents, 1,
        "the unfragmented object must map one extent"
    );
    assert!(
        c.objects[1].extents >= 128,
        "the fragmented object must map many extents (got {})",
        c.objects[1].extents
    );
    for obj in &c.objects {
        assert!(
            atlas_bytes(&c.ns, obj.inode) >= (1 << 20),
            "the atlas payload must hold the logical bytes"
        );
    }

    // The atlas is a certified, byte-identical candidate for the exact identity.
    verify_atlas_candidate(&c.ns, c.root, c.objects[0].inode, 4096);
    verify_atlas_candidate(&c.ns, c.root, c.objects[1].inode, 1 << 20);

    let rows = sweep_rows(&c, 4, 12);
    print_table(&rows);
    if let Some(p) = c.ns.read_planner() {
        eprintln!("chosen: {:?}", p.chosen_counts());
        for m in p.measurements() {
            eprintln!(
                "  measured {:<16} {:<12} ewma={:>12.1} ns  samples={}",
                m.path.name(),
                m.class.name(),
                m.ewma_ns,
                m.samples
            );
        }
    }
    // measure() already asserted byte-exactness for every read; here we only
    // require that the direct-image candidate was actually exercised somewhere.
    assert!(
        rows.iter()
            .any(|r| r.selected_path == ReadPathKind::DirectImage.name()),
        "the direct-image path was never selected in the smoke court"
    );
}

#[test]
fn direct_page_atlas_sweep() {
    if std::env::var("ORFS_ATLAS").as_deref() != Ok("1") {
        eprintln!("direct_page_atlas_sweep: skipped (set ORFS_ATLAS=1 to run the full sweep)");
        return;
    }
    let td = TempDir::new().unwrap();
    // A 1 MiB object, heavily fragmented (1024 extents).
    let c = build_court(td.path(), 1 << 20, 1024);
    let rows = sweep_rows(&c, 8, 40);
    print_table(&rows);

    // Every read is byte-exact (measure asserts it); record the object shape.
    let objects: Vec<serde_json::Value> = c
        .objects
        .iter()
        .map(|o| {
            serde_json::json!({
                "name": o.name,
                "inode": o.inode,
                "logical_len": o.data.len(),
                "extents": o.extents,
                "fragmented": o.fragmented,
                "atlas_bytes": atlas_bytes(&c.ns, o.inode),
            })
        })
        .collect();

    let environment = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());
    let doc = serde_json::json!({
        "schema": "orfs.performance.direct-page-atlas.v1",
        "generated_by": "tests/direct_page_atlas.rs",
        "note": "Single-run, single-host measurement of the manifested direct-page \
                 atlas (research §5): a page-aligned, contiguous copy of an object's \
                 committed logical bytes, served by direct slicing through the OrFS \
                 read planner. Both objects are EKBLOOM-manifested (profile path(4)) \
                 and atlas-backed at the same committed root; every planner read is \
                 asserted byte-identical to the authoritative extent read. The atlas \
                 is only ever an added, measured candidate, so it is selected only \
                 where it measured cheaper.",
        "read_sizes": SIZES,
        "objects": objects,
        "rows": rows.iter().map(row_json).collect::<Vec<_>>(),
        "parity": { "all_byte_exact": true },
        "environment": {
            "bench": serde_json::to_value(&environment).unwrap_or(serde_json::Value::Null),
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        },
    });

    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/performance/direct-page-atlas.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!("direct-page-atlas evidence written to {}", path.display());
}
