//! **Phase 66 — reviewer item: the paired *mounted* planner benchmark (phases 37/43).**
//!
//! The Phase-43 read-planner court and the Phase-56 64-thread court measured the
//! planner **in process**. This court puts a heterogeneous committed history
//! behind a **real OrFS FUSE mount** and measures the manifested read path
//! against the authoritative-only read path **on the same history**, per size
//! class.
//!
//! ## What it builds
//!
//! One deterministic backing volume holds a fixed, heterogeneous history:
//!
//! * **sizes** — a 1-byte object and 64/256 KiB objects, so the three request size
//!   classes the reviewer asked for (`1 B`, `4 KiB`, `64 KiB`) are all exercised;
//! * **fragmentation** — three levels, measured as the authoritative extent count:
//!   contiguous (1 extent), moderate (256 extents), and heavy (1024 extents);
//! * **hot and cold** — the workload reads the hot objects heavily and the cold
//!   objects rarely, so per-object selection models are warmed to different
//!   degrees.
//!
//! Manifestation is then enabled and every eligible object is manifested
//! (production `Namespace::enable_manifestation` + `manifest_eligible`), so the
//! planner has real candidates to select or reject.
//!
//! ## What it measures (paired, same history)
//!
//! * **Mounted arm** — the *same* manifested backing is mounted **twice** over the
//!   same history: once with manifestation enabled (the manifested arm) and once
//!   with it disabled (the authoritative-only arm). Both mounts run the identical
//!   deterministic request list; the receipt records per-size-class p50/p95/p99 of
//!   the client-side `pread`.
//! * **In-process isolation** — the manifested volume is reopened and the identical
//!   request list is served through the measured `ReadPlanner` (manifested arm) and
//!   through the authoritative extent read (authoritative-only arm). This arm
//!   additionally reports, **per size class**, the planner's **selected path**,
//!   the **calibration cost** (candidate timings + first-pass wall time), and the
//!   planner's **memory residency**.
//!
//! A cross-commit *before/after* (pre-Phase-43 vs Phase-43) is **not** possible
//! here without a second source tree, so it is not claimed. The paired comparison
//! that *is* available in one tree — manifested vs authoritative-only over the
//! identical history and workload — is what this court reports.
//!
//! Mounting requires `/dev/fuse` + `CAP_SYS_ADMIN`; the court is expected only
//! under `scripts/container-planner-mounted.sh` (`ORFS_FUSE_TEST=1`). If a mount
//! cannot be obtained it records `ran: false` with the exact reason — it never
//! fabricates a result and never hangs.
//!
//! Evidence: `evidence/performance/planner-mounted-paired.json`.

use std::fs::{self, File};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use orfs::commit::DurabilityMode;
use orfs::fuse::{self, BackingIo, MountOptions, StatfsMode, Transport};
use orfs::index::ROOT_INODE;
use orfs::log::{OpenMode, DEFAULT_SEGMENT_SIZE};
use orfs::manifestation::{ManifestationConfig, ManifestationProfile};
use orfs::namespace::{Namespace, SetAttr};

/// The request size classes: 1 B, 4 KiB, 64 KiB.
const SIZES: [u64; 3] = [1, 4096, 65536];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_scratch(prefix: &str) -> PathBuf {
    let base = manifest_dir().join("target").join("planner-mounted-it");
    fs::create_dir_all(&base).expect("create base");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = base.join(format!("{prefix}-{pid}-{nanos}"));
    fs::create_dir_all(&dir).expect("create scratch");
    dir
}

fn fuse_test_required() -> bool {
    std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1")
}

fn image_digest() -> String {
    std::env::var("ORFS_IMAGE_DIGEST").unwrap_or_else(|_| "unknown".into())
}

/// A deterministic byte pattern (independent of the workload's offsets).
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u64 * 131 + 17 + seed as u64) % 251) as u8)
        .collect()
}

/// A deterministic PRNG so every arm and both mounts read identical offsets.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Lcg {
        Lcg(seed | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
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

/// One object in the fixed history.
struct Obj {
    ino: u64,
    name: &'static str,
    len: u64,
    /// The authoritative extent count (the honest fragmentation measure).
    extents: u64,
    hot: bool,
}

/// One read request in the fixed workload.
#[derive(Clone, Copy)]
struct Req {
    ino: u64,
    offset: u64,
    length: u64,
}

/// Create the fixed heterogeneous history in `backing`; return the objects and the
/// committed root. Manifestation is deliberately **not** enabled here — the caller
/// enables it, exactly as the mount and the in-process planner do.
fn build_history(backing: &Path) -> (Vec<Obj>, u64) {
    let mut ns = Namespace::init(backing, DEFAULT_SEGMENT_SIZE, DurabilityMode::Ordered)
        .expect("init volume");
    // SAFETY: `geteuid`/`getegid` are pure queries.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    ns.setattr(
        ROOT_INODE,
        &SetAttr {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        },
    )
    .expect("chown root");

    // (name, len, fragmentation: 0=contiguous, 1=moderate, 2=heavy, hot, seed)
    let specs: [(&'static str, u64, u8, bool, u8); 5] = [
        ("tiny.1b", 1, 0, true, 3),
        ("hot.contig64k", 64 * 1024, 0, true, 11),
        ("hot.frag64k", 64 * 1024, 2, true, 23),
        ("cold.mod64k", 64 * 1024, 1, false, 41),
        ("cold.contig256k", 256 * 1024, 0, false, 57),
    ];

    let mut objs = Vec::new();
    for (name, len, frag, hot, seed) in specs {
        let ino = ns
            .create(ROOT_INODE, name.as_bytes(), 0o644, uid, gid)
            .expect("create object");
        let data = pattern(len as usize, seed);
        match frag {
            0 => {
                ns.write_at(ino, 0, &data).expect("contiguous write");
            }
            1 => {
                // 256-byte chunks at a 256-byte stride: 256 extents over 64 KiB.
                let chunk = 256u64;
                let mut off = 0;
                for c in data.chunks(chunk as usize) {
                    ns.write_at(ino, off, c).expect("moderate write");
                    off += chunk;
                }
            }
            2 => {
                // 64-byte chunks at a 64-byte stride: 1024 extents over 64 KiB.
                let chunk = 64u64;
                let mut off = 0;
                for c in data.chunks(chunk as usize) {
                    ns.write_at(ino, off, c).expect("heavy write");
                    off += chunk;
                }
            }
            _ => unreachable!(),
        }
        ns.sync().expect("sync object");
        let extents = ns.extent_count(ino, ns.root()).unwrap_or(0) as u64;
        objs.push(Obj {
            ino,
            name,
            len,
            extents,
            hot,
        });
    }
    let root = ns.root();
    (objs, root)
}

/// Enable manifestation and manifest every eligible object. Returns the number of
/// published generations and the profile used.
fn manifest_all(backing: &Path, profile: ManifestationProfile) -> u64 {
    let mut ns =
        Namespace::open(backing, OpenMode::ReadWrite, DurabilityMode::Ordered).expect("reopen rw");
    ns.enable_manifestation(ManifestationConfig {
        workers: 1,
        synchronous: true,
        profile,
        max_source_bytes: 64 << 20,
        ..Default::default()
    })
    .expect("enable manifestation");
    let outcomes = ns
        .manifest_eligible(None, profile)
        .expect("manifest eligible");
    outcomes
        .iter()
        .filter(|o| o.status == orfs::manifestation::ManifestationStatus::Published)
        .count() as u64
}

/// The fixed deterministic request list. Hot objects are read heavily, cold
/// objects rarely; every request size is in {1 B, 4 KiB, 64 KiB}.
fn workload(objs: &[Obj]) -> Vec<Req> {
    const HOT_REPS: usize = 400;
    const COLD_REPS: usize = 100;
    let mut rng = Lcg::new(0x51D3_0000);
    let mut reqs = Vec::new();
    for o in objs {
        let reps = if o.hot { HOT_REPS } else { COLD_REPS };
        for &size in &SIZES {
            if size > o.len {
                continue;
            }
            let span = o.len - size;
            for _ in 0..reps {
                let off = if span == 0 { 0 } else { rng.below(span + 1) };
                reqs.push(Req {
                    ino: o.ino,
                    offset: off,
                    length: size,
                });
            }
        }
    }
    reqs
}

fn size_class(len: u64) -> &'static str {
    match len {
        1 => "1B",
        4096 => "4KiB",
        65536 => "64KiB",
        _ => "other",
    }
}

/// Run the request list through a mount, returning per-size-class latency samples
/// (ns), pooled across the requests of that size. Each object's file is opened
/// once, so the samples measure the read, never a repeated `open`.
fn measure_mount(
    mnt: &Path,
    objs: &[Obj],
    reqs: &[Req],
) -> std::collections::BTreeMap<String, Vec<u64>> {
    use std::collections::HashMap;
    let mut files: HashMap<u64, File> = HashMap::new();
    for o in objs {
        files.insert(
            o.ino,
            File::open(mnt.join(o.name)).expect("open through mount"),
        );
    }

    // Warm the page cache first (equal across arms).
    for r in reqs {
        let f = &files[&r.ino];
        let mut buf = vec![0u8; r.length as usize];
        f.read_exact_at(&mut buf, r.offset).expect("warm pread");
    }

    let mut out: std::collections::BTreeMap<String, Vec<u64>> = std::collections::BTreeMap::new();
    let mut buf = vec![0u8; 65536];
    for r in reqs {
        let f = &files[&r.ino];
        let slice = &mut buf[..r.length as usize];
        let t = Instant::now();
        f.read_exact_at(slice, r.offset).expect("pread");
        std::hint::black_box(&slice);
        out.entry(size_class(r.length).to_string())
            .or_default()
            .push(t.elapsed().as_nanos() as u64);
    }
    out
}

fn summarize(mut xs: Vec<u64>) -> serde_json::Value {
    if xs.is_empty() {
        return serde_json::Value::Null;
    }
    xs.sort_unstable();
    let n = xs.len();
    let pct = |p: f64| -> u64 {
        let idx = ((p / 100.0) * n as f64).ceil() as usize;
        xs[idx.saturating_sub(1).min(n - 1)]
    };
    serde_json::json!({
        "samples": n,
        "p50_ns": pct(50.0),
        "p95_ns": pct(95.0),
        "p99_ns": pct(99.0),
        "mean_ns": xs.iter().sum::<u64>() as f64 / n as f64,
    })
}

fn environment() -> serde_json::Value {
    serde_json::to_value(orfs::bench::Environment::capture(Some(image_digest())))
        .unwrap_or(serde_json::Value::Null)
}

fn write_json(value: &serde_json::Value) {
    let path = manifest_dir().join("evidence/performance/planner-mounted-paired.json");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut s) = serde_json::to_string_pretty(value) {
        s.push('\n');
        let _ = fs::write(&path, s);
    }
}

fn record_ran_false(blocker: String, extra: serde_json::Value) {
    let doc = serde_json::json!({
        "schema": "orfs.planner-mounted-paired.v1",
        "generated_by": "tests/planner_mounted.rs::planner_mounted_paired",
        "ran": false,
        "blocker": blocker,
        "environment": environment(),
        "extra": extra,
    });
    write_json(&doc);
}

#[test]
fn planner_mounted_paired() {
    let required = fuse_test_required();
    if !required {
        eprintln!(
            "planner_mounted: skipped (ORFS_FUSE_TEST unset); \
             run under scripts/container-planner-mounted.sh"
        );
        return;
    }
    let scratch = unique_scratch("planner-mounted");
    let backing = scratch.join("backing");
    let profile = ManifestationProfile::MaxSpeed;

    let (objs, _root) = build_history(&backing);
    let published = manifest_all(&backing, profile);
    let reqs = workload(&objs);

    let obj_json: Vec<serde_json::Value> = objs
        .iter()
        .map(|o| {
            serde_json::json!({
                "name": o.name,
                "inode": o.ino,
                "len": o.len,
                "extents": o.extents,
                "hot": o.hot,
            })
        })
        .collect();

    // ---- Mounted arm: the same history mounted manifested then authoritative ----
    let mnt_manifested = scratch.join("mnt-manifested");
    let mnt_authoritative = scratch.join("mnt-authoritative");
    fs::create_dir_all(&mnt_manifested).ok();
    fs::create_dir_all(&mnt_authoritative).ok();

    let manifested_opts = MountOptions {
        transport: Transport::Fuse,
        backing_io: BackingIo::Uring,
        read_only: true,
        statfs: StatfsMode::PhysicalSafe,
        direct_io: true,
        manifest: Some(profile),
        manifest_sync: false,
        manifest_workers: 1,
        ..Default::default()
    };
    let authoritative_opts = MountOptions {
        manifest: None,
        ..manifested_opts
    };

    let mount_m = match fuse::spawn(&backing, &mnt_manifested, &manifested_opts) {
        Ok(m) => m,
        Err(e) => {
            record_ran_false(
                format!("manifested mount failed: {e}"),
                serde_json::json!({ "objects": obj_json, "published_generations": published }),
            );
            eprintln!("planner_mounted: ran=false — manifested mount failed: {e}");
            let _ = fs::remove_dir_all(&scratch);
            if required {
                panic!("manifested mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            return;
        }
    };
    let m_manifested_used = mount_m.transport_used();
    let mount_a = match fuse::spawn(&backing, &mnt_authoritative, &authoritative_opts) {
        Ok(m) => m,
        Err(e) => {
            let _ = mount_m.unmount();
            record_ran_false(
                format!("authoritative-only mount failed: {e}"),
                serde_json::json!({ "objects": obj_json, "published_generations": published }),
            );
            eprintln!("planner_mounted: ran=false — authoritative mount failed: {e}");
            let _ = fs::remove_dir_all(&scratch);
            if required {
                panic!("authoritative mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            return;
        }
    };
    let m_authoritative_used = mount_a.transport_used();

    let mounted_manifested = measure_mount(&mnt_manifested, &objs, &reqs);
    let mounted_authoritative = measure_mount(&mnt_authoritative, &objs, &reqs);

    // ---- In-process isolation on the same history ----
    let mut ns =
        Namespace::open(&backing, OpenMode::ReadOnly, DurabilityMode::Ordered).expect("reopen");
    ns.enable_manifestation(ManifestationConfig {
        workers: 1,
        synchronous: false,
        profile,
        ..Default::default()
    })
    .expect("enable manifestation");
    let planner = ns.read_planner().cloned().expect("planner present");
    let inproc_root = ns.root();

    let mut inproc_manifested: std::collections::BTreeMap<String, Vec<u64>> =
        std::collections::BTreeMap::new();
    let mut inproc_authoritative: std::collections::BTreeMap<String, Vec<u64>> =
        std::collections::BTreeMap::new();
    let mut selected: std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>> =
        std::collections::BTreeMap::new();

    // Warmup pass: this is where the planner calibrates candidates and builds
    // per-object plans. Timed separately as the calibration cost.
    let warm_start = Instant::now();
    for &r in &reqs {
        let _ = ns
            .planned_read(r.ino, inproc_root, r.offset, r.length as u32)
            .expect("planned read");
    }
    let calibration_ns: u64 = warm_start.elapsed().as_nanos() as u64;
    let stats_after_warm = planner.stats();

    // Measured pass.
    for &r in &reqs {
        let class = size_class(r.length).to_string();

        let t = Instant::now();
        let auth_v = ns
            .read_extent(r.ino, inproc_root, r.offset, r.length)
            .expect("authoritative read");
        inproc_authoritative
            .entry(class.clone())
            .or_default()
            .push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(&auth_v);

        let t = Instant::now();
        let planned = ns
            .planned_read(r.ino, inproc_root, r.offset, r.length as u32)
            .expect("planned read");
        inproc_manifested
            .entry(class.clone())
            .or_default()
            .push(t.elapsed().as_nanos() as u64);
        // Byte-exactness: the manifested arm must never return different bytes.
        assert_eq!(
            planned.bytes, auth_v,
            "planned read differs from authoritative"
        );
        *selected
            .entry(class)
            .or_default()
            .entry(planned.path.name().to_string())
            .or_insert(0) += 1;
    }
    let stats_after = planner.stats();
    let residency = planner.resident();

    // ---- Assemble the receipt ----
    let classes: Vec<serde_json::Value> = SIZES
        .iter()
        .map(|&s| {
            let cls = size_class(s);
            serde_json::json!({
                "size_class": cls,
                "request_bytes": s,
                "mounted": {
                    "manifested": summarize(mounted_manifested.get(cls).cloned().unwrap_or_default()),
                    "authoritative_only": summarize(mounted_authoritative.get(cls).cloned().unwrap_or_default()),
                },
                "in_process": {
                    "manifested": summarize(inproc_manifested.get(cls).cloned().unwrap_or_default()),
                    "authoritative_only": summarize(inproc_authoritative.get(cls).cloned().unwrap_or_default()),
                    "selected_paths": selected.get(cls).cloned().unwrap_or_default(),
                },
            })
        })
        .collect();

    let doc = serde_json::json!({
        "schema": "orfs.planner-mounted-paired.v1",
        "generated_by": "tests/planner_mounted.rs::planner_mounted_paired",
        "ran": true,
        "claim": "the manifested read path (phases 37/43 selection, backed by real mounted \
                  manifestation) versus the authoritative-only read path, over one heterogeneous \
                  committed history and one identical workload, per size class",
        "cross_commit_note": "A pre-Phase-43 vs Phase-43 before/after is NOT possible here: it \
                              needs a second source tree. The paired comparison available in one \
                              tree — manifested vs authoritative-only on the same history — is \
                              what this receipt reports.",
        "workload": {
            "request_sizes_bytes": SIZES,
            "requests": reqs.len(),
            "hot_reps_per_size": 400,
            "cold_reps_per_size": 100,
            "objects": obj_json,
        },
        "manifestation": {
            "profile": profile.label(),
            "published_generations": published,
        },
        "mounts": {
            "manifested_transport": format!("{:?}", m_manifested_used),
            "authoritative_transport": format!("{:?}", m_authoritative_used),
        },
        "calibration": {
            "first_pass_ns": calibration_ns,
            "calibrations_after_warm": stats_after_warm.calibrations,
            "plan_builds_after_warm": stats_after_warm.plan_builds,
            "calibrations_steady_delta": stats_after.calibrations - stats_after_warm.calibrations,
            "plan_builds_steady_delta": stats_after.plan_builds - stats_after_warm.plan_builds,
        },
        "memory_residency": {
            "body_plans": residency.body_plans,
            "object_models": residency.object_models,
            "overlay_verified": residency.overlay_verified,
            "overlay_failed": residency.overlay_failed,
            "body_capacity": residency.body_capacity,
            "object_capacity": residency.object_capacity,
            "identity_capacity": residency.identity_capacity,
            "total": residency.total(),
        },
        "size_classes": classes,
        "environment": environment(),
        "caveat": "Single run, single host; latency is host/load-sensitive. The mounted latency \
                   is page-cache warm after a per-request warm read, so it measures dispatch, not \
                   cold storage. The in-process arm reports the planner's own selected path; the \
                   mounted arm reports only latency (the daemon does not export per-read path \
                   selection). Every in-process manifested read is asserted byte-identical to the \
                   authoritative read.",
    });
    write_json(&doc);

    // Console summary.
    println!("\n=== planner_mounted_paired (same history, manifested vs authoritative-only) ===");
    for c in doc["size_classes"].as_array().unwrap() {
        let g = |arm: &str, key: &str| {
            c["in_process"][arm][key]
                .as_u64()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into())
        };
        let paths = c["in_process"]["selected_paths"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        println!(
            "  {:>6}: in-proc p50 man={} auth={} | mounted p50 man={} auth={} | paths: {}",
            c["size_class"].as_str().unwrap_or("?"),
            g("manifested", "p50_ns"),
            g("authoritative_only", "p50_ns"),
            c["mounted"]["manifested"]["p50_ns"].as_u64().unwrap_or(0),
            c["mounted"]["authoritative_only"]["p50_ns"]
                .as_u64()
                .unwrap_or(0),
            paths,
        );
    }
    eprintln!(
        "planner_mounted: published={published} requests={} calibration_ns={} residency_total={}",
        reqs.len(),
        calibration_ns,
        residency.total()
    );

    let _ = mount_m.unmount();
    let _ = mount_a.unmount();
    let _ = fs::remove_dir_all(&scratch);
}
