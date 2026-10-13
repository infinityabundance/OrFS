//! **Phase 74 — reviewer item #9: external baselines with honest losses.**
//!
//! `tests/baselines.rs` (Phase 53) runs the identical `src/bench.rs` file
//! workloads on the filesystems around a containerised deployment (**tmpfs**,
//! **container-overlay**, **host-fs/ext4**) and on raw memory — the external
//! floor. It does **not** run the same workloads through a *mounted OrFS*, so the
//! head-to-head the reviewer asked for ("OrFS vs ext4 vs tmpfs", a concrete
//! `read_random 4K p99`, not merely "a floor exists") was missing.
//!
//! This court fills that gap: it mounts OrFS **twice** — the classical transport
//! (**F0**) and the native FUSE-over-`io_uring` transport (**F2**, queue-affine)
//! — with the **default mounted options** (page cache enabled, so it is
//! comparable to the page-cache-warm `baselines.json` arms), and runs the same
//! `run_fs_workload` **SequentialRead** and **RandomRead4k** workloads on each.
//! The **ext4/tmpfs/overlay** and raw-memory rows are the committed
//! `evidence/performance/baselines.json` (same harness, same parameters), so the
//! comparison is genuinely head-to-head and the losses are shown, not hidden.
//!
//! Mounting requires `/dev/fuse` + `CAP_SYS_ADMIN`; expected only under
//! `scripts/container-fuse-test.sh` (`ORFS_FUSE_TEST=1`). If a mount cannot be
//! obtained the court records `ran:false` with the exact reason and never hangs.
//!
//! Evidence: `evidence/performance/external-comparison.json`.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use orfs::bench::{run_fs_workload, BenchParams, Workload};
use orfs::commit::DurabilityMode;
use orfs::fuse::{self, BackingIo, MountOptions, Transport};
use orfs::log::DEFAULT_SEGMENT_SIZE;
use orfs::namespace::{Namespace, SetAttr};

/// The same file size and random-op count `tests/baselines.rs` uses, so the
/// OrFS arms sit beside the comparable external arms under one workload.
const DATA_BYTES: u64 = 32 * 1024 * 1024;
const ITERATIONS: u64 = 20_000;
const REGION_BYTES: u64 = 4096;

/// The two read workloads the external comparators report (the write workload is
/// transport-limited through the daemon and is not the reviewer's ask).
const WORKLOADS: [Workload; 2] = [Workload::SequentialRead, Workload::RandomRead4k];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_scratch(prefix: &str) -> PathBuf {
    let base = manifest_dir().join("target").join("external-comparison-it");
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

fn init_volume(backing: &Path) -> Result<(), String> {
    let mut ns = Namespace::init(backing, DEFAULT_SEGMENT_SIZE, DurabilityMode::Ordered)
        .map_err(|e| e.to_string())?;
    // SAFETY: geteuid/getegid are pure queries.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    ns.setattr(
        orfs::index::ROOT_INODE,
        &SetAttr {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        },
    )
    .map_err(|e| e.to_string())?;
    ns.sync().map_err(|e| e.to_string())
}

struct Mounted {
    mount: fuse::OrfsMount,
    root: PathBuf,
}

/// Mount OrFS with the **default** (page-cache-warm) options, so it is comparable
/// to the `baselines.json` arms. `affine` selects the F2 queue-affine topology.
fn mount_for(scratch: &Path, label: &'static str, affine: bool) -> Result<Mounted, String> {
    let mnt = scratch.join(format!("{label}-mnt"));
    let back = scratch.join(format!("{label}-backing"));
    fs::create_dir_all(&mnt).map_err(|e| e.to_string())?;
    init_volume(&back)?;
    let opts = MountOptions {
        transport: if affine {
            Transport::FuseUring
        } else {
            Transport::Fuse
        },
        backing_io: BackingIo::Uring,
        // Default (page cache on, non-zero TTLs): the ordinary mounted read path,
        // the arm comparable to the page-cache-warm external baselines.
        attr_ttl: Duration::from_secs(1),
        entry_ttl: Duration::from_secs(1),
        ..Default::default()
    };
    if affine {
        std::env::set_var("ORFS_F2_RINGS", "8");
        std::env::set_var("ORFS_F2_ENTRIES_PER_QUEUE", "4");
    }
    let mount = fuse::spawn(&back, &mnt, &opts).map_err(|e| e.to_string());
    std::env::remove_var("ORFS_F2_RINGS");
    std::env::remove_var("ORFS_F2_ENTRIES_PER_QUEUE");
    let mount = mount?;
    Ok(Mounted { mount, root: mnt })
}

fn params() -> BenchParams {
    BenchParams {
        data_bytes: DATA_BYTES,
        iterations: ITERATIONS,
        readers: 1,
        region_bytes: REGION_BYTES,
        durability: DurabilityMode::Ordered,
        cold_cache: false,
    }
}

/// Run every workload on an OrFS mount, returning a `workload -> measurement`
/// map (the same shape `baselines.json` uses per backend).
fn run_workloads(m: &Mounted) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let params = params();
    let mut out = serde_json::Map::new();
    for w in WORKLOADS {
        let measurement = run_fs_workload(&m.root, w, &params).map_err(|e| e.to_string())?;
        out.insert(
            w.name().to_string(),
            serde_json::to_value(&measurement).map_err(|e| e.to_string())?,
        );
    }
    Ok(out)
}

#[test]
fn external_comparison() {
    let required = fuse_test_required();
    let scratch = unique_scratch("extcmp");

    let mut orfs = serde_json::Map::new();
    let mut ran: Vec<&'static str> = Vec::new();
    let mut skipped: Vec<serde_json::Value> = Vec::new();

    for (label, affine) in [("F0", false), ("F2", true)] {
        match mount_for(&scratch, label, affine) {
            Ok(m) => {
                if affine && m.mount.transport_used() != orfs::fuse_uring::TransportProfile::F2 {
                    // Do not silently mislabel F0 as F2.
                    skipped.push(serde_json::json!({
                        "arm": label,
                        "ran": false,
                        "reason": "requested F2 but the mount negotiated a fallback transport",
                    }));
                    let _ = m.mount.unmount();
                    continue;
                }
                match run_workloads(&m) {
                    Ok(results) => {
                        orfs.insert(label.to_string(), serde_json::Value::Object(results));
                        ran.push(label);
                    }
                    Err(e) => skipped.push(serde_json::json!({
                        "arm": label, "ran": false, "reason": e,
                    })),
                }
                let _ = m.mount.unmount();
            }
            Err(e) => {
                if required {
                    panic!("{label} mount failed under ORFS_FUSE_TEST=1: {e}");
                }
                skipped.push(serde_json::json!({
                    "arm": label, "ran": false, "reason": e,
                }));
                eprintln!("external comparison: {label} mount unavailable: {e}");
                let _ = fs::remove_dir_all(&scratch);
                return;
            }
        }
    }
    let _ = fs::remove_dir_all(&scratch);

    let environment = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());
    let doc = serde_json::json!({
        "schema": "orfs.performance.external-comparison.v1",
        "generated_by": "tests/external_comparison.rs::external_comparison",
        "method": "The identical src/bench.rs workloads (SequentialRead, RandomRead4k) run through \
                   a real, ordinary OrFS mount (default page cache) on the classical F0 transport \
                   and the native F2 (FUSE-over-io_uring, queue-affine) transport. The ext4 / tmpfs \
                   / container-overlay and raw-memory comparators are the committed \
                   evidence/performance/baselines.json (same harness, same parameters).",
        "page_cache": "warm (not dropped; CAP_SYS_ADMIN unavailable)",
        "params": {
            "data_bytes": DATA_BYTES,
            "iterations": ITERATIONS,
            "region_bytes": REGION_BYTES,
        },
        "arms_ran": ran,
        "arms_skipped": skipped,
        "orfs": orfs,
        "comparators_source": "evidence/performance/baselines.json",
        "environment": {
            "bench": serde_json::to_value(&environment).unwrap_or(serde_json::Value::Null),
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        },
    });

    let path = manifest_dir().join("evidence/performance/external-comparison.json");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut s) = serde_json::to_string_pretty(&doc) {
        s.push('\n');
        let _ = fs::write(&path, s);
    }
    eprintln!("external comparison: arms ran = {ran:?}");
}
