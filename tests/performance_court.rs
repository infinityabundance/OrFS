//! Phase 12 **performance court** (research §30–§32; `research/OrFS prompt.md`
//! §30–§33).
//!
//! This test drives the [`orfs::bench`] harness end to end so the performance
//! evidence is **machine-generated** by a real run, not transcribed:
//!
//! * a **conventional** baseline (a plain directory on the same backing medium);
//! * `F0` (traditional FUSE, synchronous backing), `F1` (traditional FUSE,
//!   `io_uring` backing), `F2` (FUSE-over-`io_uring`) and their EKBLOOM variants
//!   `E1`/`E2` when a real FUSE mount is available.
//!
//! It writes `evidence/performance/{sequential-read,random-read,append-write,
//! fuse-baseline,mount-replay}.json` when run against real mounts, and the
//! gitignored `evidence/performance/conventional/` copy of the same files when
//! run without `ORFS_FUSE_TEST=1`. Namespacing by mount mode means a plain
//! `cargo test` can never overwrite the benchmark evidence produced under
//! `scripts/container-fuse-test.sh`.
//!
//! ## Running it
//!
//! Under the ordinary (unprivileged) test container it runs the **conventional**
//! baseline only and records the mounted configurations as skipped. Under
//! `ORFS_FUSE_TEST=1` (the `orfs-kmount` container, `scripts/container-fuse-test.sh`)
//! a real mount is mandatory: a mount failure is a hard test failure.

use std::path::{Path, PathBuf};

use orfs::bench::{self, BenchConfig, BenchParams, Workload};
use orfs::commit::DurabilityMode;
use orfs::fuse::{MountOptions, StatfsMode};

/// Workloads driven through a filesystem root (mount point or plain directory).
const FS_WORKLOADS: [Workload; 11] = [
    Workload::SequentialRead,
    Workload::SequentialAppend,
    Workload::RandomRead4k,
    Workload::RandomWrite4k,
    Workload::RandomRead1,
    Workload::MetadataLookup,
    Workload::CreateUnlink,
    Workload::Rename,
    Workload::DirEnumeration,
    Workload::ConcurrentReaders,
    Workload::FsyncLatency,
];

/// The stored-filesystem configurations, in isolation order. `F2`/`E2` are the
/// FUSE-over-`io_uring` transport; under a non-mount-capable container they are
/// skipped with the exact static reason, and under the kmount container they are
/// attempted and the live mount decides (`src/bench.rs`).
const FUSE_CONFIGS: [BenchConfig; 5] = [
    BenchConfig::F0,
    BenchConfig::F1,
    BenchConfig::E1,
    BenchConfig::F2,
    BenchConfig::E2,
];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn evidence_dir() -> PathBuf {
    // The mounted run is the benchmark: it owns `evidence/performance/`. A plain
    // (non-FUSE) run is a smoke pass, not a benchmark, so it writes to a
    // gitignored subdirectory and can never clobber the committed benchmark
    // evidence. The two writers of mount-replay data are therefore also distinct
    // from `tests/snapshot_model.rs` (which writes `mount-replay-snapshot.json`).
    let base = manifest_dir().join("evidence/performance");
    if std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1") {
        base
    } else {
        base.join("conventional")
    }
}

fn unique_scratch(prefix: &str) -> PathBuf {
    let base = manifest_dir().join("target").join("perf-court");
    std::fs::create_dir_all(&base).expect("perf-court base");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = base.join(format!("{prefix}-{pid}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(value).expect("serialize");
    s.push('\n');
    std::fs::write(path, s).expect("write evidence");
}

/// Run one (config, workload) and return its report JSON, or an
/// `unavailable`/`skipped` marker.
fn run_one(
    backing: &Path,
    scratch: &Path,
    config: BenchConfig,
    workload: Workload,
    params: &BenchParams,
    base: &MountOptions,
) -> serde_json::Value {
    match bench::run(
        backing,
        scratch,
        config,
        workload,
        params,
        base,
        std::env::var("ORFS_IMAGE").ok(),
    ) {
        Ok(report) => serde_json::to_value(&report).expect("serialize report"),
        Err(e) => serde_json::json!({
            "config": config.name(),
            "workload": workload.name(),
            "config_available": false,
            "error": e.to_string(),
        }),
    }
}

/// Mount a real OrFS volume once and time a compact F0 baseline sample, so
/// `fuse-baseline.json` records a truthful transport description and mount
/// options even when the full per-config sweep is skipped.
fn probe_mount(backing: &Path, scratch: &Path, base: &MountOptions) -> Option<serde_json::Value> {
    let opts = BenchConfig::F0.mount_options(base);
    let mnt = scratch.join("probe-mnt");
    std::fs::create_dir_all(&mnt).ok()?;
    let t = std::time::Instant::now();
    let mount = orfs::fuse::spawn(backing, &mnt, &opts).ok()?;
    let mount_secs = t.elapsed().as_secs_f64();
    let desc = mount.transport_description();
    let requested = mount.transport_requested().requested_name();
    let used = mount.transport_used().name();
    let backing_io = if mount.backing_io_used == orfs::fuse::BackingIo::Uring {
        "uring"
    } else {
        "sync"
    };
    let negotiation = mount.fuse_uring_report();
    let unmount_ok = mount.unmount().is_ok();
    Some(serde_json::json!({
        "mount_seconds": mount_secs,
        "transport_requested": requested,
        "transport_used": used,
        "backing_io_used": backing_io,
        "durability": opts.durability.name(),
        "description": desc,
        "fuse_over_io_uring": negotiation.describe(),
        "unmounted_cleanly": unmount_ok,
    }))
}

#[test]
fn performance_court_sweep() {
    let required = std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1");
    let scratch = unique_scratch("court");
    let backing = scratch.join("backing");
    // The mountpoint (and conventional scratch) must NOT be an ancestor of the
    // backing volume, or the daemon's own backing I/O would recurse through the
    // mount. `run_root` is a sibling of `backing`.
    let run_root = scratch.join("run");
    std::fs::create_dir_all(&run_root).expect("run root");

    // Parameters: small and bounded so the whole sweep finishes quickly; identical
    // across configs so the comparison is fair. E1/E2 request asynchronous
    // manifestation, so a written object may or may not be manifested by the time
    // it is read — the honest behaviour of an optional background plane.
    let params = BenchParams {
        data_bytes: 256 * 1024,
        iterations: 200,
        readers: 4,
        region_bytes: 4096,
        durability: DurabilityMode::Ordered,
        cold_cache: false,
    };
    let base = MountOptions {
        durability: DurabilityMode::Ordered,
        statfs: StatfsMode::PhysicalSafe,
        ..Default::default()
    };

    // Create the OrFS volume (owner = the mounting uid).
    {
        let mut ns = orfs::namespace::Namespace::init(
            &backing,
            orfs::log::DEFAULT_SEGMENT_SIZE,
            DurabilityMode::Ordered,
        )
        .expect("init volume");
        // SAFETY: geteuid/getegid are pure queries.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let attrs = orfs::namespace::SetAttr {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        };
        ns.setattr(orfs::index::ROOT_INODE, &attrs)
            .expect("chown root");
        ns.sync().expect("sync");
    }
    std::fs::create_dir_all(&run_root).expect("run root");

    // Per-workload aggregator and a mount/replay record.
    let mut per_workload: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    let mut probe: serde_json::Value = serde_json::Value::Null;
    let mut mount_replay: Vec<serde_json::Value> = Vec::new();

    // Mounted configurations are only attempted under the kmount container.
    if required {
        let m = probe_mount(&backing, &scratch, &base)
            .unwrap_or_else(|| panic!("FUSE mount failed under ORFS_FUSE_TEST=1"));
        probe = m.clone();
        mount_replay.push(serde_json::json!({ "config": "f0", "probe": m }));
    }

    for workload in FS_WORKLOADS {
        let mut entries = serde_json::Map::new();

        // Conventional baseline: always.
        eprintln!("performance_court: conventional/{} ...", workload.name());
        let conv = run_one(
            &run_root,
            &run_root,
            BenchConfig::Conventional,
            workload,
            &params,
            &base,
        );
        entries.insert("conventional".to_string(), conv);

        if required {
            for config in FUSE_CONFIGS {
                eprintln!(
                    "performance_court: {}/{} ...",
                    config.name(),
                    workload.name()
                );
                let r = run_one(&backing, &run_root, config, workload, &params, &base);
                entries.insert(config.name().to_string(), r);
            }
        } else {
            let reason = "not a FUSE-capable container (ORFS_FUSE_TEST unset); \
                          run under scripts/container-fuse-test.sh";
            for config in FUSE_CONFIGS {
                entries.insert(
                    config.name().to_string(),
                    serde_json::json!({
                        "config": config.name(),
                        "config_available": false,
                        "unavailable_reason": reason,
                    }),
                );
            }
        }

        per_workload.insert(
            workload.name().to_string(),
            serde_json::Value::Object(entries),
        );
    }

    // Mount time for each stored configuration (once).
    if required {
        for config in FUSE_CONFIGS {
            let mount = run_one(
                &backing,
                &run_root,
                config,
                Workload::MountTime,
                &params,
                &base,
            );
            mount_replay.push(serde_json::json!({ "config": config.name(), "mount_time": mount }));
        }
    }

    let environment = bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());

    // Write the per-workload evidence files the directive names.
    // (file stem, schema, workload key)
    let named: [(&str, &str, &str); 3] = [
        (
            "sequential-read",
            "orfs.performance.sequential-read.v1",
            "sequential-read",
        ),
        (
            "random-read",
            "orfs.performance.random-read.v1",
            "random-read-4k",
        ),
        (
            "append-write",
            "orfs.performance.append-write.v1",
            "sequential-append",
        ),
    ];
    for (name, schema, workload_key) in named {
        let doc = serde_json::json!({
            "schema": schema,
            "generated_by": "tests/performance_court.rs",
            "mount_required": required,
            "workload": workload_key,
            "params": params,
            "environment": environment.clone(),
            "configurations": {
                "conventional": "no FUSE; conventional backing; no manifestation",
                "f0": "traditional FUSE; sync backing; no manifestation",
                "f1": "traditional FUSE; io_uring backing; no manifestation",
                "e1": "traditional FUSE; io_uring backing + EKBLOOM manifestation",
                "f2": "FUSE-over-io_uring; io_uring backing; no manifestation",
                "e2": "FUSE-over-io_uring; io_uring backing + EKBLOOM manifestation",
            },
            "results": per_workload.get(workload_key).cloned().unwrap_or(serde_json::Value::Null),
        });
        write_json(&evidence_dir().join(format!("{name}.json")), &doc);
    }

    // fuse-baseline.json — the F0 mount facts and the full measured matrix
    // (all workloads x all configurations), so every measured number is persisted.
    let f0_summary: serde_json::Value = per_workload
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                v.get("f0").cloned().unwrap_or(serde_json::Value::Null),
            )
        })
        .collect::<serde_json::Map<_, _>>()
        .into();
    write_json(
        &evidence_dir().join("fuse-baseline.json"),
        &serde_json::json!({
            "schema": "orfs.performance.fuse-baseline.v1",
            "generated_by": "tests/performance_court.rs",
            "mount_required": required,
            "environment": environment.clone(),
            "params": params,
            "mount_probe": probe,
            "f0_workloads": f0_summary,
            "workloads": per_workload,
            "note": "F0 is traditional /dev/fuse with synchronous backing I/O and no \
                     manifestation; the transport description records what actually engaged. \
                     `workloads` is the complete measured matrix (config x workload).",
        }),
    );

    // mount-replay.json — mount time (and recovery time).
    let recovery = run_one(
        &backing,
        &run_root,
        BenchConfig::Conventional,
        Workload::RecoveryTime,
        &params,
        &base,
    );
    let search = run_one(
        &backing,
        &run_root,
        BenchConfig::Conventional,
        Workload::SearchLatency,
        &params,
        &base,
    );
    let snapshot = run_one(
        &backing,
        &run_root,
        BenchConfig::Conventional,
        Workload::SnapshotLatency,
        &params,
        &base,
    );
    let mut mr = mount_replay.clone();
    mr.push(serde_json::json!({ "config": "library", "recovery_time": recovery }));
    mr.push(serde_json::json!({ "config": "library", "search_latency": search }));
    mr.push(serde_json::json!({ "config": "library", "snapshot_latency": snapshot }));
    write_json(
        &evidence_dir().join("mount-replay.json"),
        &serde_json::json!({
            "schema": "orfs.performance.mount-replay.v1",
            "generated_by": "tests/performance_court.rs",
            "environment": environment.clone(),
            "records": mr,
            "note": "mount-time is a single cold mount per stored configuration; recovery/search/\
                     snapshot are library-level (config-independent) and do not pass through FUSE.",
        }),
    );

    let _ = std::fs::remove_dir_all(&scratch);
}
