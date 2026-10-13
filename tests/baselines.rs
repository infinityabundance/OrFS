//! **Phase 53 — external baseline comparators (reviewer: "without that, 5× is just
//! vs yourself").**
//!
//! Every performance number OrFS reports is otherwise measured against OrFS. This
//! court runs the *identical* file workloads (from `src/bench.rs`) on the
//! filesystems that actually surround a containerised Linux deployment:
//!
//! * **tmpfs** (`/dev/shm`) — pure in-memory upper bound;
//! * **container scratch** (`/tmp`) — the container's own writable layer;
//! * **host filesystem** (a scratch dir on the bind-mounted project, i.e. the host
//!   disk) — the real backing store, reported with its filesystem type;
//! * **raw memory** — a `Vec<u8>` scan, the theoretical floor for "read bytes".
//!
//! It records the measured filesystem type (`stat -f`) so the comparison is not
//! mislabelled, and it is explicit that page-cache warmth is **warm** (dropping the
//! page cache needs `CAP_SYS_ADMIN`, which the sandbox does not grant).
//!
//! The always-on smoke runs a tiny version on each available backend; the full
//! sweep is opt-in behind `ORFS_BASELINES=1` and writes
//! `evidence/performance/baselines.json` (run it via
//! `scripts/container-baseline.sh`).

use std::path::{Path, PathBuf};
use std::time::Instant;

use orfs::bench::{run_fs_workload, BenchParams, Workload};
use orfs::commit::DurabilityMode;

/// The filesystem type for `dir`, from the mount table (the longest mount-point
/// prefix wins). `stat -f` is not relied on because the directory may be gone by
/// the time we report.
fn fs_type(dir: &Path) -> String {
    let canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let mut best: Option<(usize, String)> = None;
    for line in mounts.lines() {
        let mut it = line.split_whitespace();
        let _dev = it.next();
        let Some(mp) = it.next() else { continue };
        let Some(fstype) = it.next() else { continue };
        let mp = mp.replace("\\040", " ");
        if canonical.starts_with(&mp) && best.as_ref().is_none_or(|(l, _)| mp.len() > *l) {
            best = Some((mp.len(), fstype.to_string()));
        }
    }
    best.map(|(_, t)| t)
        .unwrap_or_else(|| "unknown".to_string())
}

struct Backend {
    name: &'static str,
    dir: PathBuf,
    fs_type: String,
}

/// The available backends. A backend whose directory cannot be created is skipped.
fn backends() -> Vec<Backend> {
    let pid = std::process::id();
    let candidates = vec![
        (
            "tmpfs",
            PathBuf::from(format!("/dev/shm/orfs-baseline-{pid}")),
        ),
        (
            "container-overlay",
            PathBuf::from(format!("/tmp/orfs-baseline-{pid}")),
        ),
        (
            "host-fs",
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/baseline-scratch"),
        ),
    ];
    candidates
        .into_iter()
        .filter_map(|(name, dir)| {
            std::fs::create_dir_all(&dir).ok()?;
            if std::fs::metadata(&dir).is_err() {
                return None;
            }
            let fs_type = fs_type(&dir);
            Some(Backend { name, dir, fs_type })
        })
        .collect()
}

fn params(data_bytes: u64, iterations: u64) -> BenchParams {
    BenchParams {
        data_bytes,
        iterations,
        readers: 1,
        region_bytes: 4096,
        durability: DurabilityMode::Ordered,
        cold_cache: false,
    }
}

/// A `Vec<u8>` scan: the raw memory floor for "read bytes".
fn raw_memory_read(bytes: usize) -> (u64, f64) {
    let buf = vec![0x5Au8; bytes];
    let start = Instant::now();
    let mut acc = 0u64;
    for &b in &buf {
        acc = acc.wrapping_add(b as u64);
    }
    let secs = start.elapsed().as_secs_f64();
    std::hint::black_box(acc);
    (bytes as u64, secs)
}

const WORKLOADS: [Workload; 4] = [
    Workload::SequentialAppend,
    Workload::SequentialRead,
    Workload::RandomRead4k,
    Workload::RandomRead1,
];

fn clean(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

#[test]
fn baselines_smoke() {
    let backs = backends();
    assert!(!backs.is_empty(), "no backend directory could be created");
    let params = params(1 << 20, 1_000);
    for b in &backs {
        clean(&b.dir);
        for w in [Workload::SequentialAppend, Workload::RandomRead4k] {
            let m = run_fs_workload(&b.dir, w, &params).expect("workload");
            assert!(m.ops > 0, "{}/{} produced no operations", b.name, w.name());
        }
    }
    let (bytes, secs) = raw_memory_read(1 << 20);
    assert!(bytes > 0 && secs > 0.0);
}

#[test]
fn baselines_sweep() {
    if std::env::var("ORFS_BASELINES").as_deref() != Ok("1") {
        eprintln!("baselines_sweep: skipped (set ORFS_BASELINES=1 to run the full sweep)");
        return;
    }
    let backs = backends();
    let params = params(32 << 20, 20_000);

    let mut results: Vec<serde_json::Value> = Vec::new();
    for b in &backs {
        for w in WORKLOADS {
            clean(&b.dir);
            let m = run_fs_workload(&b.dir, w, &params).expect("workload");
            results.push(serde_json::json!({
                "backend": b.name,
                "workload": w.name(),
                "measurement": serde_json::to_value(&m).unwrap_or(serde_json::Value::Null),
            }));
        }
        clean(&b.dir);
        let _ = std::fs::remove_dir(&b.dir);
    }

    let raw_bytes = 32usize << 20;
    let (raw_n, raw_secs) = raw_memory_read(raw_bytes);
    let raw_mb_per_s = (raw_n as f64 / (1024.0 * 1024.0)) / raw_secs.max(f64::MIN_POSITIVE);

    let environment = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());
    let doc = serde_json::json!({
        "schema": "orfs.performance.baselines.v1",
        "generated_by": "tests/baselines.rs",
        "note": "External baseline comparators: the identical src/bench.rs workloads run on \
                 the filesystems around a containerised deployment. This is the comparison \
                 that makes OrFS's speedups meaningful — otherwise every ratio is OrFS \
                 against OrFS. Measurements are PAGE-CACHE WARM (dropping the page cache \
                 needs CAP_SYS_ADMIN, not granted here), so they are an upper bound on the \
                 storage stack; the point is the ordering across backends under one \
                 workload, not the absolute MB/s.",
        "page_cache": "warm (not dropped; CAP_SYS_ADMIN unavailable)",
        "backends": backs
            .iter()
            .map(|b| serde_json::json!({
                "name": b.name,
                "dir": b.dir.display().to_string(),
                "fs_type": b.fs_type,
            }))
            .collect::<Vec<_>>(),
        "params": {
            "data_bytes": params.data_bytes,
            "iterations": params.iterations,
            "region_bytes": params.region_bytes,
        },
        "results": results,
        "raw_memory_read": {
            "bytes": raw_n,
            "seconds": raw_secs,
            "mb_per_s": raw_mb_per_s,
        },
        "how_to_read": [
            "tmpfs is the in-memory upper bound; host-fs is the real disk; raw_memory_read",
            "is the absolute floor for 'read bytes' with no storage stack at all.",
            "A FUSE-passthrough baseline is produced separately by the Phase-21 court",
            "(evidence/performance/passthrough.json) because it needs a real mount.",
        ],
        "environment": {
            "bench": serde_json::to_value(&environment).unwrap_or(serde_json::Value::Null),
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        },
    });

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/performance/baselines.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!("baselines evidence written to {}", path.display());
}
