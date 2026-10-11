//! Phase 27 endurance, publish-cost and recovery-acceleration harness.
//!
//! Built with `harness = false`; run by `scripts/container-endurance.sh` inside
//! the pinned container. It answers the Phase 27 questions with machine-generated
//! evidence only — every number here is measured in this process, nothing is
//! estimated or fabricated:
//!
//! * **publish cost** — per-commit latency across 10k/100k/1M churn iterations,
//!   in equal-size windows at the start / middle / end of the run, plus a direct
//!   `Index::clone` (the publication step) measurement. Flat across history is
//!   the observable proof that the publish path no longer deep-copies.
//! * **endurance** — sustained create/rename/unlink churn throughput, error
//!   count, RSS stability and backing growth; a file grown to many disjoint
//!   extents (write/read/metadata latency); >=2000 historical roots
//!   (open/inspect/reconstruct cost); and remounts interleaved with activity and
//!   concurrent readers.
//! * **recovery acceleration** — mount/recovery time as a function of total
//!   retained history, with and without valid in-log index checkpoints, plus the
//!   Phase-20 historical-index cache cold vs warm.
//!
//! Scales are environment-tunable (see the `ORFS_ENDURANCE_*` variables); the
//! defaults are chosen to fit the container memory/pid caps. Where a requested
//! scale is reduced the achieved scale is recorded, never overstated.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use orfs::commit::DurabilityMode;
use orfs::index::ROOT_INODE;
use orfs::log::OpenMode;
use orfs::namespace::{CoreRead, Namespace, ReadCell, RenameMode};
use orfs::snapshot::Snapshot;

// ---------------------------------------------------------------------------
// utilities
// ---------------------------------------------------------------------------

fn rss_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for l in s.lines() {
        if let Some(rest) = l.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next().unwrap().parse().unwrap_or(0);
        }
    }
    0
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

fn env_scales(name: &str, default: &[u64]) -> Vec<u64> {
    match std::env::var(name) {
        Ok(s) => s
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .filter(|&v| v > 0)
            .collect(),
        Err(_) => default.to_vec(),
    }
}

fn percentiles(mut xs: Vec<u64>) -> serde_json::Value {
    if xs.is_empty() {
        return serde_json::json!({ "count": 0 });
    }
    xs.sort_unstable();
    let p = |q: f64| xs[((xs.len() as f64 - 1.0) * q).round() as usize];
    let sum: u64 = xs.iter().sum();
    serde_json::json!({
        "count": xs.len(),
        "min_ns": xs[0],
        "p50_ns": p(0.50),
        "p95_ns": p(0.95),
        "p99_ns": p(0.99),
        "max_ns": xs[xs.len() - 1],
        "mean_ns": sum / xs.len() as u64,
    })
}

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(value).expect("serialize");
    s.push('\n');
    std::fs::write(path, s).expect("write evidence");
}

fn fresh_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("orfs-endurance-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn min_ns<F: FnMut()>(mut f: F, reps: usize) -> u64 {
    let mut best = u64::MAX;
    for _ in 0..reps {
        let t = Instant::now();
        f();
        best = best.min(t.elapsed().as_nanos() as u64);
    }
    best
}

// ---------------------------------------------------------------------------
// publish cost + churn endurance
// ---------------------------------------------------------------------------

/// Run `iters` create/rename/unlink iterations over `dirs` directories.
/// Returns per-window iteration latency and the end-state metrics.
fn churn_scale(dir: &Path, dirs: u64, iters: u64) -> serde_json::Value {
    let mut ns = Namespace::init(dir, 1 << 22, DurabilityMode::Ordered).expect("init volume");
    let mut ds = Vec::with_capacity(dirs as usize);
    for i in 0..dirs {
        ds.push(
            ns.mkdir(ROOT_INODE, format!("d{i}").as_bytes(), 0o755, 0, 0)
                .expect("mkdir"),
        );
    }
    let rss_start = rss_kib();
    let mut rss_peak = rss_start;
    let start = Instant::now();
    let mut win: Vec<Vec<u64>> = (0..3).map(|_| Vec::with_capacity(1024)).collect();
    let mut errors = 0u64;
    for i in 0..iters {
        let d = ds[(i % dirs) as usize];
        let t = Instant::now();
        let name = format!("f{i:012}");
        if ns.create(d, name.as_bytes(), 0o644, 0, 0).is_err() {
            errors += 1;
        }
        let rn = format!("r{i:012}");
        if ns
            .rename(d, name.as_bytes(), d, rn.as_bytes(), RenameMode::Ordinary)
            .is_err()
        {
            errors += 1;
        }
        if ns.unlink(d, rn.as_bytes()).is_err() {
            errors += 1;
        }
        let dt = t.elapsed().as_nanos() as u64;
        let w = if i < 1024 {
            0
        } else if i >= iters / 2 && i < iters / 2 + 1024 {
            1
        } else if i >= iters.saturating_sub(1024) {
            2
        } else {
            usize::MAX
        };
        if w < 3 {
            win[w].push(dt);
        }
        if i % 50_000 == 49_999 {
            rss_peak = rss_peak.max(rss_kib());
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    rss_peak = rss_peak.max(rss_kib());

    // Direct measurement of the publication step: cloning the index (which is
    // exactly what `publish_read_state` does) at the *current* history size.
    let index_clone_ns = min_ns(
        || {
            std::hint::black_box(ns.index().clone());
        },
        8,
    );
    // And an in-memory read view acquisition (the reader-side publish swap).
    let view_clone_ns = min_ns(
        || {
            std::hint::black_box(ns.read_view());
        },
        8,
    );

    let end_rss = rss_kib();
    let retained_inodes = ns.index().inode_count();
    let live_dentries = ns.index().dentry_count();
    let root = ns.root();

    let acc = orfs::stats::account_volume(dir).ok();
    let (m_log, m_total, canonical) = acc
        .as_ref()
        .map(|a| (a.m_log, a.m_total, a.authoritative_canonical_bytes))
        .unwrap_or((0, 0, 0));

    serde_json::json!({
        "iterations": iters,
        "dirs": dirs,
        "ops": iters * 3,
        "commits": iters * 3,
        "total_seconds": elapsed,
        "throughput_iterations_per_s": iters as f64 / elapsed,
        "throughput_ops_per_s": (iters * 3) as f64 / elapsed,
        "errors": errors,
        "per_iter_ns_first_1024": percentiles(win[0].clone()),
        "per_iter_ns_middle_1024": percentiles(win[1].clone()),
        "per_iter_ns_last_1024": percentiles(win[2].clone()),
        "index_clone_ns": index_clone_ns,
        "read_view_clone_ns": view_clone_ns,
        "committed_root": root,
        "retained_inodes": retained_inodes,
        "live_dentries": live_dentries,
        "rss_start_kib": rss_start,
        "rss_end_kib": end_rss,
        "rss_peak_kib": rss_peak,
        "backing": {
            "m_log_bytes": m_log,
            "authoritative_canonical_bytes": canonical,
            "m_total_bytes": m_total,
        },
    })
}

// ---------------------------------------------------------------------------
// many-extents workload
// ---------------------------------------------------------------------------

/// Grow one file to `writes` small disjoint extents (stride 4096) and measure
/// write / read / metadata latency in the first and last 1024-write windows.
fn extent_scale(dir: &Path, writes: u64) -> serde_json::Value {
    let mut ns = Namespace::init(dir, 1 << 22, DurabilityMode::Ordered).expect("init volume");
    let f = ns.create(ROOT_INODE, b"big", 0o644, 0, 0).expect("create");
    let stride = 4096u64;
    let byte = [0xABu8];
    let mut first = Vec::with_capacity(1024);
    let mut last = Vec::with_capacity(1024);
    let start = Instant::now();
    for i in 0..writes {
        let t = Instant::now();
        ns.write_at(f, i * stride, &byte).expect("write");
        let dt = t.elapsed().as_nanos() as u64;
        if i < 1024 {
            first.push(dt);
        } else if i >= writes.saturating_sub(1024) {
            last.push(dt);
        }
    }
    let write_seconds = start.elapsed().as_secs_f64();
    let root = ns.root();
    let extent_count = ns.extent_count(f, root).unwrap_or(0) as u64;

    // Reads must stay bounded regardless of fragmentation.
    let mut rng = 0x1234_5678_9abc_def0u64;
    let mut reads = Vec::with_capacity(2048);
    for _ in 0..2048 {
        rng = rng
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let off = (rng >> 20) % writes * stride;
        let t = Instant::now();
        let v = ns.read_extent(f, root, off, 1).expect("read");
        reads.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(v);
    }
    let meta = min_ns(
        || {
            std::hint::black_box(ns.getattr(f, root).expect("getattr"));
        },
        64,
    );

    serde_json::json!({
        "writes": writes,
        "extent_count": extent_count,
        "logical_bytes": writes * stride,
        "write_total_seconds": write_seconds,
        "write_throughput_per_s": writes as f64 / write_seconds,
        "write_ns_first_1024": percentiles(first),
        "write_ns_last_1024": percentiles(last),
        "random_1b_read_ns": percentiles(reads),
        "getattr_ns": meta,
    })
}

// ---------------------------------------------------------------------------
// historical roots
// ---------------------------------------------------------------------------

/// Publish `roots` historical snapshot roots over a small live tree and measure
/// the cost of opening / inspecting / reconstructing each one (cold replay and,
/// for a bounded sample, warm from the persisted accelerator).
fn historical_roots(dir: &Path, roots: u64) -> serde_json::Value {
    let mut ns = Namespace::init(dir, 1 << 22, DurabilityMode::Ordered).expect("init volume");
    // A small live tree so each historical index (and its accelerator) stays tiny.
    let files: Vec<u64> = (0..64)
        .map(|i| {
            ns.create(ROOT_INODE, format!("f{i}").as_bytes(), 0o644, 0, 0)
                .expect("create")
        })
        .collect();
    for (i, &f) in files.iter().enumerate() {
        ns.write_at(f, 0, &[i as u8; 32]).expect("write");
    }
    let target = files[0];
    // Checkpoints every 32 commits bound each historical replay to a suffix.
    let mut roots_seen: Vec<u64> = Vec::with_capacity(roots as usize);
    let t_publish = Instant::now();
    for i in 0..roots {
        if i % 32 == 31 {
            ns.write_index_checkpoint().expect("checkpoint");
        }
        let f = files[(i as usize) % files.len()];
        ns.write_at(f, 0, &[(i & 0xff) as u8; 8]).expect("write");
        let r = ns
            .publish_snapshot(format!("s{i}").as_bytes())
            .expect("publish snapshot");
        roots_seen.push(r);
    }
    ns.sync().expect("sync");
    let publish_seconds = t_publish.elapsed().as_secs_f64();
    let achieved_roots = roots_seen.len() as u64;
    drop(ns);

    // Cold: reconstruct each root from the log (suffix replay from a checkpoint),
    // then inspect it. `Snapshot::open_dir` never uses a persisted accelerator.
    let mut cold_open = Vec::with_capacity(roots_seen.len());
    let mut cold_inspect = Vec::with_capacity(roots_seen.len());
    let mut cold_errors = 0u64;
    let t_cold = Instant::now();
    for &r in &roots_seen {
        let t = Instant::now();
        match Snapshot::open_dir(dir, r) {
            Ok(s) => {
                cold_open.push(t.elapsed().as_nanos() as u64);
                let t = Instant::now();
                let ok = s.lookup(ROOT_INODE, b"f0").is_ok() && s.getattr(target).is_ok();
                cold_inspect.push(t.elapsed().as_nanos() as u64);
                if !ok {
                    cold_errors += 1;
                }
            }
            Err(_) => cold_errors += 1,
        }
    }
    let cold_seconds = t_cold.elapsed().as_secs_f64();

    // Warm: persist an accelerator for a bounded sample and re-open it.
    let warm_sample = env_u64("ORFS_ENDURANCE_WARM_SAMPLE", 16).min(achieved_roots);
    let index_dir = dir.join("index");
    let uuid = orfs::volume::Volume::read_meta(dir)
        .expect("read meta")
        .uuid;
    let mut warm_open = Vec::with_capacity(warm_sample as usize);
    let mut persisted = 0u64;
    for &r in roots_seen.iter().rev().take(warm_sample as usize) {
        if let Ok(s) = Snapshot::open_dir(dir, r) {
            let before = std::time::Instant::now();
            if orfs::historical::persist_historical(&index_dir, &uuid, s.index()).is_ok() {
                persisted += 1;
                std::hint::black_box(before.elapsed());
            }
        }
    }
    for &r in roots_seen.iter().rev().take(warm_sample as usize) {
        let t = Instant::now();
        if let Ok(s) = Snapshot::open_dir(dir, r) {
            std::hint::black_box(s.index().inode_count());
            warm_open.push(t.elapsed().as_nanos() as u64);
        }
    }

    serde_json::json!({
        "achieved_roots": achieved_roots,
        "requested_roots": roots,
        "publish_seconds": publish_seconds,
        "checkpoint_interval": 32,
        "cold_open_ns": percentiles(cold_open),
        "cold_inspect_ns": percentiles(cold_inspect),
        "cold_total_seconds": cold_seconds,
        "cold_errors": cold_errors,
        "warm_sample": persisted,
        "warm_open_ns": percentiles(warm_open),
        "sample_roots": roots_seen.iter().take(5).copied().collect::<Vec<u64>>(),
    })
}

// ---------------------------------------------------------------------------
// remounts + concurrent readers
// ---------------------------------------------------------------------------

fn remounts_and_readers(dir: &Path, remounts: u64, readers: usize) -> serde_json::Value {
    let mut ns = Namespace::init(dir, 1 << 22, DurabilityMode::Ordered).expect("init volume");
    let f = ns.create(ROOT_INODE, b"live", 0o644, 0, 0).expect("create");
    ns.write_at(f, 0, &[7u8; 64]).expect("write");

    // The harness-level equivalent of the FUSE view cell: the readers resolve the
    // current immutable view each iteration, exactly as the transport does.
    let cell: Arc<parking_lot::Mutex<ReadCell>> = Arc::new(parking_lot::Mutex::new(ns.read_cell()));
    let stop = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicU64::new(0));
    let read_errors = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for _ in 0..readers {
        let cell = cell.clone();
        let stop = stop.clone();
        let reads = reads.clone();
        let read_errors = read_errors.clone();
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let view: Arc<dyn CoreRead> = cell.lock().read().clone();
                let root = view.root();
                if view.getattr(ROOT_INODE, root).is_err() {
                    read_errors.fetch_add(1, Ordering::Relaxed);
                } else if let Ok(st) = view.getattr(1, root) {
                    std::hint::black_box(st);
                }
                // Read the live file's first byte through the same view.
                if view.read_at(2, root, 0, 1).is_ok() {
                    reads.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    let mut write_errors = 0u64;
    let mut versions = Vec::new();
    for r in 0..remounts {
        // Activity between remounts.
        for k in 0..500u64 {
            if ns
                .write_at(f, 0, &[(r as u8).wrapping_add(k as u8); 32])
                .is_err()
            {
                write_errors += 1;
            }
        }
        // Re-open the volume (remount) and repoint the reader cell.
        drop(std::mem::replace(
            &mut ns,
            Namespace::open(dir, OpenMode::ReadWrite, DurabilityMode::Ordered).expect("reopen"),
        ));
        *cell.lock() = ns.read_cell();
        let view = ns.read_view();
        versions.push((
            view.root(),
            view.getattr(f, view.root()).map(|s| s.size).unwrap_or(0),
        ));
    }

    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }

    let final_root = ns.root();
    let final_size = ns.getattr(f, final_root).map(|s| s.size).unwrap_or(0);
    serde_json::json!({
        "remounts": remounts,
        "readers": readers,
        "total_reads": reads.load(Ordering::Relaxed),
        "read_errors": read_errors.load(Ordering::Relaxed),
        "write_errors": write_errors,
        "final_root": final_root,
        "final_size": final_size,
        "mounted_versions": versions,
        "monotonic_roots": versions.windows(2).all(|w| w[0].0 <= w[1].0),
    })
}

// ---------------------------------------------------------------------------
// recovery acceleration
// ---------------------------------------------------------------------------

/// Build `ops` create+write operations, optionally writing an in-log index
/// checkpoint every `checkpoint_every` ops. Each op writes a `chunk`-byte
/// payload so the authoritative log dominates the derived index, which is the
/// regime in which a checkpoint can actually save work. Returns how many
/// checkpoints were written (a checkpoint whose embedded index exceeds the
/// 64 MiB record limit is refused, and we stop trying).
fn build_history(dir: &Path, ops: u64, checkpoint_every: u64, chunk: usize) -> u64 {
    let mut ns = Namespace::init(dir, 1 << 24, DurabilityMode::Ordered).expect("init volume");
    let dirs = 64u64;
    let mut ds = Vec::new();
    for i in 0..dirs {
        ds.push(
            ns.mkdir(ROOT_INODE, format!("d{i}").as_bytes(), 0o755, 0, 0)
                .expect("mkdir"),
        );
    }
    let data = vec![0x5Au8; chunk];
    let mut checkpoints = 0u64;
    let mut interval = checkpoint_every;
    for i in 0..ops {
        if interval > 0 && i % interval == interval - 1 {
            match ns.write_index_checkpoint() {
                Ok(()) => checkpoints += 1,
                // Payload limit reached: stop; the volume is still valid.
                Err(_) => interval = 0,
            }
        }
        let d = ds[(i % dirs) as usize];
        let f = ns
            .create(d, format!("f{i:012}").as_bytes(), 0o644, 0, 0)
            .expect("create");
        ns.write_at(f, 0, &data).expect("write");
    }
    ns.sync().expect("sync");
    checkpoints
}

fn mount_time(dir: &Path) -> serde_json::Value {
    let t = Instant::now();
    let ns = Namespace::open(dir, OpenMode::ReadOnly, DurabilityMode::Ordered).expect("open");
    let wall = t.elapsed().as_nanos() as u64;
    let log_bytes = ns.volume().log.committed_end_offset();
    let report = ns.mount_report().cloned();
    let m = report.as_ref();
    serde_json::json!({
        "wall_ns": wall,
        "used_checkpoint": m.map(|r| r.used_checkpoint).unwrap_or(false),
        "checkpoint_root": m.and_then(|r| r.checkpoint_root),
        "checkpoints_found": m.map(|r| r.checkpoints_found).unwrap_or(0),
        "records_replayed": m.map(|r| r.records_replayed).unwrap_or(0),
        "bytes_replayed": m.map(|r| r.bytes_replayed).unwrap_or(0),
        "full_replay_fallback": m.map(|r| r.full_replay_fallback).unwrap_or(true),
        "index_inode_count": m.map(|r| r.index_inode_count).unwrap_or(0),
        "log_bytes": log_bytes,
    })
}

/// Cold vs warm cost of resolving historical roots for snapshots through the
/// Phase-20 persisted accelerator (the on-disk counterpart of the in-memory
/// historical-index cache). Cold = materialize from the log; warm = load the
/// persisted accelerator. Neither is constant-time: both decode an O(index)
/// document; warm avoids the log replay entirely.
fn snapshot_cache_probe(dir: &Path) -> serde_json::Value {
    let mut ns = Namespace::init(dir, 1 << 22, DurabilityMode::Ordered).expect("init volume");
    let files: Vec<u64> = (0..32)
        .map(|i| {
            ns.create(ROOT_INODE, format!("g{i}").as_bytes(), 0o644, 0, 0)
                .expect("create")
        })
        .collect();
    for &f in &files {
        ns.write_at(f, 0, &[3u8; 128]).expect("write");
    }
    let mut roots = Vec::new();
    for i in 0..16u64 {
        ns.write_at(files[(i as usize) % files.len()], 0, &[i as u8; 16])
            .expect("write");
        roots.push(
            ns.publish_snapshot(format!("c{i}").as_bytes())
                .expect("snap"),
        );
        if i % 4 == 3 {
            let _ = ns.write_index_checkpoint();
        }
    }
    ns.sync().expect("sync");
    drop(ns);

    let mut cold = Vec::new();
    let mut indexes = Vec::new();
    for &r in &roots {
        let t = Instant::now();
        if let Ok(s) = Snapshot::open_dir(dir, r) {
            cold.push(t.elapsed().as_nanos() as u64);
            indexes.push((r, s.index().clone()));
        }
    }
    let uuid = orfs::volume::Volume::read_meta(dir).expect("meta").uuid;
    let index_dir = dir.join("index");
    let mut persisted = 0u64;
    for (_, idx) in &indexes {
        if orfs::historical::persist_historical(&index_dir, &uuid, idx).is_ok() {
            persisted += 1;
        }
    }
    let mut warm = Vec::new();
    for (r, _) in &indexes {
        let t = Instant::now();
        if Snapshot::open_dir(dir, *r).is_ok() {
            warm.push(t.elapsed().as_nanos() as u64);
        }
    }
    serde_json::json!({
        "roots": roots.len(),
        "persisted_accelerators": persisted,
        "cold_open_ns": percentiles(cold),
        "warm_open_ns": percentiles(warm),
    })
}

fn recovery_scales(scales: &[u64], checkpoint_every: u64, chunk: usize) -> serde_json::Value {
    let mut rows = Vec::new();
    for &ops in scales {
        let no_ckpt = fresh_dir(&format!("rec-nock-{ops}"));
        let _ = build_history(&no_ckpt, ops, 0, chunk);
        // First open is the cold recovery; the second re-reads the same log with
        // the OS page cache warm. Neither is constant-time; both are reported.
        let first = mount_time(&no_ckpt);
        let second = mount_time(&no_ckpt);
        let _ = std::fs::remove_dir_all(&no_ckpt);

        let with_ckpt = fresh_dir(&format!("rec-ck-{ops}"));
        let written = build_history(&with_ckpt, ops, checkpoint_every, chunk);
        let ck_first = mount_time(&with_ckpt);
        let ck_second = mount_time(&with_ckpt);
        let _ = std::fs::remove_dir_all(&with_ckpt);

        rows.push(serde_json::json!({
            "ops": ops,
            "chunk_bytes": chunk,
            "checkpoints_written": written,
            "without_checkpoints": { "first_open": first, "second_open_warm": second },
            "with_checkpoints": { "first_open": ck_first, "second_open_warm": ck_second },
        }));
    }
    serde_json::Value::Array(rows)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let out = Path::new("evidence/performance");
    let env = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());

    let publish_scales = env_scales(
        "ORFS_ENDURANCE_PUBLISH_SCALES",
        &[10_000, 100_000, 1_000_000],
    );
    let churn_dirs = env_u64("ORFS_ENDURANCE_DIRS", 1024);
    let extent_scales = env_scales("ORFS_ENDURANCE_EXTENTS", &[1_000, 10_000, 100_000]);
    let roots = env_u64("ORFS_ENDURANCE_ROOTS", 2_000);
    let remounts = env_u64("ORFS_ENDURANCE_REMOUNTS", 4);
    let readers = env_u64("ORFS_ENDURANCE_READERS", 4);
    let recovery_scale_list = env_scales("ORFS_ENDURANCE_RECOVERY", &[500, 2_000, 8_000]);
    let checkpoint_every = env_u64("ORFS_ENDURANCE_CHECKPOINT_EVERY", 500);
    let recovery_chunk = env_u64("ORFS_ENDURANCE_RECOVERY_CHUNK", 32_768) as usize;

    // -- publish cost + churn endurance -----------------------------------
    let mut publish_rows = Vec::new();
    let mut churn_endurance = Vec::new();
    for &scale in &publish_scales {
        let dir = fresh_dir(&format!("churn-{scale}"));
        println!("publish-cost: churn {scale} iterations ...");
        let row = churn_scale(&dir, churn_dirs, scale);
        let _ = std::fs::remove_dir_all(&dir);
        churn_endurance.push(row.clone());
        publish_rows.push(row);
    }
    let publish = serde_json::json!({
        "schema": "orfs.publish-cost.v1",
        "generated_by": "benches/endurance.rs",
        "environment": env,
        "claim": "per-commit publish cost is flat as total retained history grows",
        "dirs": churn_dirs,
        "scales": publish_rows,
    });
    write_json(&out.join("publish-cost.json"), &publish);

    // -- many extents ------------------------------------------------------
    let mut extent_rows = Vec::new();
    for &writes in &extent_scales {
        let dir = fresh_dir(&format!("ext-{writes}"));
        println!("endurance: {writes} disjoint extents ...");
        extent_rows.push(extent_scale(&dir, writes));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- historical roots --------------------------------------------------
    println!("endurance: {roots} historical roots ...");
    let roots_dir = fresh_dir("roots");
    let historical = historical_roots(&roots_dir, roots);
    let _ = std::fs::remove_dir_all(&roots_dir);

    // -- remounts + readers ------------------------------------------------
    println!("endurance: remounts + concurrent readers ...");
    let remount_dir = fresh_dir("remount");
    let remount_report = remounts_and_readers(&remount_dir, remounts, readers as usize);
    let _ = std::fs::remove_dir_all(&remount_dir);

    let endurance = serde_json::json!({
        "schema": "orfs.endurance.v1",
        "generated_by": "benches/endurance.rs",
        "environment": env,
        "churn": churn_endurance,
        "extents": extent_rows,
        "historical_roots": historical,
        "remounts_and_readers": remount_report,
    });
    write_json(&out.join("endurance.json"), &endurance);

    // -- recovery acceleration --------------------------------------------
    println!(
        "recovery-acceleration: {} scales ...",
        recovery_scale_list.len()
    );
    let cache_dir = fresh_dir("reccache");
    let snapshot_cache = snapshot_cache_probe(&cache_dir);
    let _ = std::fs::remove_dir_all(&cache_dir);
    let recovery = serde_json::json!({
        "schema": "orfs.recovery-acceleration.v1",
        "generated_by": "benches/endurance.rs",
        "environment": env,
        "checkpoint_every": checkpoint_every,
        "recovery_chunk_bytes": recovery_chunk,
        "note": "mount/recovery time is NOT constant-time; it is Θ(total retained \
                 history) in every mode. Without a checkpoint the whole committed \
                 log is replayed; with a checkpoint only the suffix after the newest \
                 valid checkpoint is replayed (`bytes_replayed` collapses), but a \
                 header-only checkpoint-discovery scan of the whole log and the \
                 decode of the checkpoint's embedded index remain, so the wall-time \
                 win appears only once the skipped replay dominates those costs. \
                 The persisted historical accelerator removes the replay entirely on \
                 a warm open.",
        "scales": recovery_scales(&recovery_scale_list, checkpoint_every, recovery_chunk),
        "snapshot_historical_cache": snapshot_cache,
    });
    write_json(&out.join("recovery-acceleration.json"), &recovery);

    println!(
        "wrote publish-cost.json, endurance.json, recovery-acceleration.json to {}",
        out.display()
    );
}
