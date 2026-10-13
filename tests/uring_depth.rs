//! **Reviewer task — the io_uring depth sweep with CQ/SQ mechanism counters.**
//!
//! The earlier io_uring courts measured *time* (sync vs `io_uring`, batched vs
//! unbatched). This court measures the **mechanism** as the ring depth changes:
//! how many SQEs are pushed, how often the submission queue actually fills
//! (SQ backpressure), how long the completion queue ever gets in a single drain
//! pass (CQ-overflow pressure), and how many batched submit rounds a workload
//! takes. It sweeps a batched positional **read** and a batched positional
//! **write** over a real file in a temp dir, at ring depths
//! `{1, 2, 4, 8, 16, 32, 64, 128}`.
//!
//! ## Why counters, not just time
//!
//! On this host hardware performance counters are **unavailable**
//! (`perf_event_paranoid=2`), so there are no flamegraphs and no PMU attribution.
//! The SQ/CQ counters are the PMU-free mechanism evidence: at a small depth a
//! read batch larger than the ring *must* fill the SQ (`sq_full_events > 0`),
//! whereas `write_batch` caps each batch at the ring depth so the SQ can never
//! saturate (`sq_full_events == 0`). `cq_max_len` records the largest number of
//! CQEs reaped in one pass.
//!
//! ## Running it
//!
//! * `cargo test --test uring_depth` runs a small always-on smoke that asserts a
//!   batched read backpressure event occurred and that the read-back bytes are
//!   exact.
//! * The full sweep is opt-in behind `ORFS_URING_DEPTH=1` and writes
//!   `evidence/performance/uring-depth.json` (schema
//!   `orfs.performance.uring-depth.v1`). Run it (release, representative) via
//!   `scripts/container-uring-depth.sh`.
//!
//! If `io_uring` is unavailable the court records that honestly
//! (`io_uring_available=false` plus the concrete reason) rather than fabricating
//! numbers; `ORFS_REQUIRE_URING=1` turns that into a hard failure instead (as
//! `scripts/container-uring-test.sh` does).

use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::Instant;

use orfs::uring::{probe_available, ReadJob, UringEngine, UringStats, WriteJob};
use tempfile::TempDir;

/// Bytes per positional read/write record.
const RECORD_BYTES: usize = 4096;
/// Records issued per `read_batch` / `write_batch` call in the sweep. Larger than
/// the small ring depths, so real SQ backpressure is exercised.
const BATCH_RECORDS: usize = 128;
/// Batched submit rounds per depth (independently: for writes and for reads).
const ROUNDS: usize = 32;
/// The ring-depth sweep.
const SWEEP_DEPTHS: [u32; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

/// The always-on smoke, kept small.
const SMOKE_DEPTH: u32 = 2;
const SMOKE_BATCH: usize = 16;
const SMOKE_ROUNDS: usize = 2;

fn require_uring() -> bool {
    std::env::var("ORFS_REQUIRE_URING")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Deterministic, position-dependent content so a read can be checked byte-exact.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 131 + 17) % 251) as u8).collect()
}

fn percentile(samples: &[u64], p: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut s = samples.to_vec();
    s.sort_unstable();
    let idx = (((s.len() - 1) as f64) * p).round() as usize;
    s[idx]
}

/// Per-workload measurements plus the mechanism counters for one ring depth.
struct Metrics {
    ops: u64,
    bytes: u64,
    seconds: f64,
    p50_ns: u64,
    p99_ns: u64,
    stats: UringStats,
}

impl Metrics {
    fn ops_per_s(&self) -> f64 {
        if self.seconds > 0.0 {
            self.ops as f64 / self.seconds
        } else {
            0.0
        }
    }

    fn mb_per_s(&self) -> f64 {
        if self.seconds > 0.0 {
            self.bytes as f64 / self.seconds / 1e6
        } else {
            0.0
        }
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "ops": self.ops,
            "bytes": self.bytes,
            "seconds": self.seconds,
            "ops_per_s": self.ops_per_s(),
            "mb_per_s": self.mb_per_s(),
            "latency_ns": { "p50_per_round": self.p50_ns, "p99_per_round": self.p99_ns },
            "stats": serde_json::to_value(self.stats).unwrap_or(serde_json::Value::Null),
        })
    }
}

struct DepthRow {
    requested_depth: u32,
    ring_depth: u32,
    read: Metrics,
    write: Metrics,
}

/// Run the batched write-then-read workload at one ring depth and verify the
/// read-back bytes equal what was written.
fn run_depth(dir: &Path, depth: u32, batch: usize, rounds: usize) -> Result<DepthRow, String> {
    let total_records = batch * rounds;
    let total_bytes = (total_records * RECORD_BYTES) as u64;
    let expected = pattern(total_records * RECORD_BYTES);
    let path = dir.join(format!("depth-{depth}.bin"));

    // ---- batched positional write ----
    let mut wengine = UringEngine::try_new(depth, false)?;
    let ring_depth = wengine.depth();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| format!("open {path:?}: {e}"))?;
    let wfd = file.as_raw_fd();
    let mut wsamples = Vec::with_capacity(rounds);
    let wstart = Instant::now();
    for r in 0..rounds {
        let t = Instant::now();
        let mut jobs: Vec<WriteJob<'_>> = (0..batch)
            .map(|k| {
                let idx = r * batch + k;
                let base = idx * RECORD_BYTES;
                WriteJob::new(wfd, base as u64, &expected[base..base + RECORD_BYTES])
            })
            .collect();
        wengine
            .write_batch(&mut jobs)
            .map_err(|e| format!("depth {depth} write_batch: {e}"))?;
        wsamples.push(t.elapsed().as_nanos() as u64);
    }
    let wsecs = wstart.elapsed().as_secs_f64();
    let wstats = wengine.stats();
    drop(file);

    // ---- batched positional read, then byte-exact verification ----
    let mut rengine = UringEngine::try_new(depth, false)?;
    let rfile = OpenOptions::new()
        .read(true)
        .open(&path)
        .map_err(|e| format!("open {path:?}: {e}"))?;
    let rfd = rfile.as_raw_fd();
    let mut got = vec![0u8; total_records * RECORD_BYTES];
    let mut rsamples = Vec::with_capacity(rounds);
    let rstart = Instant::now();
    {
        let mut slices: Vec<&mut [u8]> = got.chunks_mut(RECORD_BYTES).collect();
        for r in 0..rounds {
            let t = Instant::now();
            let range = &mut slices[r * batch..(r + 1) * batch];
            let mut jobs: Vec<ReadJob<'_>> = range
                .iter_mut()
                .enumerate()
                .map(|(k, s)| {
                    let idx = r * batch + k;
                    ReadJob::new(rfd, (idx * RECORD_BYTES) as u64, s)
                })
                .collect();
            rengine
                .read_batch(&mut jobs)
                .map_err(|e| format!("depth {depth} read_batch: {e}"))?;
            rsamples.push(t.elapsed().as_nanos() as u64);
        }
    }
    let rsecs = rstart.elapsed().as_secs_f64();
    let rstats = rengine.stats();
    drop(rfile);

    if got != expected {
        return Err(format!(
            "depth {depth}: read-back bytes differ from what was written"
        ));
    }

    let mk = |stats: UringStats, secs: f64, samples: Vec<u64>| Metrics {
        ops: total_records as u64,
        bytes: total_bytes,
        seconds: secs,
        p50_ns: percentile(&samples, 0.50),
        p99_ns: percentile(&samples, 0.99),
        stats,
    };

    Ok(DepthRow {
        requested_depth: depth,
        ring_depth,
        read: mk(rstats, rsecs, rsamples),
        write: mk(wstats, wsecs, wsamples),
    })
}

/// The always-on smoke: a bounded batched read/write at a tiny depth. It asserts
/// the read-back bytes are exact, that a read batch larger than the ring actually
/// filled the SQ, and that no completion was orphaned.
#[test]
fn uring_depth_smoke() {
    if let Err(reason) = probe_available() {
        if require_uring() {
            panic!("ORFS_REQUIRE_URING=1 but io_uring unavailable: {reason}");
        }
        eprintln!("uring_depth_smoke: skipped, io_uring unavailable ({reason})");
        return;
    }
    let dir = TempDir::new().unwrap();
    let row = run_depth(dir.path(), SMOKE_DEPTH, SMOKE_BATCH, SMOKE_ROUNDS)
        .expect("smoke depth workload");

    assert_eq!(
        row.read.stats.orphan_completions, 0,
        "read workload orphaned completions"
    );
    assert_eq!(
        row.write.stats.orphan_completions, 0,
        "write workload orphaned completions"
    );
    // A read batch larger than the ring must exercise real SQ backpressure...
    assert!(
        row.read.stats.sq_full_events > 0,
        "expected SQ backpressure at depth {} (batch {}), got {:?}",
        row.ring_depth,
        SMOKE_BATCH,
        row.read.stats
    );
    // ...while write_batch caps each batch at the depth, so it never saturates.
    assert_eq!(
        row.write.stats.sq_full_events, 0,
        "write_batch must not saturate the SQ (cap == depth): {:?}",
        row.write.stats
    );
    assert!(
        row.read.stats.completions >= row.read.stats.submits,
        "read: completions ({}) < submits ({})",
        row.read.stats.completions,
        row.read.stats.submits
    );
    eprintln!(
        "uring_depth smoke: ring_depth={} read[sq_full_events={} cq_max_len={} pushes={} chunks={}] \
         write[sq_full_events={} cq_max_len={} pushes={} chunks={}]",
        row.ring_depth,
        row.read.stats.sq_full_events,
        row.read.stats.cq_max_len,
        row.read.stats.sq_pushes,
        row.read.stats.batch_chunks,
        row.write.stats.sq_full_events,
        row.write.stats.cq_max_len,
        row.write.stats.sq_pushes,
        row.write.stats.batch_chunks,
    );
}

#[test]
fn uring_depth_sweep() {
    if std::env::var("ORFS_URING_DEPTH").as_deref() != Ok("1") {
        eprintln!("uring_depth_sweep: skipped (set ORFS_URING_DEPTH=1 to run the full sweep)");
        return;
    }

    let environment = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());
    let out_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/performance/uring-depth.json");

    // Honest fallback: if io_uring is unavailable, record that with the concrete
    // reason instead of fabricating a table.
    if let Err(reason) = probe_available() {
        if require_uring() {
            panic!("ORFS_REQUIRE_URING=1 but io_uring unavailable: {reason}");
        }
        let doc = serde_json::json!({
            "schema": "orfs.performance.uring-depth.v1",
            "generated_by": "tests/uring_depth.rs",
            "io_uring_available": false,
            "io_uring_reason": reason,
            "note": "io_uring is unavailable in this environment, so no depth sweep was \
                     performed. This is recorded honestly rather than fabricated.",
            "environment": serde_json::to_value(&environment).unwrap_or(serde_json::Value::Null),
        });
        write_json(&out_path, &doc);
        eprintln!(
            "uring-depth evidence (unavailable) written to {}",
            out_path.display()
        );
        return;
    }

    let dir = TempDir::new().unwrap();
    let mut rows = Vec::with_capacity(SWEEP_DEPTHS.len());
    for depth in SWEEP_DEPTHS {
        let row = run_depth(dir.path(), depth, BATCH_RECORDS, ROUNDS)
            .unwrap_or_else(|e| panic!("depth sweep failed: {e}"));
        assert_eq!(
            row.read.stats.orphan_completions, 0,
            "depth {depth}: read orphan_completions != 0"
        );
        assert_eq!(
            row.write.stats.orphan_completions, 0,
            "depth {depth}: write orphan_completions != 0"
        );
        // write_batch caps each chunk at the ring depth: the SQ can never fill.
        assert_eq!(
            row.write.stats.sq_full_events, 0,
            "depth {depth}: write_batch saturated the SQ despite the depth cap"
        );
        eprintln!(
            "depth {:>3} (ring {:>3}): read sq_full_events={:>3} cq_max_len={:>3} \
             pushes={:>6} chunks={:>3} ops/s={:>12.0} MB/s={:>8.1} | \
             write sq_full_events={:>3} cq_max_len={:>3} chunks={:>3} MB/s={:>8.1}",
            row.requested_depth,
            row.ring_depth,
            row.read.stats.sq_full_events,
            row.read.stats.cq_max_len,
            row.read.stats.sq_pushes,
            row.read.stats.batch_chunks,
            row.read.ops_per_s(),
            row.read.mb_per_s(),
            row.write.stats.sq_full_events,
            row.write.stats.cq_max_len,
            row.write.stats.batch_chunks,
            row.write.mb_per_s(),
        );
        rows.push(row);
    }

    // The smallest depth must show real submission-queue backpressure, because a
    // read batch is larger than the ring.
    let smallest = rows.first().expect("at least one depth");
    assert!(
        smallest.read.stats.sq_full_events > 0,
        "smallest depth {} did not exercise SQ backpressure (batch {}): {:?}",
        smallest.ring_depth,
        BATCH_RECORDS,
        smallest.read.stats
    );

    let doc = serde_json::json!({
        "schema": "orfs.performance.uring-depth.v1",
        "generated_by": "tests/uring_depth.rs",
        "io_uring_available": true,
        "io_uring_reason": serde_json::Value::Null,
        "note": "Single-run, single-host io_uring ring-depth sweep. Absolute \
                 nanoseconds are host/load sensitive; the mechanism counters are the \
                 point: sq_full_events shows real submission-queue backpressure \
                 (observed for byte-batched reads at small depths, and deliberately \
                 absent for write_batch, which caps each batch at the ring depth), \
                 cq_max_len shows the largest completion queue drained in one pass, \
                 and batch_chunks counts batched submit rounds.",
        "pmu": {
            "hardware_counters_available": environment.perf_counters_available,
            "perf_event_paranoid": environment.perf_event_paranoid,
            "note": "Hardware performance counters (and thus flamegraphs / PMU \
                     attribution) are unavailable on this host; the SQ/CQ counters are \
                     the PMU-free mechanism evidence.",
        },
        "design": {
            "depths": SWEEP_DEPTHS,
            "batch_records": BATCH_RECORDS,
            "record_bytes": RECORD_BYTES,
            "batch_bytes": BATCH_RECORDS * RECORD_BYTES,
            "rounds": ROUNDS,
            "records_per_depth": BATCH_RECORDS * ROUNDS,
            "bytes_per_depth": (BATCH_RECORDS * ROUNDS * RECORD_BYTES) as u64,
            "ring_depth_is_power_of_two_and_min_2": "UringEngine::try_new rounds the \
                requested depth up to a power of two with a floor of 2, so a requested \
                depth of 1 runs on a ring of depth 2",
            "backpressure_exercised": "each read batch is 128 records, larger than the \
                ring at small depths, so the SQ fills; each write batch is capped at \
                the ring depth, so the SQ never fills",
        },
        "rows": rows.iter().map(|row| serde_json::json!({
            "requested_depth": row.requested_depth,
            "ring_depth": row.ring_depth,
            "read": row.read.json(),
            "write": row.write.json(),
        })).collect::<Vec<_>>(),
        "environment": serde_json::to_value(&environment).unwrap_or(serde_json::Value::Null),
        "orfs_version": orfs::VERSION,
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
    });

    write_json(&out_path, &doc);
    eprintln!("uring-depth evidence written to {}", out_path.display());
}

fn write_json(path: &Path, doc: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut text = serde_json::to_string_pretty(doc).expect("serialize");
    text.push('\n');
    std::fs::write(path, text).expect("write evidence");
}
