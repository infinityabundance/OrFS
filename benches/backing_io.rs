//! A simple, honest sync-vs-`io_uring` backing-I/O micro-benchmark.
//!
//! Built with `harness = false`. It measures two workloads against each other
//! under identical conditions *in the same process on the same file*:
//!
//! * **sequential append** — `pwrite` vs `io_uring` `WRITE` at a monotonic offset;
//! * **random read** — `pread` vs `io_uring` `READ` at random aligned offsets.
//!
//! It also runs the explicit **ordered write+fsync** primitive and records its
//! measured ordering verdict.
//!
//! Results are written to `evidence/performance/backing-uring.json`. Nothing here
//! is fabricated: if `io_uring` is unavailable the uring fields are `null` and the
//! reason is recorded. All numbers are measured in this process.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::Instant;

use orfs::capabilities;
use orfs::uring::{ReadJob, UringConfig, UringEngine, WriteJob};

const RECORD_BYTES: usize = 4096;
const APPEND_OPS: usize = 20_000;
const READ_OPS: usize = 40_000;

/// A tiny deterministic PRNG so runs are reproducible without a dependency.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

fn fill_record(buf: &mut [u8], seed: u64) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((seed as usize).wrapping_mul(31).wrapping_add(i)) as u8;
    }
}

/// Sequential append via synchronous positional writes.
fn append_sync(path: &Path, ops: usize, record: &[u8]) -> f64 {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("create file");
    let start = Instant::now();
    let mut off = 0u64;
    for _ in 0..ops {
        file.write_all_at(record, off).expect("pwrite");
        off += record.len() as u64;
    }
    start.elapsed().as_secs_f64()
}

/// Sequential append via io_uring.
fn append_uring(path: &Path, ops: usize, record: &[u8], engine: &mut UringEngine) -> f64 {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("create file");
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let start = Instant::now();
    let mut off = 0u64;
    for _ in 0..ops {
        engine.write_at_all(fd, off, record).expect("uring write");
        off += record.len() as u64;
    }
    start.elapsed().as_secs_f64()
}

/// Sequential append via io_uring, in batches of `depth` (true async submission).
fn append_uring_batched(path: &Path, ops: usize, record: &[u8], engine: &mut UringEngine) -> f64 {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("create file");
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let batch = engine.depth() as usize;
    let start = Instant::now();
    let mut off = 0u64;
    let mut group: Vec<WriteJob<'_>> = Vec::with_capacity(batch);
    for _ in 0..ops {
        group.push(WriteJob::new(fd, off, record));
        off += record.len() as u64;
        if group.len() == batch {
            engine.write_batch(&mut group).expect("batched write");
            group.clear();
        }
    }
    if !group.is_empty() {
        engine.write_batch(&mut group).expect("batched write");
    }
    start.elapsed().as_secs_f64()
}

/// Random reads via synchronous positional reads.
fn read_sync(path: &Path, ops: usize, size: u64) -> f64 {
    let file = File::open(path).expect("open file");
    let mut rng = Lcg(0x9E3779B97F4A7C15);
    let blocks = size / RECORD_BYTES as u64;
    let mut buf = vec![0u8; RECORD_BYTES];
    let start = Instant::now();
    for _ in 0..ops {
        let off = (rng.next() % blocks) * RECORD_BYTES as u64;
        file.read_exact_at(&mut buf, off).expect("pread");
    }
    start.elapsed().as_secs_f64()
}

/// Random reads via io_uring.
fn read_uring(path: &Path, ops: usize, size: u64, engine: &mut UringEngine) -> f64 {
    let file = File::open(path).expect("open file");
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let mut rng = Lcg(0x9E3779B97F4A7C15);
    let blocks = size / RECORD_BYTES as u64;
    let mut buf = vec![0u8; RECORD_BYTES];
    let start = Instant::now();
    for _ in 0..ops {
        let off = (rng.next() % blocks) * RECORD_BYTES as u64;
        engine.read_exact_at(fd, off, &mut buf).expect("uring read");
    }
    start.elapsed().as_secs_f64()
}

/// Random reads via io_uring, issued concurrently in batches of `depth`.
fn read_uring_batched(path: &Path, ops: usize, size: u64, engine: &mut UringEngine) -> f64 {
    let file = File::open(path).expect("open file");
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let batch = engine.depth() as usize;
    let blocks = size / RECORD_BYTES as u64;
    let mut rng = Lcg(0x9E3779B97F4A7C15);
    let start = Instant::now();
    let mut remaining = ops;
    while remaining > 0 {
        let n = remaining.min(batch);
        let mut bufs: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; RECORD_BYTES]).collect();
        let mut jobs: Vec<ReadJob<'_>> = Vec::with_capacity(n);
        for b in bufs.iter_mut() {
            let off = (rng.next() % blocks) * RECORD_BYTES as u64;
            jobs.push(ReadJob::new(fd, off, b.as_mut_slice()));
        }
        engine.read_batch(&mut jobs).expect("batched read");
        remaining -= n;
    }
    start.elapsed().as_secs_f64()
}

fn mbps(bytes: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        return 0.0;
    }
    bytes as f64 / secs / 1e6
}

fn rate(ops: usize, secs: f64) -> f64 {
    if secs <= 0.0 {
        return 0.0;
    }
    ops as f64 / secs
}

fn main() {
    let out_dir = Path::new("evidence/performance");
    std::fs::create_dir_all(out_dir).expect("create evidence dir");
    let out_path = out_dir.join("backing-uring.json");

    let scratch = std::env::temp_dir().join(format!("orfs-bench-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("scratch dir");
    let path = scratch.join("data.bin");

    let caps = capabilities::probe();
    let probe = orfs::uring::probe_available();
    let uring_available = probe.is_ok();

    let mut record = vec![0u8; RECORD_BYTES];
    fill_record(&mut record, 7);

    // --- warm up the page cache / allocator ---
    let _ = append_sync(&path, APPEND_OPS, &record);

    let sync_append_secs = append_sync(&path, APPEND_OPS, &record);
    let total_bytes = (APPEND_OPS * RECORD_BYTES) as u64;
    let sync_read_secs = read_sync(&path, READ_OPS, total_bytes);

    let mut uring_engine = if uring_available {
        UringEngine::try_new(UringConfig::default().write_depth, true).ok()
    } else {
        None
    };

    let (uring_append, uring_append_batched, uring_read, uring_read_batched, ordered, stats) =
        if let Some(engine) = uring_engine.as_mut() {
            let a = append_uring(&path, APPEND_OPS, &record, engine);
            let ab = append_uring_batched(&path, APPEND_OPS, &record, engine);
            let r = read_uring(&path, READ_OPS, total_bytes, engine);
            let rb = read_uring_batched(&path, READ_OPS, total_bytes, engine);

            // Ordered write+fsync primitive on a fresh file.
            let opath = scratch.join("ordered.bin");
            let ofile = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&opath)
                .expect("ordered file");
            use std::os::unix::io::AsRawFd;
            let ofd = ofile.as_raw_fd();
            let report = engine
                .write_then_fsync_ordered(ofd, 0, &record)
                .expect("ordered write+fsync");
            (a, ab, r, rb, Some(report), Some(engine.stats()))
        } else {
            (0.0, 0.0, 0.0, 0.0, None, None)
        };

    let json = serde_json::json!({
        "generated_by": "benches/backing_io.rs",
        "orfs_version": orfs::VERSION,
        "environment": {
            "kernel_release": caps.kernel_release,
            "machine": caps.machine,
            "likely_container": caps.likely_container,
            "io_uring_disabled_sysctl": caps.io_uring_disabled,
            "io_uring_available": uring_available,
            "io_uring_reason": probe.as_ref().err(),
        },
        "method": {
            "note": "Both engines run in the same process against the same scratch files. \
                     Sync uses pread/pwrite; uring uses io_uring READ/WRITE SQEs with per-op \
                     user_data and explicit CQE validation. Sync append is measured after a \
                     warm-up pass; buffers are page-cache resident (this is a syscall/submission \
                     micro-benchmark, not a device-durability benchmark).",
            "record_bytes": RECORD_BYTES,
            "append_ops": APPEND_OPS,
            "read_ops": READ_OPS,
        },
        "results": {
            "sequential_append": {
                "bytes": total_bytes,
                "sync": {
                    "seconds": sync_append_secs,
                    "mb_per_s": mbps(total_bytes, sync_append_secs),
                    "ops_per_s": rate(APPEND_OPS, sync_append_secs),
                },
                "uring": if uring_available {
                    serde_json::json!({
                        "seconds": uring_append,
                        "mb_per_s": mbps(total_bytes, uring_append),
                        "ops_per_s": rate(APPEND_OPS, uring_append),
                    })
                } else {
                    serde_json::Value::Null
                },
                "uring_batched": if uring_available {
                    serde_json::json!({
                        "seconds": uring_append_batched,
                        "mb_per_s": mbps(total_bytes, uring_append_batched),
                        "ops_per_s": rate(APPEND_OPS, uring_append_batched),
                    })
                } else {
                    serde_json::Value::Null
                },
                "speedup_uring_over_sync": if uring_available && uring_append > 0.0 {
                    serde_json::json!(sync_append_secs / uring_append)
                } else {
                    serde_json::Value::Null
                },
                "speedup_uring_batched_over_sync": if uring_available && uring_append_batched > 0.0 {
                    serde_json::json!(sync_append_secs / uring_append_batched)
                } else {
                    serde_json::Value::Null
                },
            },
            "random_read": {
                "sync": {
                    "seconds": sync_read_secs,
                    "mb_per_s": mbps((READ_OPS * RECORD_BYTES) as u64, sync_read_secs),
                    "ops_per_s": rate(READ_OPS, sync_read_secs),
                },
                "uring": if uring_available {
                    serde_json::json!({
                        "seconds": uring_read,
                        "mb_per_s": mbps((READ_OPS * RECORD_BYTES) as u64, uring_read),
                        "ops_per_s": rate(READ_OPS, uring_read),
                    })
                } else {
                    serde_json::Value::Null
                },
                "uring_batched": if uring_available {
                    serde_json::json!({
                        "seconds": uring_read_batched,
                        "mb_per_s": mbps((READ_OPS * RECORD_BYTES) as u64, uring_read_batched),
                        "ops_per_s": rate(READ_OPS, uring_read_batched),
                    })
                } else {
                    serde_json::Value::Null
                },
                "speedup_uring_over_sync": if uring_available && uring_read > 0.0 {
                    serde_json::json!(sync_read_secs / uring_read)
                } else {
                    serde_json::Value::Null
                },
                "speedup_uring_batched_over_sync": if uring_available && uring_read_batched > 0.0 {
                    serde_json::json!(sync_read_secs / uring_read_batched)
                } else {
                    serde_json::Value::Null
                },
            },
            "ordered_write_fsync": {
                "uring": ordered,
            },
            "uring_stats_after_workload": stats,
        },
    });

    let mut text = serde_json::to_string_pretty(&json).expect("serialize");
    text.push('\n');
    std::fs::write(&out_path, text).expect("write evidence");

    println!(
        "backing-uring.json: uring_available={uring_available} \
         sync_append={:.1} MB/s uring_append={:.1} MB/s uring_append_batched={:.1} MB/s \
         sync_read={:.1} MB/s uring_read={:.1} MB/s uring_read_batched={:.1} MB/s",
        mbps(total_bytes, sync_append_secs),
        mbps(total_bytes, uring_append),
        mbps(total_bytes, uring_append_batched),
        mbps((READ_OPS * RECORD_BYTES) as u64, sync_read_secs),
        mbps((READ_OPS * RECORD_BYTES) as u64, uring_read),
        mbps((READ_OPS * RECORD_BYTES) as u64, uring_read_batched),
    );
    if let Some(reason) = probe.err() {
        println!("note: io_uring unavailable: {reason}");
    }

    let _ = std::fs::remove_dir_all(&scratch);
}
