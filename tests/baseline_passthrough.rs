//! **Phase 66 — reviewer item: the `baseline_passthrough` comparison.**
//!
//! The Phase-21 court measured a kernel-served passthrough read of a snapshot
//! against a daemon-served FUSE read and a cached plain file — but only for a
//! single 256 KiB read loop. This court runs the **same `src/bench.rs` file
//! workloads** (the ones `tests/baselines.rs` uses) three ways **over the same
//! data**, so the passthrough mechanism sits beside the two baselines the
//! reviewer expects:
//!
//! * **(a) host-ext4 scratch** — a plain file, written and read by
//!   `orfs::bench::run_fs_workload` on the bind-mounted project drive (exactly as
//!   `tests/baselines.rs` does);
//! * **(b) OrFS FUSE passthrough** — the Phase-21 immutable-snapshot mechanism:
//!   the kernel serves the registered backing image and the daemon is not
//!   invoked;
//! * **(c) OrFS ordinary mounted read path** — the same workload through a
//!   regular writable OrFS mount, where every read reaches the daemon.
//!
//! **The data is identical, not merely equal-sized.** `run_fs_workload`'s own
//! writer (`make_file`) fills a file with a deterministic pattern; the
//! passthrough fixture is filled with a byte-for-byte replica of that generator
//! (same LCG, same per-MiB seed ladder), and the passthrough read loop replays
//! the same offset generator and sizes. Arms (a) and (c) therefore read the same
//! bytes with the same access pattern through the two baselines, and arm (b)
//! reads the same bytes through the kernel passthrough.
//!
//! Mounting requires `/dev/fuse`, `CAP_SYS_ADMIN` (passthrough is gated on
//! `capable(CAP_SYS_ADMIN)`) and an unconfined seccomp profile; the court is
//! expected only under `scripts/container-baseline-passthrough.sh`
//! (`ORFS_FUSE_TEST=1`, a **root** container). If a mount cannot be obtained the
//! court records `ran: false` with the exact reason — it never fabricates a
//! result and never hangs.
//!
//! Evidence: `evidence/performance/baseline-passthrough.json`.

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use orfs::bench::{run_fs_workload, BenchParams, Latency, Measurement, Workload};
use orfs::commit::DurabilityMode;
use orfs::fuse::{self, MountOptions, StatfsMode};
use orfs::index::ROOT_INODE;
use orfs::namespace::{Namespace, SetAttr};

/// The file/workload size for every arm (8 MiB keeps the whole court bounded).
const DATA_BYTES: u64 = 8 * 1024 * 1024;
/// Random ops per workload (the same for every arm).
const ITERATIONS: u64 = 20_000;
/// Region size for the 4 KiB random workload.
const REGION_BYTES: u64 = 4096;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_scratch(prefix: &str) -> PathBuf {
    let base = manifest_dir()
        .join("target")
        .join("baseline-passthrough-it");
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

/// A byte-for-byte replica of `orfs::bench`'s private `fill_pattern` + `make_file`
/// generator, so the passthrough fixture holds exactly the bytes arm (a)/(c) read.
fn content(len: u64) -> Vec<u8> {
    const MIB: u64 = 1024 * 1024;
    fn fill(buf: &mut [u8], seed: u64) {
        let mut s = seed;
        for b in buf.iter_mut() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (s >> 33) as u8;
        }
    }
    let mut out = Vec::with_capacity(len as usize);
    let mut block = vec![0u8; MIB as usize];
    let mut remaining = len;
    let mut seed = 0x1234_5678u64;
    while remaining > 0 {
        let n = remaining.min(MIB) as usize;
        fill(&mut block[..n], seed);
        seed = seed.wrapping_add(0x9E37_79B9);
        out.extend_from_slice(&block[..n]);
        remaining -= n as u64;
    }
    out
}

/// The offset generator `orfs::bench::run_fs_workload` uses (same LCG, same seed).
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

fn measurement(ops: u64, bytes: u64, seconds: f64, samples: Vec<u64>) -> Measurement {
    let ops_per_s = if seconds > 0.0 {
        ops as f64 / seconds
    } else {
        0.0
    };
    let mb_per_s = if seconds > 0.0 {
        bytes as f64 / seconds / 1e6
    } else {
        0.0
    };
    Measurement {
        ops,
        bytes,
        seconds,
        ops_per_s,
        mb_per_s,
        latency: Some(Latency::from_samples(samples)),
        notes: Vec::new(),
    }
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

/// Initialise a volume holding one regular file `f` with `data`, owned by the
/// mounting uid (the read-only snapshot exposes only `f`).
fn build_fixture(backing: &Path, data: &[u8]) -> u64 {
    let mut ns = Namespace::init(backing, 1 << 20, DurabilityMode::Ordered).expect("init volume");
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
    let f = ns
        .create(ROOT_INODE, b"f", 0o644, uid, gid)
        .expect("create f");
    ns.write_at(f, 0, data).expect("write fixture");
    ns.sync().expect("sync fixture");
    ns.root()
}

fn snap_opts(passthrough: bool) -> MountOptions {
    // `direct_io` must stay **off**: the daemon offers FOPEN_PASSTHROUGH only when
    // it is not also requesting direct I/O (`Dispatcher::attach_passthrough`).
    MountOptions {
        read_only: true,
        statfs: StatfsMode::PhysicalSafe,
        passthrough,
        ..Default::default()
    }
}

fn ordinary_opts() -> MountOptions {
    // The ordinary mounted read path a user gets by default (page cache enabled).
    MountOptions {
        transport: fuse::Transport::Fuse,
        backing_io: fuse::BackingIo::Uring,
        ..Default::default()
    }
}

/// Run one of the read workloads **against an existing file** (the passthrough
/// snapshot's `f`), replicating `orfs::bench::run_fs_workload`'s loops exactly.
fn run_read_workload_on_file(
    path: &Path,
    workload: Workload,
    params: &BenchParams,
) -> orfs::Result<Measurement> {
    let mut rng = Lcg::new(0xC0FF_EE00);
    match workload {
        Workload::SequentialRead => {
            let mut f = File::open(path)?;
            let chunk = 1024 * 1024usize;
            let mut buf = vec![0u8; chunk];
            let start = Instant::now();
            let mut total = 0u64;
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                total += n as u64;
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(measurement(
                total / params.region_bytes.max(1),
                total,
                secs,
                Vec::new(),
            ))
        }
        Workload::RandomRead4k => {
            let f = File::open(path)?;
            let blocks = (params.data_bytes / params.region_bytes.max(1)).max(1);
            let mut buf = vec![0u8; params.region_bytes as usize];
            let mut samples = Vec::with_capacity(params.iterations as usize);
            let start = Instant::now();
            for _ in 0..params.iterations {
                let off = rng.below(blocks) * params.region_bytes;
                let t = Instant::now();
                f.read_exact_at(&mut buf, off)?;
                samples.push(t.elapsed().as_nanos() as u64);
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(measurement(
                params.iterations,
                params.iterations * params.region_bytes,
                secs,
                samples,
            ))
        }
        Workload::RandomRead1 => {
            let f = File::open(path)?;
            let mut byte = [0u8; 1];
            let mut samples = Vec::with_capacity(params.iterations as usize);
            let start = Instant::now();
            for _ in 0..params.iterations {
                let off = rng.below(params.data_bytes.max(1));
                let t = Instant::now();
                f.read_exact_at(&mut byte, off)?;
                samples.push(t.elapsed().as_nanos() as u64);
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(measurement(
                params.iterations,
                params.iterations,
                secs,
                samples,
            ))
        }
        other => Err(orfs::OrfsError::InvalidArgument(format!(
            "workload {} is not a read workload",
            other.name()
        ))),
    }
}

fn json_of(arm: &str, w: Workload, m: &Measurement) -> serde_json::Value {
    serde_json::json!({
        "arm": arm,
        "workload": w.name(),
        "measurement": serde_json::to_value(m).unwrap_or(serde_json::Value::Null),
    })
}

fn environment() -> serde_json::Value {
    serde_json::to_value(orfs::bench::Environment::capture(Some(image_digest())))
        .unwrap_or(serde_json::Value::Null)
}

/// Serialize the coarse daemon counters by hand (`Metrics` is not `Serialize`).
fn metrics_json(m: &fuse::Metrics) -> serde_json::Value {
    serde_json::json!({
        "lookups": m.lookups,
        "opens": m.opens,
        "releases": m.releases,
        "reads": m.reads,
        "byte_reads": m.byte_reads,
        "writes": m.writes,
        "byte_writes": m.byte_writes,
        "fsyncs": m.fsyncs,
        "create": m.create,
    })
}

fn write_json(value: &serde_json::Value) {
    let path = manifest_dir().join("evidence/performance/baseline-passthrough.json");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut s) = serde_json::to_string_pretty(value) {
        s.push('\n');
        let _ = fs::write(&path, s);
    }
}

/// The read workloads every arm can run (the snapshot is read-only, so the
/// append workload is arm-(a)/(c)-only; see the evidence `method`).
const READ_WORKLOADS: [Workload; 3] = [
    Workload::SequentialRead,
    Workload::RandomRead4k,
    Workload::RandomRead1,
];

#[test]
fn baseline_passthrough() {
    let required = fuse_test_required();
    if !required {
        eprintln!(
            "baseline_passthrough: skipped (ORFS_FUSE_TEST unset); \
             run under scripts/container-baseline-passthrough.sh"
        );
        return;
    }
    let scratch = unique_scratch("baseline-pt");
    let data = content(DATA_BYTES);

    // ---- Arm (a): plain file on the host-ext4 scratch (as tests/baselines.rs) ----
    let ext4_dir = scratch.join("ext4");
    fs::create_dir_all(&ext4_dir).expect("ext4 dir");
    let mut arms: Vec<(String, Workload, Measurement)> = Vec::new();
    for w in READ_WORKLOADS {
        let m = run_fs_workload(&ext4_dir, w, &params()).expect("ext4 workload");
        arms.push(("ext4".into(), w, m));
    }
    // Arm (a) additionally runs the append workload (the ext4 baseline can write).
    arms.push((
        "ext4".into(),
        Workload::SequentialAppend,
        run_fs_workload(&ext4_dir, Workload::SequentialAppend, &params()).expect("ext4 append"),
    ));

    // ---- Arm (b): OrFS FUSE passthrough snapshot (root + CAP_SYS_ADMIN) ----
    let backing = scratch.join("backing");
    let root = build_fixture(&backing, &data);
    let mnt_pt = scratch.join("mnt-pt");
    fs::create_dir_all(&mnt_pt).expect("mnt-pt");
    let mount_pt = match fuse::spawn_snapshot_native(&backing, &mnt_pt, root, &snap_opts(true)) {
        Ok(m) => m,
        Err(e) => {
            let doc = serde_json::json!({
                "schema": "orfs.baseline-passthrough.v1",
                "generated_by": "tests/baseline_passthrough.rs::baseline_passthrough",
                "ran": false,
                "blocker": format!("passthrough snapshot mount failed: {e}"),
                "environment": environment(),
                "params": {
                    "data_bytes": DATA_BYTES,
                    "iterations": ITERATIONS,
                    "region_bytes": REGION_BYTES,
                },
            });
            write_json(&doc);
            eprintln!("baseline_passthrough: ran=false — {e}");
            let _ = fs::remove_dir_all(&scratch);
            if required {
                panic!("passthrough mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            return;
        }
    };
    for w in READ_WORKLOADS {
        let m = run_read_workload_on_file(&mnt_pt.join("f"), w, &params()).expect("passthrough");
        arms.push(("orfs-fuse-passthrough".into(), w, m));
    }
    let pt_stats = mount_pt.f2_stats();
    // A kernel-served read never reaches the daemon; prove the arm really engaged.
    let pt_engaged = pt_stats
        .as_ref()
        .map(|s| s.passthrough_opens > 0 && s.passthrough_registered > 0)
        .unwrap_or(false);
    mount_pt.unmount().expect("unmount passthrough");

    // ---- Arm (c): OrFS ordinary mounted read path ----
    let backing_c = scratch.join("backing-ordinary");
    let mnt_c = scratch.join("mnt-ordinary");
    fs::create_dir_all(&mnt_c).expect("mnt-ordinary");
    {
        let mut ns =
            Namespace::init(&backing_c, 1 << 20, DurabilityMode::Ordered).expect("init volume c");
        // SAFETY: pure queries.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        ns.setattr(
            ROOT_INODE,
            &SetAttr {
                uid: Some(uid),
                gid: Some(gid),
                ..Default::default()
            },
        )
        .expect("chown root c");
        ns.sync().expect("sync c");
    }
    let mount_c = match fuse::spawn(&backing_c, &mnt_c, &ordinary_opts()) {
        Ok(m) => m,
        Err(e) => {
            let doc = serde_json::json!({
                "schema": "orfs.baseline-passthrough.v1",
                "generated_by": "tests/baseline_passthrough.rs::baseline_passthrough",
                "ran": false,
                "blocker": format!("ordinary OrFS mount failed: {e}"),
                "partial_arms": arms
                    .iter()
                    .map(|(a, w, m)| json_of(a, *w, m))
                    .collect::<Vec<_>>(),
                "environment": environment(),
            });
            write_json(&doc);
            eprintln!("baseline_passthrough: ran=false — {e}");
            let _ = fs::remove_dir_all(&scratch);
            if required {
                panic!("ordinary OrFS mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            return;
        }
    };
    for w in READ_WORKLOADS {
        let m = run_fs_workload(&mnt_c, w, &params()).expect("orfs mount workload");
        arms.push(("orfs-mount".into(), w, m));
    }
    arms.push((
        "orfs-mount".into(),
        Workload::SequentialAppend,
        run_fs_workload(&mnt_c, Workload::SequentialAppend, &params()).expect("orfs append"),
    ));
    let mount_stats = mount_c.daemon_metrics();
    mount_c.unmount().expect("unmount ordinary");

    // ---- Assemble the receipt ----
    let workloads: Vec<serde_json::Value> = READ_WORKLOADS
        .iter()
        .map(|w| {
            let mut row = serde_json::json!({ "workload": w.name() });
            for (arm, aw, m) in &arms {
                if aw == w {
                    row[arm] = serde_json::to_value(m).unwrap_or(serde_json::Value::Null);
                }
            }
            row
        })
        .chain(std::iter::once({
            let mut row = serde_json::json!({ "workload": Workload::SequentialAppend.name() });
            for (arm, aw, m) in &arms {
                if *aw == Workload::SequentialAppend {
                    row[arm] = serde_json::to_value(m).unwrap_or(serde_json::Value::Null);
                }
            }
            row
        }))
        .collect();

    let doc = serde_json::json!({
        "schema": "orfs.baseline-passthrough.v1",
        "generated_by": "tests/baseline_passthrough.rs::baseline_passthrough",
        "ran": true,
        "claim": "the same src/bench.rs file workloads, measured three ways over the same data: \
                  a plain host-ext4 scratch file, the OrFS FUSE passthrough snapshot mechanism \
                  (kernel-served; the daemon is not invoked), and OrFS's ordinary mounted read path \
                  (every read reaches the daemon)",
        "method": "all three arms run the identical deterministic data and access pattern: arms (a) \
                   and (c) via orfs::bench::run_fs_workload (which writes and reads its own file), \
                   arm (b) via a byte-for-byte replica of the same generator read through the \
                   passthrough snapshot with the identical offset generator and sizes. The two FUSE \
                   arms use the default (page-cached) open, because kernel passthrough is offered \
                   only when the mount is not also requesting direct I/O.",
        "caveat": "All three arms are page-cache warm after the first pass; the point is the ordering \
                   across mechanisms under one identical workload, not cold-storage throughput. \
                   The passthrough arm is a read-only snapshot, so the sequential-append workload \
                   has no passthrough row by construction. Single run, single host.",
        "params": {
            "data_bytes": DATA_BYTES,
            "iterations": ITERATIONS,
            "region_bytes": REGION_BYTES,
        },
        "environment": environment(),
        "workloads": workloads,
        "passthrough_engaged": pt_engaged,
        "passthrough_stats": pt_stats,
        "orfs_mount_metrics": metrics_json(&mount_stats),
    });
    write_json(&doc);

    // Console summary (machine-readable rows are in the receipt).
    println!("\n=== baseline_passthrough: same workload, three mechanisms (page-cache warm) ===");
    println!(
        "{:>18} | {:>14} | {:>14} | {:>14}",
        "workload", "ext4 MB/s", "passthrough", "orfs-mount"
    );
    for row in doc["workloads"].as_array().unwrap() {
        let get = |k: &str| {
            row.get(k)
                .and_then(|v| v.get("mb_per_s"))
                .and_then(|v| v.as_f64())
                .map(|v| format!("{v:.0}"))
                .unwrap_or_else(|| "-".to_string())
        };
        println!(
            "{:>18} | {:>14} | {:>14} | {:>14}",
            row["workload"].as_str().unwrap_or("?"),
            get("ext4"),
            get("orfs-fuse-passthrough"),
            get("orfs-mount"),
        );
    }

    let _ = fs::remove_dir_all(&scratch);
}
