//! The OrFS performance harness (research §30 methodology, §31 frontier, §32
//! controls, §34 performance model, §36 tools; `research/OrFS prompt.md` §30–§33).
//!
//! # What this harness is
//!
//! A single, honest workload runner that **isolates distinct mechanisms**. Each
//! configuration changes exactly one axis relative to a comparable one:
//!
//! | Config | FUSE transport | Backing I/O | Manifestation |
//! |---|---|---|---|
//! | `Conventional` | none (plain directory) | conventional | none |
//! | `F0` | traditional `/dev/fuse` | synchronous `pread`/`pwrite` | none |
//! | `F1` | traditional `/dev/fuse` | `io_uring` | none |
//! | `F2` | FUSE-over-`io_uring` | `io_uring` | none |
//! | `E1` | traditional `/dev/fuse` | `io_uring` | EKBLOOM |
//! | `E2` | FUSE-over-`io_uring` | `io_uring` | EKBLOOM |
//!
//! `F2`/`E2` are **reported unavailable with the concrete runtime reason** when
//! the kernel does not offer FUSE-over-`io_uring` (on this host
//! `fuse.enable_uring=0`); no number is invented for them (research §30).
//!
//! # Honesty
//!
//! Every measurement is taken from a real run and carries the environment that
//! produced it. `Conventional` is a *real* baseline (a directory on the same
//! backing medium), never a weakened straw man. Where a tool (fio, perf,
//! hyperfine) is unavailable the reason is recorded; where a configuration is
//! impossible it is marked, not fabricated.
//!
//! The library-level workloads (search, snapshot, recovery) are answered by the
//! OrFS API directly and are labelled **config-independent**: they do not pass
//! through FUSE, so they must not be attributed to a transport configuration.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;

use crate::commit::DurabilityMode;
use crate::error::{OrfsError, Result};
use crate::fuse::{self, BackingIo, MountOptions, Transport};
use crate::fuse_uring;
use crate::fuse_uring::TransportProfile;
use crate::log::OpenMode;
use crate::manifestation::ManifestationProfile;
use crate::namespace::Namespace;
use crate::query::QueryRequest;
use crate::snapshot::Snapshot;

/// Average bytes in a "1 MiB" chunk.
const MIB: u64 = 1024 * 1024;
/// Maximum per-operation latency samples retained (bounds memory).
const MAX_SAMPLES: usize = 200_000;

// ---------------------------------------------------------------------------
// Environment receipt
// ---------------------------------------------------------------------------

/// The environment that produced a measurement. Every field is read from the
/// live system (or is explicitly `None`); nothing is assumed (research §32).
#[derive(Debug, Clone, Serialize)]
pub struct Environment {
    pub cpu_model: Option<String>,
    pub cores_visible: usize,
    pub cpu_max: Option<String>,
    pub ram_total_bytes: Option<u64>,
    pub cgroup_memory_max: Option<String>,
    pub kernel_release: String,
    pub machine: String,
    pub likely_container: bool,
    pub compiler: Option<String>,
    pub container_image: Option<String>,
    pub fuse_enable_uring: Option<bool>,
    pub perf_event_paranoid: Option<String>,
    pub perf_counters_available: bool,
}

impl Environment {
    /// Capture the live environment.
    pub fn capture(container_image: Option<String>) -> Environment {
        let caps = crate::capabilities::probe();
        let perf_paranoid = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
            .ok()
            .map(|s| s.trim().to_string());
        // Hardware counters require an unprivileged-capable paranoid level AND the
        // `perf` tool; both are checked truthfully.
        let perf_counters_available = perf_paranoid
            .as_deref()
            .and_then(|s| s.parse::<i32>().ok())
            .map(|p| p <= 1)
            .unwrap_or(false)
            && which("perf").is_some();
        Environment {
            cpu_model: cpu_model(),
            cores_visible: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(0),
            cpu_max: read_trim("/sys/fs/cgroup/cpu.max"),
            ram_total_bytes: mem_total_bytes(),
            cgroup_memory_max: read_trim("/sys/fs/cgroup/memory.max"),
            kernel_release: caps.kernel_release,
            machine: caps.machine,
            likely_container: caps.likely_container,
            compiler: rustc_version(),
            container_image,
            fuse_enable_uring: std::fs::read_to_string(fuse_uring::ENABLE_URING_PARAM)
                .ok()
                .map(|t| matches!(t.trim(), "Y" | "y" | "1")),
            perf_event_paranoid: perf_paranoid,
            perf_counters_available,
        }
    }
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn cpu_model() -> Option<String> {
    let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("model name") {
            if let Some((_, v)) = rest.split_once(':') {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn mem_total_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kib: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kib * 1024);
        }
    }
    None
}

fn rustc_version() -> Option<String> {
    let out = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn which(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(tool);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Configurations
// ---------------------------------------------------------------------------

/// A benchmark configuration isolating one mechanism (research §30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BenchConfig {
    /// Plain directory on the backing medium. The honest conventional baseline.
    Conventional,
    /// Traditional FUSE, synchronous backing I/O, no manifestation (F0).
    F0,
    /// Traditional FUSE, `io_uring` backing I/O, no manifestation (F1).
    F1,
    /// FUSE-over-`io_uring` transport (F2).
    F2,
    /// Traditional FUSE, `io_uring` backing, EKBLOOM manifestation (E1).
    E1,
    /// FUSE-over-`io_uring` + `io_uring` backing + EKBLOOM (E2).
    E2,
}

impl BenchConfig {
    /// Parse a configuration name (`conventional|f0|f1|f2|e1|e2`).
    pub fn parse(s: &str) -> Result<BenchConfig> {
        match s.trim().to_ascii_lowercase().as_str() {
            "conventional" | "base" => Ok(BenchConfig::Conventional),
            "f0" => Ok(BenchConfig::F0),
            "f1" => Ok(BenchConfig::F1),
            "f2" => Ok(BenchConfig::F2),
            "e1" => Ok(BenchConfig::E1),
            "e2" => Ok(BenchConfig::E2),
            other => Err(OrfsError::InvalidArgument(format!(
                "unknown benchmark config {other:?} (expected conventional|f0|f1|f2|e1|e2)"
            ))),
        }
    }

    /// Stable lower-case name.
    pub fn name(self) -> &'static str {
        match self {
            BenchConfig::Conventional => "conventional",
            BenchConfig::F0 => "f0",
            BenchConfig::F1 => "f1",
            BenchConfig::F2 => "f2",
            BenchConfig::E1 => "e1",
            BenchConfig::E2 => "e2",
        }
    }

    /// A one-line description of the axes this configuration fixes.
    pub fn describe(self) -> &'static str {
        match self {
            BenchConfig::Conventional => "no FUSE; conventional backing; no manifestation",
            BenchConfig::F0 => "traditional FUSE; sync backing; no manifestation",
            BenchConfig::F1 => "traditional FUSE; io_uring backing; no manifestation",
            BenchConfig::F2 => "FUSE-over-io_uring; io_uring backing; no manifestation",
            BenchConfig::E1 => "traditional FUSE; io_uring backing; EKBLOOM manifestation",
            BenchConfig::E2 => "FUSE-over-io_uring; io_uring backing; EKBLOOM manifestation",
        }
    }

    /// Whether this configuration needs a real FUSE mount.
    pub fn is_mounted(self) -> bool {
        !matches!(self, BenchConfig::Conventional)
    }

    /// `Err(reason)` when the configuration cannot run in this environment.
    ///
    /// `F2`/`E2` require FUSE-over-`io_uring`. When the static preconditions
    /// provably do not hold the config is skipped with the exact reason; when
    /// they do hold it is **attempted**, and the live mount decides (see
    /// [`run`]): a mount that silently falls back to F1/F0 is reported
    /// unavailable rather than mislabelled as F2.
    pub fn unavailable(self) -> Option<String> {
        if matches!(self, BenchConfig::F2 | BenchConfig::E2) {
            let report = fuse_uring::discover_report();
            if let Err(reason) = &report.preconditions {
                return Some(reason.clone());
            }
            return None;
        }
        None
    }

    /// The mount options that realize this configuration.
    pub fn mount_options(self, base: &MountOptions) -> MountOptions {
        let mut opts = *base;
        match self {
            BenchConfig::Conventional => opts,
            BenchConfig::F0 => {
                opts.transport = Transport::Fuse;
                opts.backing_io = BackingIo::Sync;
                opts.manifest = None;
                opts
            }
            BenchConfig::F1 => {
                opts.transport = Transport::Fuse;
                opts.backing_io = BackingIo::Uring;
                opts.manifest = None;
                opts
            }
            BenchConfig::F2 => {
                opts.transport = Transport::FuseUring;
                opts.backing_io = BackingIo::Uring;
                opts.manifest = None;
                opts
            }
            BenchConfig::E1 => {
                opts.transport = Transport::Fuse;
                opts.backing_io = BackingIo::Uring;
                // Synchronous manifestation so a written object is manifested
                // before it is read (the write cost is attributed honestly).
                opts.manifest = Some(ManifestationProfile::Bloom { depth: 4 });
                opts.manifest_sync = true;
                opts
            }
            BenchConfig::E2 => {
                opts.transport = Transport::FuseUring;
                opts.backing_io = BackingIo::Uring;
                opts.manifest = Some(ManifestationProfile::Bloom { depth: 4 });
                opts.manifest_sync = true;
                opts
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Workloads
// ---------------------------------------------------------------------------

/// A required workload (research §30, §36).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Workload {
    SequentialRead,
    SequentialAppend,
    #[serde(rename = "random-read-4k")]
    RandomRead4k,
    #[serde(rename = "random-write-4k")]
    RandomWrite4k,
    #[serde(rename = "random-read-1")]
    RandomRead1,
    MetadataLookup,
    CreateUnlink,
    Rename,
    DirEnumeration,
    ConcurrentReaders,
    FsyncLatency,
    MountTime,
    RecoveryTime,
    SearchLatency,
    SnapshotLatency,
}

impl Workload {
    /// Every workload, in the order the directive lists them.
    pub const ALL: [Workload; 15] = [
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
        Workload::MountTime,
        Workload::RecoveryTime,
        Workload::SearchLatency,
        Workload::SnapshotLatency,
    ];

    /// Parse a workload selector (accepts a few aliases).
    pub fn parse(s: &str) -> Result<Workload> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "sequential-read" | "seq-read" => Workload::SequentialRead,
            "sequential-append" | "seq-append" | "append-write" | "append" => {
                Workload::SequentialAppend
            }
            "random-read" | "random-read-4k" | "random-4k" => Workload::RandomRead4k,
            "random-write" | "random-write-4k" | "random-4k-write" => Workload::RandomWrite4k,
            "random-read-1" | "one-byte" | "random-1" => Workload::RandomRead1,
            "metadata-lookup" | "lookup" | "stat" => Workload::MetadataLookup,
            "create-unlink" | "create" | "unlink" => Workload::CreateUnlink,
            "rename" => Workload::Rename,
            "dir-enumeration" | "readdir" | "enumeration" => Workload::DirEnumeration,
            "concurrent-readers" | "concurrent" => Workload::ConcurrentReaders,
            "fsync-latency" | "fsync" => Workload::FsyncLatency,
            "mount-time" | "mount" => Workload::MountTime,
            "recovery-time" | "recovery" => Workload::RecoveryTime,
            "search-latency" | "search" | "query" => Workload::SearchLatency,
            "snapshot-latency" | "snapshot" => Workload::SnapshotLatency,
            other => {
                return Err(OrfsError::InvalidArgument(format!(
                    "unknown workload {other:?}"
                )))
            }
        })
    }

    /// Stable lower-case name.
    pub fn name(self) -> &'static str {
        match self {
            Workload::SequentialRead => "sequential-read",
            Workload::SequentialAppend => "sequential-append",
            Workload::RandomRead4k => "random-read-4k",
            Workload::RandomWrite4k => "random-write-4k",
            Workload::RandomRead1 => "random-read-1",
            Workload::MetadataLookup => "metadata-lookup",
            Workload::CreateUnlink => "create-unlink",
            Workload::Rename => "rename",
            Workload::DirEnumeration => "dir-enumeration",
            Workload::ConcurrentReaders => "concurrent-readers",
            Workload::FsyncLatency => "fsync-latency",
            Workload::MountTime => "mount-time",
            Workload::RecoveryTime => "recovery-time",
            Workload::SearchLatency => "search-latency",
            Workload::SnapshotLatency => "snapshot-latency",
        }
    }

    /// Whether the workload is answered by the library (over the backing) rather
    /// than through the mounted filesystem. Such a workload is
    /// **config-independent** and must not be credited to a transport.
    pub fn is_library_only(self) -> bool {
        matches!(
            self,
            Workload::MountTime
                | Workload::RecoveryTime
                | Workload::SearchLatency
                | Workload::SnapshotLatency
        )
    }
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// The knobs that define a workload's shape (kept identical across comparable
/// configurations, research §30).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct BenchParams {
    /// Logical data size for the bulk workloads, in bytes.
    pub data_bytes: u64,
    /// Operation count for the latency/IOPS workloads.
    pub iterations: u64,
    /// Concurrent reader threads.
    pub readers: usize,
    /// Region/record size for random I/O, in bytes.
    pub region_bytes: u64,
    /// Durability mode exercised by write/fsync workloads.
    pub durability: DurabilityMode,
    /// Whether the kernel page cache is bypassed (`FOPEN_DIRECT_IO`) and/or the
    /// backing page cache is dropped before reads (cold-cache control).
    pub cold_cache: bool,
}

impl Default for BenchParams {
    fn default() -> BenchParams {
        BenchParams {
            data_bytes: 16 * MIB,
            iterations: 20_000,
            readers: 4,
            region_bytes: 4096,
            durability: DurabilityMode::Ordered,
            cold_cache: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// A latency distribution in nanoseconds.
#[derive(Debug, Clone, Serialize)]
pub struct Latency {
    pub min_ns: u64,
    pub mean_ns: f64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
    pub samples: usize,
}

impl Latency {
    /// Build a percentile summary from raw nanosecond samples.
    pub fn from_samples(mut samples: Vec<u64>) -> Latency {
        if samples.is_empty() {
            return Latency {
                min_ns: 0,
                mean_ns: 0.0,
                p50_ns: 0,
                p95_ns: 0,
                p99_ns: 0,
                max_ns: 0,
                samples: 0,
            };
        }
        samples.sort_unstable();
        let n = samples.len();
        let sum: u128 = samples.iter().map(|&v| v as u128).sum();
        let pct = |p: f64| -> u64 {
            let idx = ((n as f64) * p).ceil() as usize;
            let idx = idx.saturating_sub(1).min(n - 1);
            samples[idx]
        };
        Latency {
            min_ns: samples[0],
            mean_ns: sum as f64 / n as f64,
            p50_ns: pct(0.50),
            p95_ns: pct(0.95),
            p99_ns: pct(0.99),
            max_ns: samples[n - 1],
            samples: n,
        }
    }
}

/// The result of running one workload under one configuration.
#[derive(Debug, Clone, Serialize)]
pub struct Measurement {
    pub ops: u64,
    pub bytes: u64,
    pub seconds: f64,
    pub ops_per_s: f64,
    pub mb_per_s: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<Latency>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Measurement {
    fn simple(ops: u64, bytes: u64, seconds: f64) -> Measurement {
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
            latency: None,
            notes: Vec::new(),
        }
    }

    fn with_latency(mut self, latency: Latency) -> Measurement {
        self.latency = Some(latency);
        self
    }

    fn note(mut self, s: impl Into<String>) -> Measurement {
        self.notes.push(s.into());
        self
    }
}

/// The full, self-describing report for one (config, workload) run.
#[derive(Debug, Clone, Serialize)]
pub struct BenchReport {
    pub schema: &'static str,
    pub generated_by: &'static str,
    pub orfs_version: &'static str,
    pub config: BenchConfig,
    pub config_description: &'static str,
    pub config_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    pub workload: Workload,
    pub config_independent: bool,
    pub environment: Environment,
    pub mount_options: Option<String>,
    pub durability: String,
    pub data_size: u64,
    pub params: BenchParams,
    pub measurement: Measurement,
}

impl BenchReport {
    /// The schema identifier for every report this module emits.
    pub const SCHEMA: &'static str = "orfs.bench.v1";

    /// Serialize to a pretty JSON file (with a trailing newline).
    pub fn write_json(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut s = serde_json::to_string_pretty(self)
            .map_err(|e| OrfsError::Corrupt(format!("serialize bench report: {e}")))?;
        s.push('\n');
        std::fs::write(path, s)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Deterministic helpers
// ---------------------------------------------------------------------------

/// A tiny deterministic PRNG (no dependency, reproducible).
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

fn fill_pattern(buf: &mut [u8], seed: u64) {
    let mut s = seed;
    for b in buf.iter_mut() {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        *b = (s >> 33) as u8;
    }
}

/// Create `path` filled with `len` deterministic bytes (created fresh).
fn make_file(path: &Path, len: u64) -> Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .open(path)?;
    let chunk = MIB;
    let mut block = vec![0u8; chunk as usize];
    let mut remaining = len;
    let mut seed = 0x1234_5678;
    while remaining > 0 {
        let n = remaining.min(chunk) as usize;
        fill_pattern(&mut block[..n], seed);
        seed = seed.wrapping_add(0x9E37_79B9);
        f.write_all(&block[..n])?;
        remaining -= n as u64;
    }
    f.sync_all()?;
    Ok(())
}

/// Drop the backing page cache for `path` (cold-cache control). Best-effort.
fn drop_cache(path: &Path) {
    use std::os::unix::io::AsRawFd;
    if let Ok(f) = File::open(path) {
        // SAFETY: `f` is an open regular file; `posix_fadvise` is a hint only and
        // never dereferences memory or invalidates our fd.
        unsafe {
            libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED);
        }
    }
}

// ---------------------------------------------------------------------------
// Filesystem workloads (operate on a directory: a mount point or a plain dir)
// ---------------------------------------------------------------------------

/// Run a filesystem workload rooted at `root` (a directory). The library-only
/// workloads are rejected here; use [`run`] for those.
pub fn run_fs_workload(
    root: &Path,
    workload: Workload,
    params: &BenchParams,
) -> Result<Measurement> {
    std::fs::create_dir_all(root)?;
    let mut rng = Lcg::new(0xC0FF_EE00);
    match workload {
        Workload::SequentialRead => {
            let path = root.join("seq.dat");
            make_file(&path, params.data_bytes)?;
            if params.cold_cache {
                drop_cache(&path);
            }
            let mut f = File::open(&path)?;
            let chunk = MIB;
            let mut buf = vec![0u8; chunk as usize];
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
            Ok(Measurement::simple(
                total / params.region_bytes.max(1),
                total,
                secs,
            ))
        }
        Workload::SequentialAppend => {
            let path = root.join("append.dat");
            let mut f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)?;
            let rec = vec![0xABu8; params.region_bytes as usize];
            let ops = params.data_bytes / params.region_bytes.max(1);
            let start = Instant::now();
            for _ in 0..ops {
                f.write_all(&rec)?;
            }
            if params.durability == DurabilityMode::Sync {
                f.sync_all()?;
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(Measurement::simple(ops, ops * params.region_bytes, secs))
        }
        Workload::RandomRead4k => {
            let path = root.join("rr4k.dat");
            make_file(&path, params.data_bytes)?;
            if params.cold_cache {
                drop_cache(&path);
            }
            let f = File::open(&path)?;
            let blocks = (params.data_bytes / params.region_bytes.max(1)).max(1);
            let mut buf = vec![0u8; params.region_bytes as usize];
            let mut samples =
                Vec::with_capacity(params.iterations.min(MAX_SAMPLES as u64) as usize);
            let start = Instant::now();
            for i in 0..params.iterations {
                let off = rng.below(blocks) * params.region_bytes;
                let t = Instant::now();
                f.read_exact_at(&mut buf, off)?;
                if i < MAX_SAMPLES as u64 {
                    samples.push(t.elapsed().as_nanos() as u64);
                }
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(Measurement::simple(
                params.iterations,
                params.iterations * params.region_bytes,
                secs,
            )
            .with_latency(Latency::from_samples(samples)))
        }
        Workload::RandomWrite4k => {
            let path = root.join("rw4k.dat");
            make_file(&path, params.data_bytes)?;
            let f = OpenOptions::new().write(true).open(&path)?;
            let blocks = (params.data_bytes / params.region_bytes.max(1)).max(1);
            let buf = vec![0x5Au8; params.region_bytes as usize];
            let mut samples =
                Vec::with_capacity(params.iterations.min(MAX_SAMPLES as u64) as usize);
            let start = Instant::now();
            for i in 0..params.iterations {
                let off = rng.below(blocks) * params.region_bytes;
                let t = Instant::now();
                f.write_all_at(&buf, off)?;
                if i < MAX_SAMPLES as u64 {
                    samples.push(t.elapsed().as_nanos() as u64);
                }
            }
            if params.durability == DurabilityMode::Sync {
                f.sync_all()?;
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(Measurement::simple(
                params.iterations,
                params.iterations * params.region_bytes,
                secs,
            )
            .with_latency(Latency::from_samples(samples)))
        }
        Workload::RandomRead1 => {
            let path = root.join("rr1.dat");
            make_file(&path, params.data_bytes)?;
            if params.cold_cache {
                drop_cache(&path);
            }
            let f = File::open(&path)?;
            let mut byte = [0u8; 1];
            let mut samples =
                Vec::with_capacity(params.iterations.min(MAX_SAMPLES as u64) as usize);
            let start = Instant::now();
            for i in 0..params.iterations {
                let off = rng.below(params.data_bytes.max(1));
                let t = Instant::now();
                f.read_exact_at(&mut byte, off)?;
                if i < MAX_SAMPLES as u64 {
                    samples.push(t.elapsed().as_nanos() as u64);
                }
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(
                Measurement::simple(params.iterations, params.iterations, secs)
                    .with_latency(Latency::from_samples(samples)),
            )
        }
        Workload::MetadataLookup => {
            let dir = root.join("meta");
            std::fs::create_dir_all(&dir)?;
            let n = params.iterations.min(10_000);
            let mut paths = Vec::with_capacity(n as usize);
            for i in 0..n {
                let p = dir.join(format!("m{i}"));
                make_file(&p, 16)?;
                paths.push(p);
            }
            let mut samples = Vec::with_capacity(n as usize);
            let start = Instant::now();
            for p in &paths {
                let t = Instant::now();
                let _ = std::fs::metadata(p)?;
                samples.push(t.elapsed().as_nanos() as u64);
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(Measurement::simple(n, 0, secs).with_latency(Latency::from_samples(samples)))
        }
        Workload::CreateUnlink => {
            let n = params.iterations;
            let mut samples = Vec::with_capacity(n.min(MAX_SAMPLES as u64) as usize);
            let start = Instant::now();
            for i in 0..n {
                let p = root.join(format!("cu{i}"));
                let t = Instant::now();
                File::create(&p)?.sync_all()?;
                std::fs::remove_file(&p)?;
                if i < MAX_SAMPLES as u64 {
                    samples.push(t.elapsed().as_nanos() as u64);
                }
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(Measurement::simple(n, 0, secs).with_latency(Latency::from_samples(samples)))
        }
        Workload::Rename => {
            let n = params.iterations;
            let mut samples = Vec::with_capacity(n.min(MAX_SAMPLES as u64) as usize);
            let start = Instant::now();
            for i in 0..n {
                let a = root.join(format!("rn-a{i}"));
                let b = root.join(format!("rn-b{i}"));
                File::create(&a)?;
                let t = Instant::now();
                std::fs::rename(&a, &b)?;
                if i < MAX_SAMPLES as u64 {
                    samples.push(t.elapsed().as_nanos() as u64);
                }
                std::fs::remove_file(&b)?;
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(Measurement::simple(n, 0, secs).with_latency(Latency::from_samples(samples)))
        }
        Workload::DirEnumeration => {
            let dir = root.join("enum");
            std::fs::create_dir_all(&dir)?;
            let files = params.iterations.min(20_000);
            for i in 0..files {
                make_file(&dir.join(format!("e{i}")), 8)?;
            }
            let rounds = 32u64;
            let mut samples = Vec::with_capacity(rounds as usize);
            let start = Instant::now();
            let mut count = 0u64;
            for _ in 0..rounds {
                let t = Instant::now();
                let mut entries = 0u64;
                for e in std::fs::read_dir(&dir)? {
                    let _ = e?;
                    entries += 1;
                }
                samples.push(t.elapsed().as_nanos() as u64);
                count = entries;
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(Measurement::simple(rounds * count, 0, secs)
                .with_latency(Latency::from_samples(samples)))
        }
        Workload::ConcurrentReaders => {
            let path = root.join("cr.dat");
            make_file(&path, params.data_bytes)?;
            if params.cold_cache {
                drop_cache(&path);
            }
            let readers = params.readers.max(1);
            let per = params.iterations / readers as u64;
            let blocks = (params.data_bytes / params.region_bytes.max(1)).max(1);
            let total = AtomicU64::new(0);
            let start = Instant::now();
            std::thread::scope(|scope| {
                for t in 0..readers {
                    let path = &path;
                    let total = &total;
                    let region = params.region_bytes as usize;
                    scope.spawn(move || {
                        let f = File::open(path).expect("open shared file");
                        let mut rng = Lcg::new(0xABCD_0000 + t as u64);
                        let mut buf = vec![0u8; region];
                        let mut done = 0u64;
                        for _ in 0..per {
                            let off = rng.below(blocks) * region as u64;
                            f.read_exact_at(&mut buf, off).expect("concurrent read");
                            done += region as u64;
                        }
                        total.fetch_add(done, Ordering::Relaxed);
                    });
                }
            });
            let secs = start.elapsed().as_secs_f64();
            let bytes = total.load(Ordering::Relaxed);
            Ok(Measurement::simple(per * readers as u64, bytes, secs)
                .note(format!("{readers} concurrent reader thread(s)")))
        }
        Workload::FsyncLatency => {
            let path = root.join("fsync.dat");
            let f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .read(true)
                .open(&path)?;
            let rec = vec![0x77u8; params.region_bytes as usize];
            let n = params.iterations.min(5_000);
            let mut samples = Vec::with_capacity(n as usize);
            let mut off = 0u64;
            let start = Instant::now();
            for _ in 0..n {
                f.write_all_at(&rec, off)?;
                off += params.region_bytes;
                let t = Instant::now();
                f.sync_all()?;
                samples.push(t.elapsed().as_nanos() as u64);
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(Measurement::simple(n, n * params.region_bytes, secs)
                .with_latency(Latency::from_samples(samples)))
        }
        Workload::MountTime
        | Workload::RecoveryTime
        | Workload::SearchLatency
        | Workload::SnapshotLatency => Err(OrfsError::InvalidArgument(format!(
            "workload {} is answered by the OrFS library, not by the mounted filesystem; \
             use orfs::bench::run",
            workload.name()
        ))),
    }
}

// ---------------------------------------------------------------------------
// Library workloads (over the authoritative/derived structures)
// ---------------------------------------------------------------------------

fn run_library_workload(
    backing: &Path,
    workload: Workload,
    params: &BenchParams,
) -> Result<Measurement> {
    match workload {
        Workload::RecoveryTime => {
            // Time to open and recover the authoritative log read-only, repeated.
            let meta = crate::volume::Volume::read_meta(backing)?;
            let rounds = 32u64;
            let mut samples = Vec::with_capacity(rounds as usize);
            let start = Instant::now();
            for _ in 0..rounds {
                let t = Instant::now();
                let vol = crate::volume::Volume::open(backing, OpenMode::ReadOnly)?;
                samples.push(t.elapsed().as_nanos() as u64);
                drop(vol);
            }
            let secs = start.elapsed().as_secs_f64();
            let _ = meta;
            Ok(Measurement::simple(rounds, 0, secs)
                .with_latency(Latency::from_samples(samples))
                .note("Volume::open (scan + validate + index) repeated read-only"))
        }
        Workload::SearchLatency => {
            let ns = Namespace::open(backing, OpenMode::ReadOnly, params.durability)?;
            let root = ns.root();
            let pattern = b"OrFS".to_vec();
            let rounds = 64u64;
            let mut samples = Vec::with_capacity(rounds as usize);
            let start = Instant::now();
            let mut matches = 0u64;
            for _ in 0..rounds {
                let req = QueryRequest::new(crate::index::ROOT_INODE, root, pattern.clone());
                let t = Instant::now();
                let res = ns.query(req)?;
                samples.push(t.elapsed().as_nanos() as u64);
                matches = res.matches.len() as u64;
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(Measurement::simple(rounds, 0, secs)
                .with_latency(Latency::from_samples(samples))
                .note(format!(
                    "typed query API (Namespace::query), pattern \"OrFS\", {matches} match(es) at root {root}; \
                     not an index-backed claim unless a trigram index is present"
                )))
        }
        Workload::SnapshotLatency => {
            let vol = crate::volume::Volume::open(backing, OpenMode::ReadOnly)?;
            let root = vol.log.committed_end_offset();
            drop(vol);
            let rounds = 64u64;
            let mut samples = Vec::with_capacity(rounds as usize);
            let start = Instant::now();
            for _ in 0..rounds {
                let t = Instant::now();
                let snap = Snapshot::open_dir(backing, root)?;
                samples.push(t.elapsed().as_nanos() as u64);
                drop(snap);
            }
            let secs = start.elapsed().as_secs_f64();
            Ok(Measurement::simple(rounds, 0, secs)
                .with_latency(Latency::from_samples(samples))
                .note(format!(
                    "Snapshot::open_dir(root={root}) — pin + read handle construction"
                )))
        }
        Workload::MountTime => Err(OrfsError::InvalidArgument(
            "mount-time is handled by the configuration driver in orfs::bench::run".into(),
        )),
        other => Err(OrfsError::InvalidArgument(format!(
            "{} is not a library workload",
            other.name()
        ))),
    }
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

/// Run one (config, workload) benchmark and return a self-describing report.
///
/// * `backing` is an OrFS volume directory for the mounted/library configs, or a
///   plain directory for [`BenchConfig::Conventional`].
/// * `scratch_root` is where the filesystem workloads create files; for the
///   mounted configs a fresh subdirectory is created under it.
pub fn run(
    backing: &Path,
    scratch_root: &Path,
    config: BenchConfig,
    workload: Workload,
    params: &BenchParams,
    mount_opts: &MountOptions,
    container_image: Option<String>,
) -> Result<BenchReport> {
    let environment = Environment::capture(container_image);
    let base = |measurement: Measurement,
                available: bool,
                reason: Option<String>,
                mount_options: Option<String>| BenchReport {
        schema: BenchReport::SCHEMA,
        generated_by: "src/bench.rs",
        orfs_version: crate::VERSION,
        config,
        config_description: config.describe(),
        config_available: available,
        unavailable_reason: reason,
        workload,
        config_independent: workload.is_library_only(),
        environment: environment.clone(),
        mount_options,
        durability: params.durability.name().to_string(),
        data_size: params.data_bytes,
        params: *params,
        measurement,
    };

    if let Some(reason) = config.unavailable() {
        return Ok(base(
            Measurement::simple(0, 0, 0.0),
            false,
            Some(reason),
            None,
        ));
    }

    if workload.is_library_only() {
        let measurement = match workload {
            Workload::MountTime => {
                // Mount only to time the mount; requires a FUSE-capable config.
                if !config.is_mounted() {
                    return Ok(base(
                        Measurement::simple(0, 0, 0.0),
                        false,
                        Some("mount-time is not applicable to the conventional baseline".into()),
                        None,
                    ));
                }
                std::fs::create_dir_all(scratch_root)?;
                let opts = config.mount_options(mount_opts);
                let t = Instant::now();
                let mount = fuse::spawn(backing, scratch_root, &opts)?;
                let elapsed = t.elapsed().as_secs_f64();
                let desc = mount.transport_description();
                mount.unmount()?;
                Measurement::simple(1, 0, elapsed)
                    .note(format!("negotiated transport: {desc}"))
                    .note("single cold mount; not a warm-repeat figure")
            }
            _ => run_library_workload(backing, workload, params)?,
        };
        let opts = config.mount_options(mount_opts);
        return Ok(base(
            measurement,
            true,
            None,
            Some(format!(
                "transport={} backing_io={} manifest={:?}",
                opts.transport.requested_name(),
                backing_io_name(opts.backing_io),
                opts.manifest.map(|p| p.label())
            )),
        ));
    }

    // Filesystem workloads.
    match config {
        BenchConfig::Conventional => {
            let dir = scratch_root.join(format!("conventional-{}", workload.name()));
            let measurement = run_fs_workload(&dir, workload, params)?;
            let _ = std::fs::remove_dir_all(&dir);
            Ok(base(
                measurement,
                true,
                None,
                Some("plain directory; no mount".into()),
            ))
        }
        _ => {
            std::fs::create_dir_all(scratch_root)?;
            let opts = config.mount_options(mount_opts);
            eprintln!(
                "orfs bench: mounting {} at {}",
                config.name(),
                scratch_root.display()
            );
            let mount = fuse::spawn(backing, scratch_root, &opts)?;
            let desc = mount.transport_description();
            // F2/E2 are only genuinely measured when the native FUSE-over-io_uring
            // session actually engaged; a silent fallback is reported as
            // unavailable with the exact negotiation reason.
            if matches!(config, BenchConfig::F2 | BenchConfig::E2)
                && mount.transport_used() != TransportProfile::F2
            {
                let neg = mount.fuse_uring_negotiation();
                let reason = neg
                    .reason
                    .unwrap_or_else(|| "FUSE-over-io_uring did not engage".into());
                let _ = mount.unmount();
                return Ok(base(
                    Measurement::simple(0, 0, 0.0),
                    false,
                    Some(reason),
                    Some(desc),
                ));
            }
            let dir = scratch_root.join(format!("orfs-{}", workload.name()));
            eprintln!("orfs bench: running {}", workload.name());
            let result = run_fs_workload(&dir, workload, params);
            eprintln!("orfs bench: workload done; unmounting");
            let _ = std::fs::remove_dir_all(&dir);
            let unmount = mount.unmount();
            eprintln!("orfs bench: unmounted");
            let measurement = result?;
            unmount?;
            Ok(base(
                measurement,
                true,
                None,
                Some(format!(
                    "transport={} backing_io={} manifest={:?}; {desc}",
                    opts.transport.requested_name(),
                    backing_io_name(opts.backing_io),
                    opts.manifest.map(|p| p.label())
                )),
            ))
        }
    }
}

fn backing_io_name(io: BackingIo) -> &'static str {
    match io {
        BackingIo::Sync => "sync",
        BackingIo::Uring => "uring",
    }
}
