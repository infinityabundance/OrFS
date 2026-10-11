//! `orfs` command-line interface.
//!
//! Every subcommand in the target surface is present. A command that is part of
//! the design but not yet wired rejects the request explicitly with the owning
//! phase, rather than silently pretending to work. `doctor` is fully real: it
//! reports the actual kernel and container capabilities OrFS depends on.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use orfs::bench::{BenchConfig, BenchParams, Workload};
use orfs::commit::DurabilityMode;
use orfs::fuse::{self, BackingIo, MountOptions, StatfsMode, Transport};
use orfs::log::{scan_log, OpenMode, TailInfo, DEFAULT_SEGMENT_SIZE};
use orfs::manifestation::{ManifestationConfig, ManifestationProfile, ManifestationStatus};
use orfs::namespace::SnapshotRootPayload;
use orfs::query::QueryRequest;
use orfs::record::{record_type_name, RecordType};
use orfs::segment::{segment_file_name, SegmentExtent};
use orfs::trigram::TrigramConfig;
use orfs::volume::Volume;
use orfs::{checkpoint, OrfsError, Result};

#[derive(Parser, Debug)]
#[command(
    name = "orfs",
    version,
    about = "OrFS — non-withdrawal, concealed-expansion FUSE filesystem",
    long_about = None,
    arg_required_else_help = true
)]
struct Cli {
    /// Emit machine-readable JSON where the command supports it.
    #[arg(long, global = true)]
    json: bool,

    /// Increase log verbosity (repeatable).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create and initialise a new backing volume.
    Init {
        /// Backing directory to create.
        backing: PathBuf,
        /// Segment size policy in bytes (default 64 MiB).
        #[arg(long)]
        segment_size: Option<u64>,
    },

    /// Mount a backing volume through FUSE.
    Mount {
        /// Backing directory produced by `orfs init`.
        backing: PathBuf,
        /// Mount point.
        mountpoint: PathBuf,
        /// Transport profile: fuse | fuse-uring.
        #[arg(long, default_value = "fuse")]
        transport: String,
        /// Backing I/O engine: sync | uring.
        #[arg(long, default_value = "uring")]
        backing_io: String,
        /// Opt in to FUSE-over-io_uring zero-copy (requires CAP_SYS_ADMIN and
        /// `--transport fuse-uring`; never required for ordinary mounts).
        #[arg(long)]
        zero_copy: bool,
        /// Durability profile: ordered | sync | batched.
        #[arg(long, default_value = "ordered")]
        durability: String,
        /// Bypass the kernel page cache (`FOPEN_DIRECT_IO`).
        #[arg(long)]
        direct_io: bool,
        /// Kernel readahead in KiB (0 keeps the kernel default).
        #[arg(long, default_value_t = 128)]
        readahead_kb: u32,
        /// Maximum size of a single kernel write, in KiB.
        #[arg(long, default_value_t = 128)]
        max_write_kb: u32,
        /// Attribute cache TTL in milliseconds.
        #[arg(long, default_value_t = 1000)]
        attr_ttl_ms: u64,
        /// Directory-entry cache TTL in milliseconds.
        #[arg(long, default_value_t = 1000)]
        entry_ttl_ms: u64,
        /// Delegate permission checks to the kernel (`default_permissions`).
        #[arg(long)]
        default_permissions: bool,
        /// Allow access by other users (`allow_other`).
        #[arg(long)]
        allow_other: bool,
        /// Unmount automatically when the daemon exits.
        #[arg(long)]
        auto_unmount: bool,
        /// Mount read-only.
        #[arg(long)]
        read_only: bool,
        /// `statfs` accounting: physical-safe | plenum.
        #[arg(long, default_value = "physical-safe")]
        statfs: String,
        /// Enable concealed manifestation for eligible objects (profile name).
        #[arg(long)]
        manifest: Option<String>,
        /// Wait for the optional manifestation before acknowledging a write.
        #[arg(long)]
        manifest_sync: bool,
        /// Manifestation worker threads (0 selects the CPU count).
        #[arg(long, default_value_t = 0)]
        manifest_workers: usize,
    },

    /// Unmount a mounted OrFS volume.
    Unmount {
        /// Mount point.
        mountpoint: PathBuf,
    },

    /// Inspect backing-volume metadata and committed roots.
    Inspect {
        /// Backing directory.
        backing: PathBuf,
    },

    /// Report filesystem/backing statistics.
    Stat {
        /// Backing directory or mount point.
        path: PathBuf,
    },

    /// Verify authoritative structure and (optionally) deeper invariants.
    Verify {
        /// Backing directory.
        backing: PathBuf,
        /// Perform deep verification (record checksums, replay equivalence).
        #[arg(long)]
        deep: bool,
    },

    /// Recover a backing volume (read-only analysis by default).
    Recover {
        /// Backing directory.
        backing: PathBuf,
    },

    /// Historical snapshot operations.
    Snapshot {
        #[command(subcommand)]
        cmd: SnapshotCommand,
    },

    /// Manifest EKBLOOM acceleration structures for an eligible object.
    Manifest {
        /// Backing directory (an OrFS volume).
        backing: PathBuf,
        /// Manifest only this inode (default: every eligible regular file).
        #[arg(long)]
        inode: Option<u64>,
        /// Manifestation profile: root|sparse|dense|full|bloom4|bloom8|regional|path4|max-speed.
        #[arg(long, default_value = "bloom4")]
        profile: String,
        /// Bloom depth for depth-bearing profiles.
        #[arg(long)]
        depth: Option<u16>,
        /// Checkpoint interval for sparse/dense profiles.
        #[arg(long)]
        interval: Option<u32>,
        /// Region size in bytes for the regional profile.
        #[arg(long)]
        region_bytes: Option<u32>,
    },

    /// Expand the manifested physical body of a volume (concealed expansion).
    Grow {
        /// Backing directory.
        backing: PathBuf,
        /// Manifestation profile to grow toward.
        #[arg(long, default_value = "max-speed")]
        profile: String,
        /// Bloom depth for depth-bearing profiles.
        #[arg(long)]
        depth: Option<u16>,
        /// Checkpoint interval for sparse/dense profiles.
        #[arg(long)]
        interval: Option<u32>,
        /// Region size in bytes for the regional profile.
        #[arg(long)]
        region_bytes: Option<u32>,
    },

    /// Search file contents through the typed query API.
    Query {
        /// Path to search: a backing volume, or any path inside one.
        path: PathBuf,
        /// Literal byte pattern to find.
        #[arg(long)]
        pattern: String,
        /// Interpret `--pattern` as a hex string (for binary patterns).
        #[arg(long)]
        hex: bool,
        /// Maximum number of matches to report (0 = unlimited).
        #[arg(long, default_value_t = 0)]
        limit: u64,
        /// Build/refresh the concealed trigram index before querying.
        #[arg(long)]
        build: bool,
        /// Do not recurse into subdirectories.
        #[arg(long)]
        no_recurse: bool,
    },

    /// Run the benchmark harness.
    Bench {
        /// Backing directory (an OrFS volume, or a plain directory for
        /// `--config conventional`).
        backing: PathBuf,
        /// Workload selector.
        #[arg(long, default_value = "random-read-4k")]
        workload: String,
        /// Configuration: conventional | f0 | f1 | f2 | e1 | e2.
        #[arg(long, default_value = "conventional")]
        config: String,
        /// Output JSON path.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Logical data size for bulk workloads, in bytes.
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        data_bytes: u64,
        /// Operation count for latency/IOPS workloads.
        #[arg(long, default_value_t = 20_000)]
        iterations: u64,
        /// Concurrent reader threads.
        #[arg(long, default_value_t = 4)]
        readers: usize,
        /// Region/record size for random I/O, in bytes.
        #[arg(long, default_value_t = 4096)]
        region_bytes: u64,
        /// Durability profile exercised by write/fsync workloads.
        #[arg(long, default_value = "ordered")]
        durability: String,
        /// Drop the page cache before reads (cold-cache control; also enables
        /// `FOPEN_DIRECT_IO` for the mounted configurations).
        #[arg(long)]
        cold: bool,
    },

    /// Report real kernel and container capabilities.
    Doctor,
}

#[derive(Subcommand, Debug)]
enum SnapshotCommand {
    /// List committed roots available as snapshots.
    List {
        /// Backing directory.
        backing: PathBuf,
    },
    /// Inspect a historical root.
    Inspect {
        /// Backing directory.
        backing: PathBuf,
        /// Historical root (committed end offset).
        root: u64,
    },
    /// Mount a historical root read-only.
    Mount {
        /// Backing directory.
        backing: PathBuf,
        /// Historical root (committed end offset).
        root: u64,
        /// Read-only mount point.
        mountpoint: PathBuf,
        /// Disable kernel FUSE passthrough (enabled by default for snapshots;
        /// falls back automatically when it cannot engage).
        #[arg(long)]
        no_passthrough: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("orfs: {err}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::Doctor => doctor(cli.json),
        Command::Init {
            backing,
            segment_size,
        } => init(backing, *segment_size, cli.json),
        Command::Mount {
            backing,
            mountpoint,
            transport,
            backing_io,
            zero_copy,
            durability,
            direct_io,
            readahead_kb,
            max_write_kb,
            attr_ttl_ms,
            entry_ttl_ms,
            default_permissions,
            allow_other,
            auto_unmount,
            read_only,
            statfs,
            manifest,
            manifest_sync,
            manifest_workers,
        } => mount_cmd(MountArgs {
            backing,
            mountpoint,
            transport,
            backing_io,
            zero_copy: *zero_copy,
            durability,
            direct_io: *direct_io,
            readahead_kb: *readahead_kb,
            max_write_kb: *max_write_kb,
            attr_ttl_ms: *attr_ttl_ms,
            entry_ttl_ms: *entry_ttl_ms,
            default_permissions: *default_permissions,
            allow_other: *allow_other,
            auto_unmount: *auto_unmount,
            read_only: *read_only,
            statfs,
            manifest: manifest.as_deref(),
            manifest_sync: *manifest_sync,
            manifest_workers: *manifest_workers,
        }),
        Command::Unmount { mountpoint } => unmount_cmd(mountpoint, cli.json),
        Command::Inspect { backing } => inspect(backing, cli.json),
        Command::Stat { path } => stat_cmd(path, cli.json),
        Command::Verify { backing, deep } => verify(backing, *deep, cli.json),
        Command::Recover { backing } => recover(backing, cli.json),
        Command::Snapshot { cmd } => match cmd {
            SnapshotCommand::List { backing } => snapshot_list(backing, cli.json),
            SnapshotCommand::Inspect { backing, root } => {
                snapshot_inspect(backing, *root, cli.json)
            }
            SnapshotCommand::Mount {
                backing,
                root,
                mountpoint,
                no_passthrough,
            } => snapshot_mount_cmd(backing, *root, mountpoint, !*no_passthrough),
        },
        Command::Manifest {
            backing,
            inode,
            profile,
            depth,
            interval,
            region_bytes,
        } => {
            let profile = ManifestationProfile::parse(profile, *depth, *interval, *region_bytes)?;
            manifest_cmd(backing, *inode, profile, cli.json)
        }
        Command::Grow {
            backing,
            profile,
            depth,
            interval,
            region_bytes,
        } => {
            let profile = ManifestationProfile::parse(profile, *depth, *interval, *region_bytes)?;
            manifest_cmd(backing, None, profile, cli.json)
        }
        Command::Query {
            path,
            pattern,
            hex,
            limit,
            build,
            no_recurse,
        } => query_cmd(path, pattern, *hex, *limit, *build, *no_recurse, cli.json),
        Command::Bench {
            backing,
            workload,
            config,
            output,
            data_bytes,
            iterations,
            readers,
            region_bytes,
            durability,
            cold,
        } => bench_cmd(
            backing,
            config,
            workload,
            output.as_deref(),
            *data_bytes,
            *iterations,
            *readers,
            *region_bytes,
            durability,
            *cold,
            cli.json,
        ),
    }
}

// ---------------------------------------------------------------------------
// bench (performance harness, research §30–§32)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn bench_cmd(
    backing: &Path,
    config: &str,
    workload: &str,
    output: Option<&Path>,
    data_bytes: u64,
    iterations: u64,
    readers: usize,
    region_bytes: u64,
    durability: &str,
    cold: bool,
    json: bool,
) -> Result<()> {
    let config = BenchConfig::parse(config)?;
    let workload = Workload::parse(workload)?;
    let durability = DurabilityMode::parse(durability)?;
    let params = BenchParams {
        data_bytes,
        iterations,
        readers,
        region_bytes,
        durability,
        cold_cache: cold,
    };
    let base = MountOptions {
        durability,
        direct_io: cold,
        ..Default::default()
    };
    let image = std::env::var("ORFS_IMAGE").ok();
    let scratch = std::env::temp_dir().join(format!("orfs-bench-{}", std::process::id()));
    std::fs::create_dir_all(&scratch)?;
    let report = orfs::bench::run(backing, &scratch, config, workload, &params, &base, image)?;
    if let Some(path) = output {
        report.write_json(path)?;
        eprintln!("orfs: wrote {}", path.display());
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else if report.config_available {
        let m = &report.measurement;
        println!(
            "{} / {}: {} op(s) in {:.6}s = {:.1} op/s, {:.1} MB/s{}",
            report.config.name(),
            report.workload.name(),
            m.ops,
            m.seconds,
            m.ops_per_s,
            m.mb_per_s,
            m.latency
                .as_ref()
                .map(|l| format!(", p50={}ns p95={}ns p99={}ns", l.p50_ns, l.p95_ns, l.p99_ns))
                .unwrap_or_default(),
        );
        for n in &m.notes {
            println!("  note: {n}");
        }
    } else {
        println!(
            "{} / {}: UNAVAILABLE — {}",
            report.config.name(),
            report.workload.name(),
            report.unavailable_reason.as_deref().unwrap_or("unknown"),
        );
    }
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(())
}

// ---------------------------------------------------------------------------
// stat (physical accounting, research §33)
// ---------------------------------------------------------------------------

fn stat_cmd(path: &Path, json: bool) -> Result<()> {
    let acc = orfs::stats::account_path(path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&acc).unwrap());
        return Ok(());
    }
    println!("OrFS physical accounting for {}", path.display());
    if let Some(uuid) = &acc.uuid {
        println!("  volume uuid:            {uuid}");
    }
    println!("  committed root:         {}", acc.committed_root);
    println!("  logical live bytes:     {}", acc.logical_live_bytes);
    println!("  logical files:          {}", acc.logical_file_count);
    println!("  logical directories:    {}", acc.logical_directory_count);
    println!("  logical symlinks:       {}", acc.logical_symlink_count);
    println!("  authoritative history:  {} bytes (M_log)", acc.m_log);
    println!(
        "    canonical:            {} bytes",
        acc.authoritative_canonical_bytes
    );
    println!(
        "    uncommitted tail:     {} bytes",
        acc.uncommitted_tail_bytes
    );
    println!(
        "  EKBLOOM manifested:     {} bytes (M_ekbloom)",
        acc.m_ekbloom
    );
    println!(
        "  indexes/search:         {} bytes (M_indexes)",
        acc.m_indexes
    );
    println!(
        "  passthrough images:     {} bytes (M_passthrough)",
        acc.m_passthrough
    );
    println!(
        "  replay accelerators:    {} bytes (M_checkpoints; embedded in or.log)",
        acc.m_checkpoints
    );
    println!(
        "  other:                  {} bytes (M_other; manifests + metadata)",
        acc.m_other
    );
    println!("  total physical:         {} bytes (M_total)", acc.m_total);
    println!(
        "  physical overhead:      {} bytes over live logical",
        acc.physical_overhead_bytes
    );
    println!(
        "  manifested generations: {} across {} inode(s)",
        acc.manifested_generations, acc.manifested_inodes
    );
    match acc.capacity {
        Some(c) => {
            println!("  backing total:          {} bytes", c.total_bytes);
            println!("  backing available:      {} bytes", c.available_bytes);
        }
        None => println!("  backing capacity:       unavailable"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// query (typed query API, research §11.1, §12)
// ---------------------------------------------------------------------------

/// Walk up from `path` to the volume root (the directory containing
/// `volume.meta`), returning the root and the in-volume path components.
fn resolve_volume_path(path: &Path) -> Result<(PathBuf, Vec<Vec<u8>>)> {
    let mut cur = path.to_path_buf();
    let mut comps: Vec<Vec<u8>> = Vec::new();
    loop {
        if cur.join("volume.meta").exists() {
            comps.reverse();
            return Ok((cur, comps));
        }
        let name = cur.file_name().map(|n| n.as_bytes().to_vec());
        let parent = cur.parent().map(|p| p.to_path_buf());
        match (name, parent) {
            (Some(name), Some(parent)) if parent != cur => {
                comps.push(name);
                cur = parent;
            }
            _ => break,
        }
    }
    Err(OrfsError::InvalidArgument(format!(
        "{} is not inside an OrFS volume (no volume.meta ancestor)",
        path.display()
    )))
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .trim()
        .strip_prefix("0x")
        .unwrap_or(s.trim())
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.len() % 2 != 0 {
        return Err(OrfsError::InvalidArgument(
            "hex pattern must have an even number of digits".into(),
        ));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| OrfsError::InvalidArgument("invalid hex digit".into()))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| OrfsError::InvalidArgument("invalid hex digit".into()))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn query_cmd(
    path: &Path,
    pattern: &str,
    hex_pattern: bool,
    limit: u64,
    build: bool,
    no_recurse: bool,
    json: bool,
) -> Result<()> {
    let pattern = if hex_pattern {
        decode_hex(pattern)?
    } else {
        pattern.as_bytes().to_vec()
    };
    if pattern.is_empty() {
        return Err(OrfsError::InvalidArgument(
            "query pattern must be non-empty".into(),
        ));
    }
    let (backing, comps) = resolve_volume_path(path)?;
    let mut ns =
        orfs::namespace::Namespace::open(&backing, OpenMode::ReadOnly, DurabilityMode::Ordered)?;
    let root = ns.root();
    let mut inode = ns.root_inode();
    for comp in &comps {
        inode = ns.lookup(inode, comp, root)?;
    }

    // Generation: either build/refresh the concealed index synchronously, or
    // simply attach the recovered state. A query never *requires* an index.
    let index_note = if build {
        ns.enable_trigram(TrigramConfig {
            synchronous: true,
            ..Default::default()
        })?;
        let is_file = ns
            .getattr(inode, root)
            .map(|st| st.kind == orfs::inode::InodeType::File)
            .unwrap_or(false);
        let outcomes = ns.index_trigram_eligible(if is_file { Some(inode) } else { None })?;
        let published = outcomes.iter().filter(|o| o.status == "published").count();
        Some(format!(
            "indexed {published}/{} object(s) synchronously",
            outcomes.len()
        ))
    } else {
        let recovered = ns.attach_trigram()?;
        Some(format!(
            "attached {recovered} committed trigram generation(s)"
        ))
    };

    let request = QueryRequest {
        inode,
        root,
        pattern,
        limit: if limit == 0 { None } else { Some(limit) },
        recursive: !no_recurse,
        credential: Default::default(),
    };
    let result = ns.query(request)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        return Ok(());
    }
    println!(
        "orfs query {}: {} match(es) for pattern 0x{}",
        path.display(),
        result.matches.len(),
        result.pattern_hex
    );
    if let Some(note) = index_note {
        println!("  {note}");
    }
    for m in &result.matches {
        println!(
            "    inode {} v{} at offset {}",
            m.inode, m.inode_version, m.offset
        );
    }
    println!(
        "  files: {} considered ({} indexed, {} scanned, {} unreadable); \
         candidates {} ({} false); content read {} bytes{}{}",
        result.stats.files_considered,
        result.stats.files_indexed,
        result.stats.files_scanned,
        result.stats.files_skipped_unreadable,
        result.stats.indexed_candidates,
        result.stats.false_candidates,
        result.stats.content_bytes_read,
        if result.stats.limit_reached {
            "; limit reached"
        } else {
            ""
        },
        if result.stats.canceled {
            "; canceled"
        } else {
            ""
        },
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// manifest / grow (concealed manifestation, research §9, §10)
// ---------------------------------------------------------------------------

fn manifest_cmd(
    backing: &Path,
    inode: Option<u64>,
    profile: ManifestationProfile,
    json: bool,
) -> Result<()> {
    let mut ns =
        orfs::namespace::Namespace::open(backing, OpenMode::ReadOnly, DurabilityMode::Ordered)?;
    let cfg = ManifestationConfig {
        profile,
        synchronous: true,
        ..Default::default()
    };
    let report = ns.enable_manifestation(cfg)?;
    let outcomes = ns.manifest_eligible(inode, profile)?;
    let manifests: Vec<serde_json::Value> = ns
        .manifestation_state()
        .map(|s| s.published().iter().map(|m| m.to_json()).collect())
        .unwrap_or_default();
    let published = outcomes
        .iter()
        .filter(|o| o.status == ManifestationStatus::Published)
        .count();
    let failed = outcomes
        .iter()
        .filter(|o| o.status == ManifestationStatus::Failed)
        .count();

    if json {
        let out = serde_json::json!({
            "schema": "orfs.manifest.v1",
            "volume": backing.display().to_string(),
            "profile": report.profile,
            "backend": report.backend,
            "ekbloom_version": report.ekbloom_version,
            "workers": report.workers,
            "recovered_generations": report.recovered_generations,
            "recovered_rejected": report.recovered_rejected,
            "attempted": outcomes.len(),
            "published": published,
            "failed": failed,
            "outcomes": outcomes.iter().map(|o| serde_json::json!({
                "inode": o.inode,
                "inode_version": o.inode_version,
                "status": o.status.name(),
                "generation": o.generation,
                "physical_bytes": o.physical_bytes,
                "profile": o.profile,
                "detail": o.detail,
            })).collect::<Vec<_>>(),
            "manifests": manifests,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(());
    }
    println!(
        "manifested {} (profile {})",
        backing.display(),
        report.profile
    );
    println!(
        "  backend:                {} (EKBLOOM {})",
        report.backend, report.ekbloom_version
    );
    println!("  workers:                {}", report.workers);
    println!(
        "  recovered generations:  {} ({} rejected)",
        report.recovered_generations, report.recovered_rejected
    );
    println!("  attempted:              {}", outcomes.len());
    for o in &outcomes {
        let gen = match o.generation {
            Some(g) => format!("gen {g}, "),
            None => String::new(),
        };
        let tail = if o.physical_bytes > 0 {
            format!("{} bytes", o.physical_bytes)
        } else {
            o.detail.clone().unwrap_or_default()
        };
        println!(
            "    inode {} v{} -> {status} ({gen}{tail})",
            o.inode,
            o.inode_version,
            status = o.status.name()
        );
    }
    println!("  published:              {published} ({failed} failed)");
    Ok(())
}

// ---------------------------------------------------------------------------
// mount / unmount
// ---------------------------------------------------------------------------

/// Parsed arguments for `orfs mount`.
struct MountArgs<'a> {
    backing: &'a PathBuf,
    mountpoint: &'a PathBuf,
    transport: &'a str,
    backing_io: &'a str,
    zero_copy: bool,
    durability: &'a str,
    direct_io: bool,
    readahead_kb: u32,
    max_write_kb: u32,
    attr_ttl_ms: u64,
    entry_ttl_ms: u64,
    default_permissions: bool,
    allow_other: bool,
    auto_unmount: bool,
    read_only: bool,
    statfs: &'a str,
    manifest: Option<&'a str>,
    manifest_sync: bool,
    manifest_workers: usize,
}

fn mount_cmd(args: MountArgs<'_>) -> Result<()> {
    let transport = Transport::parse(args.transport)?;
    let backing_io = BackingIo::parse(args.backing_io)?;
    let durability = DurabilityMode::parse(args.durability)?;
    let statfs = match args.statfs {
        "physical-safe" | "physical" => StatfsMode::PhysicalSafe,
        "plenum" | "logical-plenum" => StatfsMode::LogicalPlenum,
        other => {
            return Err(OrfsError::InvalidArgument(format!(
                "unknown statfs mode {other:?} (expected physical-safe|plenum)"
            )))
        }
    };
    let manifest = match args.manifest {
        Some(p) => Some(ManifestationProfile::parse(p, None, None, None)?),
        None => None,
    };

    // FUSE-over-io_uring (F2): the decisive statement is the live INIT
    // negotiation performed during the mount; report the static preconditions and
    // any provable blocker up front so the outcome is never a surprise. Falling
    // back changes no filesystem contents.
    if transport.requests_uring_fuse() {
        let report = orfs::fuse_uring::discover_report();
        match &report.preconditions {
            Ok(()) => eprintln!(
                "orfs: FUSE-over-io_uring requested; preconditions hold — the live \
                 INIT negotiation will decide whether F2 actually engages"
            ),
            Err(reason) => eprintln!(
                "orfs: warning: FUSE-over-io_uring unavailable ({reason}); \
                 falling back to the classical /dev/fuse transport"
            ),
        }
    }
    if args.zero_copy {
        if !transport.requests_uring_fuse() {
            return Err(OrfsError::InvalidArgument(
                "--zero-copy requires --transport fuse-uring (F2)".into(),
            ));
        }
        if !orfs::fuse_uring::has_cap_sys_admin() {
            return Err(OrfsError::Unsupported(
                "--zero-copy requires CAP_SYS_ADMIN".into(),
            ));
        }
    }

    if backing_io == BackingIo::Uring {
        // Report whether io_uring can actually engage, honestly. The real
        // engagement happens inside `fuse::run`, which prints the same truth.
        match orfs::uring::probe_available() {
            Ok(()) => eprintln!("orfs: io_uring backing I/O is available"),
            Err(reason) => eprintln!(
                "orfs: warning: io_uring unavailable ({reason}); \
                 falling back to synchronous backing I/O"
            ),
        }
    }
    if !args.mountpoint.is_dir() {
        return Err(OrfsError::InvalidArgument(format!(
            "mount point {} is not an existing directory",
            args.mountpoint.display()
        )));
    }

    let opts = MountOptions {
        durability,
        read_only: args.read_only,
        transport,
        backing_io,
        zero_copy: args.zero_copy,
        direct_io: args.direct_io,
        readahead_kb: args.readahead_kb,
        max_write_kb: args.max_write_kb,
        attr_ttl: Duration::from_millis(args.attr_ttl_ms),
        entry_ttl: Duration::from_millis(args.entry_ttl_ms),
        default_permissions: args.default_permissions,
        allow_other: args.allow_other,
        auto_unmount: args.auto_unmount,
        statfs,
        passthrough: false,
        manifest,
        manifest_sync: args.manifest_sync,
        manifest_workers: args.manifest_workers,
    };

    eprintln!(
        "orfs: mounting {} at {} (transport={}, durability={durability:?}, \
         backing_io={:?}, direct_io={}, readahead_kb={}); run `orfs unmount {}`",
        args.backing.display(),
        args.mountpoint.display(),
        transport.requested_name(),
        backing_io,
        opts.direct_io,
        opts.readahead_kb,
        args.mountpoint.display(),
    );
    fuse::run(args.backing, args.mountpoint, &opts)
}

fn unmount_cmd(mountpoint: &Path, json: bool) -> Result<()> {
    fuse::unmount(mountpoint)?;
    if json {
        println!(
            "{}",
            serde_json::json!({ "unmounted": mountpoint.display().to_string() })
        );
    } else {
        println!("unmounted {}", mountpoint.display());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// snapshot: list / inspect / mount
// ---------------------------------------------------------------------------

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// List the committed roots available as snapshots: the current committed root,
/// the named `SNAPSHOT_ROOT` publications, and the `INDEX_CHECKPOINT` records.
///
/// Every committed transaction boundary is a valid snapshot root (research §2,
/// I3); this command lists the *named* and *checkpointed* ones and reports the
/// total boundary count.
fn snapshot_list(backing: &Path, json: bool) -> Result<()> {
    let vol = Volume::open(backing, OpenMode::ReadOnly)?;
    let committed = vol.log.committed_end_offset();

    let named_raw = vol
        .log
        .scan_records_of_types(committed, &[RecordType::SnapshotRoot])?;
    let mut named = Vec::new();
    for r in &named_raw {
        let p = SnapshotRootPayload::decode(&r.payload)?;
        named.push(serde_json::json!({
            "name": String::from_utf8_lossy(&p.name).to_string(),
            "root": p.root,
            "record_offset": r.offset,
        }));
    }

    let checkpoints = checkpoint::discover_checkpoints(&vol.log, committed)?;
    let checkpoint_json: Vec<serde_json::Value> = checkpoints
        .iter()
        .map(|c| {
            serde_json::json!({
                "record_offset": c.offset,
                "payload_bytes": c.raw_len,
                "valid": c.payload.is_some(),
                "root": c.root(),
            })
        })
        .collect();

    if json {
        let out = serde_json::json!({
            "schema": "orfs.snapshot.list.v1",
            "volume": backing.display().to_string(),
            "uuid": vol.meta.uuid_string(),
            "committed_root": committed,
            "transaction_boundaries": vol.log.boundaries().len(),
            "named_snapshots": named,
            "checkpoints": checkpoint_json,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(());
    }

    println!("volume {} ({})", backing.display(), vol.meta.uuid_string());
    println!("  committed root:         {committed}");
    println!(
        "  transaction boundaries: {} (every boundary is a valid snapshot root)",
        vol.log.boundaries().len()
    );
    if named.is_empty() {
        println!("  named snapshots:        none");
    } else {
        println!("  named snapshots:");
        for n in &named {
            println!(
                "    {} -> root {} (record offset {})",
                n["name"].as_str().unwrap_or(""),
                n["root"],
                n["record_offset"]
            );
        }
    }
    if checkpoint_json.is_empty() {
        println!("  index checkpoints:      none");
    } else {
        println!("  index checkpoints:");
        for c in &checkpoint_json {
            println!(
                "    record offset {} -> {} ({} bytes, valid={})",
                c["record_offset"], c["root"], c["payload_bytes"], c["valid"]
            );
        }
    }
    Ok(())
}

/// Inspect a historical root: reconstruct its namespace state and report the
/// identity and summary, plus the top-level entries as of that root.
fn snapshot_inspect(backing: &Path, root: u64, json: bool) -> Result<()> {
    let snap = orfs::snapshot::Snapshot::open_dir(backing, root)?;
    let identity = snap.identity();
    let entries = snap.readdir(orfs::index::ROOT_INODE).unwrap_or_default();
    let entries_json: Vec<serde_json::Value> = entries
        .iter()
        .map(|(name, child)| {
            let st = snap.getattr(*child).ok();
            serde_json::json!({
                "name": String::from_utf8_lossy(name).to_string(),
                "inode": child,
                "kind": st.as_ref().map(|s| format!("{:?}", s.kind).to_lowercase()),
                "size": st.as_ref().map(|s| s.size),
            })
        })
        .collect();

    // Named snapshots that point at this root.
    let vol = Volume::open(backing, OpenMode::ReadOnly)?;
    let mut names = Vec::new();
    for r in vol
        .log
        .scan_records_of_types(vol.log.committed_end_offset(), &[RecordType::SnapshotRoot])?
    {
        if let Ok(p) = SnapshotRootPayload::decode(&r.payload) {
            if p.root == root {
                names.push(String::from_utf8_lossy(&p.name).to_string());
            }
        }
    }

    if json {
        let out = serde_json::json!({
            "schema": "orfs.snapshot.inspect.v1",
            "reference": identity.to_string(),
            "uuid": identity.uuid_string(),
            "root": root,
            "read_only": true,
            "is_committed_boundary": vol.log.is_boundary(root),
            "inode_count": snap.index().inode_count(),
            "dentry_count": snap.index().dentry_count(),
            "index_digest_blake3": hex32(&snap.index().canonical_digest()),
            "named_at_root": names,
            "entries": entries_json,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(());
    }

    println!("snapshot {identity}");
    println!("  root:          {root}");
    println!("  committed:     {}", vol.log.is_boundary(root));
    println!("  read-only:     true");
    println!("  inodes:        {}", snap.index().inode_count());
    println!("  dentries:      {}", snap.index().dentry_count());
    println!(
        "  index digest:  {}",
        hex32(&snap.index().canonical_digest())
    );
    if !names.is_empty() {
        println!("  named:         {}", names.join(", "));
    }
    println!("  top-level entries:");
    for e in &entries_json {
        println!(
            "    {} (inode {}, kind {}, size {})",
            e["name"].as_str().unwrap_or(""),
            e["inode"],
            e["kind"],
            e["size"]
        );
    }
    Ok(())
}

/// Mount a historical root read-only through FUSE.
fn snapshot_mount_cmd(
    backing: &Path,
    root: u64,
    mountpoint: &Path,
    passthrough: bool,
) -> Result<()> {
    if !mountpoint.is_dir() {
        return Err(OrfsError::InvalidArgument(format!(
            "mount point {} is not an existing directory",
            mountpoint.display()
        )));
    }
    let opts = MountOptions {
        read_only: true,
        durability: DurabilityMode::Ordered,
        statfs: StatfsMode::PhysicalSafe,
        passthrough,
        ..Default::default()
    };
    eprintln!(
        "orfs: mounting snapshot root {root} of {} at {} (read-only, \
         passthrough={passthrough}); press Ctrl-C or run `orfs unmount {}`",
        backing.display(),
        mountpoint.display(),
        mountpoint.display(),
    );
    fuse::run_snapshot(backing, mountpoint, root, &opts)
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

fn init(backing: &Path, segment_size: Option<u64>, json: bool) -> Result<()> {
    let segment_size = segment_size.unwrap_or(DEFAULT_SEGMENT_SIZE);
    let vol = Volume::init(backing, segment_size)?;
    if json {
        let out = serde_json::json!({
            "volume": backing.display().to_string(),
            "uuid": vol.meta.uuid_string(),
            "format_version": vol.meta.format_version,
            "created_at_unix_secs": vol.meta.created_at_unix_secs,
            "segment_size": vol.meta.segment_size,
            "genesis_root": vol.log.committed_end_offset(),
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(());
    }
    println!("initialized OrFS volume at {}", backing.display());
    println!("  uuid:           {}", vol.meta.uuid_string());
    println!("  format version: {}", vol.meta.format_version);
    println!("  segment size:   {} bytes", vol.meta.segment_size);
    println!("  genesis root:   {}", vol.log.committed_end_offset());
    Ok(())
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

fn segment_physical_len(dir: &Path, id: u64) -> u64 {
    let path = dir.join(segment_file_name(id).unwrap_or_default());
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() {
                    total += dir_size(&entry.path());
                } else {
                    total += meta.len();
                }
            }
        }
    }
    total
}

fn type_counts_json(log: &orfs::log::Log) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (code, count) in log.record_counts_by_type() {
        map.insert(record_type_name(*code), serde_json::json!(count));
    }
    serde_json::Value::Object(map)
}

fn tail_json(tail: Option<TailInfo>) -> serde_json::Value {
    match tail {
        Some(t) => serde_json::json!({
            "kind": t.kind,
            "segment_id": t.segment_id,
            "boundary_offset": t.boundary_offset,
            "physical_end": t.physical_end,
            "abandoned_bytes": t.abandoned_bytes,
        }),
        None => serde_json::Value::Null,
    }
}

fn inspect(backing: &Path, json: bool) -> Result<()> {
    let vol = Volume::open(backing, OpenMode::ReadOnly)?;
    let log = &vol.log;
    let log_dir = Volume::log_dir(backing);
    let segments: Vec<SegmentExtent> = log.extents().to_vec();
    let m_log = dir_size(&log_dir);
    let m_index = dir_size(&backing.join("index"));
    let m_bloom = dir_size(&backing.join(".or_bloom"));

    if json {
        let segs: Vec<serde_json::Value> = segments
            .iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id,
                    "valid_len": e.valid_len,
                    "physical_len": segment_physical_len(&log_dir, e.id),
                })
            })
            .collect();
        let out = serde_json::json!({
            "volume": backing.display().to_string(),
            "uuid": vol.meta.uuid_string(),
            "format_version": vol.meta.format_version,
            "created_at_unix_secs": vol.meta.created_at_unix_secs,
            "segment_size": vol.meta.segment_size,
            "committed_root": log.committed_end_offset(),
            "committed_record_count": log.committed_record_count(),
            "record_count": log.record_count(),
            "transaction_count": log.transaction_count(),
            "boundaries": log.boundaries(),
            "canonical_bytes": log.canonical_bytes(),
            "segments": segs,
            "records_by_type": type_counts_json(log),
            "tail": tail_json(log.tail()),
            "accounting": {
                "m_log": m_log,
                "m_indexes": m_index,
                "m_bloom": m_bloom,
                "m_total": m_log + m_index + m_bloom,
            },
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(());
    }

    println!("OrFS volume {}", backing.display());
    println!("  uuid:                   {}", vol.meta.uuid_string());
    println!("  format version:         {}", vol.meta.format_version);
    println!(
        "  created at (unix secs): {}",
        vol.meta.created_at_unix_secs
    );
    println!("  segment size policy:    {} bytes", vol.meta.segment_size);
    println!("  committed root R:       {}", log.committed_end_offset());
    println!("  committed records:      {}", log.committed_record_count());
    println!("  committed transactions: {}", log.transaction_count());
    println!("  published boundaries:   {}", log.boundaries().len());
    println!("  total framed records:   {}", log.record_count());
    println!("  canonical log bytes:    {}", log.canonical_bytes());
    println!("  segments:               {}", segments.len());
    for e in &segments {
        println!(
            "    {:016}.seg  valid={} physical={}",
            e.id,
            e.valid_len,
            segment_physical_len(&log_dir, e.id)
        );
    }
    println!("  records by type:");
    for (code, count) in log.record_counts_by_type() {
        println!("    {:<20} {}", record_type_name(*code), count);
    }
    match log.tail() {
        Some(t) => println!(
            "  tail: {:?} at offset {} ({} bytes retained, not canonical)",
            t.kind, t.boundary_offset, t.abandoned_bytes
        ),
        None => println!("  tail: none (clean)"),
    }
    println!("  accounting:");
    println!("    M_log (or.log):     {} bytes", m_log);
    println!("    M_indexes:          {} bytes", m_index);
    println!("    M_bloom:            {} bytes", m_bloom);
    println!(
        "    M_total:            {} bytes",
        m_log + m_index + m_bloom
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn verify(backing: &Path, deep: bool, json: bool) -> Result<()> {
    let vol = Volume::open(backing, OpenMode::ReadOnly)?;
    let mut report = vol.verify(deep)?;
    if deep {
        // Plane B: rebuild the derived namespace index from the log twice and
        // confirm it is deterministic (the log is the only source of truth).
        let root = vol.log.committed_end_offset();
        let a = orfs::index::Index::from_log(&vol.log, root)?;
        let b = orfs::index::Index::from_log(&vol.log, root)?;
        let deterministic = a == b;
        report.checks.push(orfs::volume::VerifyCheck {
            name: "namespace_index_rebuild".to_string(),
            ok: deterministic,
            detail: format!(
                "{} inode(s), {} dentry(ies); rebuild deterministic={deterministic}",
                a.inode_count(),
                a.dentry_count()
            ),
        });
        report.ok = report.checks.iter().all(|c| c.ok);
    }
    if json {
        let out = serde_json::json!({
            "volume": backing.display().to_string(),
            "deep": deep,
            "ok": report.ok,
            "checks": report.checks,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!(
            "verifying {} ({})",
            backing.display(),
            if deep { "deep" } else { "shallow" }
        );
        for c in &report.checks {
            println!(
                "  [{}] {}: {}",
                if c.ok { "ok" } else { "FAIL" },
                c.name,
                c.detail
            );
        }
        println!("result: {}", if report.ok { "PASS" } else { "FAIL" });
    }
    if report.ok {
        Ok(())
    } else {
        Err(OrfsError::Corrupt("volume verification failed".to_string()))
    }
}

// ---------------------------------------------------------------------------
// recover
// ---------------------------------------------------------------------------

fn recover(backing: &Path, json: bool) -> Result<()> {
    let log_dir = Volume::log_dir(backing);
    let before = match scan_log(&log_dir) {
        Ok(s) => Some(s),
        Err(e) => {
            // A scan failure is reported honestly; recovery cannot invent data.
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "volume": backing.display().to_string(),
                        "scan_error": e.to_string(),
                    }))
                    .unwrap()
                );
            } else {
                println!("recover {}: scan failed: {e}", backing.display());
            }
            return Err(e);
        }
    };
    let scan = before.expect("scan present");
    let tail = scan.tail;

    // Opening read-write performs quarantine if a tail is present.
    let mut vol = Volume::open(backing, OpenMode::ReadWrite)?;
    vol.sync()?;
    let root = vol.log.committed_end_offset();
    let quarantined = tail.is_some();

    if json {
        let out = serde_json::json!({
            "volume": backing.display().to_string(),
            "recovered_root": root,
            "quarantined": quarantined,
            "tail": tail_json(tail),
            "committed_records": vol.log.committed_record_count(),
            "segments_after": vol.log.extents().len(),
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(());
    }
    println!("recovering {}", backing.display());
    match tail {
        Some(t) => println!(
            "  abandoned {:?} tail of {} bytes at offset {}: retained under or.log/quarantine/ and continued in a fresh segment",
            t.kind, t.abandoned_bytes, t.boundary_offset
        ),
        None => println!("  no abandoned tail; nothing to quarantine"),
    }
    println!("  recovered committed root R: {root}");
    println!(
        "  committed records:          {}",
        vol.log.committed_record_count()
    );
    println!("  canonical segments:         {}", vol.log.extents().len());
    Ok(())
}

fn doctor(json: bool) -> Result<()> {
    let caps = orfs::capabilities::probe();
    let uring = orfs::uring::probe_available();
    let f2 = orfs::fuse_uring::discover_report();

    // When the static preconditions hold, attempt a *live* negotiation (a
    // throwaway mount + `INIT` + ring registration) so doctor reports the real
    // result rather than a prediction. When they do not hold, the static reason
    // is exact and no mount is attempted.
    let live: Option<std::result::Result<orfs::fuse_uring::FuseUringNegotiation, String>> =
        if f2.preconditions.is_ok() {
            Some(orfs::fuse_native::negotiate_live())
        } else {
            None
        };
    let (usable, reason) = match &live {
        Some(Ok(neg)) => (neg.engaged && neg.kernel_offered, neg.describe()),
        Some(Err(e)) => (false, e.clone()),
        None => (f2.usable(), f2.reason()),
    };

    if json {
        let out = serde_json::json!({
            "orfs_version": orfs::VERSION,
            "format_version": orfs::FORMAT_VERSION,
            "capabilities": caps,
            "traditional_fuse_usable": caps.traditional_fuse_usable(),
            "fuse_over_io_uring_plausible": caps.fuse_over_io_uring_plausible(),
            "fuse_over_io_uring_usable": usable,
            "fuse_over_io_uring_reason": reason,
            "fuse_uring": f2,
            "fuse_over_io_uring_live": live.as_ref().map(|r| match r {
                Ok(n) => serde_json::to_value(n).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({ "error": e }),
            }),
            "backing_io_uring_available": uring.is_ok(),
            "backing_io_uring_reason": uring.err(),
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(());
    }

    println!("{} {}", orfs::PRODUCT, orfs::VERSION);
    println!("format version:   {}", orfs::FORMAT_VERSION);
    println!("kernel release:   {}", caps.kernel_release);
    println!("machine:          {}", caps.machine);
    println!("container:        {}", caps.likely_container);
    println!("/dev/fuse:        {}", yesno(caps.dev_fuse_present));
    println!(
        "io_uring_disabled:{}",
        caps.io_uring_disabled
            .map(|v| format!(" {v}"))
            .unwrap_or_else(|| " (unreadable)".to_string())
    );
    println!("CONFIG_FUSE_FS:      {}", tri(caps.config_fuse_fs));
    println!("CONFIG_FUSE_IO_URING:{}", tri(caps.config_fuse_io_uring));
    println!("CONFIG_IO_URING:     {}", tri(caps.config_io_uring));
    println!("CONFIG_IO_URING_ZCRX:{}", tri(caps.config_io_uring_zcrx));
    println!(
        "traditional FUSE usable:      {}",
        yesno(caps.traditional_fuse_usable())
    );
    println!(
        "FUSE-over-io_uring plausible: {}",
        yesno(caps.fuse_over_io_uring_plausible())
    );
    // Real negotiation (not a plausibility guess): the kernel module gate and,
    // during a mount, the live INIT capability handshake.
    println!(
        "  fuse.enable_uring:           {}",
        f2.discovery
            .enable_uring_param
            .map(yesno)
            .unwrap_or("unreadable")
    );
    println!(
        "  io_uring available:          {} ({})",
        yesno(f2.discovery.io_uring_available),
        f2.discovery.io_uring_reason.as_deref().unwrap_or("ok")
    );
    println!(
        "  CAP_SYS_ADMIN (zero-copy):   {}",
        yesno(f2.discovery.cap_sys_admin)
    );
    match &live {
        Some(Ok(neg)) => println!("  live negotiation:           {}", neg.describe()),
        Some(Err(e)) => println!("  live negotiation:           failed: {e}"),
        None => println!("  live negotiation:           not attempted (preconditions fail)"),
    }
    println!(
        "FUSE-over-io_uring usable:    {} ({})",
        yesno(usable),
        reason
    );
    println!(
        "backing io_uring available:   {} ({})",
        yesno(uring.is_ok()),
        uring.as_ref().err().map(|s| s.as_str()).unwrap_or("ok")
    );
    Ok(())
}

fn yesno(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn tri(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "y",
        Some(false) => "n",
        None => "? (config unreadable)",
    }
}
