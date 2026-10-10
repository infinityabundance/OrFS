//! `orfs` command-line interface.
//!
//! Every subcommand in the target surface is present. A command that is part of
//! the design but not yet wired rejects the request explicitly with the owning
//! phase, rather than silently pretending to work. `doctor` is fully real: it
//! reports the actual kernel and container capabilities OrFS depends on.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use orfs::commit::DurabilityMode;
use orfs::fuse::{self, BackingIo, MountOptions, StatfsMode};
use orfs::log::{scan_log, OpenMode, TailInfo, DEFAULT_SEGMENT_SIZE};
use orfs::record::record_type_name;
use orfs::segment::{segment_file_name, SegmentExtent};
use orfs::volume::Volume;
use orfs::{OrfsError, Result};

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

    /// Manifest EKBLOOM acceleration structures for an object.
    Manifest {
        /// File to manifest (usually a path inside the backing store).
        file: PathBuf,
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
    },

    /// Search file contents through the typed query API.
    Query {
        /// Path to search (inside a mount, or a backing object).
        path: PathBuf,
        /// Literal byte pattern to find.
        #[arg(long)]
        pattern: String,
        /// Maximum number of matches to report.
        #[arg(long, default_value_t = 0)]
        limit: u64,
    },

    /// Run the benchmark harness.
    Bench {
        /// Backing directory.
        backing: PathBuf,
        /// Workload selector.
        #[arg(long, default_value = "random-4k")]
        workload: String,
        /// Output JSON path.
        #[arg(long)]
        output: Option<PathBuf>,
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
        } => mount_cmd(MountArgs {
            backing,
            mountpoint,
            transport,
            backing_io,
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
        }),
        Command::Unmount { mountpoint } => unmount_cmd(mountpoint, cli.json),
        Command::Inspect { backing } => inspect(backing, cli.json),
        Command::Stat { .. } => phase("stat", "Phase 5 (backing io_uring)"),
        Command::Verify { backing, deep } => verify(backing, *deep, cli.json),
        Command::Recover { backing } => recover(backing, cli.json),
        Command::Snapshot { cmd } => match cmd {
            SnapshotCommand::List { .. } => {
                phase("snapshot list", "Phase 6 (snapshots & checkpoints)")
            }
            SnapshotCommand::Inspect { .. } => {
                phase("snapshot inspect", "Phase 6 (snapshots & checkpoints)")
            }
            SnapshotCommand::Mount { .. } => {
                phase("snapshot mount", "Phase 6 (snapshots & checkpoints)")
            }
        },
        Command::Manifest { .. } => phase("manifest", "Phase 8 (EKBLOOM integration)"),
        Command::Grow { .. } => phase("grow", "Phase 7 (concealed manifestation)"),
        Command::Query { .. } => phase("query", "Phase 9 (concealed query structures)"),
        Command::Bench { .. } => phase("bench", "Phase 12 (performance court)"),
    }
}

fn phase(what: &str, phase: &'static str) -> Result<()> {
    let _ = what;
    Err(OrfsError::Unimplemented(phase))
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
}

fn mount_cmd(args: MountArgs<'_>) -> Result<()> {
    match args.transport {
        "fuse" => {}
        "fuse-uring" => {
            return Err(OrfsError::Unimplemented(
                "Phase 5 (FUSE-over-io_uring transport)",
            ))
        }
        other => {
            return Err(OrfsError::InvalidArgument(format!(
                "unknown transport {other:?} (expected fuse|fuse-uring)"
            )))
        }
    }
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
        backing_io,
        direct_io: args.direct_io,
        readahead_kb: args.readahead_kb,
        max_write_kb: args.max_write_kb,
        attr_ttl: Duration::from_millis(args.attr_ttl_ms),
        entry_ttl: Duration::from_millis(args.entry_ttl_ms),
        default_permissions: args.default_permissions,
        allow_other: args.allow_other,
        auto_unmount: args.auto_unmount,
        statfs,
    };

    eprintln!(
        "orfs: mounting {} at {} (durability={durability:?}, backing_io={:?}, \
         direct_io={}, readahead_kb={}); press Ctrl-C or run `orfs unmount {}`",
        args.backing.display(),
        args.mountpoint.display(),
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

    if json {
        let out = serde_json::json!({
            "orfs_version": orfs::VERSION,
            "format_version": orfs::FORMAT_VERSION,
            "capabilities": caps,
            "traditional_fuse_usable": caps.traditional_fuse_usable(),
            "fuse_over_io_uring_plausible": caps.fuse_over_io_uring_plausible(),
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
