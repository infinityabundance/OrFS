//! `orfs` command-line interface.
//!
//! Every subcommand in the target surface is present. A command that is part of
//! the design but not yet wired rejects the request explicitly with the owning
//! phase, rather than silently pretending to work. `doctor` is fully real: it
//! reports the actual kernel and container capabilities OrFS depends on.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
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
        Command::Init { .. } => phase("init", "Phase 1 (authoritative append-only log)"),
        Command::Mount { .. } => phase("mount", "Phase 4 (traditional FUSE)"),
        Command::Unmount { .. } => phase("unmount", "Phase 4 (traditional FUSE)"),
        Command::Inspect { .. } => phase("inspect", "Phase 1 (authoritative append-only log)"),
        Command::Stat { .. } => phase("stat", "Phase 5 (backing io_uring)"),
        Command::Verify { .. } => phase("verify", "Phase 1 (authoritative append-only log)"),
        Command::Recover { .. } => phase("recover", "Phase 1 (authoritative append-only log)"),
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

fn doctor(json: bool) -> Result<()> {
    let caps = orfs::capabilities::probe();

    if json {
        let out = serde_json::json!({
            "orfs_version": orfs::VERSION,
            "format_version": orfs::FORMAT_VERSION,
            "capabilities": caps,
            "traditional_fuse_usable": caps.traditional_fuse_usable(),
            "fuse_over_io_uring_plausible": caps.fuse_over_io_uring_plausible(),
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
