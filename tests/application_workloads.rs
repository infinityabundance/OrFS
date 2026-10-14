//! **Phase 81 — end-to-end application workloads with a real baseline.**
//!
//! The reviewer's P0 was *"end-to-end filesystem workloads … measure application
//! throughput and latency rather than only filesystem operations."* This court
//! drives five **real applications** against (a) a real OrFS FUSE mount and
//! (b) external baselines, on the *same* machine in the *same* container, and
//! publishes the losses as losses:
//!
//! * **Git repository** (`git`) — init/add/commit ×2/clone/checkout/gc over a
//!   bounded nested tree.
//! * **SQLite database** (`sqlite3`) — WAL + `synchronous=FULL`, a bulk insert
//!   transaction, individual fsync'd inserts, indexed queries, and `VACUUM`.
//! * **Container-image extraction analogue** (`tar`) — extract a bounded,
//!   **synthetic** OCI-layer-like tarball (many small files + a few large). It is
//!   labelled a synthetic analogue, not a real `docker pull`.
//! * **Source build** (`make`/`gcc`) — a generated C project with many
//!   translation units, built with `make -j`.
//! * **Metadata-heavy tree** — a bounded 50 000-file tree exercised with
//!   `stat`/`readdir`/`rename`/`unlink` **in process**, so per-operation client
//!   latency percentiles are recorded for both arms.
//!
//! ## The baseline contract (why this comparator is fair)
//!
//! The **primary** baseline is a directory on the **same bind-mounted host
//! filesystem as the OrFS backing volume** (`target/…`). The two arms therefore
//! share the same storage *device*; the only difference is the filesystem stack
//! (OrFS-over-FUSE versus the host's native filesystem). That isolates the
//! thing under test instead of conflating it with device speed. A second,
//! clearly-labelled **tmpfs** arm (an in-container RAM `tmpfs`) is run as a
//! reference floor, *not* as the headline comparator, because RAM speed is not a
//! filesystem property.
//!
//! ## Honesty
//!
//! Every workload is **bounded** (fixed file/op counts, recorded in the receipt)
//! so it completes reliably. Trials are **order-balanced** (the arm order rotates
//! between trials) and each arm's median is reported together with every trial.
//! A workload that fails on an arm records the failure and its stderr tail — it
//! never fabricates a time. The receipt carries a machine-readable
//! `orfs_faster_than_baseline` verdict per workload so the docs cannot drift into
//! an unfounded claim.
//!
//! Mounting requires `/dev/fuse` + `CAP_SYS_ADMIN`; the court is expected only
//! under `scripts/container-application-workloads.sh` (`ORFS_FUSE_TEST=1`). If a
//! mount cannot be obtained it records `ran: false` with the exact reason and
//! never hangs. The full sweep is opt-in (`ORFS_APP_SWEEP=1`); the always-on
//! smoke runs a tiny bounded subset.
//!
//! Evidence: `evidence/performance/application-workloads.json`
//! (schema `orfs.performance.application-workloads.v1`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use orfs::commit::DurabilityMode;
use orfs::fuse::{self, MountOptions};
use orfs::index::ROOT_INODE;
use orfs::log::DEFAULT_SEGMENT_SIZE;
use orfs::namespace::{Namespace, SetAttr};

// ---------------------------------------------------------------------------
// Scales
// ---------------------------------------------------------------------------

/// The bounded configuration of every workload. Every workload records its
/// concrete counts from here, so the receipt is self-describing.
#[derive(Clone, Copy)]
struct Scale {
    git_dirs: usize,
    git_files: usize,
    sqlite_bulk_rows: usize,
    sqlite_fsync_rows: usize,
    sqlite_queries: usize,
    tar_small: usize,
    tar_large: usize,
    tar_small_bytes: usize,
    tar_large_bytes: usize,
    make_tus: usize,
    meta_dirs: usize,
    meta_files_per_dir: usize,
    trials: usize,
}

impl Scale {
    /// The always-on smoke: the same workloads at a tiny, bounded scale so the
    /// phase runner is cheap and reliable.
    const fn smoke() -> Scale {
        Scale {
            git_dirs: 12,
            git_files: 120,
            sqlite_bulk_rows: 500,
            sqlite_fsync_rows: 10,
            sqlite_queries: 3,
            tar_small: 50,
            tar_large: 1,
            tar_small_bytes: 1024,
            tar_large_bytes: 1 << 20,
            make_tus: 16,
            meta_dirs: 8,
            meta_files_per_dir: 10,
            trials: 1,
        }
    }

    /// The opt-in sweep: substantial but bounded.
    const fn sweep() -> Scale {
        Scale {
            git_dirs: 60,
            git_files: 1200,
            sqlite_bulk_rows: 20_000,
            sqlite_fsync_rows: 200,
            sqlite_queries: 50,
            tar_small: 2_000,
            tar_large: 4,
            tar_small_bytes: 1024,
            tar_large_bytes: 4 << 20,
            make_tus: 120,
            meta_dirs: 250,
            meta_files_per_dir: 200,
            trials: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Workloads
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Workload {
    GitRepository,
    SqliteDatabase,
    ImageExtraction,
    SourceBuild,
    MetadataTree,
}

impl Workload {
    const ALL: [Workload; 5] = [
        Workload::GitRepository,
        Workload::SqliteDatabase,
        Workload::ImageExtraction,
        Workload::SourceBuild,
        Workload::MetadataTree,
    ];

    const fn name(self) -> &'static str {
        match self {
            Workload::GitRepository => "git-repository",
            Workload::SqliteDatabase => "sqlite-database",
            Workload::ImageExtraction => "image-extraction-analogue",
            Workload::SourceBuild => "source-build",
            Workload::MetadataTree => "metadata-tree",
        }
    }

    fn config(self, s: &Scale) -> serde_json::Value {
        match self {
            Workload::GitRepository => serde_json::json!({
                "dirs": s.git_dirs,
                "files": s.git_files,
                "commits": 2,
                "sequences": "init -> add -> commit -> modify -> add -> commit -> clone --no-local -> checkout -b -> gc",
            }),
            Workload::SqliteDatabase => serde_json::json!({
                "journal_mode": "WAL",
                "synchronous": "FULL",
                "bulk_rows": s.sqlite_bulk_rows,
                "fsync_rows": s.sqlite_fsync_rows,
                "indexed_queries": s.sqlite_queries,
                "vacuum": true,
            }),
            Workload::ImageExtraction => serde_json::json!({
                "kind": "synthetic OCI-layer-like tarball (NOT a real docker pull)",
                "small_files": s.tar_small,
                "small_bytes_each": s.tar_small_bytes,
                "large_files": s.tar_large,
                "large_bytes_each": s.tar_large_bytes,
            }),
            Workload::SourceBuild => serde_json::json!({
                "translation_units": s.make_tus,
                "build": "make -j<cpus>",
                "compiler": "cc (gcc)",
            }),
            Workload::MetadataTree => serde_json::json!({
                "dirs": s.meta_dirs,
                "files_per_dir": s.meta_files_per_dir,
                "files": s.meta_dirs * s.meta_files_per_dir,
                "ops": ["create", "stat", "readdir", "rename", "unlink"],
                "measured": "in process (real syscalls through the mount), per-op latency recorded",
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fuse_test_required() -> bool {
    std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1")
}

fn image_digest() -> String {
    std::env::var("ORFS_IMAGE_DIGEST").unwrap_or_else(|_| "unknown".into())
}

fn unique_scratch(prefix: &str) -> PathBuf {
    let base = manifest_dir()
        .join("target")
        .join("application-workloads-it");
    fs::create_dir_all(&base).expect("create base");
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = base.join(format!("{prefix}-{pid}-{nanos}"));
    fs::create_dir_all(&dir).expect("create scratch");
    dir
}

/// A deterministic byte pattern for generated data.
fn fill_pattern(buf: &mut [u8], seed: usize) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((i as u64 * 131 + 17 + seed as u64) % 251) as u8;
    }
}

fn fstype(path: &Path) -> String {
    let out = Command::new("stat")
        .args(["-f", "-c", "%T"])
        .arg(path)
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "unknown".into(),
    }
}

fn tail_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join(" | ")
}

/// POSIX: a file created with mode `0444` is writable through the descriptor the
/// create returned — permission is checked at `open`, not on every `write`. OrFS
/// documents **per-write** permission enforcement (`docs/FUSE-SEMANTICS.md` §5/§6),
/// so it may refuse. This records each arm's honest outcome, turning the git
/// failure into evidence rather than an inference.
fn probe_write_through_created_fd(root: &Path) -> String {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = root.join(".wprobe");
    if fs::create_dir_all(&dir).is_err() {
        return "setup-error".into();
    }
    let p = dir.join("obj");
    let _ = fs::remove_file(&p);
    let res = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(&p)
        .and_then(|mut f| f.write_all(b"hello"));
    let out = match res {
        Ok(()) => "ok (write via the created fd succeeded)".to_string(),
        Err(e) => format!("refused: {e}"),
    };
    let _ = fs::remove_dir_all(&dir);
    out
}

/// Run an external program, returning `(seconds, stdout, stderr)`.
fn run_cmd(
    program: &str,
    args: &[&str],
    cwd: &Path,
    envs: &[(&str, String)],
) -> Result<(f64, String, String), String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let started = Instant::now();
    let out = cmd
        .output()
        .map_err(|e| format!("spawn `{program}`: {e}"))?;
    let secs = started.elapsed().as_secs_f64();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        return Err(format!(
            "`{program}` exited {}: {}",
            out.status.code().unwrap_or(-1),
            tail_lines(&stderr, 4)
        ));
    }
    Ok((secs, stdout, stderr))
}

fn summarize_ns(mut xs: Vec<u64>) -> serde_json::Value {
    if xs.is_empty() {
        return serde_json::Value::Null;
    }
    xs.sort_unstable();
    let n = xs.len();
    let pct = |p: f64| -> u64 {
        let idx = ((p / 100.0) * n as f64).ceil() as usize;
        xs[idx.saturating_sub(1).min(n - 1)]
    };
    serde_json::json!({
        "samples": n,
        "p50_ns": pct(50.0),
        "p95_ns": pct(95.0),
        "p99_ns": pct(99.0),
        "mean_ns": xs.iter().sum::<u64>() as f64 / n as f64,
    })
}

fn median(mut xs: Vec<f64>) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = xs.len();
    Some(if n % 2 == 1 {
        xs[n / 2]
    } else {
        (xs[n / 2 - 1] + xs[n / 2]) / 2.0
    })
}

// ---------------------------------------------------------------------------
// The measured outcome of one arm on one workload/trial
// ---------------------------------------------------------------------------

struct Outcome {
    seconds: f64,
    ops: u64,
    detail: serde_json::Value,
    latency: Option<serde_json::Value>,
}

type RunResult = Result<Outcome, String>;

#[derive(Default)]
struct OpLatency {
    create: Vec<u64>,
    stat: Vec<u64>,
    readdir: Vec<u64>,
    rename: Vec<u64>,
    unlink: Vec<u64>,
}

impl OpLatency {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "create": summarize_ns(self.create.clone()),
            "stat": summarize_ns(self.stat.clone()),
            "readdir": summarize_ns(self.readdir.clone()),
            "rename": summarize_ns(self.rename.clone()),
            "unlink": summarize_ns(self.unlink.clone()),
        })
    }
}

// ---------------------------------------------------------------------------
// Workload implementations
// ---------------------------------------------------------------------------

fn write_tree(root: &Path, dirs: usize, files: usize) -> std::io::Result<()> {
    for d in 0..dirs {
        let dir = root
            .join(format!("p{:03}", d % 32))
            .join(format!("d{d:04}"));
        fs::create_dir_all(&dir)?;
        let n = files / dirs + usize::from(d < files % dirs);
        for f in 0..n {
            let mut buf = vec![0u8; 256 + (f % 8) * 64];
            fill_pattern(&mut buf, d * 7 + f);
            fs::write(dir.join(format!("file{f:05}.dat")), &buf)?;
        }
    }
    Ok(())
}

fn git_env(home: &Path) -> Vec<(&'static str, String)> {
    vec![
        ("GIT_AUTHOR_NAME", "OrFS".into()),
        ("GIT_AUTHOR_EMAIL", "orfs@example.invalid".into()),
        ("GIT_COMMITTER_NAME", "OrFS".into()),
        ("GIT_COMMITTER_EMAIL", "orfs@example.invalid".into()),
        ("GIT_AUTHOR_DATE", "2026-10-14T00:00:00 +0000".into()),
        ("GIT_COMMITTER_DATE", "2026-10-14T00:00:00 +0000".into()),
        ("GIT_CONFIG_NOSYSTEM", "1".into()),
        ("GIT_CONFIG_GLOBAL", "/dev/null".into()),
        ("GIT_TERMINAL_PROMPT", "0".into()),
        ("HOME", home.display().to_string()),
    ]
}

fn workload_git(root: &Path, s: &Scale, git_home: &Path) -> RunResult {
    let repo = root.join("repo");
    let clone = root.join("clone");
    let envs = git_env(git_home);
    let started = Instant::now();
    fs::create_dir_all(&repo).map_err(|e| format!("create repo dir: {e}"))?;
    write_tree(&repo, s.git_dirs, s.git_files).map_err(|e| format!("write tree: {e}"))?;
    run_cmd("git", &["init", "-q"], &repo, &envs)?;
    run_cmd("git", &["add", "-A"], &repo, &envs)?;
    run_cmd("git", &["commit", "-q", "-m", "c1"], &repo, &envs)?;
    // Modify a subset and make a second commit.
    for d in 0..s.git_dirs.min(8) {
        let dir = repo
            .join(format!("p{:03}", d % 32))
            .join(format!("d{d:04}"));
        let mut buf = vec![0u8; 1024];
        fill_pattern(&mut buf, d + 999);
        let _ = fs::write(dir.join("file00000.dat"), &buf);
    }
    run_cmd("git", &["add", "-A"], &repo, &envs)?;
    run_cmd("git", &["commit", "-q", "-m", "c2"], &repo, &envs)?;
    let repo_s = repo.display().to_string();
    let clone_s = clone.display().to_string();
    run_cmd(
        "git",
        &["clone", "--no-local", "--quiet", &repo_s, &clone_s],
        root,
        &envs,
    )?;
    run_cmd("git", &["checkout", "-q", "-b", "feature"], &clone, &envs)?;
    run_cmd("git", &["gc", "-q"], &repo, &envs)?;
    let seconds = started.elapsed().as_secs_f64();
    Ok(Outcome {
        seconds,
        ops: s.git_files as u64,
        detail: serde_json::json!({
            "repo": repo.display().to_string(),
            "clone": clone.display().to_string(),
            "files": s.git_files,
            "dirs": s.git_dirs,
        }),
        latency: None,
    })
}

fn sqlite_script(s: &Scale) -> String {
    let mut out = String::new();
    out.push_str("PRAGMA journal_mode=WAL;\n");
    out.push_str("PRAGMA synchronous=FULL;\n");
    out.push_str("CREATE TABLE t(id INTEGER PRIMARY KEY, k TEXT NOT NULL, v INTEGER NOT NULL);\n");
    out.push_str("BEGIN;\n");
    for i in 0..s.sqlite_bulk_rows {
        out.push_str(&format!(
            "INSERT INTO t(k,v) VALUES('k{}',{});\n",
            i % 1000,
            i
        ));
    }
    out.push_str("COMMIT;\n");
    out.push_str("CREATE INDEX idx_k ON t(k);\n");
    // Individual, fsync'd inserts (each its own implicit transaction).
    for i in 0..s.sqlite_fsync_rows {
        out.push_str(&format!(
            "INSERT INTO t(k,v) VALUES('f{}',{});\n",
            i % 1000,
            i
        ));
    }
    for q in 0..s.sqlite_queries {
        out.push_str(&format!(
            "SELECT count(*), sum(v) FROM t WHERE k='k{}';\n",
            q % 1000
        ));
    }
    out.push_str("VACUUM;\n");
    out
}

fn workload_sqlite(root: &Path, s: &Scale) -> RunResult {
    let db = root.join("data.db");
    let script = root.join("workload.sql");
    fs::write(&script, sqlite_script(s)).map_err(|e| format!("write script: {e}"))?;
    let db_s = db.display().to_string();
    let read_arg = format!(".read {}", script.display());
    let (seconds, _out, _err) = run_cmd("sqlite3", &[&db_s, &read_arg], root, &[])?;
    let bytes = fs::metadata(&db).map(|m| m.len()).unwrap_or(0);
    let total_rows = (s.sqlite_bulk_rows + s.sqlite_fsync_rows) as u64;
    Ok(Outcome {
        seconds,
        ops: total_rows,
        detail: serde_json::json!({
            "db": db.display().to_string(),
            "db_bytes": bytes,
            "rows": total_rows,
            "bulk_rows": s.sqlite_bulk_rows,
            "fsync_rows": s.sqlite_fsync_rows,
        }),
        latency: None,
    })
}

/// Build the (shared, setup-time) synthetic layer tarball. Returns its path.
fn build_layer(shared: &Path, s: &Scale) -> Result<PathBuf, String> {
    let src = shared.join("layer-src");
    fs::create_dir_all(&src).map_err(|e| format!("layer src: {e}"))?;
    for i in 0..s.tar_small {
        let d = src.join(format!("dir{:03}", i % 40));
        fs::create_dir_all(&d).map_err(|e| format!("layer dir: {e}"))?;
        let mut buf = vec![0u8; s.tar_small_bytes];
        fill_pattern(&mut buf, i);
        fs::write(d.join(format!("f{i:05}.bin")), &buf).map_err(|e| format!("layer file: {e}"))?;
    }
    for i in 0..s.tar_large {
        let mut buf = vec![0u8; s.tar_large_bytes];
        fill_pattern(&mut buf, i + 7000);
        fs::write(src.join(format!("large{i:02}.bin")), &buf)
            .map_err(|e| format!("layer large: {e}"))?;
    }
    let layer = shared.join("layer.tar");
    let layer_s = layer.display().to_string();
    let src_s = src.display().to_string();
    run_cmd("tar", &["-cf", &layer_s, "-C", &src_s, "."], shared, &[])?;
    Ok(layer)
}

fn workload_tar(root: &Path, s: &Scale, layer: &Path) -> RunResult {
    let layer_s = layer.display().to_string();
    let dest = root.display().to_string();
    let (seconds, _o, _e) = run_cmd("tar", &["-xf", &layer_s, "-C", &dest], root, &[])?;
    let bytes = (s.tar_small * s.tar_small_bytes + s.tar_large * s.tar_large_bytes) as u64;
    Ok(Outcome {
        seconds,
        ops: (s.tar_small + s.tar_large) as u64,
        detail: serde_json::json!({
            "layer": layer_s,
            "small_files": s.tar_small,
            "large_files": s.tar_large,
            "bytes": bytes,
        }),
        latency: None,
    })
}

fn write_c_project(dir: &Path, tus: usize) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    for i in 0..tus {
        let body = format!(
            "#include \"common.h\"\n\
             int func_{i}(int x) {{\n\
             \x20 int acc = x;\n\
             \x20 for (int j = 0; j < {n}; ++j) {{ acc = acc * 1103515245 + j + {i}; }}\n\
             \x20 return acc ^ {i};\n\
             }}\n",
            i = i,
            n = (i % 7) + 3,
        );
        fs::write(dir.join(format!("unit_{i:04}.c")), body)?;
    }
    fs::write(
        dir.join("common.h"),
        "#ifndef COMMON_H\n#define COMMON_H\nint func_0(int x);\n#endif\n",
    )?;
    let mut main = String::from("int main(void) {\n  int acc = 0;\n");
    for i in 0..tus {
        main.push_str(&format!("  acc += func_{i}(acc);\n"));
    }
    main.push_str("  return acc & 0;\n}\n");
    fs::write(dir.join("main.c"), main)?;

    let mut makefile = String::from("CC ?= cc\nCFLAGS ?= -O0\n");
    makefile.push_str("SRCS := $(wildcard *.c)\nOBJS := $(SRCS:.c=.o)\n");
    makefile.push_str("prog: $(OBJS)\n\t$(CC) $(CFLAGS) -o prog $(OBJS)\n");
    makefile.push_str("%.o: %.c\n\t$(CC) $(CFLAGS) -c $< -o $@\n");
    makefile.push_str(".PHONY: clean\nclean:\n\trm -f $(OBJS) prog\n");
    fs::write(dir.join("Makefile"), makefile)?;
    Ok(())
}

fn workload_make(root: &Path, s: &Scale, nproc: usize) -> RunResult {
    let src = root.join("src");
    write_c_project(&src, s.make_tus).map_err(|e| format!("generate project: {e}"))?;
    let jobs = format!("-j{nproc}");
    let (seconds, _o, _e) = run_cmd("make", &[&jobs], &src, &[])?;
    let prog = src.join("prog");
    let exists = prog.is_file();
    Ok(Outcome {
        seconds,
        ops: s.make_tus as u64,
        detail: serde_json::json!({
            "translation_units": s.make_tus,
            "jobs": nproc,
            "prog_built": exists,
        }),
        latency: None,
    })
}

fn workload_metadata(root: &Path, s: &Scale) -> RunResult {
    let mut lat = OpLatency::default();
    let started = Instant::now();
    for d in 0..s.meta_dirs {
        let dir = root.join(format!("d{d:05}"));
        fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
        for f in 0..s.meta_files_per_dir {
            let p = dir.join(format!("f{f:05}"));
            let t = Instant::now();
            fs::write(&p, b"x").map_err(|e| format!("create {}: {e}", p.display()))?;
            lat.create.push(t.elapsed().as_nanos() as u64);

            let t = Instant::now();
            let _ = fs::metadata(&p).map_err(|e| format!("stat {}: {e}", p.display()))?;
            lat.stat.push(t.elapsed().as_nanos() as u64);
        }
        let t = Instant::now();
        let n = fs::read_dir(&dir)
            .map_err(|e| format!("opendir {}: {e}", dir.display()))?
            .count();
        lat.readdir.push(t.elapsed().as_nanos() as u64);
        if n != s.meta_files_per_dir {
            return Err(format!("readdir {}: {n} entries", dir.display()));
        }
        for f in 0..s.meta_files_per_dir {
            let from = dir.join(format!("f{f:05}"));
            let to = dir.join(format!("f{f:05}.rn"));
            let t = Instant::now();
            fs::rename(&from, &to).map_err(|e| format!("rename {}: {e}", from.display()))?;
            lat.rename.push(t.elapsed().as_nanos() as u64);
        }
        for f in 0..s.meta_files_per_dir {
            let p = dir.join(format!("f{f:05}.rn"));
            let t = Instant::now();
            fs::remove_file(&p).map_err(|e| format!("unlink {}: {e}", p.display()))?;
            lat.unlink.push(t.elapsed().as_nanos() as u64);
        }
    }
    let seconds = started.elapsed().as_secs_f64();
    let files = (s.meta_dirs * s.meta_files_per_dir) as u64;
    Ok(Outcome {
        seconds,
        ops: files,
        detail: serde_json::json!({
            "dirs": s.meta_dirs,
            "files": files,
        }),
        latency: Some(lat.to_json()),
    })
}

fn run_workload(
    w: Workload,
    root: &Path,
    s: &Scale,
    git_home: &Path,
    layer: &Path,
    nproc: usize,
) -> RunResult {
    fs::create_dir_all(root).map_err(|e| format!("create run root: {e}"))?;
    match w {
        Workload::GitRepository => workload_git(root, s, git_home),
        Workload::SqliteDatabase => workload_sqlite(root, s),
        Workload::ImageExtraction => workload_tar(root, s, layer),
        Workload::SourceBuild => workload_make(root, s, nproc),
        Workload::MetadataTree => workload_metadata(root, s),
    }
}

// ---------------------------------------------------------------------------
// Arms and the court
// ---------------------------------------------------------------------------

struct Arm {
    id: &'static str,
    kind: &'static str,
    root: PathBuf,
}

fn arm_json(a: &Arm) -> serde_json::Value {
    serde_json::json!({
        "id": a.id,
        "kind": a.kind,
        "root": a.root.display().to_string(),
        "fs_type": fstype(&a.root),
    })
}

struct TrialOutcome {
    seconds: f64,
    ops: u64,
    detail: serde_json::Value,
    latency: Option<serde_json::Value>,
}

impl TrialOutcome {
    fn from_result(r: RunResult) -> TrialOutcome {
        match r {
            Ok(o) => TrialOutcome {
                seconds: o.seconds,
                ops: o.ops,
                detail: o.detail,
                latency: o.latency,
            },
            Err(e) => TrialOutcome {
                seconds: f64::NAN,
                ops: 0,
                detail: serde_json::json!({ "error": e }),
                latency: None,
            },
        }
    }

    fn ok(&self) -> bool {
        self.seconds.is_finite()
    }
}

fn arm_summary(trials: &[TrialOutcome]) -> serde_json::Value {
    let ok: Vec<&TrialOutcome> = trials.iter().filter(|t| t.ok()).collect();
    let failed: Vec<serde_json::Value> = trials
        .iter()
        .filter(|t| !t.ok())
        .map(|t| t.detail.clone())
        .collect();
    if ok.is_empty() {
        return serde_json::json!({
            "status": "error",
            "trials": trials.len(),
            "failures": failed,
        });
    }
    let secs: Vec<f64> = ok.iter().map(|t| t.seconds).collect();
    let med = median(secs.clone()).unwrap_or(f64::NAN);
    let ops = ok.iter().map(|t| t.ops).max().unwrap_or(0);
    let rates: Vec<f64> = ok
        .iter()
        .filter(|t| t.seconds > 0.0)
        .map(|t| t.ops as f64 / t.seconds)
        .collect();
    let latency = ok.iter().find_map(|t| t.latency.clone());
    serde_json::json!({
        "status": "ok",
        "trials": trials.len(),
        "trials_ok": ok.len(),
        "seconds_median": med,
        "seconds_trials": secs,
        "ops": ops,
        "ops_per_s_median": median(rates).unwrap_or(f64::NAN),
        "latency_ns": latency,
        "detail": ok.first().map(|t| t.detail.clone()).unwrap_or(serde_json::Value::Null),
        "failures": failed,
    })
}

fn ratio_str(ratio: f64) -> String {
    if !ratio.is_finite() {
        "n/a".into()
    } else {
        format!("{ratio:.2}x")
    }
}

/// Assemble the per-workload receipt object and its boolean verdict.
fn workload_receipt(
    w: Workload,
    s: &Scale,
    arms: &[Arm],
    per_arm_trials: &[Vec<TrialOutcome>],
) -> serde_json::Value {
    let summaries: Vec<serde_json::Value> = per_arm_trials.iter().map(|t| arm_summary(t)).collect();
    let get = |id: &str| -> Option<&serde_json::Value> {
        arms.iter().position(|a| a.id == id).map(|i| &summaries[i])
    };
    let med = |id: &str| -> Option<f64> {
        get(id)
            .filter(|v| v["status"] == "ok")
            .and_then(|v| v["seconds_median"].as_f64())
    };
    let orfs = med("orfs");
    let host = med("host_fs");
    let tmpfs = med("tmpfs");
    let orfs_fail = arms
        .iter()
        .position(|a| a.id == "orfs")
        .and_then(|i| summaries[i]["failures"].as_array().cloned())
        .and_then(|v| v.first().map(|x| x.to_string()))
        .unwrap_or_default();

    let mut arms_json = serde_json::Map::new();
    let mut per_arm_verdict = serde_json::Map::new();
    for (i, a) in arms.iter().enumerate() {
        arms_json.insert(a.id.to_string(), summaries[i].clone());
        if let Some(m) = med(a.id) {
            let ratio = orfs.map(|o| m / o).unwrap_or(f64::NAN);
            per_arm_verdict.insert(
                a.id.to_string(),
                serde_json::json!({
                    "seconds_median": m,
                    "ratio_arm_over_orfs": ratio,
                    "orfs_faster_than_arm": orfs.map(|o| o < m).unwrap_or(false),
                }),
            );
        }
    }

    let (faster, direction, reason) = match (orfs, host) {
        (Some(o), Some(h)) => {
            let ratio = h / o;
            let faster = o < h;
            let dir = if faster { "orfs_faster" } else { "orfs_slower" };
            let reason = format!(
                "OrFS median {o:.4}s vs host_fs median {h:.4}s ({ratio:.2}x the baseline's time{}); \
                 tmpfs median {}s",
                if faster { " — OrFS faster" } else { " — OrFS slower" },
                tmpfs.map(|t| format!("{t:.4}")).unwrap_or_else(|| "n/a".into())
            );
            (faster, dir, reason)
        }
        (Some(_), None) => (
            false,
            "baseline_unavailable",
            "the host_fs baseline did not produce a time; verdict defaults to not-faster".into(),
        ),
        (None, _) => (
            false,
            "orfs_unavailable",
            format!("the OrFS arm produced no time: {orfs_fail}"),
        ),
    };

    let ratio_host = match (orfs, host) {
        (Some(o), Some(h)) if o > 0.0 => h / o,
        _ => f64::NAN,
    };
    serde_json::json!({
        "workload": w.name(),
        "config": w.config(s),
        "primary_baseline": "host_fs",
        "arms": arms_json,
        "per_arm": per_arm_verdict,
        "comparison": {
            "orfs_seconds_median": orfs,
            "host_fs_seconds_median": host,
            "tmpfs_seconds_median": tmpfs,
            "ratio_host_fs_over_orfs": ratio_host,
            "ratio_tmpfs_over_orfs": match (orfs, tmpfs) {
                (Some(o), Some(t)) if o > 0.0 => t / o,
                _ => f64::NAN,
            },
            "direction": direction,
            "orfs_faster_than_baseline": faster,
        },
        "verdict": {
            "orfs_faster_than_baseline": faster,
            "reason": reason,
        },
    })
}

// ---------------------------------------------------------------------------
// Environment / tooling
// ---------------------------------------------------------------------------

fn version_of(program: &str) -> String {
    match Command::new(program).arg("--version").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string(),
        _ => "unavailable".into(),
    }
}

fn os_pretty_name() -> String {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| {
                l.trim_start_matches("PRETTY_NAME=")
                    .trim_matches('"')
                    .to_string()
            })
        })
        .unwrap_or_else(|| "unknown".into())
}

fn tool_versions() -> serde_json::Value {
    serde_json::json!({
        "git": version_of("git"),
        "sqlite3": version_of("sqlite3"),
        "gcc": version_of("gcc"),
        "make": version_of("make"),
        "tar": version_of("tar"),
        "os": os_pretty_name(),
    })
}

fn environment() -> serde_json::Value {
    serde_json::to_value(orfs::bench::Environment::capture(Some(image_digest())))
        .unwrap_or(serde_json::Value::Null)
}

fn write_json(value: &serde_json::Value) {
    let path = manifest_dir().join("evidence/performance/application-workloads.json");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut s) = serde_json::to_string_pretty(value) {
        s.push('\n');
        let _ = fs::write(&path, s);
    }
}

fn record_ran_false(blocker: String, extra: serde_json::Value) {
    let doc = serde_json::json!({
        "schema": "orfs.performance.application-workloads.v1",
        "generated_by": "tests/application_workloads.rs::application_workloads_sweep",
        "ran": false,
        "blocker": blocker,
        "tool_versions": tool_versions(),
        "environment": environment(),
        "extra": extra,
    });
    write_json(&doc);
    eprintln!("application_workloads: ran=false — {blocker}");
}

// ---------------------------------------------------------------------------
// The court
// ---------------------------------------------------------------------------

fn nproc() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

fn run_court(scale: Scale, write_receipt: bool, label: &str) {
    if !fuse_test_required() {
        eprintln!(
            "application_workloads: skipped ({label}, ORFS_FUSE_TEST unset); \
             run under scripts/container-application-workloads.sh"
        );
        return;
    }

    let scratch = unique_scratch("app");
    let backing = scratch.join("backing");
    let mnt = scratch.join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    if let Err(e) = init_volume(&backing) {
        if write_receipt {
            record_ran_false(
                format!("volume init failed: {e}"),
                serde_json::json!({ "scale": label.to_string() }),
            );
        }
        panic!("volume init failed under ORFS_FUSE_TEST=1: {e}");
    }

    let opts = MountOptions::default();
    let mount = match fuse::spawn(&backing, &mnt, &opts) {
        Ok(m) => m,
        Err(e) => {
            if write_receipt {
                record_ran_false(
                    format!("mount failed: {e}"),
                    serde_json::json!({ "scale": label.to_string() }),
                );
            }
            let _ = fs::remove_dir_all(&scratch);
            panic!("mount failed under ORFS_FUSE_TEST=1: {e}");
        }
    };
    let transport_used = format!("{:?}", mount.transport_used());
    let backing_io_used = format!("{:?}", mount.backing_io_used);

    // Baseline roots.
    let host_root = scratch.join("hostfs");
    fs::create_dir_all(&host_root).ok();
    let mut arms = vec![
        Arm {
            id: "orfs",
            kind: "real OrFS FUSE mount (fuse::spawn; the same code path as `orfs mount`)",
            root: mnt.clone(),
        },
        Arm {
            id: "host_fs",
            kind: "external baseline: the same bind-mounted host filesystem as the OrFS backing",
            root: host_root,
        },
    ];
    let tmpfs_base = std::env::var("ORFS_APP_TMPFS").unwrap_or_else(|_| "/orfs-app-tmpfs".into());
    let tmpfs_root = PathBuf::from(&tmpfs_base).join(format!("app-{label}"));
    let tmpfs_note = if fs::create_dir_all(&tmpfs_root).is_ok() {
        let probe = tmpfs_root.join(".probe");
        if fs::write(&probe, b"ok").is_ok() {
            let _ = fs::remove_file(&probe);
            arms.push(Arm {
                id: "tmpfs",
                kind: "reference floor: in-container tmpfs (RAM), not the headline comparator",
                root: tmpfs_root,
            });
            None
        } else {
            Some(format!("{tmpfs_base} not writable"))
        }
    } else {
        Some(format!("{tmpfs_base} unavailable (run via docker_run_app)"))
    };

    let git_home = scratch.join("githome");
    fs::create_dir_all(&git_home).ok();

    // Prove (do not infer) each arm's `create(0444)`-then-write semantics; this is
    // the mechanism behind any `git`-on-OrFS failure and is recorded in the receipt.
    let mut write_probe = serde_json::Map::new();
    for a in &arms {
        write_probe.insert(
            a.id.to_string(),
            serde_json::Value::String(probe_write_through_created_fd(&a.root)),
        );
    }
    let write_probe_json = serde_json::Value::Object(write_probe.clone());
    println!("write-through-created-fd (mode 0444) probe:");
    for (k, v) in &write_probe {
        println!("    {k}: {}", v.as_str().unwrap_or("?"));
    }

    // The synthetic layer tarball is built once (setup, not measured).
    let mut layer_note = None;
    let layer = match build_layer(&scratch, &scale) {
        Ok(p) => Some(p),
        Err(e) => {
            layer_note = Some(e);
            None
        }
    };

    println!("\n=== application_workloads ({label}) ===");
    println!(
        "baseline arms: {:?}",
        arms.iter().map(|a| a.id).collect::<Vec<_>>()
    );
    if let Some(n) = &tmpfs_note {
        println!("tmpfs arm skipped: {n}");
    }

    let mut workload_json = Vec::new();
    let mut per_workload_verdict = serde_json::Map::new();
    let mut all_faster = true;

    for w in Workload::ALL {
        if w == Workload::ImageExtraction && layer.is_none() {
            let entry = serde_json::json!({
                "workload": w.name(),
                "config": w.config(&scale),
                "arms": {},
                "verdict": {
                    "orfs_faster_than_baseline": false,
                    "reason": format!("layer tarball not built: {}", layer_note.clone().unwrap_or_default()),
                },
            });
            per_workload_verdict.insert(w.name().into(), serde_json::Value::Bool(false));
            all_faster = false;
            workload_json.push(entry);
            continue;
        }
        let layer_path = layer.clone().unwrap_or_else(|| scratch.join("layer.tar"));
        let mut per_arm_trials: Vec<Vec<TrialOutcome>> =
            (0..arms.len()).map(|_| Vec::new()).collect();
        let mut orders: Vec<Vec<&str>> = Vec::new();
        for trial in 0..scale.trials {
            let mut order: Vec<usize> = (0..arms.len()).collect();
            let n_arms = order.len();
            if n_arms > 0 {
                order.rotate_left(trial % n_arms);
            }
            orders.push(order.iter().map(|&i| arms[i].id).collect());
            for &ai in &order {
                let a = &arms[ai];
                let run_root = a.root.join(format!("{}-t{trial}", w.name()));
                let r = run_workload(w, &run_root, &scale, &git_home, &layer_path, nproc());
                per_arm_trials[ai].push(TrialOutcome::from_result(r));
            }
        }
        let mut entry = workload_receipt(w, &scale, &arms, &per_arm_trials);
        entry["trial_arm_order"] =
            serde_json::json!(orders.iter().map(|o| o.join(", ")).collect::<Vec<String>>());
        let faster = entry["verdict"]["orfs_faster_than_baseline"]
            .as_bool()
            .unwrap_or(false);
        if !faster {
            all_faster = false;
        }
        per_workload_verdict.insert(w.name().into(), serde_json::Value::Bool(faster));

        let g = |id: &str| -> String {
            entry["arms"][id]["seconds_median"]
                .as_f64()
                .map(|v| format!("{v:.4}s"))
                .unwrap_or_else(|| "n/a".into())
        };
        println!(
            "  {:26} orfs={:>10} host_fs={:>10} tmpfs={:>10}  verdict={}{}",
            w.name(),
            g("orfs"),
            g("host_fs"),
            g("tmpfs"),
            if faster { "orfs_faster" } else { "orfs_slower" },
            entry["comparison"]["ratio_host_fs_over_orfs"]
                .as_f64()
                .map(|r| format!(" ({})", ratio_str(r)))
                .unwrap_or_default(),
        );
        for a in &arms {
            if entry["arms"][a.id]["status"] != "ok" {
                if let Some(f) = entry["arms"][a.id]["failures"]
                    .as_array()
                    .and_then(|v| v.first())
                {
                    println!("      [{}] failed: {}", a.id, f);
                }
            }
        }
        workload_json.push(entry);
    }

    if write_receipt {
        let doc = serde_json::json!({
            "schema": "orfs.performance.application-workloads.v1",
            "generated_by": "tests/application_workloads.rs::application_workloads_sweep",
            "ran": true,
            "claim": "five real applications (git, sqlite3, tar, make/gcc, and an in-process \
                      metadata-heavy tree) driven end to end against a real OrFS FUSE mount and \
                      against external baselines on the same machine in the same container; the \
                      losses are published as losses",
            "units": {
                "primary_metric": "wall_clock_seconds",
                "ratio": "baseline_median_seconds / orfs_median_seconds; a ratio > 1 means OrFS completed in less time (faster)",
                "verdict": "orfs_faster_than_baseline is true only when the OrFS median is strictly below the host_fs baseline median",
            },
            "mount": {
                "options": "MountOptions::default() (classical FUSE transport, synchronous backing I/O, page cache on, durability Ordered)",
                "transport_used": transport_used,
                "backing_io_used": backing_io_used,
                "read_only": false,
            },
            "baseline_contract": "The primary baseline (host_fs) is a directory on the SAME bind-mounted \
                                  host filesystem as the OrFS backing volume, so the two arms share the \
                                  storage device and differ only in the filesystem stack. The tmpfs arm is \
                                  an in-container RAM reference floor, reported for context only; it is not \
                                  the headline comparator because RAM speed is not a filesystem property.",
            "arms": arms.iter().map(arm_json).collect::<Vec<_>>(),
            "trials": scale.trials,
            "order_balancing": "the arm order rotates between trials (arm order starts at a different arm each trial), and every arm's median is reported alongside every individual trial time",
            "scale": {
                "git_dirs": scale.git_dirs,
                "git_files": scale.git_files,
                "sqlite_bulk_rows": scale.sqlite_bulk_rows,
                "sqlite_fsync_rows": scale.sqlite_fsync_rows,
                "tar_small": scale.tar_small,
                "tar_large": scale.tar_large,
                "make_tus": scale.make_tus,
                "meta_dirs": scale.meta_dirs,
                "meta_files_per_dir": scale.meta_files_per_dir,
            },
            "workloads": workload_json,
            "verdict": {
                "orfs_faster_than_baseline": all_faster,
                "all_workloads_faster": all_faster,
                "per_workload": per_workload_verdict,
                "summary": if all_faster {
                    "OrFS completed every workload at least as fast as the same-device host filesystem baseline".to_string()
                } else {
                    "OrFS did NOT complete every workload faster than the same-device host filesystem baseline; the losses are reported per workload".to_string()
                },
            },
            "tmpfs_arm_note": tmpfs_note,
            "write_semantics_probe": write_probe_json,
            "tool_versions": tool_versions(),
            "environment": environment(),
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "caveat": "Single host, single run; wall-clock is host/load-sensitive. The container is \
                        CFS-capped and the host is under external load, so absolute times vary run to \
                        run; the same-device baseline and the order-balanced, repeated trials are what \
                        make the direction meaningful. The image-extraction workload is a SYNTHETIC \
                        OCI-layer-like tarball, not a real `docker pull`. No speedup is claimed without \
                        a measured external baseline in this same container.",
        });
        write_json(&doc);
        println!("application_workloads: wrote evidence/performance/application-workloads.json");
    }

    let _ = mount.unmount();
    let _ = fs::remove_dir_all(&scratch);
}

fn init_volume(backing: &Path) -> Result<(), String> {
    let mut ns = Namespace::init(backing, DEFAULT_SEGMENT_SIZE, DurabilityMode::Ordered)
        .map_err(|e| e.to_string())?;
    // SAFETY: geteuid/getegid are pure queries.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    ns.setattr(
        ROOT_INODE,
        &SetAttr {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        },
    )
    .map_err(|e| e.to_string())?;
    ns.sync().map_err(|e| e.to_string())
}

#[test]
fn application_workloads_smoke() {
    run_court(Scale::smoke(), false, "smoke");
}

#[test]
fn application_workloads_sweep() {
    if std::env::var("ORFS_APP_SWEEP").as_deref() != Ok("1") {
        eprintln!("application_workloads_sweep: skipped (ORFS_APP_SWEEP unset)");
        return;
    }
    run_court(Scale::sweep(), true, "sweep");
}
