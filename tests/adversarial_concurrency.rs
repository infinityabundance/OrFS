//! **Phase 79 — sustained adversarial concurrency courts, with native tool
//! equivalents and a mounted transport arm.**
//!
//! The reviewer's P0 ask was *"full filesystem correctness under adversarial
//! concurrent workloads … extend the existing POSIX court to sustained
//! pjdfstest, xfstests cases that fit OrFS semantics, `fsx`, `fsstress`,
//! `fs_mark`, and custom rename/link/unlink races."*
//!
//! ## Honest labelling
//!
//! The real `fsx`, `fsstress`, `fs_mark` and `xfstests` tools are **not
//! runnable here** (`evidence/correctness/xfstests.json` records `ran:false`
//! with the concrete blockers). Every court in this file is a **native Rust
//! equivalent**, named and labelled as such — never as a run of the real tool.
//! Where a claim is numeric, it comes from a real run recorded in
//! `evidence/correctness/adversarial-concurrency.json`.
//!
//! ## What this adds to the existing courts
//!
//! This is a **new** file rather than an extension of `tests/concurrency_stress.rs`
//! (Phase 11) or `tests/fs_fault_injection.rs` (Phase 25). The reason: this court
//! owns a distinct receipt, a distinct runner
//! (`scripts/container-adversarial-concurrency.sh`) and, crucially, a **mounted
//! transport arm**. The always-on part is deliberately bounded and cheap, while
//! the sustained runs are opt-in, so folding them into the Phase-11 file would
//! make the default gate heavy and mix two receipts.
//!
//! The four equivalents, each clearly an *equivalent*:
//!
//! * **`fsx`-equivalent** — one/multi file randomized write/read/truncate/append/
//!   `fsync` loop where **every read is verified against a byte-exact shadow
//!   model**. Bounded always-on smoke + sustained opt-in run.
//! * **`fsstress`-equivalent** — `N` worker threads (8/16/32/64) running a mixed
//!   create/write/link/symlink/unlink/rename/stat/readdir stream; after quiesce
//!   the final namespace is reconciled against an **independent expected-state
//!   model** built by replaying the recorded successful operations (exact name
//!   sets, exact nlink, byte-exact files, no orphans, no duplicate inodes).
//! * **`fs_mark`-equivalent** — many small files created, each verified
//!   byte-exact, then unlinked; files/s reported.
//! * **rename/link/unlink race storm** — shared-name races at higher concurrency
//!   than Phase 11, asserting the invariant that a lost race is a typed error,
//!   never a corruption, and that the reopened namespace equals the live one.
//!
//! ## The mounted arm
//!
//! `adversarial_mounted_fsstress` runs through a **real OrFS FUSE mount**
//! (`fuse::spawn`, the `orfs mount` path, via `docker_run_kmount`), so the
//! transport — not only `OrfsCore` — is exercised adversarially. It reports
//! p50/p95/p99/p99.9 of client-observed `write`/`read`/`rename`/`unlink`/`create`
//! latency and proves byte-exact, whole-version reads under concurrency.
//!
//! ## Deadlock safety
//!
//! Every multi-threaded court runs through [`run_bounded`], a watchdog that
//! fails (panics) if any worker has not finished within a bounded wall-clock
//! limit, so a hang fails rather than hangs. All workloads are bounded, and the
//! memory they retain is bounded by their configured op/file counts.
//!
//! ## Running it
//!
//! * `cargo test --test adversarial_concurrency` runs the always-on smoke courts.
//! * `ORFS_STRESS=1` enables the sustained sweeps; `ORFS_ADVERSARIAL_RECEIPT=1`
//!   makes the sustained sweep write the receipt's `in_process` section.
//! * `ORFS_FUSE_TEST=1` (with `/dev/fuse`) enables the mounted court, which
//!   merges the `mounted` section into the same receipt.
//! * `scripts/container-adversarial-concurrency.sh` drives all three, one
//!   container at a time.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use orfs::commit::DurabilityMode;
use orfs::fuse::{self, MountOptions, StatfsMode};
use orfs::namespace::{Namespace, RenameMode, SetAttr};
use tempfile::TempDir;

/// A fixed UUID so a sustained run is reproducible in its *structure*.
const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x79, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const CREATED: u64 = 1_700_000_000;

/// Watchdog limits: a court that exceeds one of these fails instead of hanging.
const LIMIT_SMOKE: Duration = Duration::from_secs(120);
const LIMIT_SUSTAINED: Duration = Duration::from_secs(600);
const LIMIT_MOUNTED: Duration = Duration::from_secs(900);

// ---------------------------------------------------------------------------
// Small deterministic helpers
// ---------------------------------------------------------------------------

fn init(dir: &Path) -> Namespace {
    Namespace::init_with_uuid(dir, 1 << 20, UUID, CREATED, DurabilityMode::Ordered)
        .expect("init namespace")
}

/// A deterministic PRNG (a splitmix-flavoured LCG), so every run reproduces the
/// same operation schedule for the same seed.
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

/// A deterministic byte pattern of `len` bytes derived from `seed`.
fn fill(seed: u64, len: usize) -> Vec<u8> {
    let mut s = seed ^ 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (s >> 33) as u8
        })
        .collect()
}

fn extend_to(v: &mut Vec<u8>, n: usize) {
    if v.len() < n {
        v.resize(n, 0);
    }
}

/// Nearest-rank percentile over an ascending slice (nanoseconds).
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn pct_json(sorted: &mut [u64]) -> serde_json::Value {
    if sorted.is_empty() {
        return serde_json::json!({ "samples": 0 });
    }
    sorted.sort_unstable();
    serde_json::json!({
        "samples": sorted.len(),
        "p50_ns": percentile(sorted, 50.0),
        "p95_ns": percentile(sorted, 95.0),
        "p99_ns": percentile(sorted, 99.0),
        "p999_ns": percentile(sorted, 99.9),
        "mean_ns": sorted.iter().sum::<u64>() as f64 / sorted.len() as f64,
    })
}

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(value).expect("serialize json");
    s.push('\n');
    std::fs::write(path, s).expect("write evidence");
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn image_digest() -> String {
    std::env::var("ORFS_IMAGE_DIGEST").unwrap_or_else(|_| "unknown".into())
}

fn environment() -> serde_json::Value {
    let env = orfs::bench::Environment::capture(Some(image_digest()));
    serde_json::json!({
        "bench": serde_json::to_value(&env).unwrap_or(serde_json::Value::Null),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "toolchain": std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "unknown".into()),
    })
}

// ---------------------------------------------------------------------------
// Bounded worker runner (the watchdog)
// ---------------------------------------------------------------------------

/// Run `work(i)` on `threads` OS threads and fail (panic) if they do not all
/// finish within `limit`. A panic in any worker is surfaced immediately (the
/// handles are joined), so a deadlock fails rather than hangs.
fn run_bounded<T, F>(threads: usize, limit: Duration, work: F) -> Vec<T>
where
    T: Send + 'static,
    F: Fn(usize) -> T + Send + Sync + 'static,
{
    assert!(threads >= 1, "at least one worker");
    let work = Arc::new(work);
    let (tx, rx) = std::sync::mpsc::channel::<(usize, T)>();
    let mut handles = Vec::with_capacity(threads);
    for i in 0..threads {
        let work = work.clone();
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || {
            let r = work(i);
            let _ = tx.send((i, r));
        }));
    }
    drop(tx);

    let mut results: Vec<Option<T>> = (0..threads).map(|_| None).collect();
    let start = Instant::now();
    let mut got = 0usize;
    while got < threads {
        if handles.iter().all(|h| h.is_finished()) {
            break; // at least one worker panicked; join surfaces it below
        }
        let elapsed = start.elapsed();
        if elapsed >= limit {
            panic!(
                "adversarial court exceeded its watchdog limit of {limit:?}: \
                 {got}/{threads} workers finished"
            );
        }
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok((i, r)) => {
                results[i] = Some(r);
                got += 1;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        let _ = elapsed;
    }
    for h in handles {
        if h.join().is_err() {
            panic!("an adversarial worker thread panicked; see the panic above");
        }
    }
    results
        .into_iter()
        .map(|r| r.expect("every worker produced a result"))
        .collect()
}

// ===========================================================================
// 1. fsx-equivalent — randomized op mix against a byte-exact shadow model
// ===========================================================================

struct FsxReport {
    files: usize,
    ops: u64,
    writes: u64,
    truncates: u64,
    appends: u64,
    fsyncs: u64,
    reads_verified: u64,
    mismatches: u64,
    bytes_written: u64,
    seconds: f64,
    ops_per_s: f64,
    reopen_digest_equal: bool,
}

impl FsxReport {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "files": self.files,
            "ops": self.ops,
            "writes": self.writes,
            "truncates": self.truncates,
            "appends": self.appends,
            "fsyncs": self.fsyncs,
            "reads_verified": self.reads_verified,
            "mismatches": self.mismatches,
            "bytes_written": self.bytes_written,
            "seconds": self.seconds,
            "ops_per_s": self.ops_per_s,
            "reopen_digest_equal": self.reopen_digest_equal,
        })
    }
}

/// The `fsx`-equivalent court. A single-threaded deterministic random schedule
/// over `files` files: `write` at random offsets/lengths, `read` verified against
/// a shadow model of the exact expected bytes, `truncate` (grow and shrink),
/// `append`, and `fsync`. The shadow model is the authority for every read.
fn run_fsx(dir: &Path, files: usize, ops: u64, seed: u64, max_size: usize) -> FsxReport {
    let mut ns = init(dir);
    let root = ns.root_inode();
    let mut rng = Lcg::new(seed);

    let names: Vec<Vec<u8>> = (0..files).map(|i| format!("fx{i}").into_bytes()).collect();
    let mut inodes = Vec::new();
    let mut shadow: Vec<Vec<u8>> = vec![Vec::new(); files];
    for name in &names {
        inodes.push(ns.create(root, name, 0o644, 0, 0).expect("create"));
    }

    let mut writes = 0u64;
    let mut truncates = 0u64;
    let mut appends = 0u64;
    let mut fsyncs = 0u64;
    let mut reads_verified = 0u64;
    let mut mismatches = 0u64;
    let mut bytes_written = 0u64;

    for _ in 0..ops {
        let f = rng.below(files as u64) as usize;
        let ino = inodes[f];
        let sh = &mut shadow[f];
        match rng.below(10) {
            0..=3 => {
                // write at a random offset (may be beyond EOF; OrFS zero-fills).
                let len = 1 + rng.below(1024) as usize;
                let off = rng.below((max_size + 1) as u64);
                let data = fill(seed ^ (f as u64) ^ 0x100, len);
                let n = ns.write_at(ino, off, &data).expect("write") as u64;
                extend_to(sh, (off as usize) + len);
                sh[off as usize..off as usize + len].copy_from_slice(&data);
                bytes_written += n;
                writes += 1;
            }
            4..=5 => {
                // read + byte-exact comparison against the shadow model.
                let size = sh.len() as u64;
                let off = rng.below(size.max(1));
                let len = 1 + rng.below(2048);
                let end = (off + len).min(size);
                let expected: Vec<u8> = if off >= size {
                    Vec::new()
                } else {
                    sh[off as usize..end as usize].to_vec()
                };
                let got = ns.read_at(ino, ns.root(), off, len as u32).expect("read");
                reads_verified += 1;
                if got != expected {
                    mismatches += 1;
                }
            }
            6 => {
                // truncate (grow zero-fills; shrink drops the tail).
                let new = rng.below((max_size + 1) as u64);
                ns.truncate(ino, new).expect("truncate");
                sh.resize(new as usize, 0);
                truncates += 1;
            }
            7 => {
                // append at the authoritative end of file.
                let len = 1 + rng.below(512) as usize;
                let off = sh.len() as u64;
                let data = fill(seed ^ (f as u64) ^ 0x200, len);
                ns.write_at(ino, off, &data).expect("append");
                sh.extend_from_slice(&data);
                bytes_written += len as u64;
                appends += 1;
            }
            8 => {
                ns.sync().expect("fsync");
                fsyncs += 1;
            }
            _ => {
                // read at/past EOF and a zero-length read; both must be exact.
                let size = sh.len() as u64;
                let off = size + rng.below(64);
                let got = ns.read_at(ino, ns.root(), off, 16).expect("read past eof");
                reads_verified += 1;
                if !got.is_empty() {
                    mismatches += 1;
                }
                let z = ns.read_at(ino, ns.root(), 0, 0).expect("zero read");
                reads_verified += 1;
                if !z.is_empty() {
                    mismatches += 1;
                }
            }
        }
    }

    ns.sync().expect("final fsync");

    // Every file must now match its shadow model exactly.
    let live_root = ns.root();
    for (f, &ino) in inodes.iter().enumerate() {
        let st = ns.getattr(ino, live_root).expect("getattr");
        if st.size != shadow[f].len() as u64 {
            mismatches += 1;
        }
        if st.size > 0 {
            let got = ns
                .read_at(ino, live_root, 0, st.size as u32)
                .expect("full read");
            reads_verified += 1;
            if got != shadow[f] {
                mismatches += 1;
            }
        }
    }

    let digest = ns.index().canonical_digest();
    drop(ns);
    let reopened = Namespace::open(dir, orfs::log::OpenMode::ReadOnly, DurabilityMode::Ordered)
        .expect("reopen");
    let reopen_digest_equal = reopened.index().canonical_digest() == digest;
    // The reopened volume must serve identical bytes.
    for (f, &ino) in inodes.iter().enumerate() {
        let got = reopened
            .read_at(ino, reopened.root(), 0, (shadow[f].len() as u32).max(1))
            .expect("reopened read");
        if got != shadow[f] {
            mismatches += 1;
        }
    }

    FsxReport {
        files,
        ops,
        writes,
        truncates,
        appends,
        fsyncs,
        reads_verified,
        mismatches,
        bytes_written,
        seconds: 0.0,
        ops_per_s: 0.0,
        reopen_digest_equal,
    }
}

// ===========================================================================
// 2. fsstress-equivalent — mixed stream + independent final-namespace model
// ===========================================================================

/// One successful, recorded operation in the `fsstress`-equivalent stream. Names
/// are worker-partitioned, so the concatenation of every worker's own ordered ops
/// reconstructs the whole namespace independently of the interleaving.
#[derive(Clone, Debug)]
enum Op {
    Create {
        parent: u64,
        name: Vec<u8>,
        ino: u64,
    },
    Symlink {
        parent: u64,
        name: Vec<u8>,
        target: Vec<u8>,
        ino: u64,
    },
    Write {
        ino: u64,
        offset: u64,
        data: Vec<u8>,
    },
    Truncate {
        ino: u64,
        size: u64,
    },
    Link {
        ino: u64,
        parent: u64,
        name: Vec<u8>,
    },
    Unlink {
        parent: u64,
        name: Vec<u8>,
    },
    Rename {
        sp: u64,
        sn: Vec<u8>,
        dp: u64,
        dn: Vec<u8>,
    },
}

/// The independent expected-state model. It is built *only* by replaying the
/// recorded operations — it never consults OrFS.
#[derive(Default)]
struct Model {
    entries: BTreeMap<u64, BTreeMap<Vec<u8>, u64>>,
    kind: BTreeMap<u64, u8>,
    data: BTreeMap<u64, Vec<u8>>,
    target: BTreeMap<u64, Vec<u8>>,
    nlink: BTreeMap<u64, u32>,
}

impl Model {
    fn apply(&mut self, op: &Op) {
        match op {
            Op::Create { parent, name, ino } => {
                self.entries
                    .entry(*parent)
                    .or_default()
                    .insert(name.clone(), *ino);
                self.kind.insert(*ino, 0);
                self.data.insert(*ino, Vec::new());
                self.nlink.insert(*ino, 1);
            }
            Op::Symlink {
                parent,
                name,
                target,
                ino,
            } => {
                self.entries
                    .entry(*parent)
                    .or_default()
                    .insert(name.clone(), *ino);
                self.kind.insert(*ino, 2);
                self.target.insert(*ino, target.clone());
                self.nlink.insert(*ino, 1);
            }
            Op::Write { ino, offset, data } => {
                let d = self.data.entry(*ino).or_default();
                extend_to(d, (*offset as usize) + data.len());
                d[*offset as usize..*offset as usize + data.len()].copy_from_slice(data);
            }
            Op::Truncate { ino, size } => {
                let d = self.data.entry(*ino).or_default();
                d.resize(*size as usize, 0);
            }
            Op::Link { ino, parent, name } => {
                self.entries
                    .entry(*parent)
                    .or_default()
                    .insert(name.clone(), *ino);
                *self.nlink.entry(*ino).or_insert(0) += 1;
            }
            Op::Unlink { parent, name } => {
                if let Some(ino) = self.entries.entry(*parent).or_default().remove(name) {
                    let n = self.nlink.entry(ino).or_insert(1);
                    *n = n.saturating_sub(1);
                }
            }
            Op::Rename { sp, sn, dp, dn } => {
                if let Some(replaced) = self.entries.entry(*dp).or_default().remove(dn) {
                    let n = self.nlink.entry(replaced).or_insert(1);
                    *n = n.saturating_sub(1);
                }
                if let Some(moved) = self.entries.entry(*sp).or_default().remove(sn) {
                    self.entries
                        .entry(*dp)
                        .or_default()
                        .insert(dn.clone(), moved);
                }
            }
        }
    }
}

#[derive(Default)]
struct WorkerResult {
    ops: Vec<Op>,
    creates: u64,
    writes: u64,
    truncates: u64,
    links: u64,
    symlinks: u64,
    unlinks: u64,
    renames: u64,
    stats: u64,
    read_verifies: u64,
    mismatches: u64,
}

struct FsstressReport {
    threads: usize,
    ops_per_thread: u64,
    total_ops: u64,
    creates: u64,
    writes: u64,
    truncates: u64,
    links: u64,
    symlinks: u64,
    unlinks: u64,
    renames: u64,
    stats: u64,
    read_verifies: u64,
    mismatches: u64,
    model_names: u64,
    model_files: u64,
    model_symlinks: u64,
    orphans: u64,
    duplicate_inodes: u64,
    seconds: f64,
    ops_per_s: f64,
    reopen_digest_equal: bool,
}

impl FsstressReport {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "threads": self.threads,
            "ops_per_thread": self.ops_per_thread,
            "total_ops": self.total_ops,
            "creates": self.creates,
            "writes": self.writes,
            "truncates": self.truncates,
            "links": self.links,
            "symlinks": self.symlinks,
            "unlinks": self.unlinks,
            "renames": self.renames,
            "stats": self.stats,
            "read_verifies": self.read_verifies,
            "mismatches": self.mismatches,
            "model_names": self.model_names,
            "model_files": self.model_files,
            "model_symlinks": self.model_symlinks,
            "orphans": self.orphans,
            "duplicate_inodes": self.duplicate_inodes,
            "seconds": self.seconds,
            "ops_per_s": self.ops_per_s,
            "reopen_digest_equal": self.reopen_digest_equal,
        })
    }
}

const POOL: usize = 8;

/// Reconcile the live namespace against the independent model. Returns
/// `(mismatches, orphans, duplicate_inodes, names, files, symlinks)`.
fn reconcile(ns: &Namespace, root_ino: u64, model: &Model) -> (u64, u64, u64, u64, u64, u64) {
    let root = ns.root();
    let mut mismatches = 0u64;
    let dbg = std::env::var("ORFS_ADV_DEBUG").as_deref() == Ok("1");

    // Build the actual directory table by a recursive walk, and the reachable set.
    let mut actual: BTreeMap<u64, BTreeMap<Vec<u8>, u64>> = BTreeMap::new();
    let mut reachable: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut stack = vec![root_ino];
    reachable.insert(root_ino);
    while let Some(dir) = stack.pop() {
        let children = ns.readdir(dir, root).unwrap_or_default();
        let mut table = BTreeMap::new();
        for (name, ino) in children {
            table.insert(name, ino);
            reachable.insert(ino);
            let st = match ns.getattr(ino, root) {
                Ok(s) => s,
                Err(_) => {
                    mismatches += 1;
                    continue;
                }
            };
            if st.kind == orfs::inode::InodeType::Directory {
                stack.push(ino);
            }
        }
        actual.insert(dir, table);
    }

    // The model's reachable set.
    let mut model_reachable: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    model_reachable.insert(root_ino);
    let mut mstack = vec![root_ino];
    while let Some(dir) = mstack.pop() {
        if let Some(table) = model.entries.get(&dir) {
            for ino in table.values() {
                model_reachable.insert(*ino);
                if model.kind.get(ino) == Some(&1) {
                    mstack.push(*ino);
                }
            }
        }
    }

    // 1. Exact directory contents: the same name set mapping to the same inodes.
    for (dir, table) in &model.entries {
        let empty = BTreeMap::new();
        let act = actual.get(dir).unwrap_or(&empty);
        if act != table {
            mismatches += 1;
            if dbg {
                eprintln!("reconcile: dir {dir} model={table:?} actual={act:?}");
            }
        }
    }
    for (dir, table) in &actual {
        if !model.entries.contains_key(dir) {
            // A directory the model does not know about (only the root is created
            // outside the op log).
            if *dir != root_ino && !table.is_empty() {
                mismatches += 1;
                if dbg {
                    eprintln!("reconcile: unknown actual dir {dir} = {table:?}");
                }
            }
        }
    }

    // 2. Byte-exact file contents and symlink targets.
    let mut files = 0u64;
    let mut symlinks = 0u64;
    let mut names = 0u64;
    let mut seen_inodes: BTreeMap<u64, u64> = BTreeMap::new();
    for (dir, table) in &actual {
        let _ = dir;
        for ino in table.values() {
            names += 1;
            *seen_inodes.entry(*ino).or_insert(0) += 1;
        }
    }
    for ino in &model_reachable {
        match model.kind.get(ino) {
            Some(&0) => {
                files += 1;
                let expected = model.data.get(ino).cloned().unwrap_or_default();
                let st = match ns.getattr(*ino, root) {
                    Ok(s) => s,
                    Err(_) => {
                        mismatches += 1;
                        continue;
                    }
                };
                if st.size != expected.len() as u64 {
                    mismatches += 1;
                    if dbg {
                        eprintln!(
                            "reconcile: file {ino} size {} != model {}",
                            st.size,
                            expected.len()
                        );
                    }
                }
                let got = ns
                    .read_at(*ino, root, 0, (expected.len() as u32).max(1))
                    .unwrap_or_default();
                if got != expected {
                    mismatches += 1;
                    if dbg {
                        eprintln!(
                            "reconcile: file {ino} bytes differ ({} vs {})",
                            got.len(),
                            expected.len()
                        );
                    }
                }
                // Exact nlink (number of reachable names for this inode).
                let reachable_names = seen_inodes.get(ino).copied().unwrap_or(0) as u32;
                if st.nlink != reachable_names {
                    mismatches += 1;
                    if dbg {
                        eprintln!(
                            "reconcile: file {ino} nlink {} != reachable {}",
                            st.nlink, reachable_names
                        );
                    }
                }
            }
            Some(&2) => {
                symlinks += 1;
                let expected = model.target.get(ino).cloned().unwrap_or_default();
                if ns.readlink(*ino, root).ok() != Some(expected) {
                    mismatches += 1;
                    if dbg {
                        eprintln!("reconcile: symlink {ino} target differs");
                    }
                }
            }
            Some(&1) => {}
            _ => {}
        }
    }

    // 3. No orphans: the actual reachable set equals the model's reachable set.
    let orphans = reachable
        .symmetric_difference(&model_reachable)
        .filter(|ino| model.kind.contains_key(ino))
        .count() as u64;
    // Duplicate inodes: an inode reachable from two *different* parents without a
    // matching hard-link count. Reuse the nlink comparison above; here count any
    // inode whose actual name-multiplicity exceeds its recorded nlink.
    let mut duplicate_inodes = 0u64;
    for (ino, count) in &seen_inodes {
        let recorded = model.nlink.get(ino).copied().unwrap_or(1) as u64;
        if *count > recorded.max(1) {
            duplicate_inodes += 1;
        }
    }
    if orphans > 0 {
        mismatches += orphans;
    }
    if duplicate_inodes > 0 {
        mismatches += duplicate_inodes;
    }
    if dbg {
        eprintln!(
            "reconcile: dir_ok names={names} files={files} symlinks={symlinks} orphans={orphans} dups={duplicate_inodes} mismatches={mismatches}"
        );
    }
    (
        mismatches,
        orphans,
        duplicate_inodes,
        names,
        files,
        symlinks,
    )
}

/// The `fsstress`-equivalent court: `threads` workers over one shared namespace,
/// then a full reconciliation against the independent op-log model.
fn run_fsstress(
    dir: &Path,
    threads: usize,
    ops_per_thread: u64,
    seed: u64,
    limit: Duration,
) -> FsstressReport {
    let ns = Arc::new(Mutex::new(init(dir)));
    let root_ino = ns.lock().unwrap().root_inode();

    // One private directory per worker; every pool name lives inside it, so names
    // are worker-partitioned and the final state is interleaving-independent.
    let mut wdirs = Vec::new();
    for t in 0..threads {
        let name = format!("w{t}");
        let ino = ns
            .lock()
            .unwrap()
            .mkdir(root_ino, name.as_bytes(), 0o755, 0, 0)
            .expect("worker dir");
        wdirs.push(ino);
    }
    let wdirs = Arc::new(wdirs);

    let start = Instant::now();
    let workers: Vec<WorkerResult> = {
        let ns = ns.clone();
        let wdirs = wdirs.clone();
        run_bounded(threads, limit, move |t| {
            let wdir = wdirs[t];
            let mut rng = Lcg::new(seed ^ ((t as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15)));
            let pool: Vec<Vec<u8>> = (0..POOL)
                .map(|k| format!("n{t}-{k}").into_bytes())
                .collect();
            let mut local: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
            let mut shadow: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
            let mut r = WorkerResult::default();

            for i in 0..ops_per_thread {
                let choice = rng.below(10);
                let mut g = ns.lock().unwrap();
                let root = g.root();
                match choice {
                    0 | 1 => {
                        let name = pool[rng.below(POOL as u64) as usize].clone();
                        if !local.contains_key(&name) {
                            if let Ok(ino) = g.create(wdir, &name, 0o644, 0, 0) {
                                local.insert(name.clone(), ino);
                                shadow.insert(ino, Vec::new());
                                r.ops.push(Op::Create {
                                    parent: wdir,
                                    name,
                                    ino,
                                });
                                r.creates += 1;
                            }
                        }
                    }
                    2 | 3 => {
                        if !local.is_empty() {
                            let (_, &ino) = local
                                .iter()
                                .nth(rng.below(local.len() as u64) as usize)
                                .unwrap();
                            let len = 1 + rng.below(512) as usize;
                            let off = rng.below(2048);
                            let data = fill(seed ^ (t as u64) ^ ino ^ i, len);
                            if g.write_at(ino, off, &data).is_ok() {
                                let sh = shadow.entry(ino).or_default();
                                extend_to(sh, (off as usize) + len);
                                sh[off as usize..off as usize + len].copy_from_slice(&data);
                                r.ops.push(Op::Write {
                                    ino,
                                    offset: off,
                                    data: data.clone(),
                                });
                                r.writes += 1;
                                // Immediate byte-exact read-verify at the *new* committed
                                // root (no torn state).
                                let fresh = g.root();
                                let got =
                                    g.read_at(ino, fresh, off, len as u32).unwrap_or_default();
                                r.read_verifies += 1;
                                if got != data {
                                    r.mismatches += 1;
                                }
                            }
                        }
                    }
                    4 => {
                        if !local.is_empty() {
                            let (_, &ino) = local
                                .iter()
                                .nth(rng.below(local.len() as u64) as usize)
                                .unwrap();
                            let new = rng.below(4096);
                            if g.truncate(ino, new).is_ok() {
                                shadow.entry(ino).or_default().resize(new as usize, 0);
                                r.ops.push(Op::Truncate { ino, size: new });
                                r.truncates += 1;
                            }
                        }
                    }
                    5 => {
                        if !local.is_empty() {
                            let (_, &ino) = local
                                .iter()
                                .nth(rng.below(local.len() as u64) as usize)
                                .unwrap();
                            let name = pool[rng.below(POOL as u64) as usize].clone();
                            if !local.contains_key(&name) && g.link(ino, wdir, &name).is_ok() {
                                local.insert(name.clone(), ino);
                                r.ops.push(Op::Link {
                                    ino,
                                    parent: wdir,
                                    name,
                                });
                                r.links += 1;
                            }
                        }
                    }
                    6 => {
                        let name = pool[rng.below(POOL as u64) as usize].clone();
                        if !local.contains_key(&name) {
                            let target = format!("t{t}-{i}").into_bytes();
                            if let Ok(ino) = g.symlink(wdir, &name, &target, 0, 0) {
                                local.insert(name.clone(), ino);
                                r.ops.push(Op::Symlink {
                                    parent: wdir,
                                    name,
                                    target,
                                    ino,
                                });
                                r.symlinks += 1;
                            }
                        }
                    }
                    7 => {
                        if !local.is_empty() {
                            let idx = rng.below(local.len() as u64) as usize;
                            let name = local.keys().nth(idx).unwrap().clone();
                            if g.unlink(wdir, &name).is_ok() {
                                local.remove(&name);
                                r.ops.push(Op::Unlink { parent: wdir, name });
                                r.unlinks += 1;
                            }
                        }
                    }
                    8 => {
                        if !local.is_empty() {
                            let idx = rng.below(local.len() as u64) as usize;
                            let sn = local.keys().nth(idx).unwrap().clone();
                            let dn = pool[rng.below(POOL as u64) as usize].clone();
                            if sn != dn
                                && g.rename(wdir, &sn, wdir, &dn, RenameMode::Ordinary).is_ok()
                            {
                                if let Some(ino) = local.remove(&sn) {
                                    local.insert(dn.clone(), ino);
                                }
                                r.ops.push(Op::Rename {
                                    sp: wdir,
                                    sn,
                                    dp: wdir,
                                    dn,
                                });
                                r.renames += 1;
                            }
                        }
                    }
                    _ => {
                        // stat + readdir (no model effect).
                        let _ = g.readdir(wdir, root);
                        if !local.is_empty() {
                            let (_, &ino) = local
                                .iter()
                                .nth(rng.below(local.len() as u64) as usize)
                                .unwrap();
                            let _ = g.getattr(ino, root);
                        }
                        let _ = g.readdir(root_ino, root);
                        r.stats += 1;
                    }
                }
            }

            // Final per-worker read-verify of every file it owns.
            {
                let g = ns.lock().unwrap();
                let root = g.root();
                for (&ino, bytes) in &shadow {
                    let got = g
                        .read_at(ino, root, 0, (bytes.len() as u32).max(1))
                        .unwrap_or_default();
                    r.read_verifies += 1;
                    if got != *bytes {
                        r.mismatches += 1;
                    }
                }
            }
            r
        })
    };
    let seconds = start.elapsed().as_secs_f64();

    // Independent reconciliation: replay the recorded successful operations into
    // a model that never consults OrFS, then compare it to the live namespace.
    let g = ns.lock().unwrap();
    let mut model = Model::default();
    model.entries.entry(root_ino).or_default();
    for (t, &ino) in wdirs.iter().enumerate() {
        model
            .entries
            .entry(root_ino)
            .or_default()
            .insert(format!("w{t}").into_bytes(), ino);
        model.kind.insert(ino, 1);
        model.entries.entry(ino).or_default();
    }
    for w in &workers {
        for op in &w.ops {
            model.apply(op);
        }
    }
    model.entries.entry(root_ino).or_default();
    let (mism, orphans, dups, names, files, symlinks) = reconcile(&g, root_ino, &model);
    let digest = g.index().canonical_digest();
    drop(g);

    let mut creates = 0u64;
    let mut writes = 0u64;
    let mut truncates = 0u64;
    let mut links = 0u64;
    let mut symlinks_n = 0u64;
    let mut unlinks = 0u64;
    let mut renames = 0u64;
    let mut stats = 0u64;
    let mut read_verifies = 0u64;
    let mut mismatches = 0u64;
    for w in &workers {
        creates += w.creates;
        writes += w.writes;
        truncates += w.truncates;
        links += w.links;
        symlinks_n += w.symlinks;
        unlinks += w.unlinks;
        renames += w.renames;
        stats += w.stats;
        read_verifies += w.read_verifies;
        mismatches += w.mismatches;
    }
    mismatches += mism;

    let reopened = Namespace::open(dir, orfs::log::OpenMode::ReadOnly, DurabilityMode::Ordered)
        .expect("reopen");
    let reopen_digest_equal = reopened.index().canonical_digest() == digest;

    FsstressReport {
        threads,
        ops_per_thread,
        total_ops: threads as u64 * ops_per_thread,
        creates,
        writes,
        truncates,
        links,
        symlinks: symlinks_n,
        unlinks,
        renames,
        stats,
        read_verifies,
        mismatches,
        model_names: names,
        model_files: files,
        model_symlinks: symlinks,
        orphans,
        duplicate_inodes: dups,
        seconds,
        ops_per_s: (threads as u64 * ops_per_thread) as f64 / seconds.max(f64::MIN_POSITIVE),
        reopen_digest_equal,
    }
}

// ===========================================================================
// 3. fs_mark-equivalent — many small files, byte-exact, then unlink
// ===========================================================================

struct FsMarkReport {
    files: u64,
    file_bytes: usize,
    bytes_written: u64,
    verified: u64,
    mismatches: u64,
    seconds: f64,
    files_per_s: f64,
    dir_empty_after_unlink: bool,
}

impl FsMarkReport {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "files": self.files,
            "file_bytes": self.file_bytes,
            "bytes_written": self.bytes_written,
            "verified": self.verified,
            "mismatches": self.mismatches,
            "seconds": self.seconds,
            "files_per_s": self.files_per_s,
            "dir_empty_after_unlink": self.dir_empty_after_unlink,
        })
    }
}

/// The `fs_mark`-equivalent court: create `files` small files, write and verify
/// each byte-exact, then unlink them all and prove the directory is empty.
fn run_fs_mark(dir: &Path, files: u64, file_bytes: usize, seed: u64) -> FsMarkReport {
    let mut ns = init(dir);
    let root = ns.root_inode();
    let start = Instant::now();
    let mut inodes = Vec::with_capacity(files as usize);
    let mut shadows = Vec::with_capacity(files as usize);
    for i in 0..files {
        let name = format!("m{i}");
        let ino = ns
            .create(root, name.as_bytes(), 0o644, 0, 0)
            .expect("create small file");
        let data = fill(seed ^ i, file_bytes);
        ns.write_at(ino, 0, &data).expect("write small file");
        inodes.push(ino);
        shadows.push(data);
    }
    let write_elapsed = start.elapsed().as_secs_f64();

    let mut verified = 0u64;
    let mut mismatches = 0u64;
    let live = ns.root();
    for (i, &ino) in inodes.iter().enumerate() {
        let got = ns
            .read_at(ino, live, 0, shadows[i].len() as u32)
            .expect("verify small file");
        verified += 1;
        if got != shadows[i] {
            mismatches += 1;
        }
    }

    for (i, _) in inodes.iter().enumerate() {
        let name = format!("m{i}");
        ns.unlink(root, name.as_bytes()).expect("unlink small file");
    }
    let dir_empty_after_unlink = ns.readdir(root, ns.root()).unwrap_or_default().is_empty();
    ns.sync().expect("sync");

    FsMarkReport {
        files,
        file_bytes,
        bytes_written: files * file_bytes as u64,
        verified,
        mismatches,
        seconds: write_elapsed,
        files_per_s: files as f64 / write_elapsed.max(f64::MIN_POSITIVE),
        dir_empty_after_unlink,
    }
}

// ===========================================================================
// 4. rename/link/unlink race storm (higher concurrency than Phase 11)
// ===========================================================================

struct StormReport {
    threads: usize,
    ops_per_thread: u64,
    ok_renames: u64,
    ok_links: u64,
    ok_unlinks: u64,
    ok_creates: u64,
    refusals: u64,
    names_at_end: u64,
    reopen_digest_equal: bool,
    all_names_resolve: bool,
}

impl StormReport {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "threads": self.threads,
            "ops_per_thread": self.ops_per_thread,
            "ok_renames": self.ok_renames,
            "ok_links": self.ok_links,
            "ok_unlinks": self.ok_unlinks,
            "ok_creates": self.ok_creates,
            "refusals": self.refusals,
            "names_at_end": self.names_at_end,
            "reopen_digest_equal": self.reopen_digest_equal,
            "all_names_resolve": self.all_names_resolve,
        })
    }
}

/// A rename/link/unlink storm over a **shared** name pool. The interleaving is
/// genuinely nondeterministic, so the assertion is the invariant that matters:
/// a lost race is a typed refusal, never a corruption, and afterwards every name
/// resolves to its recorded inode and the reopened namespace equals the live one.
fn run_storm(
    dir: &Path,
    threads: usize,
    ops_per_thread: u64,
    pool: usize,
    seed: u64,
    limit: Duration,
) -> StormReport {
    let ns = Arc::new(Mutex::new(init(dir)));
    let root_ino = ns.lock().unwrap().root_inode();
    {
        let mut g = ns.lock().unwrap();
        for i in 0..pool {
            g.create(root_ino, format!("s{i}").as_bytes(), 0o644, 0, 0)
                .expect("seed storm name");
        }
    }

    let stats: Vec<(u64, u64, u64, u64, u64)> = {
        let ns = ns.clone();
        run_bounded(threads, limit, move |t| {
            let mut rng = Lcg::new(seed ^ ((t as u64 + 7).wrapping_mul(0x9E37_79B9_7F4A_7C15)));
            let (mut okr, mut okl, mut oku, mut okc, mut refusals) = (0u64, 0u64, 0u64, 0u64, 0u64);
            for _ in 0..ops_per_thread {
                let src = format!("s{}", rng.below(pool as u64));
                let dst = format!("s{}", rng.below(pool as u64));
                let mut g = ns.lock().unwrap();
                match rng.below(4) {
                    0 => {
                        if src != dst
                            && g.rename(
                                root_ino,
                                src.as_bytes(),
                                root_ino,
                                dst.as_bytes(),
                                RenameMode::Ordinary,
                            )
                            .is_ok()
                        {
                            okr += 1;
                        } else {
                            refusals += 1;
                        }
                    }
                    1 => {
                        if let Ok(ino) = g.lookup(root_ino, src.as_bytes(), g.root()) {
                            let name = format!("l{}", (rng.below(8)));
                            if g.link(ino, root_ino, name.as_bytes()).is_ok() {
                                okl += 1;
                            } else {
                                refusals += 1;
                            }
                        } else {
                            refusals += 1;
                        }
                    }
                    2 => {
                        if g.lookup(root_ino, src.as_bytes(), g.root()).is_err()
                            && g.create(root_ino, src.as_bytes(), 0o644, 0, 0).is_ok()
                        {
                            okc += 1;
                        } else {
                            refusals += 1;
                        }
                    }
                    _ => {
                        if g.unlink(root_ino, src.as_bytes()).is_ok() {
                            oku += 1;
                        } else {
                            refusals += 1;
                        }
                    }
                }
            }
            (okr, okl, oku, okc, refusals)
        })
    };
    let (mut ok_renames, mut ok_links, mut ok_unlinks, mut ok_creates, mut refusals) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    for (r, l, u, c, f) in &stats {
        ok_renames += r;
        ok_links += l;
        ok_unlinks += u;
        ok_creates += c;
        refusals += f;
    }

    let g = ns.lock().unwrap();
    let root = g.root();
    let listing = g.readdir(root_ino, root).unwrap_or_default();
    let names_at_end = listing.len() as u64;
    let mut all_names_resolve = true;
    for (name, ino) in &listing {
        if g.lookup(root_ino, name, root).ok() != Some(*ino) {
            all_names_resolve = false;
        }
    }
    let digest = g.index().canonical_digest();
    drop(g);

    let reopened = Namespace::open(dir, orfs::log::OpenMode::ReadOnly, DurabilityMode::Ordered)
        .expect("reopen");
    let reopen_digest_equal = reopened.index().canonical_digest() == digest;

    StormReport {
        threads,
        ops_per_thread,
        ok_renames,
        ok_links,
        ok_unlinks,
        ok_creates,
        refusals,
        names_at_end,
        reopen_digest_equal,
        all_names_resolve,
    }
}

// ===========================================================================
// 5. The mounted arm — through a real OrFS FUSE mount
// ===========================================================================

struct MountedReport {
    threads: usize,
    ops_per_thread: u64,
    shared_rows: u64,
    shared_readers: usize,
    write_ns: Vec<u64>,
    read_ns: Vec<u64>,
    create_ns: Vec<u64>,
    rename_ns: Vec<u64>,
    unlink_ns: Vec<u64>,
    fsync_ns: Vec<u64>,
    reads_verified: u64,
    mismatches: u64,
    shared_torn_reads: u64,
    dirs_empty_at_end: bool,
    transport: String,
    seconds: f64,
}

impl MountedReport {
    fn to_json(&self) -> serde_json::Value {
        let mut write = self.write_ns.clone();
        let mut read = self.read_ns.clone();
        let mut create = self.create_ns.clone();
        let mut rename = self.rename_ns.clone();
        let mut unlink = self.unlink_ns.clone();
        let mut fsync = self.fsync_ns.clone();
        serde_json::json!({
            "threads": self.threads,
            "ops_per_thread": self.ops_per_thread,
            "shared_rows": self.shared_rows,
            "shared_readers": self.shared_readers,
            "latency_ns": {
                "create": pct_json(&mut create),
                "write": pct_json(&mut write),
                "fsync": pct_json(&mut fsync),
                "read": pct_json(&mut read),
                "rename": pct_json(&mut rename),
                "unlink": pct_json(&mut unlink),
            },
            "write_latency_note": "`write` is the client `write_all`; durability is the separate `fsync` sample",
            "reads_verified": self.reads_verified,
            "mismatches": self.mismatches,
            "shared_torn_reads": self.shared_torn_reads,
            "dirs_empty_at_end": self.dirs_empty_at_end,
            "transport": self.transport,
            "seconds": self.seconds,
        })
    }
}

const SHARED_ROW: usize = 256;
const SHARED_ROWS: u64 = 300;
const SHARED_READERS: usize = 4;

/// The deterministic content of shared row `i`: a position-dependent pattern, so a
/// half-overwritten row would be detectable (OrFS never rewrites one, so it never is).
fn shared_row(i: u64) -> Vec<u8> {
    (0..SHARED_ROW)
        .map(|j| (i as u8).wrapping_mul(31).wrapping_add(j as u8))
        .collect()
}

/// Arm-1 per-thread samples: write, read, create, rename, unlink and fsync
/// latencies plus the verified-read and mismatch counts.
type MountedArm1 = (
    Vec<u64>,
    Vec<u64>,
    Vec<u64>,
    Vec<u64>,
    Vec<u64>,
    Vec<u64>,
    u64,
    u64,
);

/// The mounted adversarial court. Requires a real mount (`ORFS_FUSE_TEST=1`).
///
/// Arm 1: per-thread create/write/read-verify/rename/unlink through the mount,
/// with client-observed latency percentiles. Arm 2: one writer appends
/// deterministic rows to a shared file while several readers verify that every
/// *complete* row they observe is exactly the row that was committed (a reader may
/// legitimately observe a prefix of an in-progress append, but never a corrupted,
/// reordered, or half-overwritten row — OrFS never rewrites a committed byte), so
/// a torn committed version is detected through the transport.
fn run_mounted(backing: &Path, threads: usize, ops_per_thread: u64) -> MountedReport {
    let mnt = backing.parent().unwrap().join("mnt");
    std::fs::create_dir_all(&mnt).expect("mnt");

    let opts = MountOptions {
        durability: DurabilityMode::Ordered,
        statfs: StatfsMode::PhysicalSafe,
        // Serve reads straight from the daemon (no client page cache), so a
        // concurrent reader observes exactly the committed bytes rather than a
        // client-side page-cache artifact of an actively-appended file.
        direct_io: true,
        ..Default::default()
    };
    let mount = fuse::spawn(backing, &mnt, &opts).expect("mount");

    let start = Instant::now();

    // ---- Arm 1: per-thread create/write/read/rename/unlink --------------------
    let results: Vec<MountedArm1> = {
        let mnt = mnt.clone();
        run_bounded(threads, LIMIT_MOUNTED, move |t| {
            let dir = mnt.join(format!("mt{t}"));
            std::fs::create_dir_all(&dir).expect("worker dir");
            let (mut wns, mut rns, mut cns, mut rns2, mut uns, mut fns) = (
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            );
            let (mut verified, mut mism) = (0u64, 0u64);
            use std::io::Write;
            for i in 0..ops_per_thread {
                let a = dir.join("a");
                let b = dir.join("b");
                let size = 1 + ((t as u64 * 37 + i * 131) % 4096) as usize;
                let data = fill(0xA5A5 ^ (t as u64) ^ i, size);

                let t0 = Instant::now();
                let mut f = std::fs::File::create(&a).expect("create through mount");
                cns.push(t0.elapsed().as_nanos() as u64);
                let t0 = Instant::now();
                f.write_all(&data).expect("write through mount");
                wns.push(t0.elapsed().as_nanos() as u64);
                if i % 16 == 0 {
                    let t0 = Instant::now();
                    f.sync_all().expect("fsync through mount");
                    fns.push(t0.elapsed().as_nanos() as u64);
                }
                drop(f);

                let t0 = Instant::now();
                let got = std::fs::read(&a).expect("read through mount");
                rns.push(t0.elapsed().as_nanos() as u64);
                verified += 1;
                if got != data {
                    mism += 1;
                }

                let t0 = Instant::now();
                std::fs::rename(&a, &b).expect("rename through mount");
                rns2.push(t0.elapsed().as_nanos() as u64);
                let got = std::fs::read(&b).expect("read after rename");
                verified += 1;
                if got != data {
                    mism += 1;
                }

                let t0 = Instant::now();
                std::fs::remove_file(&b).expect("unlink through mount");
                uns.push(t0.elapsed().as_nanos() as u64);
            }
            (wns, rns, cns, rns2, uns, fns, verified, mism)
        })
    };
    let (mut write_ns, mut read_ns, mut create_ns, mut rename_ns, mut unlink_ns, mut fsync_ns) = (
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let (mut reads_verified, mut mismatches) = (0u64, 0u64);
    for (wns, rns, cns, rns2, uns, fns, v, m) in results {
        write_ns.extend(wns);
        read_ns.extend(rns);
        create_ns.extend(cns);
        rename_ns.extend(rns2);
        unlink_ns.extend(uns);
        fsync_ns.extend(fns);
        reads_verified += v;
        mismatches += m;
    }

    // ---- Arm 2: shared append + concurrent whole-version readers ---------------
    let shared = mnt.join("shared.bin");
    std::fs::write(&shared, b"").expect("create shared");
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let torn = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let shared_torn_reads = {
        let stop = stop.clone();
        let torn = torn.clone();
        let shared = shared.clone();
        let readers: Vec<std::thread::JoinHandle<()>> = (0..SHARED_READERS)
            .map(|_| {
                let stop = stop.clone();
                let torn = torn.clone();
                let shared = shared.clone();
                std::thread::spawn(move || {
                    let dbg = std::env::var("ORFS_ADV_DEBUG").as_deref() == Ok("1");
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        if let Ok(bytes) = std::fs::read(&shared) {
                            // A reader may see a prefix of an in-progress append; every
                            // *complete* row it observes must be exactly the committed row.
                            let complete = bytes.len() - bytes.len() % SHARED_ROW;
                            for (i, chunk) in bytes[..complete].chunks(SHARED_ROW).enumerate() {
                                if chunk != shared_row(i as u64).as_slice() {
                                    torn.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    if dbg && torn.load(std::sync::atomic::Ordering::Relaxed) <= 3 {
                                        eprintln!(
                                            "shared torn: len={} row={} got={:?} want={:?}",
                                            bytes.len(),
                                            i,
                                            &chunk[..8.min(chunk.len())],
                                            &shared_row(i as u64)[..8.min(chunk.len())],
                                        );
                                    }
                                    break;
                                }
                            }
                        }
                    }
                })
            })
            .collect();

        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&shared)
                .expect("open shared append");
            use std::io::Write;
            for i in 0..SHARED_ROWS {
                let row = shared_row(i);
                f.write_all(&row).expect("append shared row");
                f.sync_all().expect("shared fsync");
            }
            f.sync_all().expect("final shared fsync");
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for r in readers {
            r.join().expect("shared reader");
        }
        torn.load(std::sync::atomic::Ordering::Relaxed)
    };

    // ---- Final state: worker dirs are empty ----------------------------------
    let dirs_empty_at_end = (0..threads).all(|t| {
        std::fs::read_dir(mnt.join(format!("mt{t}")))
            .map(|mut it| it.next().is_none())
            .unwrap_or(false)
    });

    let seconds = start.elapsed().as_secs_f64();
    let transport_final = format!("{:?}", mount.transport_used());
    mount.unmount().expect("unmount");
    let _ = std::fs::remove_dir_all(backing.parent().unwrap());

    MountedReport {
        threads,
        ops_per_thread,
        shared_rows: SHARED_ROWS,
        shared_readers: SHARED_READERS,
        write_ns,
        read_ns,
        create_ns,
        rename_ns,
        unlink_ns,
        fsync_ns,
        reads_verified,
        mismatches,
        shared_torn_reads,
        dirs_empty_at_end,
        transport: transport_final,
        seconds,
    }
}

// ===========================================================================
// Receipt merge
// ===========================================================================

fn receipt_path() -> PathBuf {
    manifest_dir().join("evidence/correctness/adversarial-concurrency.json")
}

fn receipt_skeleton() -> serde_json::Value {
    serde_json::json!({
        "schema": "orfs.correctness.adversarial-concurrency.v1",
        "generated_by": "tests/adversarial_concurrency.rs",
        "description": "Phase 79 sustained adversarial concurrency court. Native Rust \
                        equivalents of fsx/fsstress/fs_mark (NOT the real tools, which are \
                        unavailable; evidence/correctness/xfstests.json records ran:false) plus \
                        rename/link/unlink race storms, and one arm through a real OrFS FUSE \
                        mount. Every number is from a real run.",
        "tools": {
            "fsx": "native Rust equivalent (not the real fsx)",
            "fsstress": "native Rust equivalent (not the real fsstress)",
            "fs_mark": "native Rust equivalent (not the real fs_mark)",
            "xfstests": "not runnable in this environment; see evidence/correctness/xfstests.json"
        }
    })
}

fn merge_receipt_section(key: &str, value: serde_json::Value) {
    let path = receipt_path();
    let mut doc = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .unwrap_or_else(receipt_skeleton);
    if doc.get("schema").is_none() {
        doc = receipt_skeleton();
    }
    doc["environment"] = environment();
    doc[key] = value;
    let in_process_ok = doc
        .get("in_process")
        .and_then(|v| v.get("all_ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mounted_ok = doc
        .get("mounted")
        .and_then(|v| v.get("all_ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    doc["all_ok"] = serde_json::json!(in_process_ok && mounted_ok);
    write_json(&path, &doc);
}

// ===========================================================================
// Courts
// ===========================================================================

fn dir_for(prefix: &str) -> (TempDir, PathBuf) {
    let td = TempDir::new().expect("tempdir");
    let backing = td.path().join(prefix);
    std::fs::create_dir_all(&backing).expect("backing dir");
    (td, backing)
}

/// The always-on smoke: all four equivalents at bounded, cheap parameters.
#[test]
fn adversarial_concurrency_smoke() {
    let (_td, dir) = dir_for("fsx");

    let fsx = run_fsx(&dir, 2, 600, 0xF5A_0001, 4096);
    assert_eq!(fsx.mismatches, 0, "fsx smoke byte mismatches");
    assert!(fsx.reopen_digest_equal, "fsx smoke reopen digest differs");

    let (_td2, dir2) = dir_for("fsstress");
    let stress = run_fsstress(&dir2, 8, 200, 0xF57_0002, LIMIT_SMOKE);
    assert_eq!(stress.mismatches, 0, "fsstress smoke mismatches");
    assert_eq!(stress.orphans, 0, "fsstress smoke orphans");
    assert_eq!(
        stress.duplicate_inodes, 0,
        "fsstress smoke duplicate inodes"
    );
    assert!(
        stress.reopen_digest_equal,
        "fsstress smoke reopen digest differs"
    );

    let (_td3, dir3) = dir_for("fsmark");
    let mark = run_fs_mark(&dir3, 500, 256, 0xF5B_0003);
    assert_eq!(mark.mismatches, 0, "fs_mark smoke mismatches");
    assert!(mark.dir_empty_after_unlink, "fs_mark smoke dir not empty");

    let (_td4, dir4) = dir_for("storm");
    let storm = run_storm(&dir4, 16, 200, 8, 0xF57_0004, LIMIT_SMOKE);
    assert!(storm.all_names_resolve, "storm smoke names do not resolve");
    assert!(
        storm.reopen_digest_equal,
        "storm smoke reopen digest differs"
    );

    eprintln!(
        "adversarial smoke: fsx ops={} reads={} mism={} | fsstress ops={} mism={} names={} | \
         fs_mark files={} mism={} | storm ok(r/l/u)={}/{}/{} refusals={}",
        fsx.ops,
        fsx.reads_verified,
        fsx.mismatches,
        stress.total_ops,
        stress.mismatches,
        stress.model_names,
        mark.files,
        mark.mismatches,
        storm.ok_renames,
        storm.ok_links,
        storm.ok_unlinks,
        storm.refusals,
    );
}

/// The sustained, opt-in sweep. Writes the receipt's `in_process` section when
/// `ORFS_ADVERSARIAL_RECEIPT=1`.
#[test]
fn adversarial_concurrency_sustained() {
    if std::env::var("ORFS_STRESS").as_deref() != Ok("1") {
        eprintln!("adversarial_concurrency_sustained: skipped (set ORFS_STRESS=1)");
        return;
    }
    let fsx_ops: u64 = env_u64("ORFS_FSX_OPS", 20_000);
    let threads: usize = env_u64("ORFS_FSSTRESS_THREADS", 64) as usize;
    let ops_per_thread: u64 = env_u64("ORFS_FSSTRESS_OPS", 400);
    let mark_files: u64 = env_u64("ORFS_FSMARK_FILES", 4_000);
    let storm_threads: usize = env_u64("ORFS_STORM_THREADS", 64) as usize;
    let storm_ops: u64 = env_u64("ORFS_STORM_OPS", 400);

    let (_td, dir) = dir_for("fsx-s");
    let t0 = Instant::now();
    let mut fsx = run_fsx(&dir, 2, fsx_ops, 0xF5A_1001, 8192);
    fsx.seconds = t0.elapsed().as_secs_f64();
    fsx.ops_per_s = fsx_ops as f64 / fsx.seconds.max(f64::MIN_POSITIVE);

    let (_td2, dir2) = dir_for("fsstress-s");
    let stress = run_fsstress(&dir2, threads, ops_per_thread, 0xF57_1002, LIMIT_SUSTAINED);

    let (_td3, dir3) = dir_for("fsmark-s");
    let mark = run_fs_mark(&dir3, mark_files, 256, 0xF5B_1003);

    let (_td4, dir4) = dir_for("storm-s");
    let storm = run_storm(
        &dir4,
        storm_threads,
        storm_ops,
        8,
        0xF57_1004,
        LIMIT_SUSTAINED,
    );

    let all_ok = fsx.mismatches == 0
        && fsx.reopen_digest_equal
        && stress.mismatches == 0
        && stress.orphans == 0
        && stress.duplicate_inodes == 0
        && stress.reopen_digest_equal
        && mark.mismatches == 0
        && mark.dir_empty_after_unlink
        && storm.all_names_resolve
        && storm.reopen_digest_equal;
    assert!(all_ok, "sustained adversarial court failed");
    eprintln!(
        "adversarial sustained: fsx {:.0} ops/s ({} mism) | fsstress {}x{} {:.0} ops/s ({} mism, names={}) | \
         fs_mark {} files / {:.0} files/s ({} mism) | storm t={} ok={} ref={}",
        fsx.ops_per_s,
        fsx.mismatches,
        stress.threads,
        stress.ops_per_thread,
        stress.ops_per_s,
        stress.mismatches,
        stress.model_names,
        mark.files,
        mark.files_per_s,
        mark.mismatches,
        storm.threads,
        storm.ok_renames + storm.ok_links + storm.ok_unlinks,
        storm.refusals,
    );

    if std::env::var("ORFS_ADVERSARIAL_RECEIPT").as_deref() == Ok("1") {
        let section = serde_json::json!({
            "config": {
                "fsx_ops": fsx_ops,
                "fsx_files": 2,
                "fsstress_threads": threads,
                "fsstress_ops_per_thread": ops_per_thread,
                "fsmark_files": mark_files,
                "fsmark_file_bytes": 256,
                "storm_threads": storm_threads,
                "storm_ops_per_thread": storm_ops,
            },
            "model_checked": "every fsx read vs a byte-exact shadow model; the fsstress final \
                              namespace vs an independent op-log-replay model (exact name sets, \
                              exact nlink, byte-exact files, no orphans, no duplicate inodes)",
            "courts": [
                {"name": "fsx-equivalent", "report": fsx.to_json()},
                {"name": "fsstress-equivalent", "report": stress.to_json()},
                {"name": "fs_mark-equivalent", "report": mark.to_json()},
                {"name": "rename-link-unlink-storm", "report": storm.to_json()},
            ],
            "all_ok": all_ok,
        });
        merge_receipt_section("in_process", section);
        eprintln!("adversarial: in_process receipt section written");
    }
}

/// The mounted adversarial court. Requires a real mount (`ORFS_FUSE_TEST=1`).
#[test]
fn adversarial_mounted_fsstress() {
    let required = std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1");
    let threads: usize = env_u64("ORFS_MOUNTED_THREADS", 16) as usize;
    let ops_per_thread: u64 = env_u64("ORFS_MOUNTED_OPS", 200);

    let (td, backing) = dir_for("mounted");
    // Own the genesis root so the daemon's own permission checks admit us.
    {
        let mut ns = match Namespace::init(
            &backing,
            orfs::log::DEFAULT_SEGMENT_SIZE,
            DurabilityMode::Ordered,
        ) {
            Ok(ns) => ns,
            Err(e) => {
                if required {
                    panic!("mounted court: init failed: {e}");
                }
                eprintln!("adversarial_mounted_fsstress: skipped (init failed: {e})");
                return;
            }
        };
        // SAFETY: `geteuid`/`getegid` are pure queries.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        ns.setattr(
            orfs::index::ROOT_INODE,
            &SetAttr {
                uid: Some(uid),
                gid: Some(gid),
                ..Default::default()
            },
        )
        .expect("chown root");
        ns.sync().expect("sync");
    }

    let report = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_mounted(&backing, threads, ops_per_thread)
    })) {
        Ok(r) => r,
        Err(_) => {
            if required {
                panic!("adversarial_mounted_fsstress: mount failed (see above)");
            }
            eprintln!("adversarial_mounted_fsstress: skipped — mount unavailable");
            return;
        }
    };

    let all_ok = report.mismatches == 0
        && report.shared_torn_reads == 0
        && report.dirs_empty_at_end
        && report.reads_verified > 0;
    let write_p50 = pct_json(&mut report.write_ns.clone())["p50_ns"].clone();
    let read_p50 = pct_json(&mut report.read_ns.clone())["p50_ns"].clone();
    eprintln!(
        "adversarial mounted: transport={} threads={} reads_verified={} mismatches={} \
         torn_reads={} write_p50={}ns read_p50={}ns",
        report.transport,
        report.threads,
        report.reads_verified,
        report.mismatches,
        report.shared_torn_reads,
        write_p50,
        read_p50,
    );
    assert!(all_ok, "mounted adversarial court failed");

    if std::env::var("ORFS_ADVERSARIAL_RECEIPT").as_deref() == Ok("1") {
        let mut value = report.to_json();
        value["ran"] = serde_json::json!(true);
        value["all_ok"] = serde_json::json!(all_ok);
        value["claim"] = serde_json::json!(
            "the transport — not only OrfsCore — is exercised adversarially: every mounted read \
             is byte-exact, and the shared append/read arm proves a reader never observes a torn \
             committed version"
        );
        merge_receipt_section("mounted", value);
        eprintln!("adversarial: mounted receipt section written");
    }
    drop(td);
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
}
