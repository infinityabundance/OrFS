//! Phase 59 — **OrFS-native `fsx`/`fsstress`-equivalent fault-injection court**.
//!
//! # Why these are *native equivalents*, not the external tools
//!
//! The external `xfstests`/`fsx`/`fsstress` tools are **not runnable in this
//! environment**: `evidence/correctness/xfstests.json` records `ran: false` with
//! the concrete blockers (xfstests does not configure or start without its own
//! built helpers, which need `libtool`/`acl`/`attr`/`uuid` dev libraries;
//! `fsstress` and `xfs_io` are absent; there is no `FSTYP` for OrFS). Rather than
//! pretend otherwise, this file implements the **same two courts** the reviewer
//! named, in Rust, against the **library** (no FUSE mount), so they run
//! everywhere the ordinary test suite runs:
//!
//! 1. **`fsx`-equivalent** — for each of several files, a deterministic
//!    pseudo-random op loop over `write`/`read`/`truncate`/`append`/`fsync`,
//!    where **every read is verified against an in-memory reference model** of
//!    the expected bytes. It covers non-page-aligned offsets and lengths, growth
//!    and shrink, and the project's durability model (`ordered`, with explicit
//!    [`Namespace::sync`] as the `fsync` equivalent). OrFS has a **single**
//!    durability barrier and no separate `fdatasync`: metadata is committed
//!    inside the same authoritative transaction as the data, so there is no
//!    data-vs-metadata split to honour (only `flush` is a non-barrier; see
//!    `docs/RECOVERY.md` §4 and `src/fuse.rs`). The FUSE `fsync` entry point
//!    receives a `datasync` flag and deliberately treats it identically.
//! 2. **`fsstress`-equivalent** — `N` parallel worker threads perform a random
//!    mix of namespace + file operations (create, write, read-verify, rename,
//!    link/unlink, mkdir/rmdir, symlink, truncate, fsync, readdir) on a **shared
//!    namespace**, with the reference model reconciled at the end and **no lost
//!    or corrupted committed data**.
//!
//! Both are small and deterministic by default (so they are always-on in the
//! ordinary `cargo test` gate) and have opt-in heavy sweeps:
//!
//! * fsx heavy: `ORFS_FSINJ_HEAVY=1`.
//! * fsstress heavy: `ORFS_FSSTRESS=1` with `ORFS_FSSTRESS_P` / `ORFS_FSSTRESS_N`
//!   (the reviewer's `-p 64 -n 100000` *shape*; `-n` is operations **per worker**,
//!   matching `fsstress(1)`'s per-process count). `ORFS_FSINJ_HEAVY=1` enables
//!   both. The heavy sweep is bounded rather than literal because a library-level
//!   commit here is a full authoritative transaction (a plan, an appended record,
//!   an index publication), not a syscall into a loop-mounted block device; the
//!   committed run is recorded in `docs/PERFORMANCE.md` §25.
//!
//! A machine-generated receipt is written to
//! `evidence/security/fault-injection.json` (schema
//! `orfs.security.fault-injection.v1`); it also references the existing
//! Phase 28 native-FUSE adversarial fuzzer receipt
//! (`evidence/security/native-fuse-fuzz.json`) without re-running the mount.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use orfs::commit::DurabilityMode;
use orfs::index::ROOT_INODE;
use orfs::log::OpenMode;
use orfs::namespace::{Namespace, RenameMode};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tempfile::TempDir;

/// A fixed volume UUID so the receipts are byte-reproducible.
const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x59, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
/// A fixed creation timestamp for reproducible volumes.
const CREATED: u64 = 1_700_000_000;

/// Fixed seed for the `fsx` court: the run is fully reproducible.
const FSX_SEED: u64 = 0x0F5C_0000_0000_5901;
/// Fixed seed base for the `fsstress` court.
const STRESS_SEED: u64 = 0x0F5C_0000_0000_5902;

/// A large segment so a short workload rarely rolls over (rollover is not the
/// subject here; it is exercised by the power-loss and ENOSPC courts).
const FSX_SEG: u64 = 1 << 20;
const STRESS_SEG: u64 = 1 << 24;

/// Never grow a model file past this, so a read's `u32` length is always valid
/// and the run stays bounded.
const FSX_MAX: u64 = 1 << 15;
const STRESS_MAX: u64 = 1 << 14;

fn flag(key: &str) -> bool {
    matches!(
        std::env::var(key).as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn num(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(default)
}

fn init(dir: &Path, segment_size: u64, durability: DurabilityMode) -> Namespace {
    Namespace::init_with_uuid(dir, segment_size, UUID, CREATED, durability).expect("init namespace")
}

fn rand_bytes(rng: &mut StdRng, n: usize) -> Vec<u8> {
    (0..n).map(|_| rng.gen::<u8>()).collect()
}

/// Per-court read/verification counters.
#[derive(Default, Clone, Copy)]
struct Checks {
    reads: u64,
    dir_checks: u64,
    mismatches: u64,
}

// ===========================================================================
// 1. fsx-equivalent court
// ===========================================================================

/// The in-memory reference model of one `fsx` file: exactly the bytes OrFS must
/// return for any `(offset, length)`.
struct FsxModel {
    data: Vec<u8>,
}

impl FsxModel {
    fn write(&mut self, offset: u64, buf: &[u8]) {
        let end = offset as usize + buf.len();
        if self.data.len() < end {
            self.data.resize(end, 0);
        }
        self.data[offset as usize..end].copy_from_slice(buf);
    }

    fn append(&mut self, buf: &[u8]) {
        let offset = self.data.len() as u64;
        self.write(offset, buf);
    }

    fn truncate(&mut self, size: u64) {
        self.data.resize(size as usize, 0);
    }

    /// The reference bytes for `(offset, length)`, clamped exactly like a POSIX
    /// read at/past EOF.
    fn read(&self, offset: u64, length: usize) -> &[u8] {
        let start = (offset as usize).min(self.data.len());
        let end = (start + length).min(self.data.len());
        &self.data[start..end]
    }
}

/// Verify one `read_at` against the model.
fn fsx_read(
    ns: &Namespace,
    root: u64,
    inode: u64,
    model: &FsxModel,
    offset: u64,
    length: u32,
    checks: &mut Checks,
) {
    let got = ns
        .read_at(inode, root, offset, length)
        .unwrap_or_else(|e| panic!("fsx read_at(off={offset}, len={length}): {e}"));
    checks.reads += 1;
    if got.as_slice() != model.read(offset, length as usize) {
        checks.mismatches += 1;
        eprintln!(
            "fsx MISMATCH inode={inode} off={offset} len={length}: got {} bytes, want {} bytes",
            got.len(),
            model.read(offset, length as usize).len()
        );
    }
}

/// Verify the whole file in random, deliberately non-page-aligned chunks, plus
/// reads at and past EOF and a zero-length read.
fn fsx_verify_whole(
    ns: &Namespace,
    root: u64,
    inode: u64,
    model: &FsxModel,
    rng: &mut StdRng,
    checks: &mut Checks,
) {
    let size = model.data.len() as u64;
    let mut offset = 0u64;
    while offset < size {
        let remaining = (size - offset) as usize;
        let len = rng.gen_range(1..=4096).min(remaining);
        fsx_read(ns, root, inode, model, offset, len as u32, checks);
        offset += len as u64;
    }
    // Boundary reads: zero length, exactly at EOF, and one/two pages past it.
    fsx_read(ns, root, inode, model, 0, 0, checks);
    for off in [size, size + 1, size + 4095, size + 4097] {
        fsx_read(ns, root, inode, model, off, 128, checks);
    }
}

fn run_fsx(files: usize, ops: u64) -> (Checks, serde_json::Value) {
    let td = TempDir::new().unwrap();
    let mut ns = init(td.path(), FSX_SEG, DurabilityMode::Ordered);
    let mut inodes = Vec::with_capacity(files);
    let mut models = Vec::with_capacity(files);
    for i in 0..files {
        let ino = ns
            .create(ROOT_INODE, format!("fsx{i}").as_bytes(), 0o644, 0, 0)
            .unwrap();
        inodes.push(ino);
        models.push(FsxModel { data: Vec::new() });
    }

    let mut rng = StdRng::seed_from_u64(FSX_SEED);
    let mut checks = Checks::default();
    let mut syncs = 0u64;

    for _ in 0..ops {
        let f = rng.gen_range(0..files);
        let ino = inodes[f];
        match rng.gen_range(0..100u32) {
            0..=23 => {
                // overwrite a window (non-page-aligned offset and length)
                let offset = rng.gen_range(0..=FSX_MAX - 4096);
                let len = rng.gen_range(1..=4096);
                let data = rand_bytes(&mut rng, len);
                ns.write_at(ino, offset, &data).unwrap();
                models[f].write(offset, &data);
            }
            24..=37 => {
                // append at the current end
                let len = rng.gen_range(1..=2048);
                let data = rand_bytes(&mut rng, len);
                ns.write_at(ino, models[f].data.len() as u64, &data)
                    .unwrap();
                models[f].append(&data);
            }
            38..=51 => {
                // grow or shrink
                let new_size = rng.gen_range(0..=FSX_MAX);
                ns.truncate(ino, new_size).unwrap();
                models[f].truncate(new_size);
            }
            52..=67 => {
                // a single random read, verified
                let size = models[f].data.len() as u64;
                let offset = if size == 0 {
                    0
                } else {
                    rng.gen_range(0..=size)
                };
                let len = rng.gen_range(0..=8192u32);
                let root = ns.root();
                fsx_read(&ns, root, ino, &models[f], offset, len, &mut checks);
                continue;
            }
            68..=87 => {
                // a full-file verification pass
                let root = ns.root();
                fsx_verify_whole(&ns, root, ino, &models[f], &mut rng, &mut checks);
                continue;
            }
            _ => {
                // the fsync equivalent: the single durability barrier
                ns.sync().unwrap();
                syncs += 1;
                continue;
            }
        }
        // Every mutation is immediately verified against the model, at the root
        // the mutation just published (never a stale pre-mutation root).
        let root = ns.root();
        fsx_verify_whole(&ns, root, ino, &models[f], &mut rng, &mut checks);
    }

    // Durability: sync, capture the committed identity, then reopen and check
    // both the recovered index and every model byte.
    ns.sync().unwrap();
    let (live_digest, live_root) = (ns.index().canonical_digest(), ns.root());
    drop(ns);

    let reopened = Namespace::open(td.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).unwrap();
    let mut reopened_checks = Checks::default();
    for (&ino, model) in inodes.iter().zip(&models) {
        let size = model.data.len() as u64;
        fsx_read(
            &reopened,
            reopened.root(),
            ino,
            model,
            0,
            size.min(u32::MAX as u64) as u32,
            &mut reopened_checks,
        );
    }
    let digest_matches = reopened.index().canonical_digest() == live_digest;
    let root_matches = reopened.root() == live_root;
    let model_bytes_match = reopened_checks.mismatches == 0;

    let section = serde_json::json!({
        "durability": {
            "mode": "ordered",
            "barrier": "Namespace::sync (the fsync equivalent)",
            "fdatasync": "not a separate path: metadata is committed inside the same authoritative transaction as the data"
        },
        "files": files,
        "operations": ops,
        "reads_verified": checks.reads + reopened_checks.reads,
        "syncs": syncs + 1,
        "wall_time_s": serde_json::Value::Null, // filled by the caller
        "mismatches": checks.mismatches + reopened_checks.mismatches,
        "reconciliation": {
            "synced": true,
            "reopened_root_matches": root_matches,
            "reopened_digest_matches": digest_matches,
            "model_bytes_match": model_bytes_match,
            "ok": digest_matches && root_matches && model_bytes_match
        }
    });
    (checks, section)
}

#[test]
fn fsx_equivalent_court() {
    let heavy = flag("ORFS_FSINJ_HEAVY");
    let (files, ops) = if heavy {
        (6usize, 12_000u64)
    } else {
        (3usize, 400u64)
    };

    let started = Instant::now();
    let (checks, mut section) = run_fsx(files, ops);
    let elapsed = started.elapsed().as_secs_f64();

    assert_eq!(
        checks.mismatches, 0,
        "fsx-equivalent: every read must match the reference model"
    );
    assert!(
        section["reconciliation"]["ok"].as_bool() == Some(true),
        "fsx-equivalent: post-sync reopen must reproduce the model"
    );
    section["wall_time_s"] = serde_json::json!((elapsed * 1000.0).round() / 1000.0);
    eprintln!(
        "fsx-equivalent: files={files} ops={ops} reads_verified={} syncs={} mismatches=0 wall={elapsed:.3}s",
        section["reads_verified"].as_u64().unwrap_or(0),
        section["syncs"].as_u64().unwrap_or(0),
    );

    merge_evidence(
        "fsx_equivalent",
        if heavy { "heavy" } else { "smoke" },
        section,
    );
}

// ===========================================================================
// 2. fsstress-equivalent court
// ===========================================================================

/// What a namespace entry points at, per the reference model.
#[derive(Clone)]
enum Target {
    File(u64),
    Dir(u64),
    Symlink(u64, Vec<u8>),
}

fn target_ino(t: &Target) -> u64 {
    match t {
        Target::File(i) | Target::Dir(i) | Target::Symlink(i, _) => *i,
    }
}

/// One worker's private reference model. Names are worker-partitioned
/// (`w<worker>-<kind><n>`), so no two workers ever touch the same name: the
/// final state is exact even though the *interleaving* is not.
///
/// The dense `file_keys`/`file_ino` vectors (with `key_pos`) keep the random
/// pick O(1), so the court scales to a large operation count instead of
/// rescanning the whole namespace on every op.
struct WorkerModel {
    worker: u64,
    counter: u64,
    /// (parent inode, name) -> target (the authoritative model of the namespace)
    entries: BTreeMap<(u64, String), Target>,
    /// file inode -> expected bytes (only for reachable files)
    content: BTreeMap<u64, Vec<u8>>,
    /// dense index of live file entries
    file_keys: Vec<(u64, String)>,
    file_ino: Vec<u64>,
    key_pos: BTreeMap<(u64, String), usize>,
    /// number of live names per file inode
    nlink: BTreeMap<u64, u64>,
    /// owned directory inodes; index 0 is always the root
    dirs_all: Vec<u64>,
    dirs_pos: BTreeMap<u64, usize>,
    dir_key: BTreeMap<u64, (u64, String)>,
    dir_children: BTreeMap<u64, u64>,
}

impl WorkerModel {
    fn new(worker: u64) -> Self {
        let mut dirs_pos = BTreeMap::new();
        dirs_pos.insert(ROOT_INODE, 0usize);
        Self {
            worker,
            counter: 0,
            entries: BTreeMap::new(),
            content: BTreeMap::new(),
            file_keys: Vec::new(),
            file_ino: Vec::new(),
            key_pos: BTreeMap::new(),
            nlink: BTreeMap::new(),
            dirs_all: vec![ROOT_INODE],
            dirs_pos,
            dir_key: BTreeMap::new(),
            dir_children: BTreeMap::new(),
        }
    }

    fn next_name(&mut self, kind: &str) -> String {
        self.counter += 1;
        format!("w{}-{}{}", self.worker, kind, self.counter)
    }

    fn insert_entry(&mut self, parent: u64, name: String, target: Target) {
        *self.dir_children.entry(parent).or_insert(0) += 1;
        self.entries.insert((parent, name), target);
    }

    fn remove_entry(&mut self, key: &(u64, String)) -> Option<Target> {
        let t = self.entries.remove(key)?;
        if let Some(c) = self.dir_children.get_mut(&key.0) {
            *c = c.saturating_sub(1);
        }
        Some(t)
    }

    fn add_file(&mut self, parent: u64, name: String, ino: u64) {
        self.insert_entry(parent, name.clone(), Target::File(ino));
        let idx = self.file_keys.len();
        self.key_pos.insert((parent, name.clone()), idx);
        self.file_keys.push((parent, name));
        self.file_ino.push(ino);
        *self.nlink.entry(ino).or_insert(0) += 1;
    }

    /// Remove a file key from the dense index (without touching `entries` or
    /// `nlink`); used by both unlink and rename.
    fn take_file_key(&mut self, key: &(u64, String)) -> Option<u64> {
        let idx = self.key_pos.remove(key)?;
        let ino = self.file_ino[idx];
        let last = self.file_keys.len() - 1;
        if idx != last {
            let moved = self.file_keys[last].clone();
            self.file_keys[idx] = moved.clone();
            self.file_ino[idx] = self.file_ino[last];
            self.key_pos.insert(moved, idx);
        }
        self.file_keys.pop();
        self.file_ino.pop();
        Some(ino)
    }

    fn del_file(&mut self, key: &(u64, String)) -> Option<u64> {
        let ino = self.take_file_key(key)?;
        self.remove_entry(key);
        if let Some(n) = self.nlink.get_mut(&ino) {
            *n -= 1;
            if *n == 0 {
                self.nlink.remove(&ino);
                self.content.remove(&ino);
            }
        }
        Some(ino)
    }

    fn rename_file(&mut self, old: &(u64, String), new_parent: u64, new_name: String, ino: u64) {
        self.take_file_key(old);
        self.remove_entry(old);
        self.insert_entry(new_parent, new_name.clone(), Target::File(ino));
        let idx = self.file_keys.len();
        self.key_pos.insert((new_parent, new_name.clone()), idx);
        self.file_keys.push((new_parent, new_name));
        self.file_ino.push(ino);
    }

    fn add_dir(&mut self, name: String, ino: u64) {
        self.insert_entry(ROOT_INODE, name.clone(), Target::Dir(ino));
        let idx = self.dirs_all.len();
        self.dirs_all.push(ino);
        self.dirs_pos.insert(ino, idx);
        self.dir_key.insert(ino, (ROOT_INODE, name));
        self.dir_children.entry(ino).or_insert(0);
    }

    fn del_dir(&mut self, key: &(u64, String), ino: u64) {
        self.remove_entry(key);
        if let Some(idx) = self.dirs_pos.remove(&ino) {
            let last = self.dirs_all.len() - 1;
            if idx != last {
                let moved = self.dirs_all[last];
                self.dirs_all[idx] = moved;
                self.dirs_pos.insert(moved, idx);
            }
            self.dirs_all.pop();
        }
        self.dir_key.remove(&ino);
    }

    fn pick_dir(&self, rng: &mut StdRng) -> u64 {
        self.dirs_all[rng.gen_range(0..self.dirs_all.len())]
    }

    fn pick_file(&self, rng: &mut StdRng) -> Option<((u64, String), u64)> {
        if self.file_keys.is_empty() {
            return None;
        }
        let idx = rng.gen_range(0..self.file_keys.len());
        Some((self.file_keys[idx].clone(), self.file_ino[idx]))
    }

    /// A random *empty* owned directory (never the root), with its entry key.
    /// If the uniformly chosen directory is not empty the op is simply skipped.
    fn pick_empty_dir(&self, rng: &mut StdRng) -> Option<((u64, String), u64)> {
        if self.dirs_all.len() <= 1 {
            return None;
        }
        let ino = self.dirs_all[rng.gen_range(1..self.dirs_all.len())];
        if self.dir_children.get(&ino).copied().unwrap_or(0) == 0 {
            self.dir_key.get(&ino).map(|k| (k.clone(), ino))
        } else {
            None
        }
    }
}

fn stress_worker(worker: u64, ops: u64, ns: Arc<Mutex<Namespace>>) -> (WorkerModel, Checks) {
    let mut rng = StdRng::seed_from_u64(
        STRESS_SEED ^ worker.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1),
    );
    let mut model = WorkerModel::new(worker);
    let mut checks = Checks::default();

    for _ in 0..ops {
        let mut g = ns.lock().unwrap();
        let root = g.root();
        match rng.gen_range(0..100u32) {
            // --- create a file -------------------------------------------------
            0..=13 => {
                let parent = model.pick_dir(&mut rng);
                let name = model.next_name("f");
                let ino = g
                    .create(parent, name.as_bytes(), 0o644, 0, 0)
                    .expect("create");
                model.add_file(parent, name, ino);
                model.content.insert(ino, Vec::new());
            }
            // --- mkdir (directly under the root) ------------------------------
            14..=19 => {
                let name = model.next_name("d");
                let ino = g
                    .mkdir(ROOT_INODE, name.as_bytes(), 0o755, 0, 0)
                    .expect("mkdir");
                model.add_dir(name, ino);
            }
            // --- symlink ------------------------------------------------------
            20..=26 => {
                let parent = model.pick_dir(&mut rng);
                let name = model.next_name("s");
                let target = format!("p/w{}-t{}", model.worker, model.counter).into_bytes();
                let ino = g
                    .symlink(parent, name.as_bytes(), &target, 0, 0)
                    .expect("symlink");
                model.insert_entry(parent, name, Target::Symlink(ino, target));
            }
            // --- write (non-page-aligned offset/length) -----------------------
            27..=42 => {
                if let Some((_, ino)) = model.pick_file(&mut rng) {
                    let offset = rng.gen_range(0..=STRESS_MAX - 1024);
                    let len = rng.gen_range(1..=1024);
                    let data = rand_bytes(&mut rng, len);
                    g.write_at(ino, offset, &data).expect("write_at");
                    let bytes = model.content.get_mut(&ino).unwrap();
                    let end = offset as usize + data.len();
                    if bytes.len() < end {
                        bytes.resize(end, 0);
                    }
                    bytes[offset as usize..end].copy_from_slice(&data);
                }
            }
            // --- append -------------------------------------------------------
            43..=50 => {
                if let Some((_, ino)) = model.pick_file(&mut rng) {
                    let len = rng.gen_range(1..=1024);
                    let data = rand_bytes(&mut rng, len);
                    let offset = model.content.get(&ino).map(|b| b.len() as u64).unwrap_or(0);
                    g.write_at(ino, offset, &data).expect("append");
                    model
                        .content
                        .get_mut(&ino)
                        .unwrap()
                        .extend_from_slice(&data);
                }
            }
            // --- truncate (grow or shrink) ------------------------------------
            51..=57 => {
                if let Some((_, ino)) = model.pick_file(&mut rng) {
                    let new_size = rng.gen_range(0..=STRESS_MAX);
                    g.truncate(ino, new_size).expect("truncate");
                    model
                        .content
                        .get_mut(&ino)
                        .unwrap()
                        .resize(new_size as usize, 0);
                }
            }
            // --- read-verify the whole file -----------------------------------
            58..=70 => {
                if let Some((_, ino)) = model.pick_file(&mut rng) {
                    let want = model.content.get(&ino).cloned().unwrap_or_default();
                    let size = want.len() as u64;
                    let mut offset = 0u64;
                    while offset < size {
                        let remaining = (size - offset) as usize;
                        let len = rng.gen_range(1..=2048).min(remaining);
                        let got = g.read_at(ino, root, offset, len as u32).expect("read_at");
                        checks.reads += 1;
                        if got.as_slice() != &want[offset as usize..offset as usize + len] {
                            checks.mismatches += 1;
                        }
                        offset += len as u64;
                    }
                    // a read at EOF must be empty
                    let got = g.read_at(ino, root, size, 64).expect("read_at eof");
                    checks.reads += 1;
                    if !got.is_empty() {
                        checks.mismatches += 1;
                    }
                }
            }
            // --- rename a file to a fresh name in a random owned dir ----------
            71..=79 => {
                if let Some((old, ino)) = model.pick_file(&mut rng) {
                    let np = model.pick_dir(&mut rng);
                    let nn = model.next_name("r");
                    g.rename(
                        old.0,
                        old.1.as_bytes(),
                        np,
                        nn.as_bytes(),
                        RenameMode::Ordinary,
                    )
                    .expect("rename");
                    model.rename_file(&old, np, nn, ino);
                }
            }
            // --- hard link ----------------------------------------------------
            80..=86 => {
                if let Some((_, ino)) = model.pick_file(&mut rng) {
                    let np = model.pick_dir(&mut rng);
                    let nn = model.next_name("l");
                    g.link(ino, np, nn.as_bytes()).expect("link");
                    model.add_file(np, nn, ino);
                }
            }
            // --- unlink -------------------------------------------------------
            87..=92 => {
                if let Some((key, _ino)) = model.pick_file(&mut rng) {
                    g.unlink(key.0, key.1.as_bytes()).expect("unlink");
                    model.del_file(&key);
                }
            }
            // --- rmdir (only an empty directory) ------------------------------
            93..=96 => {
                if let Some((key, ino)) = model.pick_empty_dir(&mut rng) {
                    g.rmdir(key.0, key.1.as_bytes()).expect("rmdir");
                    model.del_dir(&key, ino);
                }
            }
            // --- readdir (exactness for owned dirs; presence for the root) -----
            _ => {
                let dir = model.pick_dir(&mut rng);
                let listing: BTreeMap<Vec<u8>, u64> =
                    g.readdir(dir, root).expect("readdir").into_iter().collect();
                checks.dir_checks += 1;
                if dir == ROOT_INODE {
                    for ((parent, name), t) in &model.entries {
                        if *parent == ROOT_INODE
                            && listing.get(name.as_bytes()) != Some(&target_ino(t))
                        {
                            checks.mismatches += 1;
                        }
                    }
                } else {
                    let want: BTreeMap<Vec<u8>, u64> = model
                        .entries
                        .iter()
                        .filter(|((p, _), _)| *p == dir)
                        .map(|((_, n), t)| (n.clone().into_bytes(), target_ino(t)))
                        .collect();
                    if want != listing {
                        checks.mismatches += 1;
                    }
                }
            }
        }
    }

    (model, checks)
}

/// The result of reconciling one worker's model against a namespace at `root`.
struct Reconcile {
    names_ok: bool,
    data_ok: bool,
    dirs_ok: bool,
    names: u64,
    files: u64,
    dirs: u64,
    symlinks: u64,
}

impl Reconcile {
    fn new() -> Self {
        Self {
            names_ok: true,
            data_ok: true,
            dirs_ok: true,
            names: 0,
            files: 0,
            dirs: 0,
            symlinks: 0,
        }
    }

    fn merge(&mut self, other: Reconcile) {
        self.names_ok &= other.names_ok;
        self.data_ok &= other.data_ok;
        self.dirs_ok &= other.dirs_ok;
        self.names += other.names;
        self.files += other.files;
        self.dirs += other.dirs;
        self.symlinks += other.symlinks;
    }

    fn ok(&self) -> bool {
        self.names_ok && self.data_ok && self.dirs_ok
    }
}

/// Reconcile one worker's reference model against `ns` at `root`: every name
/// resolves to the right entry, every file's bytes match, and every worker-owned
/// directory lists exactly the model's entries.
fn reconcile(model: &WorkerModel, ns: &Namespace, root: u64) -> Reconcile {
    let mut r = Reconcile::new();
    for ((parent, name), target) in &model.entries {
        r.names += 1;
        match target {
            Target::File(_) => r.files += 1,
            Target::Dir(_) => r.dirs += 1,
            Target::Symlink(_, _) => r.symlinks += 1,
        }
        match ns.lookup(*parent, name.as_bytes(), root) {
            Ok(ino) => match target {
                Target::File(i) | Target::Dir(i) => {
                    if ino != *i {
                        r.names_ok = false;
                    }
                }
                Target::Symlink(_, want) => {
                    if !matches!(ns.readlink(ino, root), Ok(t) if &t == want) {
                        r.names_ok = false;
                    }
                }
            },
            Err(_) => r.names_ok = false,
        }
    }

    for (ino, want) in &model.content {
        match ns.read_at(*ino, root, 0, want.len() as u32) {
            Ok(got) => {
                if &got != want {
                    r.data_ok = false;
                }
            }
            Err(_) => r.data_ok = false,
        }
    }

    for &dir in &model.dirs_all {
        if dir == ROOT_INODE {
            continue;
        }
        let listing: BTreeMap<Vec<u8>, u64> = ns
            .readdir(dir, root)
            .map(|v| v.into_iter().collect())
            .unwrap_or_default();
        let want: BTreeMap<Vec<u8>, u64> = model
            .entries
            .iter()
            .filter(|((p, _), _)| *p == dir)
            .map(|((_, n), t)| (n.clone().into_bytes(), target_ino(t)))
            .collect();
        if want != listing {
            r.dirs_ok = false;
        }
    }

    r
}

fn run_fsstress(
    workers: u64,
    ops_per_worker: u64,
) -> (Checks, Reconcile, Reconcile, serde_json::Value) {
    let td = TempDir::new().unwrap();
    let ns = Arc::new(Mutex::new(init(
        td.path(),
        STRESS_SEG,
        DurabilityMode::Ordered,
    )));

    let handles: Vec<_> = (0..workers)
        .map(|w| {
            let ns = ns.clone();
            thread::spawn(move || stress_worker(w, ops_per_worker, ns))
        })
        .collect();

    let mut models = Vec::with_capacity(workers as usize);
    let mut checks = Checks::default();
    for h in handles {
        let (m, c) = h.join().expect("worker joined");
        models.push(m);
        checks.reads += c.reads;
        checks.dir_checks += c.dir_checks;
        checks.mismatches += c.mismatches;
    }

    // Reconcile against the live namespace, then against an independent reopen.
    let (live_rec, live_root, live_digest) = {
        let mut g = ns.lock().unwrap();
        g.sync().expect("sync");
        let root = g.root();
        let mut rec = Reconcile::new();
        for m in &models {
            rec.merge(reconcile(m, &g, root));
        }
        (rec, root, g.index().canonical_digest())
    };
    drop(ns);

    let reopened =
        Namespace::open(td.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).expect("reopen");
    let reopened_root_matches = reopened.root() == live_root;
    let reopened_digest_matches = reopened.index().canonical_digest() == live_digest;
    let mut reopened_rec = Reconcile::new();
    for m in &models {
        reopened_rec.merge(reconcile(m, &reopened, reopened.root()));
    }

    let reconciliation_ok =
        live_rec.ok() && reopened_rec.ok() && reopened_root_matches && reopened_digest_matches;

    let section = serde_json::json!({
        "workers": workers,
        "operations": workers * ops_per_worker,
        "ops_per_worker": ops_per_worker,
        "reads_verified": checks.reads,
        "readdir_checks": checks.dir_checks,
        "mismatches": checks.mismatches,
        "wall_time_s": serde_json::Value::Null, // filled by the caller
        "reference_model": {
            "names": live_rec.names,
            "files": live_rec.files,
            "dirs": live_rec.dirs,
            "symlinks": live_rec.symlinks
        },
        "reconciliation": {
            "live_names_ok": live_rec.names_ok,
            "live_data_ok": live_rec.data_ok,
            "live_dirs_ok": live_rec.dirs_ok,
            "reopened_names_ok": reopened_rec.names_ok,
            "reopened_data_ok": reopened_rec.data_ok,
            "reopened_dirs_ok": reopened_rec.dirs_ok,
            "reopened_root_matches": reopened_root_matches,
            "reopened_digest_matches": reopened_digest_matches,
            "ok": reconciliation_ok
        }
    });
    (checks, live_rec, reopened_rec, section)
}

#[test]
fn fsstress_equivalent_court() {
    let heavy = flag("ORFS_FSINJ_HEAVY") || flag("ORFS_FSSTRESS");
    let (workers, ops_per_worker) = if heavy {
        (num("ORFS_FSSTRESS_P", 64), num("ORFS_FSSTRESS_N", 1_000))
    } else {
        (4, 150)
    };

    let started = Instant::now();
    let (checks, live_rec, reopened_rec, mut section) = run_fsstress(workers, ops_per_worker);
    let elapsed = started.elapsed().as_secs_f64();

    assert_eq!(
        checks.mismatches, 0,
        "fsstress-equivalent: no read/readdir may disagree with the reference model"
    );
    assert!(
        live_rec.ok() && reopened_rec.ok(),
        "fsstress-equivalent: the reference model must reconcile against the live namespace and an independent reopen"
    );
    assert!(
        section["reconciliation"]["ok"].as_bool() == Some(true),
        "fsstress-equivalent: reconciliation (incl. reopened digest) must be ok"
    );
    section["wall_time_s"] = serde_json::json!((elapsed * 1000.0).round() / 1000.0);
    eprintln!(
        "fsstress-equivalent: workers={workers} ops={} ops/worker={ops_per_worker} \
         reads_verified={} readdir_checks={} mismatches=0 wall={elapsed:.3}s \
         model(names={} files={} dirs={} symlinks={})",
        workers * ops_per_worker,
        checks.reads,
        checks.dir_checks,
        live_rec.names,
        live_rec.files,
        live_rec.dirs,
        live_rec.symlinks,
    );

    merge_evidence(
        "fsstress_equivalent",
        if heavy { "heavy" } else { "smoke" },
        section,
    );
}

// ===========================================================================
// Evidence
// ===========================================================================

static EV_LOCK: Mutex<()> = Mutex::new(());

fn evidence_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/security/fault-injection.json")
}

fn base_doc() -> serde_json::Value {
    serde_json::json!({
        "schema": "orfs.security.fault-injection.v1",
        "generator": "tests/fs_fault_injection.rs",
        "note": "OrFS-native, explicitly-labelled fsx/fsstress-equivalent fault-injection courts. The external xfstests/fsx/fsstress tools are NOT runnable in this environment (see evidence/correctness/xfstests.json); this receipt is an equivalent court, not a claim to have run those tools.",
        "external_tools": {
            "ran": false,
            "xfstests": "does not configure or start without its own built helpers (libtool/acl/attr/uuid dev libs absent); no FSTYP for OrFS",
            "fsx": "shipped by xfsprogs, a separate build that is not installed",
            "fsstress": "built by xfstests' own `make`, which is not runnable here",
            "reference": "evidence/correctness/xfstests.json"
        },
        "related_evidence": {},
        "courts": {},
        "all_ok": false
    })
}

/// The existing Phase 28 native-FUSE adversarial fuzzer receipt, referenced (not
/// re-run): it is surfaced in the same fault-injection section.
fn related_evidence() -> serde_json::Value {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/security/native-fuse-fuzz.json");
    match std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
    {
        Some(v) => {
            let total_iterations = v
                .get("total_iterations")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let panics: u64 = v
                .get("targets")
                .and_then(|t| t.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.get("panics").and_then(|p| p.as_u64()))
                        .sum()
                })
                .unwrap_or(0);
            serde_json::json!({
                "native_fuse_adversarial_fuzzer": {
                    "path": "evidence/security/native-fuse-fuzz.json",
                    "generated_by": "tests/native_fuse_fuzz.rs",
                    "total_iterations": total_iterations,
                    "panics": panics,
                    "note": "Existing Phase 28 receipt, referenced here for the fault-injection section; not re-run (no mount)."
                }
            })
        }
        None => serde_json::json!({
            "native_fuse_adversarial_fuzzer": {
                "path": "evidence/security/native-fuse-fuzz.json",
                "present": false
            }
        }),
    }
}

fn compute_all_ok(doc: &serde_json::Value) -> bool {
    let Some(courts) = doc.get("courts").and_then(|c| c.as_object()) else {
        return false;
    };
    if courts.is_empty() {
        return false;
    }
    for court in courts.values() {
        let Some(runs) = court.as_object() else {
            return false;
        };
        for run in runs.values() {
            if run.get("mismatches").and_then(|m| m.as_u64()) != Some(0) {
                return false;
            }
            if run
                .get("reconciliation")
                .and_then(|r| r.get("ok"))
                .and_then(|o| o.as_bool())
                != Some(true)
            {
                return false;
            }
        }
    }
    true
}

/// Merge one court/kind section into the receipt (read-modify-write under a
/// process lock, so the two courts running in parallel cannot clobber each
/// other; a later heavy run preserves an earlier smoke section and vice versa).
fn merge_evidence(court: &str, kind: &str, section: serde_json::Value) {
    let _guard = EV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = evidence_path();
    let mut doc: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .filter(|v: &serde_json::Value| v.get("schema").is_some())
        .unwrap_or_else(base_doc);
    if !doc.get("courts").map(|c| c.is_object()).unwrap_or(false) {
        doc["courts"] = serde_json::json!({});
    }
    doc["related_evidence"] = related_evidence();
    {
        let courts = doc["courts"].as_object_mut().unwrap();
        let entry = courts
            .entry(court.to_string())
            .or_insert_with(|| serde_json::json!({}));
        entry[kind] = section;
    }
    doc["all_ok"] = serde_json::json!(compute_all_ok(&doc));
    write_json(&path, &doc);
}

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(value).expect("json");
    s.push('\n');
    std::fs::write(path, s).expect("write evidence");
}
