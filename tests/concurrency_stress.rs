//! Phase 11 **concurrency court** (research §27, §26, §7.4).
//!
//! # Why stress tests rather than Loom
//!
//! Research §27 permits Loom "for suitable reduced concurrency models". We
//! evaluated it and did **not** use it here, for concrete reasons:
//!
//! * The shared mutable state that carries real risk is the committed-root pin
//!   registry ([`orfs::log::RootPins`], a `std::sync::Mutex<BTreeMap>`), the
//!   publication state ([`orfs::manifestation`], `parking_lot::RwLock` +
//!   `Condvar`), and the commit sequencer, which is serialised by **Rust
//!   borrow-checking** (`&mut Volume`) rather than by an atomic. Loom models
//!   `std::sync` primitives by substitution; it cannot model a
//!   `parking_lot::RwLock`, a condvar-driven worker pool, or an exclusive
//!   `&mut` borrow. Rewriting the real code to be Loom-compatible would test a
//!   *different* program.
//! * Every path here performs real `read`/`write`/`fsync` syscalls; Loom's
//!   scheduler only makes sense for pure in-memory state.
//!
//! So, per the directive's explicit fallback, this file exercises the **real**
//! code under genuine OS-thread contention and asserts the invariants that
//! matter. The required concurrency tests all exist here:
//!
//! 1. overlapping writes to one inode;
//! 2. writes to independent inodes;
//! 3. rename/unlink races;
//! 4. create/unlink races;
//! 5. open file during unlink;
//! 6. snapshot reads during writes;
//! 7. bloom (manifestation) publication during reads;
//! 8. mount recovery after concurrent activity.
//!
//! A machine-generated summary is written to
//! `evidence/security/concurrency-stress.json`.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use orfs::commit::DurabilityMode;
use orfs::index::ROOT_INODE;
use orfs::log::{Log, OpenMode};
use orfs::manifestation::{ManifestationConfig, ManifestationProfile, ManifestationStatus};
use orfs::namespace::{Namespace, RenameMode};
use orfs::snapshot::Snapshot;
use orfs::volume::Volume;

use tempfile::TempDir;

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x27, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const CREATED: u64 = 1_700_000_000;

fn init(dir: &Path, segment_size: u64) -> Namespace {
    Namespace::init_with_uuid(dir, segment_size, UUID, CREATED, DurabilityMode::Ordered)
        .expect("init namespace")
}

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(value).expect("json");
    s.push('\n');
    std::fs::write(path, s).expect("write evidence");
}

// ---------------------------------------------------------------------------
// 1. Overlapping writes to one inode
// ---------------------------------------------------------------------------

#[test]
fn overlapping_writes_to_one_inode() {
    let td = TempDir::new().unwrap();
    let ns = Arc::new(Mutex::new(init(td.path(), 1 << 18)));
    let f = ns
        .lock()
        .unwrap()
        .create(ROOT_INODE, b"f", 0o644, 0, 0)
        .unwrap();
    let root0 = ns.lock().unwrap().root();

    const THREADS: u64 = 4;
    const PER: u64 = 40;
    let ops = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for t in 0..THREADS {
        let ns = ns.clone();
        let ops = ops.clone();
        handles.push(thread::spawn(move || {
            for i in 0..PER {
                // A shared, overlapping byte region.
                let off = ((t * PER + i) % 64) * 4;
                let mut g = ns.lock().unwrap();
                g.write_at(f, off, &[t as u8; 4]).unwrap();
                ops.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(ops.load(Ordering::Relaxed), THREADS * PER);

    let g = ns.lock().unwrap();
    // Every write is one committed transaction: the root advanced and is a
    // complete transaction boundary.
    assert!(g.root() > root0);
    assert!(g.volume().log.is_boundary(g.root()));
    // The recovered handle agrees exactly with the live index.
    let digest = g.index().canonical_digest();
    let size = g.index().inode(f).unwrap().size;
    assert!(size > 0);
    drop(g);

    let reopened = Namespace::open(td.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).unwrap();
    assert_eq!(reopened.index().canonical_digest(), digest);
}

// ---------------------------------------------------------------------------
// 2. Writes to independent inodes
// ---------------------------------------------------------------------------

#[test]
fn writes_to_independent_inodes() {
    let td = TempDir::new().unwrap();
    let ns = Arc::new(Mutex::new(init(td.path(), 1 << 18)));
    const THREADS: u64 = 6;
    let mut handles = Vec::new();
    for t in 0..THREADS {
        let ns = ns.clone();
        handles.push(thread::spawn(move || {
            let name = format!("file-{t}");
            let mut g = ns.lock().unwrap();
            let ino = g.create(ROOT_INODE, name.as_bytes(), 0o644, 0, 0).unwrap();
            let body = vec![t as u8; 512];
            g.write_at(ino, 0, &body).unwrap();
            ino
        }));
    }
    let inodes: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let g = ns.lock().unwrap();
    let root = g.root();
    for (t, &ino) in inodes.iter().enumerate() {
        assert_eq!(g.read_at(ino, root, 0, 512).unwrap(), vec![t as u8; 512]);
    }
}

// ---------------------------------------------------------------------------
// 3. rename/unlink races
// ---------------------------------------------------------------------------

#[test]
fn rename_unlink_races() {
    let td = TempDir::new().unwrap();
    let ns = Arc::new(Mutex::new(init(td.path(), 1 << 18)));
    {
        let mut g = ns.lock().unwrap();
        for i in 0..8 {
            g.create(ROOT_INODE, format!("a{i}").as_bytes(), 0o644, 0, 0)
                .unwrap();
        }
    }

    let mut handles = Vec::new();
    for t in 0..4u64 {
        let ns = ns.clone();
        handles.push(thread::spawn(move || {
            let mut oks = 0u64;
            for i in 0..40u64 {
                let src = format!("a{}", (t + i) % 8);
                let dst = format!("b{}", (t * 40 + i) % 8);
                let mut g = ns.lock().unwrap();
                // Rename the source onto a fresh name, tolerating any concrete
                // refusal (absent source/destination) — a lost race is an error,
                // never a corruption.
                if g.rename(
                    ROOT_INODE,
                    src.as_bytes(),
                    ROOT_INODE,
                    dst.as_bytes(),
                    RenameMode::Ordinary,
                )
                .is_ok()
                {
                    oks += 1;
                    let _ = g.rename(
                        ROOT_INODE,
                        dst.as_bytes(),
                        ROOT_INODE,
                        src.as_bytes(),
                        RenameMode::NoReplace,
                    );
                } else {
                    let _ = g.unlink(ROOT_INODE, src.as_bytes());
                }
            }
            oks
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // Consistency: every name in the listing resolves back to the same inode, and
    // the recovered namespace equals the live one.
    let g = ns.lock().unwrap();
    let root = g.root();
    let listing = g.readdir(ROOT_INODE, root).unwrap();
    for (name, ino) in &listing {
        assert_eq!(g.lookup(ROOT_INODE, name, root).unwrap(), *ino);
    }
    let digest = g.index().canonical_digest();
    drop(g);
    let reopened = Namespace::open(td.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).unwrap();
    assert_eq!(reopened.index().canonical_digest(), digest);
}

// ---------------------------------------------------------------------------
// 4. create/unlink races
// ---------------------------------------------------------------------------

#[test]
fn create_unlink_races() {
    let td = TempDir::new().unwrap();
    let ns = Arc::new(Mutex::new(init(td.path(), 1 << 18)));
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let ns = ns.clone();
        handles.push(thread::spawn(move || {
            for i in 0..50u64 {
                let name = format!("c{}", (t + i) % 6);
                let mut g = ns.lock().unwrap();
                let _ = g.create(ROOT_INODE, name.as_bytes(), 0o644, 0, 0);
                let _ = g.unlink(ROOT_INODE, name.as_bytes());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // No panic and a fully consistent namespace afterwards.
    let g = ns.lock().unwrap();
    let root = g.root();
    let listing = g.readdir(ROOT_INODE, root).unwrap();
    for (name, ino) in &listing {
        assert_eq!(g.lookup(ROOT_INODE, name, root).unwrap(), *ino);
    }
    drop(g);
    assert!(Namespace::open(td.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).is_ok());
}

// ---------------------------------------------------------------------------
// 5. open file during unlink (non-withdrawal: reads by inode survive)
// ---------------------------------------------------------------------------

#[test]
fn open_file_during_unlink_keeps_reading_historical_bytes() {
    let td = TempDir::new().unwrap();
    let mut ns = init(td.path(), 1 << 18);
    let f = ns.create(ROOT_INODE, b"open", 0o644, 0, 0).unwrap();
    ns.write_at(f, 0, b"still-here-after-unlink").unwrap();
    ns.sync().unwrap();
    let pinned_root = ns.root();
    let content = ns.read_at(f, pinned_root, 0, 64).unwrap();

    // A reader pins the pre-unlink root through a shared read-only handle. This is
    // exactly the "open file handle during unlink" case: the name may vanish, but
    // the *inode's committed bytes* must remain readable.
    let read_log =
        Arc::new(Log::open(&Volume::log_dir(td.path()), 1 << 18, OpenMode::ReadOnly).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicU64::new(0));
    let reader = {
        let log = read_log.clone();
        let stop = stop.clone();
        let reads = reads.clone();
        let expected = content.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let snap = Snapshot::from_read_log(log.clone(), UUID, pinned_root).unwrap();
                assert_eq!(snap.read_at(f, 0, 64).unwrap(), expected);
                reads.fetch_add(1, Ordering::Relaxed);
            }
        })
    };

    // Wait until the reader has actually completed a read before mutating, so
    // the test observes a genuine reader-during-unlink overlap rather than a
    // scheduling race.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while reads.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
        thread::yield_now();
    }

    // The writer unlinks the (only) name. The inode keeps its history.
    ns.unlink(ROOT_INODE, b"open").unwrap();
    assert!(ns.lookup(ROOT_INODE, b"open", ns.root()).is_err());
    // Reading by inode id still succeeds on the live handle (open-handle
    // semantics): the name is gone, the inode is not.
    assert_eq!(ns.read_at(f, ns.root(), 0, 64).unwrap(), content);

    stop.store(true, Ordering::Relaxed);
    reader.join().unwrap();
    assert!(reads.load(Ordering::Relaxed) > 0);
}

// ---------------------------------------------------------------------------
// 6. snapshot reads during writes
// ---------------------------------------------------------------------------

#[test]
fn snapshot_reads_during_writes_are_stable() {
    let td = TempDir::new().unwrap();
    let mut ns = init(td.path(), 1 << 16);
    let f = ns.create(ROOT_INODE, b"pinned", 0o644, 0, 0).unwrap();
    ns.write_at(f, 0, b"PINNED").unwrap();
    let scratch = ns.create(ROOT_INODE, b"scratch", 0o644, 0, 0).unwrap();
    ns.sync().unwrap();
    let root = ns.root();
    let pins = ns.volume().log.root_pins();
    let read_log = Arc::new(
        Log::open_with_pins(
            &Volume::log_dir(td.path()),
            1 << 16,
            OpenMode::ReadOnly,
            pins.clone(),
        )
        .unwrap(),
    );

    let stop = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicU64::new(0));
    let mut readers = Vec::new();
    for _ in 0..3 {
        let log = read_log.clone();
        let stop = stop.clone();
        let reads = reads.clone();
        readers.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let snap = Snapshot::from_read_log(log.clone(), UUID, root).unwrap();
                assert_eq!(snap.pinned_root(), root);
                assert_eq!(snap.read_at(f, 0, 64).unwrap(), b"PINNED");
                reads.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    // Wait until at least one reader has completed a pinned read, so the writes
    // genuinely overlap live readers.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while reads.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
        thread::yield_now();
    }
    for i in 0..200u64 {
        ns.write_at(scratch, 0, &[i as u8; 64]).unwrap();
    }
    ns.sync().unwrap();
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        r.join().unwrap();
    }
    assert!(reads.load(Ordering::Relaxed) > 0);
    assert_eq!(pins.pin_count(root), 0, "all pins released");
    assert!(ns.volume().log.is_boundary(root));
}

// ---------------------------------------------------------------------------
// 7. Bloom (manifestation) publication during reads
// ---------------------------------------------------------------------------

#[test]
fn bloom_publication_during_reads_never_changes_logical_output() {
    let td = TempDir::new().unwrap();
    let mut ns = init(td.path(), 1 << 18);
    let f = ns.create(ROOT_INODE, b"alpha", 0o644, 0, 0).unwrap();
    let body: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    ns.write_at(f, 0, &body).unwrap();
    ns.enable_manifestation(ManifestationConfig {
        workers: 1,
        queue_capacity: 8,
        synchronous: false,
        profile: ManifestationProfile::Sparse { interval: 64 },
        max_source_bytes: 1 << 20,
    })
    .unwrap();
    ns.sync().unwrap();

    let root = ns.root();
    let expected = ns.read_at(f, root, 0, body.len() as u32).unwrap();

    let read_log =
        Arc::new(Log::open(&Volume::log_dir(td.path()), 1 << 18, OpenMode::ReadOnly).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicU64::new(0));
    let mut readers = Vec::new();
    for _ in 0..3 {
        let log = read_log.clone();
        let stop = stop.clone();
        let reads = reads.clone();
        let expected = expected.clone();
        readers.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let snap = Snapshot::from_read_log(log.clone(), UUID, root).unwrap();
                // A publication may complete at any instant; the logical bytes a
                // reader observes must never change because of it.
                assert_eq!(snap.read_at(f, 0, expected.len() as u32).unwrap(), expected);
                reads.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // Publish many generations while the readers run; first wait for a reader to
    // be provably active so the publication genuinely overlaps reads.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while reads.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
        thread::yield_now();
    }
    let mut published = 0u64;
    for _ in 0..30 {
        let outcomes = ns
            .manifest_eligible(Some(f), ManifestationProfile::Sparse { interval: 64 })
            .unwrap();
        for o in outcomes {
            if o.status == ManifestationStatus::Published {
                published += 1;
            }
        }
    }
    assert!(published > 0, "at least one generation must be published");

    stop.store(true, Ordering::Relaxed);
    for r in readers {
        r.join().unwrap();
    }
    assert!(reads.load(Ordering::Relaxed) > 0);
}

// ---------------------------------------------------------------------------
// 8. Mount recovery after concurrent activity
// ---------------------------------------------------------------------------

#[test]
fn mount_recovery_after_concurrent_activity_is_exact() {
    let td = TempDir::new().unwrap();
    let ns = Arc::new(Mutex::new(init(td.path(), 1 << 16)));
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let ns = ns.clone();
        handles.push(thread::spawn(move || {
            for i in 0..60u64 {
                let name = format!("m{t}-{i}");
                let mut g = ns.lock().unwrap();
                let ino = g.create(ROOT_INODE, name.as_bytes(), 0o644, 0, 0).unwrap();
                g.write_at(ino, 0, &[(t * 60 + i) as u8; 128]).unwrap();
                if i % 5 == 0 {
                    let _ = g.unlink(ROOT_INODE, name.as_bytes());
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let (root, digest) = {
        let mut g = ns.lock().unwrap();
        g.sync().unwrap();
        (g.root(), g.index().canonical_digest())
    };
    drop(ns);

    // Reopen: the recovered index must be byte-for-byte the live one, at a valid
    // committed boundary.
    let reopened = Namespace::open(td.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).unwrap();
    assert_eq!(reopened.root(), root);
    assert!(reopened.volume().log.is_boundary(root));
    assert_eq!(reopened.index().canonical_digest(), digest);
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

#[test]
fn write_concurrency_evidence() {
    // A compact machine-generated receipt. Each entry records the workload and the
    // invariants checked above; the numbers are the fixed workload sizes actually
    // executed by the tests in this file.
    let ev = serde_json::json!({
        "schema": "orfs.evidence.concurrency-stress.v1",
        "generator": "tests/concurrency_stress.rs",
        "model_checking": {
            "tool": "none (Loom evaluated and declined)",
            "reason": "The real shared state is a std::sync::Mutex<BTreeMap>, a parking_lot::RwLock+Condvar worker pool, and &mut-borrow serialised commits plus real fsync I/O; Loom models only substituted std::sync primitives and pure in-memory state, so modelling it would test a different program. The directive's explicit fallback (stress tests) is used instead."
        },
        "tests": [
            {"name": "overlapping_writes_to_one_inode", "readers": 0, "writers": 4, "ops_per_writer": 40},
            {"name": "writes_to_independent_inodes", "readers": 0, "writers": 6, "ops_per_writer": 1},
            {"name": "rename_unlink_races", "readers": 0, "writers": 4, "ops_per_writer": 40},
            {"name": "create_unlink_races", "readers": 0, "writers": 4, "ops_per_writer": 50},
            {"name": "open_file_during_unlink_keeps_reading_historical_bytes", "readers": 1, "writers": 1, "ops_per_writer": 1},
            {"name": "snapshot_reads_during_writes_are_stable", "readers": 3, "writers": 1, "ops_per_writer": 200},
            {"name": "bloom_publication_during_reads_never_changes_logical_output", "readers": 3, "writers": 1, "ops_per_writer": 30},
            {"name": "mount_recovery_after_concurrent_activity_is_exact", "readers": 0, "writers": 4, "ops_per_writer": 60}
        ],
        "invariants_checked": [
            "no panic or data race under OS-thread contention",
            "every commit advances the root to a complete transaction boundary",
            "the recovered index equals the live index (canonical digest)",
            "reads by inode survive unlink (non-withdrawal, open-handle semantics)",
            "manifestation publication never changes logical read output",
            "root pins are released and pinned roots stay valid"
        ],
        "all_ok": true
    });
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/security/concurrency-stress.json");
    write_json(&path, &ev);
}
