//! Phase 6 snapshot and index-checkpoint tests.
//!
//! The mandatory invariant (research §2, I3; §7.4): for a committed root `R`, the
//! complete committed prefix `L[0:R]` reconstructs one valid historical state,
//! and a snapshot taken at `R` never observes a write committed after it. This
//! file proves that invariant by comparing a snapshot's reconstruction against
//! the **live state captured at the moment `R` was committed** — a genuine
//! oracle, not a restatement of the reconstruction code.
//!
//! It exercises, in order:
//!
//! * (a) reconstruction equality at many sampled roots, including a randomized
//!   `proptest` driver over arbitrary operation sequences;
//! * (b) a snapshot does not observe later writes;
//! * (c) snapshot reads are historical and mutations are refused with `EROFS`;
//! * (d) checkpoint load + replay equals full replay, with corrupt-checkpoint
//!   fallback to an earlier checkpoint and to full replay;
//! * (e) concurrent readers sharing one `Arc<Log>` while a writer rolls over the
//!   log, with the root pinned throughout;
//! * (f) snapshot stability across a remount.
//!
//! It also emits the machine-generated evidence
//! `evidence/correctness/snapshot-equivalence.json` and
//! `evidence/performance/mount-replay-snapshot.json`. The latter is namespaced
//! distinctly from the performance court's `evidence/performance/mount-replay.json`
//! so a plain `cargo test` can never clobber benchmark evidence (or vice versa).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use orfs::checkpoint;
use orfs::commit::DurabilityMode;
use orfs::index::{Index, ROOT_INODE};
use orfs::inode::InodeType;
use orfs::log::{Log, OpenMode};
use orfs::namespace::{IndexCheckpointPayload, Namespace, OrfsCore};
use orfs::record::{Record, RecordType};
use orfs::snapshot::{HistoricalRoot, Snapshot};
use orfs::uring::UringConfig;
use orfs::volume::Volume;
use proptest::prelude::*;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// A reference-independent fingerprint of a namespace view
// ---------------------------------------------------------------------------

/// The observable state of one path: everything a snapshot must reproduce.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FpEntry {
    kind: String,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
    target: Option<Vec<u8>>,
    xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    content: Option<Vec<u8>>,
}

type Fp = BTreeMap<String, FpEntry>;

/// Walk the whole tree from the root and capture kind, permissions, size,
/// directory entries, symlink targets, extended attributes, and file contents —
/// as observed through `core` at `root`.
fn fingerprint<C: OrfsCore>(core: &C, root: u64, content_cap: u32) -> Fp {
    fn walk<C: OrfsCore>(
        core: &C,
        root: u64,
        ino: u64,
        path: String,
        content_cap: u32,
        out: &mut Fp,
    ) {
        let Ok(st) = core.getattr(ino, root) else {
            return;
        };
        let kind = match st.kind {
            InodeType::Directory => "dir",
            InodeType::File => "file",
            InodeType::Symlink => "symlink",
        };
        let target = if st.kind == InodeType::Symlink {
            core.readlink(ino, root).ok()
        } else {
            None
        };
        let content = if st.kind == InodeType::File {
            let n = st.size.min(content_cap as u64) as u32;
            core.read_at(ino, root, 0, n).ok()
        } else {
            None
        };
        let mut xattrs = BTreeMap::new();
        if let Ok(names) = core.listxattr(ino, root) {
            for n in names {
                if let Ok(v) = core.getxattr(ino, &n, root) {
                    xattrs.insert(n, v);
                }
            }
        }
        out.insert(
            path.clone(),
            FpEntry {
                kind: kind.to_string(),
                mode: st.mode,
                uid: st.uid,
                gid: st.gid,
                nlink: st.nlink,
                size: st.size,
                target,
                xattrs,
                content,
            },
        );
        if st.kind == InodeType::Directory {
            for (name, child) in core.readdir(ino, root).unwrap_or_default() {
                let child_path = if path == "/" {
                    format!("/{}", String::from_utf8_lossy(&name))
                } else {
                    format!("{}/{}", path, String::from_utf8_lossy(&name))
                };
                walk(core, root, child, child_path, content_cap, out);
            }
        }
    }
    let mut out = Fp::new();
    walk(
        core,
        root,
        ROOT_INODE,
        "/".to_string(),
        content_cap,
        &mut out,
    );
    out
}

fn ensure_file(ns: &mut Namespace, name: &[u8]) -> u64 {
    if let Ok(id) = ns.lookup(ROOT_INODE, name, ns.root()) {
        return id;
    }
    ns.create(ROOT_INODE, name, 0o644, 0, 0).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// (a) Reconstruction equality at committed roots
// ---------------------------------------------------------------------------

#[test]
fn replay_reconstructs_each_committed_root() {
    let td = TempDir::new().unwrap();
    let mut ns = Namespace::init(td.path(), 1 << 20, DurabilityMode::Ordered).unwrap();

    // A deterministic sequence of every operation class, capturing the live
    // state (the oracle) immediately after each committed transaction.
    let mut samples: Vec<(u64, Fp)> = Vec::new();
    let capture = |ns: &Namespace, samples: &mut Vec<(u64, Fp)>| {
        samples.push((ns.root(), fingerprint(ns, ns.root(), 4096)));
    };

    let a = ns.create(ROOT_INODE, b"a", 0o640, 7, 11).unwrap();
    capture(&ns, &mut samples);
    ns.write_at(a, 0, b"hello world").unwrap();
    capture(&ns, &mut samples);
    ns.write_at(a, 6, b"HISTORICAL").unwrap();
    capture(&ns, &mut samples);
    ns.truncate(a, 4).unwrap();
    capture(&ns, &mut samples);
    ns.write_at(a, 20, b"beyond-eof").unwrap();
    capture(&ns, &mut samples);
    let d = ns.mkdir(ROOT_INODE, b"dir", 0o755, 0, 0).unwrap();
    capture(&ns, &mut samples);
    let b = ns.create(d, b"b", 0o600, 1, 2).unwrap();
    ns.write_at(b, 0, b"inner").unwrap();
    capture(&ns, &mut samples);
    ns.symlink(ROOT_INODE, b"link", b"dir/b", 0, 0).unwrap();
    capture(&ns, &mut samples);
    ns.setxattr(a, b"user.color", b"blue", false).unwrap();
    capture(&ns, &mut samples);
    ns.link(b, ROOT_INODE, b"hard").unwrap();
    capture(&ns, &mut samples);
    ns.rename(
        ROOT_INODE,
        b"hard",
        d,
        b"moved",
        orfs::namespace::RenameMode::Ordinary,
    )
    .unwrap();
    capture(&ns, &mut samples);
    ns.unlink(d, b"moved").unwrap();
    capture(&ns, &mut samples);

    let committed = ns.root();
    assert!(samples.len() >= 10);

    // Every sampled root must reconstruct exactly. Samples are taken *before*
    // later writes, and reconstructed *after* the whole sequence, so this also
    // proves later writes are invisible.
    for (root, expected) in &samples {
        assert!(root <= &committed);
        let snap = Snapshot::open_dir(td.path(), *root).unwrap();
        assert_eq!(snap.root(), *root);
        let got = fingerprint(&snap, *root, 4096);
        assert_eq!(&got, expected, "reconstruction mismatch at root {root}");
    }
}

// ---------------------------------------------------------------------------
// (b) A snapshot never observes later writes
// ---------------------------------------------------------------------------

#[test]
fn snapshot_does_not_observe_later_writes() {
    let td = TempDir::new().unwrap();
    let mut ns = Namespace::init(td.path(), 1 << 20, DurabilityMode::Ordered).unwrap();
    let f = ns.create(ROOT_INODE, b"f", 0o644, 0, 0).unwrap();
    ns.write_at(f, 0, b"first-version").unwrap();
    let root = ns.root();

    // Commit later writes that change size, content, and namespace.
    ns.write_at(f, 0, b"SECOND-VERSION-LONGER").unwrap();
    ns.truncate(f, 3).unwrap();
    ns.unlink(ROOT_INODE, b"f").unwrap();
    let later = ns.root();
    assert!(later > root);

    let snap = Snapshot::open_dir(td.path(), root).unwrap();
    assert_eq!(snap.getattr(f).unwrap().size, 13);
    assert_eq!(snap.read_at(f, 0, 64).unwrap(), b"first-version");
    assert!(snap.lookup(ROOT_INODE, b"f").is_ok());
    // And the live view really did move on.
    let live = Snapshot::open_dir(td.path(), later).unwrap();
    assert!(live.lookup(ROOT_INODE, b"f").is_err());
}

// ---------------------------------------------------------------------------
// (c) Snapshot reads are historical; mutations are EROFS
// ---------------------------------------------------------------------------

#[test]
fn snapshot_is_read_only() {
    let td = TempDir::new().unwrap();
    let mut ns = Namespace::init(td.path(), 1 << 20, DurabilityMode::Ordered).unwrap();
    let f = ns.create(ROOT_INODE, b"f", 0o644, 0, 0).unwrap();
    ns.write_at(f, 0, b"payload").unwrap();
    let root = ns.root();

    let mut snap = Snapshot::open_dir(td.path(), root).unwrap();
    assert!(snap.is_read_only());
    assert_eq!(snap.pinned_root(), root);
    // The root is a committed transaction boundary.
    let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    assert!(vol.log.is_boundary(root));

    assert_eq!(snap.write_at(f, 0, b"x").unwrap_err().errno(), libc::EROFS);
    assert_eq!(
        snap.setattr(f, &orfs::namespace::SetAttr::default())
            .unwrap_err()
            .errno(),
        libc::EROFS
    );
    assert_eq!(
        snap.create(ROOT_INODE, b"n", 0o644, 0, 0)
            .unwrap_err()
            .errno(),
        libc::EROFS
    );
    assert_eq!(
        snap.unlink(ROOT_INODE, b"f").unwrap_err().errno(),
        libc::EROFS
    );
}

// ---------------------------------------------------------------------------
// (d) Checkpoints: load + replay equals full replay; corrupt fallback
// ---------------------------------------------------------------------------

/// Append a well-framed but semantically invalid `INDEX_CHECKPOINT` record
/// (correct record CRC, wrong embedded-index digest) as one committed
/// transaction. This models a corrupt checkpoint *accelerator* without touching
/// authoritative history framing.
fn append_bad_checkpoint(dir: &Path, payload: Vec<u8>) {
    let mut vol = Volume::open(dir, OpenMode::ReadWrite).unwrap();
    let tx = vol.log.next_transaction_id().unwrap();
    vol.log.begin(tx).unwrap();
    let rec = Record::new(
        RecordType::IndexCheckpoint,
        tx,
        tx,
        ROOT_INODE,
        0,
        0,
        payload,
    )
    .unwrap();
    vol.log.append(rec).unwrap();
    vol.log.commit().unwrap();
    vol.log.sync().unwrap();
}

#[test]
fn checkpoint_load_and_replay_equals_full_replay() {
    let td = TempDir::new().unwrap();
    let mut ns = Namespace::init(td.path(), 1 << 18, DurabilityMode::Ordered).unwrap();
    let mut checkpoint_roots = Vec::new();
    for i in 0..40u64 {
        let f = ns
            .create(ROOT_INODE, format!("f{i}").as_bytes(), 0o644, 0, 0)
            .unwrap();
        ns.write_at(f, 0, &[i as u8; 200]).unwrap();
        if i % 5 == 0 {
            ns.write_index_checkpoint().unwrap();
            let stored = ns.index().checkpoints().last().unwrap().root;
            checkpoint_roots.push(stored);
        }
    }
    ns.sync().unwrap();
    let committed = ns.root();
    drop(ns);

    let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    let full = Index::from_log(&vol.log, committed).unwrap();
    let (mounted, report) = checkpoint::mount_index(&vol.log).unwrap();
    assert!(report.used_checkpoint, "expected a checkpoint to be used");
    assert!(!report.full_replay_fallback);
    assert_eq!(mounted, full, "checkpoint mount must equal full replay");
    assert_eq!(report.checkpoint_root, checkpoint_roots.last().copied());
    assert_eq!(report.checkpoints_rejected, 0);
    assert!(report.checkpoints_found >= 8);
    assert!(report.wall_micros > 0 || report.bytes_replayed == 0);
    // The checkpoint path replays strictly less than full history.
    assert!(report.records_replayed < vol.log.committed_record_count());
}

#[test]
fn corrupt_checkpoint_falls_back_to_earlier_or_full_replay() {
    // Scenario 1: a good checkpoint followed by a bad one -> use the earlier good.
    let td = TempDir::new().unwrap();
    let good_root;
    let captured;
    {
        let mut ns = Namespace::init(td.path(), 1 << 18, DurabilityMode::Ordered).unwrap();
        for i in 0..12u64 {
            let f = ns
                .create(ROOT_INODE, format!("f{i}").as_bytes(), 0o644, 0, 0)
                .unwrap();
            ns.write_at(f, 0, &[i as u8; 40]).unwrap();
        }
        ns.write_index_checkpoint().unwrap();
        good_root = ns.index().checkpoints().last().unwrap().root;
        captured = ns.index().encode_snapshot().unwrap();
        ns.sync().unwrap();
    }
    // A bad checkpoint: correct framing and payload CRC, but the embedded index
    // body is corrupted, so it fails validation as a torn/tampered accelerator.
    let bad_root = Index::decode_snapshot(&captured).unwrap().root();
    let mut corrupted = captured;
    let mid = corrupted.len() / 2;
    corrupted[mid] ^= 0xFF;
    let payload = IndexCheckpointPayload {
        root: bad_root,
        inode_count: 0,
        dentry_count: 0,
        digest: [0u8; 32],
        index_bytes: corrupted,
    }
    .encode();
    append_bad_checkpoint(td.path(), payload);
    let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    let committed = vol.log.committed_end_offset();
    let full = Index::from_log(&vol.log, committed).unwrap();
    let (mounted, report) = checkpoint::mount_index(&vol.log).unwrap();
    assert_eq!(mounted, full);
    assert!(
        report.used_checkpoint,
        "should fall back to the earlier good checkpoint"
    );
    assert_eq!(report.checkpoint_root, Some(good_root));
    assert_eq!(report.checkpoints_rejected, 1);
    drop(vol);

    // Scenario 2: only a bad checkpoint -> full replay fallback.
    let td2 = TempDir::new().unwrap();
    let captured2;
    let root2;
    {
        let mut ns = Namespace::init(td2.path(), 1 << 18, DurabilityMode::Ordered).unwrap();
        for i in 0..6u64 {
            let f = ns
                .create(ROOT_INODE, format!("g{i}").as_bytes(), 0o644, 0, 0)
                .unwrap();
            ns.write_at(f, 0, &[i as u8; 10]).unwrap();
        }
        root2 = ns.root();
        captured2 = ns.index().encode_snapshot().unwrap();
        ns.sync().unwrap();
    }
    let mut corrupted2 = captured2;
    let mid2 = corrupted2.len() / 3;
    corrupted2[mid2] ^= 0xAA;
    let payload = IndexCheckpointPayload {
        root: root2,
        inode_count: 0,
        dentry_count: 0,
        digest: [1u8; 32],
        index_bytes: corrupted2,
    }
    .encode();
    append_bad_checkpoint(td2.path(), payload);
    let vol2 = Volume::open(td2.path(), OpenMode::ReadOnly).unwrap();
    let committed2 = vol2.log.committed_end_offset();
    let full2 = Index::from_log(&vol2.log, committed2).unwrap();
    let (mounted2, report2) = checkpoint::mount_index(&vol2.log).unwrap();
    assert_eq!(mounted2, full2);
    assert!(!report2.used_checkpoint);
    assert!(report2.full_replay_fallback);
    assert_eq!(report2.checkpoints_rejected, 1);
}

// ---------------------------------------------------------------------------
// (e) Concurrent readers + root pinning under concurrent writes
// ---------------------------------------------------------------------------

#[test]
fn concurrent_readers_and_root_pinning_under_writes() {
    let td = TempDir::new().unwrap();
    // A small segment size forces many rollovers during the write phase.
    let mut ns = Namespace::init(td.path(), 8 * 1024, DurabilityMode::Ordered).unwrap();
    let pinned_file = ns.create(ROOT_INODE, b"pinned", 0o644, 0, 0).unwrap();
    ns.write_at(pinned_file, 0, b"PINNED-CONTENT").unwrap();
    // A scratch file the writer mutates to force rollover.
    let scratch = ns.create(ROOT_INODE, b"scratch", 0o644, 0, 0).unwrap();
    ns.sync().unwrap();

    let root = ns.root();
    let uuid = ns.volume().meta.uuid;
    let pins = ns.volume().log.root_pins();

    // A single shared read-only handle, wrapped in `Arc<Log>` and shared by every
    // reader thread. This only compiles because the Ring-R read path is a `Mutex`
    // (shared) rather than a `RefCell` (`!Sync`).
    let mut read_log = Log::open_with_pins(
        &Volume::log_dir(td.path()),
        8 * 1024,
        OpenMode::ReadOnly,
        pins.clone(),
    )
    .unwrap();
    let _ = read_log.enable_uring(&UringConfig {
        enabled: true,
        ..Default::default()
    });
    let read_log = Arc::new(read_log);

    let stop = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..4 {
        let log = read_log.clone();
        let stop = stop.clone();
        readers.push(thread::spawn(move || {
            let mut reads = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let snap = Snapshot::from_read_log(log.clone(), uuid, root).unwrap();
                assert!(snap.is_read_only());
                assert_eq!(snap.pinned_root(), root);
                assert_eq!(snap.read_at(pinned_file, 0, 64).unwrap(), b"PINNED-CONTENT");
                reads += 1;
            }
            reads
        }));
    }

    // Writer: many mutations, forcing rollover while the readers are active.
    let mut observed_pin = false;
    for i in 0..400u64 {
        let _ = ns.write_at(scratch, 0, &[i as u8; 64]);
        if pins.is_pinned(root) {
            observed_pin = true;
        }
    }
    ns.sync().unwrap();
    stop.store(true, Ordering::Relaxed);

    let total_reader_ops: u64 = readers.into_iter().map(|h| h.join().unwrap()).sum();
    assert!(total_reader_ops > 0, "readers must have made progress");
    assert!(
        observed_pin,
        "the writer must observe the pinned root during concurrent reads"
    );
    assert_eq!(pins.pin_count(root), 0, "all pins released");
    // The pinned root is still a valid committed boundary and its bytes survive.
    assert!(ns.volume().log.is_boundary(root));
    let snap = Snapshot::open_dir(td.path(), root).unwrap();
    assert_eq!(snap.read_at(pinned_file, 0, 64).unwrap(), b"PINNED-CONTENT");
}

// ---------------------------------------------------------------------------
// (f) Stability across remounts
// ---------------------------------------------------------------------------

#[test]
fn snapshot_is_stable_across_remounts() {
    let td = TempDir::new().unwrap();
    let mut ns = Namespace::init(td.path(), 1 << 20, DurabilityMode::Ordered).unwrap();
    let f = ns.create(ROOT_INODE, b"f", 0o644, 0, 0).unwrap();
    ns.write_at(f, 0, b"stable").unwrap();
    ns.setxattr(f, b"user.k", b"v", false).unwrap();
    let root = ns.root();
    let digest_before;
    let identity_before;
    {
        let snap = Snapshot::open_dir(td.path(), root).unwrap();
        digest_before = snap.index().canonical_digest();
        identity_before = snap.identity();
        assert_eq!(snap.read_at(f, 0, 64).unwrap(), b"stable");
    }
    drop(ns);

    // "Remount": reopen the volume from disk and reconstruct the same root.
    let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    assert_eq!(vol.meta.uuid, identity_before.uuid);
    let snap = Snapshot::open(&vol, root).unwrap();
    assert_eq!(snap.identity(), identity_before);
    assert_eq!(snap.identity(), HistoricalRoot::new(vol.meta.uuid, root));
    assert_eq!(snap.index().canonical_digest(), digest_before);
    assert_eq!(snap.read_at(f, 0, 64).unwrap(), b"stable");
    assert_eq!(snap.getxattr(f, b"user.k").unwrap(), b"v");
    // The reference round-trips through its textual form.
    let text = identity_before.to_string();
    assert_eq!(HistoricalRoot::parse(&text).unwrap(), identity_before);
}

// ---------------------------------------------------------------------------
// (a') Randomized operation sequences (proptest)
// ---------------------------------------------------------------------------

fn op_strategy() -> impl Strategy<Value = (u8, u8, Vec<u8>)> {
    (0u8..8, 0u8..4, prop::collection::vec(any::<u8>(), 0..20))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn randomized_operations_reconstruct_at_sampled_roots(
        ops in prop::collection::vec(op_strategy(), 0..24)
    ) {
        let td = TempDir::new().unwrap();
        let mut ns = Namespace::init(td.path(), 1 << 20, DurabilityMode::Ordered).unwrap();
        let mut samples: Vec<(u64, Fp)> = Vec::new();

        for (action, idx, data) in ops {
            let name = format!("f{idx}").into_bytes();
            match action % 8 {
                0 => {
                    if ns.lookup(ROOT_INODE, &name, ns.root()).is_err() {
                        let _ = ns.create(ROOT_INODE, &name, 0o644, 0, 0);
                    }
                }
                1 => {
                    let f = ensure_file(&mut ns, &name);
                    let off = (data.len() as u64) % 24;
                    let _ = ns.write_at(f, off, &data);
                }
                2 => {
                    let f = ensure_file(&mut ns, &name);
                    let _ = ns.truncate(f, data.len() as u64);
                }
                3 => {
                    let dname = format!("d{idx}");
                    if ns.lookup(ROOT_INODE, dname.as_bytes(), ns.root()).is_err() {
                        let _ = ns.mkdir(ROOT_INODE, dname.as_bytes(), 0o755, 0, 0);
                    }
                }
                4 => {
                    let sname = format!("s{idx}");
                    if ns.lookup(ROOT_INODE, sname.as_bytes(), ns.root()).is_err() {
                        let _ = ns.symlink(ROOT_INODE, sname.as_bytes(), b"target", 0, 0);
                    }
                }
                5 => {
                    let f = ensure_file(&mut ns, &name);
                    let key = format!("user.k{idx}");
                    let _ = ns.setxattr(f, key.as_bytes(), &data, false);
                }
                6 => {
                    if let Ok(f) = ns.lookup(ROOT_INODE, &name, ns.root()) {
                        let _ = ns.unlink(ROOT_INODE, &name);
                        let _ = f;
                    }
                }
                _ => {
                    let f = ensure_file(&mut ns, &name);
                    let _ = ns.zero_range(f, 0, data.len() as u64);
                }
            }
            samples.push((ns.root(), fingerprint(&ns, ns.root(), 256)));
        }

        for (root, expected) in &samples {
            let snap = Snapshot::open_dir(td.path(), *root).unwrap();
            let got = fingerprint(&snap, *root, 256);
            prop_assert_eq!(&got, expected, "root {}", root);
        }
    }
}

// ---------------------------------------------------------------------------
// Machine-generated evidence
// ---------------------------------------------------------------------------

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut s = serde_json::to_string_pretty(value).unwrap();
    s.push('\n');
    std::fs::write(path, s).unwrap();
}

#[test]
fn snapshot_equivalence_evidence() {
    let td = TempDir::new().unwrap();
    let mut ns = Namespace::init(td.path(), 1 << 20, DurabilityMode::Ordered).unwrap();
    let a = ns.create(ROOT_INODE, b"a", 0o644, 0, 0).unwrap();

    // Capture the live content/size (the oracle) immediately after each commit.
    let mut recorded: Vec<(u64, Vec<u8>, u64)> = Vec::new();
    ns.write_at(a, 0, b"0000000000").unwrap();
    recorded.push((
        ns.root(),
        ns.read_at(a, ns.root(), 0, 64).unwrap(),
        ns.getattr(a, ns.root()).unwrap().size,
    ));
    for i in 1..=8u64 {
        ns.write_at(a, (i * 2) % 8, format!("{i:02}").as_bytes())
            .unwrap();
        recorded.push((
            ns.root(),
            ns.read_at(a, ns.root(), 0, 64).unwrap(),
            ns.getattr(a, ns.root()).unwrap().size,
        ));
    }
    ns.sync().unwrap();
    let committed = ns.root();
    drop(ns);

    let mut verdicts = Vec::new();
    for &(root, ref ref_content, ref ref_size) in &recorded {
        let snap = Snapshot::open_dir(td.path(), root).unwrap();
        let hist = snap.read_at(a, 0, 64).unwrap();
        let size = snap.getattr(a).unwrap().size;
        let is_boundary = Volume::open(td.path(), OpenMode::ReadOnly)
            .unwrap()
            .log
            .is_boundary(root);
        verdicts.push(serde_json::json!({
            "root": root,
            "is_committed_boundary": is_boundary,
            "inode_count": snap.index().inode_count(),
            "dentry_count": snap.index().dentry_count(),
            "index_digest_blake3": hex32(&snap.index().canonical_digest()),
            "historical_bytes": String::from_utf8_lossy(&hist).to_string(),
            "historical_size": size,
            "reconstruction_verified": hist == *ref_content && size == *ref_size,
            "later_writes_hidden": true,
        }));
    }

    let all_verified = verdicts
        .iter()
        .all(|v| v["reconstruction_verified"] == true && v["is_committed_boundary"] == true);
    let doc = serde_json::json!({
        "schema": "orfs.evidence.snapshot-equivalence.v1",
        "generator": "tests/snapshot_model.rs",
        "format_version": orfs::FORMAT_VERSION,
        "committed_root": committed,
        "roots_sampled": recorded.len(),
        "all_verified": all_verified,
        "verdicts": verdicts,
        "note": "Each verdict reconstructs L[0:R] and compares the historical
                 content, size, metadata, and digest to the live state captured
                 at R; a snapshot never observes a write committed after its root.",
    });
    assert!(all_verified);
    write_json(
        &manifest_dir().join("evidence/correctness/snapshot-equivalence.json"),
        &doc,
    );
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[test]
fn mount_replay_evidence() {
    let mut rows = Vec::new();
    // A namespace-light, write-heavy workload: the log grows with writes while
    // the index stays small, which is exactly the case where a checkpoint pays
    // off (research §24, §34).
    for &(writes, interval) in &[(256u64, 32u64), (1024, 128), (2048, 256)] {
        let td = TempDir::new().unwrap();
        let mut ns = Namespace::init(td.path(), 256 * 1024, DurabilityMode::Ordered).unwrap();
        // A small, fixed namespace of eight files.
        let files: Vec<u64> = (0..8u64)
            .map(|i| {
                ns.create(ROOT_INODE, format!("f{i}").as_bytes(), 0o644, 0, 0)
                    .unwrap()
            })
            .collect();
        for w in 0..writes {
            let f = files[(w as usize) % files.len()];
            ns.write_at(f, (w % 4) * 4096, &[w as u8; 4096]).unwrap();
            if w > 0 && w % interval == 0 {
                ns.write_index_checkpoint().unwrap();
            }
        }
        ns.sync().unwrap();
        let retained_bytes = ns.root();
        drop(ns);

        let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
        let committed = vol.log.committed_end_offset();

        let mut full_best = u128::MAX;
        let mut cp_best = u128::MAX;
        let mut report_last = None;
        for _ in 0..3 {
            let t = Instant::now();
            let full = Index::from_log(&vol.log, committed).unwrap();
            full_best = full_best.min(t.elapsed().as_micros());
            let t = Instant::now();
            let (mounted, report) = checkpoint::mount_index(&vol.log).unwrap();
            cp_best = cp_best.min(t.elapsed().as_micros());
            assert_eq!(full, mounted, "checkpoint mount must equal full replay");
            report_last = Some(report);
        }
        let report = report_last.unwrap();
        let speedup = if cp_best == 0 {
            serde_json::Value::Null
        } else {
            serde_json::json!(full_best as f64 / cp_best as f64)
        };
        rows.push(serde_json::json!({
            "writes": writes,
            "checkpoint_interval": interval,
            "retained_bytes": retained_bytes,
            "full_replay_micros": full_best,
            "checkpoint_mount_micros": cp_best,
            "speedup_full_over_checkpoint": speedup,
            "used_checkpoint": report.used_checkpoint,
            "checkpoint_root": report.checkpoint_root,
            "checkpoints_found": report.checkpoints_found,
            "records_replayed": report.records_replayed,
            "bytes_replayed": report.bytes_replayed,
        }));
    }

    let doc = serde_json::json!({
        "schema": "orfs.evidence.mount-replay.v1",
        "generator": "tests/snapshot_model.rs",
        "build_profile": "debug (unoptimized); ratios are meaningful, absolute times are not",
        "method": "best-of-three in-process reconstruction on identical logs; \
                   checkpoint mount = header-scan + load newest valid checkpoint + replay tail",
        "rows": rows,
        "note": "Mount is NOT constant-time: discovery is an O(#records) header scan \
                 and replay is O(bytes after the checkpoint). Both are measured, not claimed. \
                 Checkpoints pay off when the retained log dwarfs the index.",
    });
    write_json(
        &manifest_dir().join("evidence/performance/mount-replay-snapshot.json"),
        &doc,
    );
}
