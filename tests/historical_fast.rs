//! Phase 43 — the persistent historical fast path: the immutable binary
//! historical accelerator and the derived committed-root directory.
//!
//! # Quick open vs. complete audit
//!
//! Two operations are deliberately distinct and this file exercises both:
//!
//! * a **quick open** reuses a persisted accelerator validated for exactly
//!   `(uuid, root)`; `checkpoint::DiscoverySource::ValidatedAccelerator` and
//!   `MountReport::audited() == false` mark it. The log is not replayed.
//! * a **complete audit** reads and validates authoritative records
//!   (`checkpoint::mount_index`, `checkpoint::mount_index_at`,
//!   `checkpoint::mount_index_scan`) and reports a discovery source that is an
//!   audit.
//!
//! The correctness court proves a quick open returns **byte-identical** state to
//! the audit at the same root, and the adversarial court proves that a torn,
//! truncated, corrupt, or foreign accelerator — and a missing or corrupt derived
//! committed-root directory — always falls back to the authoritative
//! reconstruction and never returns wrong bytes or a wrong root.
//!
//! It emits `evidence/performance/historical-fast.json`. A larger sweep is opt-in
//! via `scripts/container-historical-fast.sh` (env `ORFS_HISTORICAL_FAST_OPS`,
//! `ORFS_HISTORICAL_FAST_ROOTS`); the defaults keep the plain `cargo test` gate
//! bounded.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use orfs::checkpoint::{self, DiscoverySource};
use orfs::commit::DurabilityMode;
use orfs::historical::{
    self, historical_accelerator_path, historical_index_path, load_persisted_historical,
    RootCatalogue,
};
use orfs::index::{Index, ROOT_INODE};
use orfs::inode::InodeType;
use orfs::log::OpenMode;
use orfs::namespace::{Namespace, OrfsCore};
use orfs::snapshot::Snapshot;
use orfs::volume::Volume;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// A process-global allocation counter, so the acceptance court can report
// allocations directly rather than guessing. Deltas are taken around a tight
// measured region; other tests in this binary may add noise (the evidence note
// says so honestly).
// ---------------------------------------------------------------------------

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn alloc_snapshot() -> (u64, u64) {
    (
        ALLOCS.load(Ordering::Relaxed),
        ALLOC_BYTES.load(Ordering::Relaxed),
    )
}

fn alloc_delta(before: (u64, u64)) -> (u64, u64) {
    let after = alloc_snapshot();
    (after.0 - before.0, after.1 - before.1)
}

/// Process page faults (minor + major) since start.
fn page_faults() -> (i64, i64) {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `getrusage` with a valid out-pointer; the pid argument is ignored.
    unsafe {
        libc::getrusage(libc::RUSAGE_SELF, &mut ru);
    }
    (ru.ru_minflt as i64, ru.ru_majflt as i64)
}

fn fault_delta(before: (i64, i64)) -> (i64, i64) {
    let after = page_faults();
    (after.0 - before.0, after.1 - before.1)
}

// ---------------------------------------------------------------------------
// History building
// ---------------------------------------------------------------------------

/// Build a namespace-light, write-heavy history with a checkpoint every
/// `checkpoint_every` ops; returns the committed root sampled after each op.
fn build_history(dir: &Path, ops: u64, checkpoint_every: u64, chunk: usize) -> Vec<u64> {
    let mut ns = Namespace::init(dir, 1 << 24, DurabilityMode::Ordered).expect("init volume");
    let dirs: Vec<u64> = (0..16)
        .map(|i| {
            ns.mkdir(ROOT_INODE, format!("d{i}").as_bytes(), 0o755, 0, 0)
                .expect("mkdir")
        })
        .collect();
    let data = vec![0x5Au8; chunk];
    let mut roots = Vec::new();
    for i in 0..ops {
        if checkpoint_every > 0 && i > 0 && i % checkpoint_every == 0 {
            ns.write_index_checkpoint().expect("checkpoint");
        }
        let d = dirs[(i as usize) % dirs.len()];
        let f = ns
            .create(d, format!("f{i:012}").as_bytes(), 0o644, 0, 0)
            .expect("create");
        ns.write_at(f, 0, &data).expect("write");
        roots.push(ns.root());
    }
    ns.sync().expect("sync");
    roots
}

/// A reference-independent fingerprint of the namespace at a root, used to prove
/// byte-exactness of a fast open against an authoritative reconstruction.
type Fp = BTreeMap<String, (u32, u64, Option<Vec<u8>>)>;

fn fingerprint<C: OrfsCore>(core: &C, root: u64, cap: u32) -> Fp {
    fn walk<C: OrfsCore>(core: &C, root: u64, ino: u64, path: String, cap: u32, out: &mut Fp) {
        let Ok(st) = core.getattr(ino, root) else {
            return;
        };
        let content = if st.kind == InodeType::File {
            core.read_at(ino, root, 0, cap).ok()
        } else {
            None
        };
        out.insert(path.clone(), (st.mode, st.size, content));
        if st.kind == InodeType::Directory {
            for (name, child) in core.readdir(ino, root).unwrap_or_default() {
                let child_path = if path == "/" {
                    format!("/{}", String::from_utf8_lossy(&name))
                } else {
                    format!("{}/{}", path, String::from_utf8_lossy(&name))
                };
                walk(core, root, child, child_path, cap, out);
            }
        }
    }
    let mut out = Fp::new();
    walk(core, root, ROOT_INODE, "/".to_string(), cap, &mut out);
    out
}

fn percentiles(mut xs: Vec<u64>) -> serde_json::Value {
    if xs.is_empty() {
        return serde_json::json!({ "count": 0 });
    }
    xs.sort_unstable();
    let p = |q: f64| xs[((xs.len() as f64 - 1.0) * q).round() as usize];
    let sum: u64 = xs.iter().sum();
    serde_json::json!({
        "count": xs.len(),
        "min_ns": xs[0],
        "p50_ns": p(0.50),
        "p95_ns": p(0.95),
        "p99_ns": p(0.99),
        "max_ns": xs[xs.len() - 1],
        "mean_ns": sum / xs.len() as u64,
    })
}

// ---------------------------------------------------------------------------
// Correctness: a fast open equals the audited reconstruction, byte-for-byte
// ---------------------------------------------------------------------------

#[test]
fn fast_open_equals_audited_reconstruction_byte_exact() {
    let td = TempDir::new().unwrap();
    let roots = build_history(td.path(), 160, 20, 3072);
    let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    let log = &vol.log;
    let uuid = vol.meta.uuid;
    let index_dir = td.path().join("index");

    // Sample roots across the history, including the head.
    let samples: Vec<u64> = (0..roots.len()).step_by(23).map(|i| roots[i]).collect();
    assert!(samples.len() >= 5);

    for &root in &samples {
        // The authoritative reconstruction (an audit).
        let (audited, report) = checkpoint::mount_index_at(log, root).unwrap();
        assert!(report.discovery_source.is_audit(), "must be an audit");
        assert_eq!(audited, Index::from_log(log, root).unwrap());

        // An audit-only snapshot: ensure no accelerator exists for this root, so
        // the snapshot reconstructs from the log.
        let _ = std::fs::remove_file(historical_accelerator_path(&index_dir, root));
        let audited_only = Snapshot::open_dir(td.path(), root).unwrap();

        // A validated quick open: persist the binary accelerator, then open again.
        historical::persist_historical(&index_dir, &uuid, &audited).unwrap();
        let quick = load_persisted_historical(&index_dir, &uuid, root)
            .unwrap()
            .expect("accelerator loads");
        assert_eq!(quick, audited, "quick open must equal the audit at {root}");
        assert_eq!(quick.canonical_digest(), audited.canonical_digest());

        let fast = Snapshot::open_dir(td.path(), root).unwrap();
        assert_eq!(
            fingerprint(&fast, root, 64),
            fingerprint(&audited_only, root, 64),
            "historical reads at {root} must be byte-exact between the quick open \
             and the audited reconstruction"
        );
    }
}

#[test]
fn binary_accelerator_decodes_identically_to_the_legacy_json_form() {
    let td = TempDir::new().unwrap();
    let mut ns = Namespace::init(td.path(), 1 << 20, DurabilityMode::Ordered).unwrap();
    let d = ns.mkdir(ROOT_INODE, b"dir", 0o755, 0, 0).unwrap();
    let f = ns.create(d, b"f", 0o644, 123, 456).unwrap();
    ns.write_at(f, 0, b"payload").unwrap();
    ns.setxattr(f, b"user.k", b"v", false).unwrap();
    ns.symlink(ROOT_INODE, b"link", b"dir/f", 0, 0).unwrap();
    let root = ns.root();
    let uuid = ns.volume().meta.uuid;
    let index = Index::from_log(&ns.volume().log, root).unwrap();

    let binary = historical::encode_historical_accelerator(&index, &uuid).unwrap();
    let legacy = historical::encode_historical(&index, &uuid).unwrap();
    assert_eq!(
        historical::decode_historical_accelerator(&binary, &uuid, root).unwrap(),
        index
    );
    assert_eq!(
        historical::decode_historical(&legacy, &uuid, root).unwrap(),
        index
    );
    // The binary container is the smaller, JSON-free representation.
    assert!(
        binary.len() < legacy.len(),
        "binary {} bytes should be smaller than JSON {} bytes",
        binary.len(),
        legacy.len()
    );
}

// ---------------------------------------------------------------------------
// Quick open is distinguished from an audit, and falls back when untrusted
// ---------------------------------------------------------------------------

#[test]
fn open_index_quick_is_a_marked_quick_open_and_falls_back() {
    let td = TempDir::new().unwrap();
    let _ = build_history(td.path(), 120, 24, 1024);
    let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    let log = &vol.log;
    let committed = log.committed_end_offset();
    let reference = Index::from_log(log, committed).unwrap();

    // Nothing persisted yet: `open_index_quick` must fall back to an audit.
    let (index, report) = checkpoint::open_index_quick(log).unwrap();
    assert_eq!(index, reference);
    assert!(report.audited(), "no accelerator means an audit");
    assert_ne!(
        report.discovery_source,
        DiscoverySource::ValidatedAccelerator
    );

    // Publish a validated accelerator for the committed root.
    historical::publish_head_accelerator(log, &reference).unwrap();
    let path = historical_accelerator_path(&td.path().join("index"), committed);
    assert!(path.exists());

    let (index, report) = checkpoint::open_index_quick(log).unwrap();
    assert_eq!(index, reference, "the quick open equals the audit");
    assert_eq!(
        report.discovery_source,
        DiscoverySource::ValidatedAccelerator
    );
    assert!(!report.audited(), "a quick open is not an audit");
    assert_eq!(report.bytes_replayed, 0);

    // Torn accelerator: fall back to the audit, still byte-identical.
    let good = std::fs::read(&path).unwrap();
    std::fs::write(&path, &good[..good.len() / 2]).unwrap();
    let (index, report) = checkpoint::open_index_quick(log).unwrap();
    assert_eq!(index, reference);
    assert!(report.audited(), "a torn accelerator must not be trusted");

    // Foreign volume uuid: rejected.
    let mut foreign = good.clone();
    foreign[16] ^= 0xFF;
    std::fs::write(&path, &foreign).unwrap();
    let (index, report) = checkpoint::open_index_quick(log).unwrap();
    assert_eq!(index, reference);
    assert!(report.audited());
}

// ---------------------------------------------------------------------------
// Adversarial: torn / truncated / corrupt accelerator, missing directory,
// corrupt directory — all fall back and never return wrong bytes or a root
// ---------------------------------------------------------------------------

/// A committed-root directory record is `[len u32][body 60][crc u32]` = 68 bytes;
/// the body is `kind u32 @0`, `watermark u64 @4`, `offset u64 @12`, `root u64
/// @20`, `digest [32] @28`. Patch one 8-byte field and fix the CRC, modelling a
/// corrupt (but well-framed) directory record.
fn patch_catalogue_field(path: &Path, record_index: usize, body_offset: usize, value: u64) {
    let mut bytes = std::fs::read(path).unwrap();
    let off = record_index * 68;
    let at = off + 4 + body_offset;
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    let crc = crc32c::crc32c(&bytes[off..off + 64]);
    bytes[off + 64..off + 68].copy_from_slice(&crc.to_le_bytes());
    std::fs::write(path, &bytes).unwrap();
}

#[test]
fn a_corrupt_accelerator_never_yields_a_wrong_root_or_bytes() {
    let td = TempDir::new().unwrap();
    let roots = build_history(td.path(), 140, 20, 2048);
    let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    let log = &vol.log;
    let uuid = vol.meta.uuid;
    let index_dir = td.path().join("index");
    let target = roots[roots.len() * 3 / 4];
    let reference = Index::from_log(log, target).unwrap();
    historical::persist_historical(&index_dir, &uuid, &reference).unwrap();
    let path = historical_accelerator_path(&index_dir, target);
    let encoded = std::fs::read(&path).unwrap();

    let hdr = historical::HISTORICAL_ACCELERATOR_HEADER_LEN;

    // (1) Zero-length file.
    std::fs::write(&path, b"").unwrap();
    assert!(load_persisted_historical(&index_dir, &uuid, target)
        .unwrap()
        .is_none());
    assert_eq!(
        checkpoint::mount_index_at(log, target).unwrap().0,
        reference
    );

    // (2) Truncated inside the header.
    std::fs::write(&path, &encoded[..hdr - 4]).unwrap();
    assert!(load_persisted_historical(&index_dir, &uuid, target)
        .unwrap()
        .is_none());
    assert_eq!(
        checkpoint::mount_index_at(log, target).unwrap().0,
        reference
    );

    // (3) Truncated at the tail (a torn write).
    std::fs::write(&path, &encoded[..encoded.len() - 3]).unwrap();
    assert!(load_persisted_historical(&index_dir, &uuid, target)
        .unwrap()
        .is_none());

    // (4) Corrupt header magic.
    let mut bad = encoded.clone();
    bad[0] ^= 0xFF;
    std::fs::write(&path, &bad).unwrap();
    assert!(load_persisted_historical(&index_dir, &uuid, target)
        .unwrap()
        .is_none());

    // (5) Corrupt declared header length.
    let mut bad = encoded.clone();
    bad[12] = 0x40;
    std::fs::write(&path, &bad).unwrap();
    assert!(load_persisted_historical(&index_dir, &uuid, target)
        .unwrap()
        .is_none());

    // (6) Corrupt blob byte (the whole-representation digest must catch it).
    let mut bad = encoded.clone();
    bad[hdr + 8] ^= 0xFF;
    std::fs::write(&path, &bad).unwrap();
    assert!(load_persisted_historical(&index_dir, &uuid, target)
        .unwrap()
        .is_none());

    // (7) Corrupt footer digest.
    let mut bad = encoded.clone();
    let n = bad.len();
    bad[n - 1] ^= 0xFF;
    std::fs::write(&path, &bad).unwrap();
    assert!(load_persisted_historical(&index_dir, &uuid, target)
        .unwrap()
        .is_none());

    // (8) A well-formed accelerator for a *different* root must not be
    //     reinterpreted: it fails the root check.
    let other = roots[roots.len() / 4];
    let other_index = Index::from_log(log, other).unwrap();
    historical::persist_historical(&index_dir, &uuid, &other_index).unwrap();
    let other_path = historical_accelerator_path(&index_dir, other);
    std::fs::copy(&other_path, &path).unwrap();
    assert!(load_persisted_historical(&index_dir, &uuid, target)
        .unwrap()
        .is_none());

    // (9) A foreign volume uuid is rejected.
    std::fs::write(&path, &encoded).unwrap();
    let mut foreign = encoded.clone();
    foreign[16] ^= 0xFF;
    std::fs::write(&path, &foreign).unwrap();
    assert!(load_persisted_historical(&index_dir, &uuid, target)
        .unwrap()
        .is_none());

    // In every case the authoritative reconstruction is still exact, and a
    // snapshot over the volume still reads the right bytes.
    let (audited, report) = checkpoint::mount_index_at(log, target).unwrap();
    assert_eq!(audited, reference);
    assert!(report.discovery_source.is_audit());
    let snap = Snapshot::open_dir(td.path(), target).unwrap();
    assert_eq!(
        snap.index().canonical_digest(),
        reference.canonical_digest()
    );
}

#[test]
fn a_missing_or_corrupt_directory_falls_back_to_the_authoritative_scan() {
    let td = TempDir::new().unwrap();
    let _ = build_history(td.path(), 160, 20, 2048);
    let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    let log = &vol.log;
    let committed = log.committed_end_offset();
    let reference = Index::from_log(log, committed).unwrap();

    // (1) Missing directory: the audit scans and rebuilds it.
    assert!(!RootCatalogue::new(td.path()).dir().exists());
    let (mounted, report) = checkpoint::mount_index(log).unwrap();
    assert_eq!(mounted, reference);
    assert!(report.audited());
    assert_eq!(report.discovery_source, DiscoverySource::LogScan);

    // The directory now exists and is complete for the committed root.
    let catalogue = RootCatalogue::new(td.path());
    assert_eq!(catalogue.watermark(), Some(committed));
    let offsets = catalogue.checkpoint_offsets_below(committed).unwrap();
    assert!(!offsets.is_empty());

    // (2) A warm mount uses the directory and skips the whole-log scan.
    let (mounted, report) = checkpoint::mount_index(log).unwrap();
    assert_eq!(mounted, reference);
    assert_eq!(report.discovery_source, DiscoverySource::Catalogue);
    assert!(report.audited());

    // (3) Corrupt the *newest* recorded checkpoint offset to a large invalid
    //     value (well-framed, fixed CRC). The directory now points at a bogus
    //     location; the audit must reject it and fall back to the scan.
    let seg = catalogue.dir().join("seg-0000000000.cat");
    patch_catalogue_field(&seg, offsets.len() - 1, 12, committed - 1);
    let (mounted, report) = checkpoint::mount_index(log).unwrap();
    assert_eq!(
        mounted, reference,
        "a bogus directory entry must not be trusted"
    );
    assert!(report.audited());
    assert_ne!(
        report.discovery_source,
        DiscoverySource::ValidatedAccelerator
    );

    // (4) Truncate the directory segments to garbage: unusable, so scan.
    std::fs::write(&seg, b"\x00\x01\x02not a record").unwrap();
    let (mounted, report) = checkpoint::mount_index(log).unwrap();
    assert_eq!(mounted, reference);
    assert_eq!(report.discovery_source, DiscoverySource::LogScan);

    // (5) A hole (an interior segment appearing) must not be trusted.
    std::fs::write(catalogue.dir().join("seg-0000000003.cat"), b"x").unwrap();
    let (mounted, report) = checkpoint::mount_index(log).unwrap();
    assert_eq!(mounted, reference);
    assert_eq!(report.discovery_source, DiscoverySource::LogScan);

    // (6) A directory claiming a watermark *ahead of the log* is over-claiming
    //     (corruption) and is distrusted.
    let td2 = TempDir::new().unwrap();
    let _ = build_history(td2.path(), 60, 15, 1024);
    let vol2 = Volume::open(td2.path(), OpenMode::ReadOnly).unwrap();
    let reference2 = Index::from_log(&vol2.log, vol2.log.committed_end_offset()).unwrap();
    let _ = checkpoint::mount_index(&vol2.log).unwrap();
    let cat2 = RootCatalogue::new(td2.path());
    let seg2 = cat2.dir().join("seg-0000000000.cat");
    let offs2 = cat2
        .checkpoint_offsets_below(vol2.log.committed_end_offset())
        .unwrap();
    // The watermark record follows the checkpoint records; patch its `root`.
    patch_catalogue_field(&seg2, offs2.len(), 20, u64::MAX - 1);
    let (mounted, report) = checkpoint::mount_index(&vol2.log).unwrap();
    assert_eq!(mounted, reference2);
    assert_eq!(report.discovery_source, DiscoverySource::LogScan);
}

#[test]
fn a_catalogue_pointing_at_an_older_checkpoint_is_still_exact() {
    // Even when the derived directory names an older (but valid) checkpoint, the
    // reconstruction must be byte-identical; the fast path may only cost replay,
    // never correctness.
    let td = TempDir::new().unwrap();
    let _ = build_history(td.path(), 180, 20, 2048);
    let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    let log = &vol.log;
    let committed = log.committed_end_offset();
    let reference = Index::from_log(log, committed).unwrap();
    let _ = checkpoint::mount_index(log).unwrap();

    let cat = RootCatalogue::new(td.path());
    let seg = cat.dir().join("seg-0000000000.cat");
    let offsets = cat.checkpoint_offsets_below(committed).unwrap();
    assert!(offsets.len() >= 2);
    // Point the newest recorded checkpoint at the *oldest* one's offset.
    patch_catalogue_field(&seg, offsets.len() - 1, 12, offsets[0]);

    let (mounted, report) = checkpoint::mount_index(log).unwrap();
    assert_eq!(mounted, reference, "must remain byte-exact");
    assert!(report.used_checkpoint);
    assert_eq!(report.discovery_source, DiscoverySource::Catalogue);
}

// ---------------------------------------------------------------------------
// Acceptance / measurement court
// ---------------------------------------------------------------------------

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

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

fn evidence_environment() -> serde_json::Value {
    serde_json::json!({
        "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "image_digest": std::env::var("ORFS_IMAGE_DIGEST").unwrap_or_else(|_| "unknown".into()),
    })
}

#[test]
fn historical_fast_evidence() {
    // Bounded by default; the opt-in container runner scales these up.
    let ops = env_u64("ORFS_HISTORICAL_FAST_OPS", 600);
    let checkpoint_every = env_u64("ORFS_HISTORICAL_FAST_CHECKPOINT_EVERY", 100);
    let history_roots = env_u64("ORFS_HISTORICAL_FAST_ROOTS", 64);
    let warm_sample = env_u64("ORFS_HISTORICAL_FAST_WARM_SAMPLE", 24).min(history_roots);

    // --- A. Mount recovery: scan (before) vs. directory (after) --------------
    let td = TempDir::new().unwrap();
    let _ = build_history(td.path(), ops, checkpoint_every, 4096);
    let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
    let log = &vol.log;
    let committed = log.committed_end_offset();
    let uuid = vol.meta.uuid;
    let reference = Index::from_log(log, committed).unwrap();

    let mut mount_rows = Vec::new();
    // Cold: the first mount_index completes a scan and publishes the directory.
    let t = Instant::now();
    let (m, cold_report) = checkpoint::mount_index(log).unwrap();
    let cold_ns = t.elapsed().as_nanos() as u64;
    assert_eq!(m, reference);
    assert_eq!(cold_report.discovery_source, DiscoverySource::LogScan);
    // Warm: the directory is complete, so no whole-log discovery scan.
    let mut warm_ns = Vec::new();
    for _ in 0..3 {
        let t = Instant::now();
        let (m, r) = checkpoint::mount_index(log).unwrap();
        warm_ns.push(t.elapsed().as_nanos() as u64);
        assert_eq!(m, reference);
        assert_eq!(r.discovery_source, DiscoverySource::Catalogue);
    }
    // "Before": the pre-Phase-43 algorithm, which always scans the whole log.
    let mut scan_ns = Vec::new();
    for _ in 0..3 {
        let t = Instant::now();
        let (m, r) = checkpoint::mount_index_scan(log).unwrap();
        scan_ns.push(t.elapsed().as_nanos() as u64);
        assert_eq!(m, reference);
        assert_eq!(r.discovery_source, DiscoverySource::LogScan);
    }
    let warm_best = warm_ns.iter().copied().min().unwrap();
    let scan_best = scan_ns.iter().copied().min().unwrap();
    mount_rows.push(serde_json::json!({
        "ops": ops,
        "checkpoint_every": checkpoint_every,
        "retained_bytes": committed,
        "checkpoints_found": cold_report.checkpoints_found,
        "index_inode_count": cold_report.index_inode_count,
        "mount_cold_scan_and_publish_ns": cold_ns,
        "mount_scan_only_ns": percentiles(scan_ns),
        "mount_catalogue_ns": percentiles(warm_ns.clone()),
        "speedup_scan_over_catalogue": if warm_best == 0 { serde_json::Value::Null }
            else { serde_json::json!(scan_best as f64 / warm_best as f64) },
    }));

    // --- B. Historical-root opens: cold (replay) vs. warm (accelerator) ------
    // A separate, small-payload history so that opening many distinct roots (each
    // of which re-opens the log) stays practical at the opt-in scale.
    let root_ops = env_u64("ORFS_HISTORICAL_FAST_ROOT_OPS", 400);
    let td2 = TempDir::new().unwrap();
    let roots = build_history(td2.path(), root_ops, (root_ops / 8).max(1), 64);
    let vol2 = Volume::open(td2.path(), OpenMode::ReadOnly).unwrap();
    let log2 = &vol2.log;
    let uuid2 = vol2.meta.uuid;
    let index_dir2 = td2.path().join("index");
    let step = (roots.len() / history_roots as usize).max(1);
    let sample: Vec<u64> = roots
        .iter()
        .step_by(step)
        .copied()
        .take(history_roots as usize)
        .collect();

    let mut cold_ns = Vec::new();
    for &r in &sample {
        let t = Instant::now();
        let s = Snapshot::open_dir(td2.path(), r).unwrap();
        std::hint::black_box(s.index().inode_count());
        cold_ns.push(t.elapsed().as_nanos() as u64);
    }

    // Persist binary accelerators for a bounded sample, then measure warm opens.
    let warm_roots: Vec<u64> = sample
        .iter()
        .rev()
        .take(warm_sample as usize)
        .copied()
        .collect();
    for &r in &warm_roots {
        let idx = Index::from_log(log2, r).unwrap();
        historical::persist_historical(&index_dir2, &uuid2, &idx).unwrap();
    }
    let mut hist_warm_ns = Vec::new();
    for &r in &warm_roots {
        let t = Instant::now();
        let s = Snapshot::open_dir(td2.path(), r).unwrap();
        std::hint::black_box(s.index().inode_count());
        hist_warm_ns.push(t.elapsed().as_nanos() as u64);
    }

    // --- C. Accelerator load: binary vs. legacy JSON, with allocations ------
    let index_dir = td.path().join("index");
    let big_index = Index::from_log(log, committed).unwrap();
    let binary = historical::encode_historical_accelerator(&big_index, &uuid).unwrap();
    let legacy = historical::encode_historical(&big_index, &uuid).unwrap();
    let bin_path = historical_accelerator_path(&index_dir, committed);
    let legacy_path = historical_index_path(&index_dir, committed);
    std::fs::create_dir_all(bin_path.parent().unwrap()).unwrap();
    std::fs::write(&bin_path, &binary).unwrap();
    std::fs::write(&legacy_path, &legacy).unwrap();

    // A validated quick open at the committed root (loads the binary accelerator).
    let (quick, quick_report) = checkpoint::open_index_quick(log).unwrap();
    assert_eq!(quick, reference);
    assert_eq!(
        quick_report.discovery_source,
        DiscoverySource::ValidatedAccelerator
    );
    assert!(!quick_report.audited());

    // Time the quick open against the audited catalogue-assisted mount on the
    // same volume: this is the clean measurement of "quick open vs. audit".
    let mut quick_ns = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        let (q, r) = checkpoint::open_index_quick(log).unwrap();
        quick_ns.push(t.elapsed().as_nanos() as u64);
        assert_eq!(q, reference);
        assert_eq!(r.discovery_source, DiscoverySource::ValidatedAccelerator);
    }
    let quick_best = quick_ns.iter().copied().min().unwrap();
    let audited_best = warm_ns.iter().copied().min().unwrap();

    let reps = 20;
    let a0 = alloc_snapshot();
    let f0 = page_faults();
    let t = Instant::now();
    for _ in 0..reps {
        let idx = load_persisted_historical(&index_dir, &uuid, committed)
            .unwrap()
            .unwrap();
        std::hint::black_box(idx.inode_count());
    }
    let binary_load_ns = t.elapsed().as_nanos() as u64 / reps;
    let binary_alloc = alloc_delta(a0);
    let binary_faults = fault_delta(f0);

    let a0 = alloc_snapshot();
    let f0 = page_faults();
    let t = Instant::now();
    for _ in 0..reps {
        let bytes = std::fs::read(&legacy_path).unwrap();
        let idx = historical::decode_historical(&bytes, &uuid, committed).unwrap();
        std::hint::black_box(idx.inode_count());
    }
    let legacy_load_ns = t.elapsed().as_nanos() as u64 / reps;
    let legacy_alloc = alloc_delta(a0);
    let legacy_faults = fault_delta(f0);

    let doc = serde_json::json!({
        "schema": "orfs.evidence.historical-fast.v1",
        "generator": "tests/historical_fast.rs",
        "format_version": orfs::FORMAT_VERSION,
        "environment": evidence_environment(),
        "build_profile": "debug (unoptimized) unless built with --release; absolute times are \
                          host/build dependent, byte counts are exact",
        "mount_recovery": {
            "method": "mount_index cold completes a scan and publishes the derived committed-root \
                       directory; mount_index warm consults it and skips the whole-log discovery \
                       scan; mount_index_scan is the pre-Phase-43 algorithm (always scans)",
            "rows": mount_rows,
        },
        "mount_quick_open": {
            "method": "checkpoint::open_index_quick loads a validated accelerator for exactly the \
                       committed root: a quick open (log not replayed), never an audit. Compare \
                       against the catalogue-assisted audited mount on the same volume.",
            "quick_open_ns": percentiles(quick_ns),
            "audited_catalogue_mount_ns": percentiles(warm_ns.clone()),
            "speedup_audit_over_quick_open": if quick_best == 0 { serde_json::Value::Null }
                else { serde_json::json!(audited_best as f64 / quick_best as f64) },
            "quick_open_is_an_audit": false,
        },
        "historical_root_open": {
            "method": "Snapshot::open_dir for distinct roots of a small-payload history: cold (no \
                       accelerator) replays from a checkpoint; warm loads the persisted accelerator. \
                       The discovery directory is already complete, so cold opens differ only by \
                       the accelerator.",
            "history_ops": root_ops,
            "roots_sampled": sample.len(),
            "warm_sample": warm_roots.len(),
            "cold_open_ns": percentiles(cold_ns),
            "warm_open_ns": percentiles(hist_warm_ns),
        },
        "accelerator_load": {
            "method": "load the persisted accelerator for the committed root, binary container vs. \
                       legacy JSON envelope, mean over repeated loads",
            "root": committed,
            "index_inode_count": big_index.inode_count(),
            "reps": reps,
            "binary_bytes": binary.len(),
            "legacy_json_bytes": legacy.len(),
            "size_ratio_json_over_binary": legacy.len() as f64 / binary.len() as f64,
            "binary_load_ns": binary_load_ns,
            "legacy_json_load_ns": legacy_load_ns,
            "speedup_legacy_over_binary": if binary_load_ns == 0 { serde_json::Value::Null }
                else { serde_json::json!(legacy_load_ns as f64 / binary_load_ns as f64) },
            "binary_allocations_per_load": binary_alloc.0 as f64 / reps as f64,
            "binary_bytes_allocated_per_load": binary_alloc.1 as f64 / reps as f64,
            "legacy_allocations_per_load": legacy_alloc.0 as f64 / reps as f64,
            "legacy_bytes_allocated_per_load": legacy_alloc.1 as f64 / reps as f64,
            "binary_minor_page_faults_per_load": binary_faults.0 as f64 / reps as f64,
            "legacy_minor_page_faults_per_load": legacy_faults.0 as f64 / reps as f64,
        },
        "note": "This file measures where Phase 43 does and does not help, honestly. (1) The \
                 binary accelerator replaces a large JSON envelope with a small validated header \
                 plus packed inode/directory tables, so a *warm* historical-root open (and a \
                 validated quick open) parses fewer bytes and allocates less; a *cold* open is \
                 largely unchanged because it is dominated by the log reconstruction, not by the \
                 accelerator. (2) The committed-root directory lets a warm restart skip the \
                 whole-log checkpoint discovery scan, but the checkpoint's embedded index must \
                 still be decoded, and a mount with no usable checkpoint still replays the whole \
                 log. The directory and every accelerator are derived state: a corrupt, torn, \
                 truncated, foreign, or missing one always falls back to the authoritative \
                 reconstruction. Allocation and page-fault figures are process-global deltas and \
                 may be perturbed by concurrently running tests.",
    });
    write_json(
        &manifest_dir().join("evidence/performance/historical-fast.json"),
        &doc,
    );
}
