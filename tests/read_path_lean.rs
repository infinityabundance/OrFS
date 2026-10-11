//! Phase 18 — the lean authoritative read path and the manifestation
//! regression bounds (research §10.2, §16; external review P0 items 3 and 4).
//!
//! Proved here:
//!
//! * **No per-request allocation on the hot single-extent path** — the
//!   authoritative read writes directly into the destination through
//!   [`orfs::log::Log::read_range_into`]; once a segment handle is cached, a read
//!   allocates nothing.
//! * **Byte identity** — the into-buffer API and the owning API return the same
//!   bytes, equal to the committed canonical bytes.
//! * **Bounded manifestation** — with manifestation enabled, a small-write
//!   workload's reads and writes stay within a small bounded factor of the same
//!   workload with manifestation disabled. Synchronous (foreground-waiting)
//!   manifestation is off by default; asynchronous manifestation never amplifies
//!   small writes without bound.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::path::Path;
use std::time::{Duration, Instant};

use orfs::commit::DurabilityMode;
use orfs::log::Log;
use orfs::manifestation::{ManifestationConfig, ManifestationProfile};
use orfs::namespace::Namespace;
use orfs::record::{Record, RecordType};
use orfs::volume::Volume;
use tempfile::TempDir;

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x18, 0x22, 0x40, 0x33, 0x81, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
];
const CREATED: u64 = 1_700_000_000;

// ---------------------------------------------------------------------------
// A per-thread allocation counter (isolates tests that run in parallel).
// ---------------------------------------------------------------------------

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

// SAFETY: this is a thin wrapper over `System`, the default allocator. It only
// bumps a thread-local counter before delegating, and the counter never
// allocates (a `Cell<usize>` with a `const` initialiser). All pointer/layout
// arguments are forwarded unchanged, so the global allocator contract is exactly
// `System`'s.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.with(|c| c.set(c.get() + 1));
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.with(|c| c.set(c.get() + 1));
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.with(|c| c.set(c.get() + 1));
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Begin counting allocations on this thread; returns the previous count.
fn alloc_counting(on: bool) {
    COUNTING.with(|c| c.set(on));
    ALLOCS.with(|c| c.set(0));
}

fn allocs_since() -> usize {
    let n = ALLOCS.with(|c| c.get());
    COUNTING.with(|c| c.set(false));
    n
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn payload(tx: u64, i: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|k| {
            ((tx as u8).wrapping_mul(31))
                .wrapping_add((i as u8).wrapping_mul(17))
                .wrapping_add(k as u8)
        })
        .collect()
}

/// A committed volume with `txns` transactions, each carrying a distinct
/// `DataExtent` payload, so the canonical byte stream is non-trivial.
fn build_volume(dir: &Path, txns: u64, payload_len: usize) -> Volume {
    let mut vol = Volume::init_with_uuid(dir, 1 << 20, UUID, CREATED).expect("init volume");
    for tx in 1..=txns {
        vol.log.begin(tx).expect("begin");
        let off0 = vol
            .log
            .append(
                Record::new(RecordType::InodeCreate, 0, tx, tx, 0, 0, payload(tx, 0, 16)).unwrap(),
            )
            .expect("append");
        vol.log
            .append(
                Record::new(
                    RecordType::DataExtent,
                    0,
                    tx,
                    tx,
                    off0,
                    0,
                    payload(tx, 1, payload_len),
                )
                .unwrap(),
            )
            .expect("append extent");
        vol.log.commit().expect("commit");
    }
    vol
}

fn log_of(vol: &Volume) -> &Log {
    &vol.log
}

// ---------------------------------------------------------------------------
// (3) Reusable handles + direct-into-buffer reads
// ---------------------------------------------------------------------------

#[test]
fn read_into_buffer_is_allocation_free_on_the_warm_path_and_byte_identical() {
    let td = TempDir::new().unwrap();
    let vol = build_volume(td.path(), 6, 2048);
    let log = log_of(&vol);
    let total = log.committed_end_offset();
    assert!(total > 0, "nothing was committed");

    // Warm the handle cache and prove the API returns exactly the canonical
    // bytes.
    let mut warm = vec![0u8; total as usize];
    log.read_range_into(0, &mut warm).expect("warm read");
    assert_eq!(warm, log.read_committed_bytes().expect("committed"));
    assert_eq!(warm, log.read_range(0, total).expect("owning read"));

    // The hot path allocates nothing: the segment handle is cached and the bytes
    // are written straight into the caller's buffer.
    let mut buf = vec![0u8; total as usize];
    alloc_counting(true);
    log.read_range_into(0, &mut buf).expect("hot read");
    let allocs = allocs_since();
    assert_eq!(allocs, 0, "hot read_range_into allocated {allocs} time(s)");
    assert_eq!(buf, warm);

    // A suffix range too, to exercise the physical-offset mapping.
    let mut tail = vec![0u8; 64];
    alloc_counting(true);
    log.read_range_into(total - 64, &mut tail)
        .expect("tail read");
    assert_eq!(allocs_since(), 0);
    assert_eq!(tail, warm[(total as usize - 64)..]);
}

#[test]
fn read_range_into_rejects_out_of_bounds_without_writing() {
    let td = TempDir::new().unwrap();
    let vol = build_volume(td.path(), 2, 128);
    let log = log_of(&vol);
    let total = log.committed_end_offset();
    let mut buf = vec![0xAAu8; 16];
    let prev = buf.clone();
    assert!(log.read_range_into(total - 1, &mut buf).is_err());
    assert_eq!(buf, prev, "a rejected read must not touch the buffer");
}

// ---------------------------------------------------------------------------
// (4) Manifestation regression bounds
// ---------------------------------------------------------------------------

fn build_ns(dir: &Path) -> Namespace {
    Namespace::init_with_uuid(dir, 1 << 20, UUID, CREATED, DurabilityMode::Ordered).expect("init")
}

/// The default manifestation configuration is asynchronous (it never makes the
/// caller wait for a whole-object rebuild).
#[test]
fn synchronous_manifestation_is_opt_in_only() {
    let cfg = ManifestationConfig::default();
    assert!(
        !cfg.synchronous,
        "the default manifestation configuration must be asynchronous"
    );
}

/// A small-write workload: with manifestation enabled (and asynchronous), reads
/// and writes stay within a small bounded factor of the same workload with
/// manifestation disabled. The pre-Phase-18 synchronous path was ~1000x slower
/// on reads (cold planner selection) and unboundedly amplified on writes.
#[test]
fn manifestation_keeps_small_write_reads_and_writes_bounded() {
    let chunk = 4096usize;
    let writes = 24u64;

    let td_plain = TempDir::new().unwrap();
    let mut plain = build_ns(td_plain.path());
    let plain_root = plain.root_inode();
    let plain_ino = plain.create(plain_root, b"f", 0o644, 0, 0).unwrap();

    let td_man = TempDir::new().unwrap();
    let mut man = build_ns(td_man.path());
    let man_root = man.root_inode();
    let man_ino = man.create(man_root, b"f", 0o644, 0, 0).unwrap();
    man.enable_manifestation(ManifestationConfig {
        workers: 1,
        queue_capacity: 8,
        synchronous: false,
        profile: ManifestationProfile::Bloom { depth: 4 },
        max_source_bytes: 64 << 20,
    })
    .expect("enable manifestation");

    let data: Vec<u8> = (0..chunk).map(|i| (i % 251) as u8).collect();

    // --- writes (small appends) ---
    let t = Instant::now();
    for i in 0..writes {
        plain.write_at(plain_ino, i * chunk as u64, &data).unwrap();
        plain.sync().unwrap();
    }
    let plain_write = t.elapsed();
    let t = Instant::now();
    for i in 0..writes {
        man.write_at(man_ino, i * chunk as u64, &data).unwrap();
        man.sync().unwrap();
    }
    let man_write = t.elapsed();

    // --- reads (small, spread across the object) ---
    let plain_root = plain.root();
    let t = Instant::now();
    for i in 0..writes {
        let b = plain
            .read_at(plain_ino, plain_root, i * chunk as u64, 4096)
            .unwrap();
        assert_eq!(b.len(), 4096);
    }
    let plain_read = t.elapsed();

    let man_root = man.root();
    let t = Instant::now();
    for i in 0..writes {
        let b = man
            .read_at(man_ino, man_root, i * chunk as u64, 4096)
            .unwrap();
        assert_eq!(b.len(), 4096);
    }
    let man_read = t.elapsed();

    // A generous but finite bound (a runaway O(N^2) amplification blows through
    // it by orders of magnitude). Timing on an unoptimized test build, so the
    // bound is deliberately loose; the point is that it is *bounded*.
    const FACTOR: u32 = 30;
    assert!(
        man_read <= plain_read * FACTOR + Duration::from_millis(50),
        "manifesting reads are not bounded: plain={plain_read:?} manifesting={man_read:?}"
    );
    assert!(
        man_write <= plain_write * FACTOR + Duration::from_millis(50),
        "manifesting writes are not bounded: plain={plain_write:?} manifesting={man_write:?}"
    );
}
