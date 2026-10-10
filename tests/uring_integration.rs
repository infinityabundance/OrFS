//! Phase 5 io_uring integration tests: equivalence with the synchronous path,
//! explicit write/fsync ordering, short-write retry, cancellation and teardown,
//! and honest fallback when `io_uring` is unavailable.
//!
//! `ORFS_REQUIRE_URING=1` (set by `scripts/container-uring-test.sh`, which runs
//! under a seccomp profile that permits `io_uring_setup`) turns a fallback into a
//! test failure, so a green run there proves that `io_uring` really ran. Without
//! it (the default, more restricted container), the tests that need a live ring
//! skip with a clear message and the fallback/equivalence tests still run.

use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use orfs::commit::{CommitSequencer, DurabilityMode};
use orfs::record::RecordType;
use orfs::transaction::{Transaction, TransactionBuilder};
use orfs::uring::{
    advance_write, probe_available, UringConfig, UringEngine, UringReport, DEFAULT_WRITE_DEPTH,
};
use orfs::volume::Volume;

use tempfile::TempDir;

/// A fixed volume identity so the two engines produce byte-comparable volumes.
const FIXED_UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x05, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const FIXED_CREATED: u64 = 1_700_000_000;
const SEGMENT_SIZE: u64 = 256 * 1024;
const TXNS: u64 = 24;

fn require_uring() -> bool {
    std::env::var("ORFS_REQUIRE_URING")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn cfg() -> UringConfig {
    UringConfig {
        enabled: true,
        ..Default::default()
    }
}

fn payload(tx: u64, i: u64) -> Vec<u8> {
    let len = 40 + ((tx * 13 + i * 7) % 160) as usize;
    (0..len)
        .map(|k| {
            ((tx as u8).wrapping_mul(31))
                .wrapping_add((i as u8).wrapping_mul(17))
                .wrapping_add(k as u8)
        })
        .collect()
}

fn build_tx(id: u64, tx: u64) -> Transaction {
    let mut b = TransactionBuilder::new(id).expect("builder");
    let types = [
        RecordType::InodeCreate,
        RecordType::DataExtent,
        RecordType::DentryAdd,
    ];
    for (i, ty) in types.iter().enumerate() {
        b.add(*ty, 1, 0, payload(tx, i as u64)).expect("add");
    }
    b.build().expect("build")
}

struct Workload {
    root: u64,
    digest: String,
    bytes: Vec<u8>,
}

/// Run the same deterministic write workload, optionally through io_uring, and
/// return the resulting committed state.
fn run_workload(dir: &Path, uring: bool) -> (Workload, Option<UringReport>) {
    let mut vol =
        Volume::init_with_uuid(dir, SEGMENT_SIZE, FIXED_UUID, FIXED_CREATED).expect("init volume");
    let report = if uring {
        Some(vol.enable_backing_io(&cfg()))
    } else {
        None
    };
    {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
        for tx in 1..=TXNS {
            let id = seq.peek_transaction_id();
            seq.commit(build_tx(id, tx)).expect("commit");
        }
        seq.flush().expect("flush");
    }
    let root = vol.log.committed_end_offset();
    let digest = vol.log.committed_digest_hex().expect("digest");
    let bytes = vol.log.read_committed_bytes().expect("read committed");
    // Exercise the Ring R read path end-to-end too and require agreement.
    let ranged = vol
        .log
        .read_range(0, bytes.len() as u64)
        .expect("read range");
    assert_eq!(
        ranged, bytes,
        "read_range disagrees with read_committed_bytes"
    );
    (
        Workload {
            root,
            digest,
            bytes,
        },
        report,
    )
}

#[test]
fn equivalence_sync_vs_uring_is_byte_identical() {
    let d_sync = TempDir::new().unwrap();
    let d_uring = TempDir::new().unwrap();
    let (sync, _) = run_workload(d_sync.path(), false);
    let (uring, report) = run_workload(d_uring.path(), true);
    let report = report.expect("uring report");

    assert_eq!(sync.root, uring.root, "committed roots differ");
    assert_eq!(sync.digest, uring.digest, "committed digests differ");
    assert_eq!(sync.bytes, uring.bytes, "committed bytes differ");

    if require_uring() {
        assert!(
            report.engaged,
            "ORFS_REQUIRE_URING=1 but io_uring did not engage: {:?}",
            report.reason
        );
    }
    if !report.engaged {
        assert!(report.requested);
        assert!(
            report.reason.is_some(),
            "a failed engagement must carry a reason"
        );
    }

    // Correctness evidence is written only from a genuine io_uring run, so the
    // committed artifact always reflects real asynchronous backing I/O.
    if require_uring() {
        let json = serde_json::json!({
            "generated_by": "tests/uring_integration.rs",
            "workload": { "transactions": TXNS, "segment_size": SEGMENT_SIZE },
            "engine": {
                "engaged": report.engaged,
                "write_depth": report.depth,
                "read_depth": report.read_depth,
                "registered_buffers": report.registered_buffers,
            },
            "result": {
                "sync_root": sync.root,
                "uring_root": uring.root,
                "roots_equal": sync.root == uring.root,
                "sync_digest": sync.digest,
                "uring_digest": uring.digest,
                "digests_equal": sync.digest == uring.digest,
                "bytes_equal": sync.bytes == uring.bytes,
                "committed_bytes": sync.bytes.len(),
            },
        });
        let path = Path::new("evidence/correctness/uring-equivalence.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut text = serde_json::to_string_pretty(&json).unwrap();
        text.push('\n');
        std::fs::write(path, text).expect("write evidence");
    }
}

#[test]
fn fallback_is_honest_and_the_log_still_works() {
    let dir = TempDir::new().unwrap();
    let mut vol =
        Volume::init_with_uuid(dir.path(), SEGMENT_SIZE, FIXED_UUID, FIXED_CREATED).expect("init");
    let report = vol.enable_backing_io(&cfg());

    if require_uring() {
        assert!(
            report.engaged,
            "ORFS_REQUIRE_URING=1 but io_uring did not engage: {:?}",
            report.reason
        );
    }
    if !report.engaged {
        assert!(report.requested, "io_uring was requested");
        assert!(report.reason.is_some(), "fallback must report a reason");
    }
    // Whichever engine is in force, the log functions identically.
    assert_eq!(vol.log.backing_io_is_uring(), report.engaged);

    let root = {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
        let id = seq.peek_transaction_id();
        seq.commit(build_tx(id, 1)).expect("commit").root
    };
    assert!(root > 0, "the root must advance");
    assert_eq!(vol.log.committed_end_offset(), root);
    assert!(!vol.log.read_committed_bytes().unwrap().is_empty());
}

#[test]
fn ordering_write_fsync_is_not_reordered() {
    let mut engine = match UringEngine::try_new(DEFAULT_WRITE_DEPTH, false) {
        Ok(e) => e,
        Err(reason) => {
            if require_uring() {
                panic!("ORFS_REQUIRE_URING=1 but io_uring unavailable: {reason}");
            }
            eprintln!("skip ordering test: io_uring unavailable ({reason})");
            return;
        }
    };
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ordered.bin");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    let data: Vec<u8> = (0..48 * 1024).map(|i| (i * 7 + 3) as u8).collect();

    let report = engine
        .write_then_fsync_ordered(file.as_raw_fd(), 0, &data)
        .expect("write+fsync");
    assert!(
        report.fsync_after_write_every_round,
        "the fsync must not complete before the write (completion order violated)"
    );
    assert_eq!(report.bytes_written, data.len() as u64);
    drop(file);

    // Durability: the bytes are visible after reopening.
    assert_eq!(std::fs::read(&path).unwrap(), data);
}

#[test]
fn short_write_retry_simulation_preserves_offset() {
    // The production write loop is driven by `advance_write`; feed it scripted
    // completions and assert the offsets it would resubmit never rewrite the
    // prefix of the reservation.
    let mut done = 0usize;
    let mut offsets = Vec::new();
    for res in [17i32, 40, 43] {
        offsets.push(done);
        done = advance_write(done, 100, res).expect("advance");
    }
    assert_eq!(done, 100);
    assert_eq!(offsets, vec![0, 17, 57]);

    // A positive-but-zero write is not progress and is an error.
    assert!(advance_write(0, 100, 0).is_err());
    // EINTR is retried in place (same offset).
    assert_eq!(advance_write(12, 100, -libc::EINTR).unwrap(), 12);
    // Cancellation is surfaced, never silently treated as success.
    assert!(advance_write(0, 100, -libc::ECANCELED).is_err());
    // Over-reporting is a hard corruption error.
    assert!(advance_write(0, 10, 11).is_err());
}

#[test]
fn large_write_is_byte_identical_to_sync() {
    // Larger than one staging buffer, so the staged path chunks and loops; the
    // result must be byte-identical to a plain synchronous write.
    let dir = TempDir::new().unwrap();
    let src: Vec<u8> = (0..900 * 1024).map(|i| (i * 131 + 7) as u8).collect();

    let sync_path = dir.path().join("sync.bin");
    {
        use std::os::unix::fs::FileExt;
        let f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&sync_path)
            .unwrap();
        f.write_all_at(&src, 0).unwrap();
    }

    let mut engine = match UringEngine::try_new(DEFAULT_WRITE_DEPTH, true) {
        Ok(e) => e,
        Err(reason) => {
            if require_uring() {
                panic!("ORFS_REQUIRE_URING=1 but io_uring unavailable: {reason}");
            }
            eprintln!("skip large-write test: io_uring unavailable ({reason})");
            return;
        }
    };
    let uring_path = dir.path().join("uring.bin");
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&uring_path)
        .unwrap();
    let written = engine
        .write_at_all(file.as_raw_fd(), 0, &src)
        .expect("uring write");
    assert_eq!(written, src.len() as u64);
    drop(file);

    assert_eq!(std::fs::read(&sync_path).unwrap(), src);
    assert_eq!(
        std::fs::read(&uring_path).unwrap(),
        src,
        "io_uring write differs from the synchronous write"
    );
}

#[test]
fn cancellation_and_teardown_are_safe() {
    let mut engine = match UringEngine::try_new(8, false) {
        Ok(e) => e,
        Err(reason) => {
            if require_uring() {
                panic!("ORFS_REQUIRE_URING=1 but io_uring unavailable: {reason}");
            }
            eprintln!("skip cancellation test: io_uring unavailable ({reason})");
            return;
        }
    };

    // A read on an empty pipe blocks; cancel it and observe -ECANCELED.
    let mut fds = [0i32; 2];
    // SAFETY: `pipe` writes two valid fds into the array.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    let mut buf = vec![0u8; 32];
    let ud = engine
        .submit_read_nowait(read_fd, &mut buf)
        .expect("submit read");
    engine.cancel(ud).expect("cancel");
    let res = engine.wait_for(ud).expect("wait for canceled op");
    assert_eq!(res, -libc::ECANCELED, "expected ECANCELED, got {res}");

    // Teardown drains remaining outstanding operations.
    engine.drain().expect("drain");
    drop(engine);

    // SAFETY: both fds were returned by `pipe` and are still open.
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
}

#[test]
fn probe_matches_engagability() {
    // The probe and the engine's real construction must agree, so callers can
    // trust the CLI/`doctor` report.
    let probed = probe_available().is_ok();
    let engaged = UringEngine::try_new(8, false).is_ok();
    assert_eq!(
        probed, engaged,
        "probe ({probed}) disagrees with actual ring creation ({engaged})"
    );
}
