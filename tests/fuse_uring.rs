//! Phase 10 integration tests: the FUSE-over-`io_uring` transport (profile F2)
//! with classical fallback.
//!
//! Three concerns are covered:
//!
//! 1. **Transport equivalence** — the same POSIX operations applied through the
//!    FUSE layer yield identical logical results whether the mount used profile
//!    F0 (`/dev/fuse` + sync backing), F1 (`/dev/fuse` + `io_uring` backing), or a
//!    *requested* F2 mount that falls back. This proves the filesystem core is
//!    transport-neutral.
//! 2. **Negotiation and fallback** — requesting F2 performs a real `INIT`
//!    negotiation; when the kernel does not enable FUSE-over-`io_uring` the mount
//!    records the precise reason and continues with byte-identical contents.
//! 3. **Cancellation and safe shutdown** — the native ring layer submits,
//!    reaps, cancels, and shuts down without panicking or leaking.
//!
//! Mounting requires `/dev/fuse` + `CAP_SYS_ADMIN` and is expected only under
//! `scripts/container-fuse-test.sh` (`ORFS_FUSE_TEST=1`). The ring tests require a
//! working `io_uring` and are expected under `scripts/container-uring-test.sh`
//! (`ORFS_REQUIRE_URING=1`). When the prerequisite is missing the test **skips**
//! and prints the exact reason; it never fabricates a pass.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use orfs::commit::DurabilityMode;
use orfs::fuse::{self, BackingIo, MountOptions, Transport};
use orfs::fuse_uring::{self, FuseUringRing, TransportProfile};
use orfs::log::DEFAULT_SEGMENT_SIZE;
use orfs::namespace::{Namespace, SetAttr};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_scratch(prefix: &str) -> PathBuf {
    let base = manifest_dir().join("target").join("fuse-uring-it");
    fs::create_dir_all(&base).expect("create base");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = base.join(format!("{prefix}-{pid}-{nanos}"));
    fs::create_dir_all(&dir).expect("create scratch");
    dir
}

fn io_err<T>(r: std::io::Result<T>) -> Result<T, String> {
    r.map_err(|e| format!("{:?}", e.kind()))
}

/// Apply a fixed sequence of logical operations under `root` and return a
/// deterministic transcript of the observable results. Running this under each
/// transport profile and comparing the transcripts is the equivalence proof.
fn apply_ops(root: &Path) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();

    // create + write + read back
    let f = root.join("a.txt");
    {
        let mut h = io_err(File::create(&f))?;
        io_err(h.write_all(b"hello orfs"))?;
        io_err(h.sync_all())?;
    }
    let mut s = String::new();
    io_err(File::open(&f).and_then(|mut h| h.read_to_string(&mut s)))?;
    out.push(("create_write_read".into(), s));

    // append + positional read
    {
        let mut h = io_err(OpenOptions::new().append(true).open(&f))?;
        io_err(h.write_all(b"!"))?;
    }
    {
        let mut h = io_err(File::open(&f))?;
        io_err(h.seek(SeekFrom::Start(5)))?;
        let mut buf = [0u8; 5];
        io_err(h.read_exact(&mut buf))?;
        out.push(("pread".into(), String::from_utf8_lossy(&buf).into_owned()));
    }

    // mkdir + readdir (sorted for determinism)
    let d = root.join("sub");
    io_err(fs::create_dir(&d))?;
    io_err(fs::write(d.join("inner"), b"x"))?;
    let mut names: Vec<String> = io_err(fs::read_dir(&d))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    out.push(("readdir".into(), names.join(",")));

    // symlink + readlink
    let link = root.join("link");
    io_err(std::os::unix::fs::symlink("a.txt", &link))?;
    out.push((
        "readlink".into(),
        io_err(fs::read_link(&link))?.display().to_string(),
    ));

    // hard link shares content
    let hl = root.join("hard");
    io_err(fs::hard_link(&f, &hl))?;
    out.push(("hardlink-content".into(), io_err(fs::read_to_string(&hl))?));

    // rename
    let renamed = root.join("b.txt");
    io_err(fs::rename(&f, &renamed))?;
    out.push(("rename-exists".into(), format!("{}", renamed.exists())));

    // truncate + re-extend (sparse)
    {
        let h = io_err(OpenOptions::new().write(true).open(&renamed))?;
        io_err(h.set_len(2))?;
    }
    out.push((
        "truncate-size".into(),
        io_err(fs::read_to_string(&renamed))?,
    ));
    {
        let h = io_err(OpenOptions::new().write(true).open(&renamed))?;
        io_err(h.set_len(10))?;
    }
    let md = io_err(fs::metadata(&renamed))?;
    out.push((
        "reextend".into(),
        format!(
            "size={} perm={:o}",
            md.len(),
            md.permissions().mode() & 0o777
        ),
    ));

    // unlink
    io_err(fs::remove_file(&hl))?;
    out.push(("unlink-exists".into(), format!("{}", hl.exists())));

    Ok(out)
}

fn init_volume(backing: &Path) -> Result<(), String> {
    let mut ns = Namespace::init(backing, DEFAULT_SEGMENT_SIZE, DurabilityMode::Ordered)
        .map_err(|e| e.to_string())?;
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
    .map_err(|e| e.to_string())?;
    ns.sync().map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Ring layer: submission, cancellation, shutdown (io_uring required)
// ---------------------------------------------------------------------------

fn io_uring_available() -> bool {
    orfs::uring::probe_available().is_ok()
}

/// The native ring submits a command, the kernel rejects it for a non-`fuse`
/// file, and cancellation + shutdown remain safe. This exercises the real
/// `IORING_OP_URING_CMD` / `IORING_OP_ASYNC_CANCEL` machinery without a mount.
#[test]
fn ring_control_cancel_and_shutdown_are_safe() {
    let required = std::env::var("ORFS_REQUIRE_URING").as_deref() == Ok("1");
    if !io_uring_available() {
        if required {
            panic!("io_uring required but unavailable");
        }
        eprintln!("fuse_uring ring test: skipped — io_uring unavailable");
        return;
    }

    // A pipe read end: a valid fd whose f_op has no `uring_cmd`, so the kernel
    // rejects the command with -EOPNOTSUPP. That is the honest, safe result.
    let mut fds = [0i32; 2];
    // SAFETY: `pipe` fills the caller-owned 2-element array on success.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (r, w) = (fds[0], fds[1]);

    let mut ring = FuseUringRing::new(r, 8).expect("SQE128 ring");

    // ADD_QUEUE against a non-fuse fd is rejected (no fuse f_op).
    let res = ring.add_queue(0, false).expect("add_queue submit");
    assert!(
        res < 0,
        "a non-fuse fd must be rejected, got {res} (errno {})",
        -res
    );
    let errno = -res;

    // Buffer-pool registration and reply commit also go through the same layer.
    let bp = ring
        .add_bufpool(0, 0, 4096, None)
        .expect("add_bufpool submit");
    assert!(bp < 0);
    let cf = ring
        .commit_and_fetch(0, 7)
        .expect("commit_and_fetch submit");
    assert!(cf < 0);

    // Cancellation of a target that never completed is a no-op, not a fault.
    ring.cancel(999).expect("cancel");
    // Safe shutdown drains and unsubmits nothing.
    ring.shutdown();

    let stats = ring.stats();
    assert!(
        stats.submits >= 3,
        "expected >=3 submissions, got {stats:?}"
    );
    assert!(stats.completions >= 3, "expected >=3 completions");
    assert_eq!(stats.cancels, 1);

    // SAFETY: the descriptors came from `pipe` above and are closed exactly once.
    unsafe {
        libc::close(r);
        libc::close(w);
    }

    write_ring_evidence(errno, stats.submits, stats.completions, stats.cancels);
}

fn write_ring_evidence(errno: i32, submits: u64, completions: u64, cancels: u64) {
    let doc = serde_json::json!({
        "generated_by": "tests/fuse_uring.rs::ring_control_cancel_and_shutdown_are_safe",
        "what": "native FUSE-over-io_uring ring layer (IORING_OP_URING_CMD + ASYNC_CANCEL)",
        "note": "submitted against a non-fuse fd; the kernel rejects URING_CMD for a file whose f_op lacks uring_cmd",
        "uring_cmd_rejected_errno": errno,
        "submits": submits,
        "completions": completions,
        "cancels": cancels,
        "shutdown": "clean",
    });
    let path = manifest_dir().join("evidence/correctness/fuse-uring-ring.json");
    if let Some(p) = path.parent() {
        let _ = fs::create_dir_all(p);
    }
    if let Ok(mut s) = serde_json::to_string_pretty(&doc) {
        s.push('\n');
        let _ = fs::write(&path, s);
    }
}

// ---------------------------------------------------------------------------
// Transport equivalence + negotiation/fallback (mount required)
// ---------------------------------------------------------------------------

fn mount_profile(
    scratch: &Path,
    label: &str,
    opts: &MountOptions,
) -> Result<(fuse::OrfsMount, Vec<(String, String)>), String> {
    let backing = scratch.join(format!("{label}-backing"));
    let mnt = scratch.join(format!("{label}-mnt"));
    fs::create_dir_all(&mnt).map_err(|e| e.to_string())?;
    init_volume(&backing)?;
    let mount = fuse::spawn(&backing, &mnt, opts).map_err(|e| e.to_string())?;
    let transcript = apply_ops(&mnt)?;
    Ok((mount, transcript))
}

#[test]
fn transport_equivalence_and_f2_fallback() {
    let required = std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1");
    let scratch = unique_scratch("equiv");

    let f0_opts = MountOptions {
        transport: Transport::Fuse,
        backing_io: BackingIo::Sync,
        ..Default::default()
    };
    let f1_opts = MountOptions {
        transport: Transport::Fuse,
        backing_io: BackingIo::Uring,
        ..Default::default()
    };
    let f2_opts = MountOptions {
        transport: Transport::FuseUring,
        backing_io: BackingIo::Uring,
        ..Default::default()
    };

    let (m0, t0) = match mount_profile(&scratch, "f0", &f0_opts) {
        Ok(v) => v,
        Err(e) => {
            if required {
                panic!("F0 mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            eprintln!("transport_equivalence: skipped — mount unavailable: {e}");
            let _ = fs::remove_dir_all(&scratch);
            return;
        }
    };
    let p0 = m0.transport_used();
    let m0_unmount = m0.unmount();

    let (m1, t1) = mount_profile(&scratch, "f1", &f1_opts).expect("F1 mount");
    let p1 = m1.transport_used();
    let backing1 = m1.backing_io_used;
    let m1_unmount = m1.unmount();

    let (m2, t2) = mount_profile(&scratch, "f2", &f2_opts).expect("F2-request mount");
    let p2 = m2.transport_used();
    let backing2 = m2.backing_io_used;
    let neg2 = m2.fuse_uring_negotiation();
    let report2 = m2.fuse_uring_report();
    let desc2 = m2.transport_description();
    let m2_unmount = m2.unmount();

    // Transport neutrality: identical logical results under every profile.
    assert_eq!(t0, t1, "F0 and F1 transcripts differ");
    assert_eq!(t0, t2, "F0 and requested-F2 transcripts differ");

    // Profiles must be exactly as reported.
    assert_eq!(
        p0,
        TransportProfile::F0,
        "sync backing with transport=fuse is F0"
    );
    assert_ne!(
        p1,
        TransportProfile::F2,
        "backing io_uring alone must never be F2"
    );
    assert_ne!(
        p2,
        TransportProfile::F2,
        "F2 cannot be active in this build"
    );

    // The F2 request must have negotiated for real and recorded a reason.
    assert!(
        !neg2.engaged,
        "F2 must not claim engagement without a running ring"
    );
    assert!(
        neg2.reason
            .as_deref()
            .map(|r| !r.is_empty())
            .unwrap_or(false),
        "a non-engaged F2 must carry a reason"
    );
    if !neg2.kernel_offered {
        let reason = neg2.reason.clone().unwrap_or_default();
        assert!(
            reason.contains("FUSE_OVER_IO_URING") || reason.contains("enable_uring"),
            "unexpected reason: {reason}"
        );
    }
    assert!(!report2.usable(), "F2 must not be reported usable here");

    write_mount_evidence(
        &scratch, p0, p1, backing1, p2, backing2, &neg2, &t0, &desc2, &report2,
    );

    let _ = fs::remove_dir_all(&scratch);
    m0_unmount.expect("unmount F0");
    m1_unmount.expect("unmount F1");
    m2_unmount.expect("unmount requested-F2");
}

#[allow(clippy::too_many_arguments)]
fn write_mount_evidence(
    _scratch: &Path,
    p0: TransportProfile,
    p1: TransportProfile,
    backing1: BackingIo,
    p2: TransportProfile,
    backing2: BackingIo,
    neg2: &fuse_uring::FuseUringNegotiation,
    transcript: &[(String, String)],
    desc2: &str,
    report2: &fuse_uring::FuseUringReport,
) {
    let caps = orfs::capabilities::probe();
    let perf = serde_json::json!({
        "schema": "orfs.fuse-uring.v1",
        "generated_by": "tests/fuse_uring.rs::transport_equivalence_and_f2_fallback",
        "environment": {
            "kernel_release": caps.kernel_release,
            "machine": caps.machine,
            "container": caps.likely_container,
            "dev_fuse": caps.dev_fuse_present,
        },
        "uapi": {
            "fuse_kernel_version": fuse_uring::FUSE_KERNEL_VERSION,
            "baseline_minor": fuse_uring::FUSE_KERNEL_MINOR_BASELINE,
            "add_queue_minor": fuse_uring::FUSE_KERNEL_MINOR_ADD_QUEUE,
            "commands": [
                "FUSE_IO_URING_CMD_REGISTER",
                "FUSE_IO_URING_CMD_COMMIT_AND_FETCH",
                "FUSE_IO_URING_CMD_ADD_QUEUE",
                "FUSE_IO_URING_CMD_ADD_BUFPOOL",
            ],
        },
        "profiles": {
            "F0": { "reported": p0.name(), "requested": "fuse + sync" },
            "F1": { "reported": p1.name(), "requested": "fuse + uring", "backing_used": format!("{backing1:?}") },
            "F2": {
                "reported": p2.name(),
                "requested": "fuse-uring + uring",
                "backing_used": format!("{backing2:?}"),
                "description": desc2,
            },
        },
        "f2_negotiation": neg2,
        "f2_report": report2,
        "measurements": {
            "note": "submission micro-benchmarks are recorded in evidence/performance/backing-uring.json; \
                     F2 transport throughput could not be measured because F2 did not engage",
            "f2": "not measured (F2 unavailable)",
        },
    });
    let path = manifest_dir().join("evidence/performance/fuse-uring.json");
    if let Some(p) = path.parent() {
        let _ = fs::create_dir_all(p);
    }
    if let Ok(mut s) = serde_json::to_string_pretty(&perf) {
        s.push('\n');
        let _ = fs::write(&path, s);
    }

    let correct = serde_json::json!({
        "schema": "orfs.fuse-uring-equivalence.v1",
        "generated_by": "tests/fuse_uring.rs::transport_equivalence_and_f2_fallback",
        "claim": "the same operations yield identical logical results across F0, F1 and the F2-request fallback",
        "transcript": transcript,
        "profiles_compared": [p0.name(), p1.name(), p2.name()],
        "fallback_reason": neg2.reason,
        "contents_identical": true,
    });
    let path = manifest_dir().join("evidence/correctness/fuse-uring-equivalence.json");
    if let Some(p) = path.parent() {
        let _ = fs::create_dir_all(p);
    }
    if let Ok(mut s) = serde_json::to_string_pretty(&correct) {
        s.push('\n');
        let _ = fs::write(&path, s);
    }
}

/// The negotiation must be a real `INIT` result even when F2 does not engage: a
/// fresh F2 request reports `kernel_offered`/`reason` rather than a bare guess.
#[test]
fn f2_negotiation_records_a_real_reason() {
    let required = std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1");
    let scratch = unique_scratch("neg");
    let backing = scratch.join("backing");
    let mnt = scratch.join("mnt");
    fs::create_dir_all(&mnt).expect("mnt");
    if let Err(e) = init_volume(&backing) {
        if required {
            panic!("init failed: {e}");
        }
        eprintln!("f2_negotiation: skipped — {e}");
        return;
    }
    let opts = MountOptions {
        transport: Transport::FuseUring,
        backing_io: BackingIo::Uring,
        ..Default::default()
    };
    let mount = match fuse::spawn(&backing, &mnt, &opts) {
        Ok(m) => m,
        Err(e) => {
            if required {
                panic!("F2-request mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            eprintln!("f2_negotiation: skipped — mount unavailable: {e}");
            let _ = fs::remove_dir_all(&scratch);
            return;
        }
    };
    let neg = mount.fuse_uring_negotiation();
    assert!(!neg.engaged);
    assert!(neg.reason.is_some(), "negotiation must record a reason");
    assert_ne!(mount.transport_used(), TransportProfile::F2);
    let _ = mount.unmount();
    let _ = fs::remove_dir_all(&scratch);
}
