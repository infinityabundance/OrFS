//! Phase 15 integration tests: the native FUSE-over-`io_uring` transport
//! (profile **F2**) that owns the `/dev/fuse` descriptor, with the classical
//! F0/F1 transports alongside it.
//!
//! Four concerns are covered:
//!
//! 1. **Real F2 engagement** — a `--transport fuse-uring` mount performs its own
//!    `mount(2)` + `INIT`, advertises `FUSE_OVER_IO_URING`, registers ring
//!    entries, and reports `F2`; the live `INIT` flags and the ring counters are
//!    recorded as evidence.
//! 2. **Transport equivalence** — the same POSIX operations applied through F0,
//!    F1, and F2 yield byte-identical logical results.
//! 3. **Measurements** — real F0/F1/F2 numbers for sequential read, random 4K
//!    read, random 1-byte read, metadata lookup, create/unlink, and fsync.
//! 4. **Ring layer safety** — submission, cancellation, and safe shutdown of the
//!    native ring.
//!
//! Mounting requires `/dev/fuse` + `CAP_SYS_ADMIN` and is expected only under
//! `scripts/container-fuse-test.sh` (`ORFS_FUSE_TEST=1`). The ring-layer test
//! requires a working `io_uring` (`ORFS_REQUIRE_URING=1`). When a prerequisite is
//! missing the test **skips** and prints the exact reason; it never fabricates a
//! pass.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use orfs::commit::DurabilityMode;
use orfs::fuse::{self, BackingIo, F2Servicing, Metrics, MountOptions, Transport};
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

fn image_digest() -> String {
    std::env::var("ORFS_IMAGE_DIGEST").unwrap_or_else(|_| "unknown".to_string())
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

    // Phase 82: POSIX decides access at `open`/`create`, so a file created with
    // mode `0444` is writable through the descriptor the create returned (the
    // `git` loose-object pattern), and an already-open descriptor keeps its rights
    // after a later chmod. Byte-identical across F0/F1/F2 is the transport-
    // neutrality proof for the conformance correction (docs/FUSE-SEMANTICS.md §6).
    {
        use std::os::unix::fs::OpenOptionsExt;
        let obj = root.join("loose-obj");
        let mut h = io_err(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .open(&obj),
        )?;
        io_err(h.write_all(b"git object"))?;
        io_err(h.sync_all())?;
        out.push((
            "create-0444-write".into(),
            io_err(fs::read_to_string(&obj))?,
        ));
        out.push((
            "create-0444-mode".into(),
            format!(
                "{:o}",
                io_err(fs::metadata(&obj))?.permissions().mode() & 0o777
            ),
        ));
    }

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

fn fuse_test_required() -> bool {
    std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1")
}

fn io_uring_available() -> bool {
    orfs::uring::probe_available().is_ok()
}

// ---------------------------------------------------------------------------
// Ring layer: submission, cancellation, shutdown (io_uring required)
// ---------------------------------------------------------------------------

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
// Mount helpers
// ---------------------------------------------------------------------------

fn mount_profile(
    scratch: &Path,
    label: &str,
    opts: &MountOptions,
) -> Result<fuse::OrfsMount, String> {
    let backing = scratch.join(format!("{label}-backing"));
    let mnt = scratch.join(format!("{label}-mnt"));
    fs::create_dir_all(&mnt).map_err(|e| e.to_string())?;
    init_volume(&backing)?;
    fuse::spawn(&backing, &mnt, opts).map_err(|e| e.to_string())
}

fn f0_opts() -> MountOptions {
    MountOptions {
        transport: Transport::Fuse,
        backing_io: BackingIo::Sync,
        ..Default::default()
    }
}
fn f1_opts() -> MountOptions {
    MountOptions {
        transport: Transport::Fuse,
        backing_io: BackingIo::Uring,
        ..Default::default()
    }
}
fn f2_opts() -> MountOptions {
    MountOptions {
        transport: Transport::FuseUring,
        backing_io: BackingIo::Uring,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Equivalence across F0 / F1 / F2 (mount required)
// ---------------------------------------------------------------------------

#[test]
fn transport_equivalence_across_f0_f1_f2() {
    let required = fuse_test_required();
    let scratch = unique_scratch("equiv");

    let (m0, t0) = match mount_profile(&scratch, "f0", &f0_opts()).and_then(|m| {
        let mnt = scratch.join("f0-mnt");
        let t = apply_ops(&mnt)?;
        Ok((m, t))
    }) {
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
    let m0u = m0.unmount();

    let m1 = mount_profile(&scratch, "f1", &f1_opts()).expect("F1 mount");
    let p1 = m1.transport_used();
    let backing1 = m1.backing_io_used;
    let t1 = apply_ops(&scratch.join("f1-mnt")).expect("F1 ops");
    let m1u = m1.unmount();

    let m2 = mount_profile(&scratch, "f2", &f2_opts()).expect("F2 mount");
    let p2 = m2.transport_used();
    let backing2 = m2.backing_io_used;
    let neg2 = m2.fuse_uring_negotiation();
    let report2 = m2.fuse_uring_report();
    let desc2 = m2.transport_description();
    let stats2 = m2.f2_stats();
    let env2 = m2.f2_environment();
    let t2 = apply_ops(&scratch.join("f2-mnt")).expect("F2 ops");
    // Re-read stats after serving the F2 transcript, so the counters cover it.
    let stats2_after = m2.f2_stats();
    let m2u = m2.unmount();

    // Transport neutrality: identical logical results under every profile.
    assert_eq!(t0, t1, "F0 and F1 transcripts differ");
    assert_eq!(t0, t2, "F0 and F2 transcripts differ");

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

    if required {
        // Under the F2-capable container the F2 request must have really engaged.
        assert_eq!(p2, TransportProfile::F2, "F2 must be active: {desc2}");
        assert!(
            neg2.kernel_offered,
            "kernel must have offered FUSE_OVER_IO_URING at INIT"
        );
        assert!(neg2.accepted, "server must have echoed FUSE_OVER_IO_URING");
        assert!(neg2.engaged, "a real ring must be running");
        assert!(neg2.reason.is_none());
        assert!(report2.usable(), "F2 must be reported usable");
        let st = stats2_after.as_ref().expect("native F2 stats");
        assert!(
            st.requests_served > 0,
            "the F2 ring must have carried requests, got {st:?}"
        );
        assert!(
            st.register_sqes > 0,
            "register SQEs must have been submitted"
        );
        assert_eq!(st.register_failures, 0, "REGISTER must not have failed");
    }

    write_equivalence_evidence(
        &t0,
        p0,
        p1,
        p2,
        &neg2,
        &desc2,
        &report2,
        &stats2,
        &stats2_after,
        &env2,
        backing1,
        backing2,
    );

    let _ = fs::remove_dir_all(&scratch);
    m0u.expect("unmount F0");
    m1u.expect("unmount F1");
    m2u.expect("unmount F2");
}

#[allow(clippy::too_many_arguments)]
fn write_equivalence_evidence(
    transcript: &[(String, String)],
    p0: TransportProfile,
    p1: TransportProfile,
    p2: TransportProfile,
    neg2: &fuse_uring::FuseUringNegotiation,
    desc2: &str,
    report2: &fuse_uring::FuseUringReport,
    stats2: &Option<orfs::fuse_native::NativeStats>,
    stats2_after: &Option<orfs::fuse_native::NativeStats>,
    env2: &Option<orfs::fuse_native::NativeEnvironment>,
    backing1: BackingIo,
    backing2: BackingIo,
) {
    let caps = orfs::capabilities::probe();
    let doc = serde_json::json!({
        "schema": "orfs.fuse-uring-equivalence.v2",
        "generated_by": "tests/fuse_uring.rs::transport_equivalence_across_f0_f1_f2",
        "claim": "the same operations yield byte-identical logical results across F0, F1 and F2",
        "environment": {
            "kernel_release": caps.kernel_release,
            "machine": caps.machine,
            "container": caps.likely_container,
            "image_digest": image_digest(),
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
        "f2_stats_before_transcript": stats2,
        "f2_stats_after_transcript": stats2_after,
        "f2_environment": env2,
        "transcript": transcript,
        "contents_identical": true,
    });
    let path = manifest_dir().join("evidence/correctness/fuse-uring-equivalence.json");
    if let Some(p) = path.parent() {
        let _ = fs::create_dir_all(p);
    }
    if let Ok(mut s) = serde_json::to_string_pretty(&doc) {
        s.push('\n');
        let _ = fs::write(&path, s);
    }
}

// ---------------------------------------------------------------------------
// Explicit F2 engagement proof (INIT flags + ring really carrying requests)
// ---------------------------------------------------------------------------

#[test]
fn f2_real_mount_engages_and_carries_requests() {
    let required = fuse_test_required();
    let scratch = unique_scratch("f2engage");
    let mnt = scratch.join("mnt");
    fs::create_dir_all(&mnt).unwrap();
    let backing = scratch.join("backing");

    let mount = match init_volume(&backing)
        .and_then(|()| fuse::spawn(&backing, &mnt, &f2_opts()).map_err(|e| e.to_string()))
    {
        Ok(m) => m,
        Err(e) => {
            if required {
                panic!("F2 mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            eprintln!("f2_real_mount: skipped — {e}");
            let _ = fs::remove_dir_all(&scratch);
            return;
        }
    };

    let neg = mount.fuse_uring_negotiation();
    let used = mount.transport_used();
    let stats_before = mount.f2_stats();
    let env = mount.f2_environment();

    if required {
        assert_eq!(used, TransportProfile::F2, "expected real F2");
        assert!(
            neg.kernel_offered,
            "INIT did not advertise FUSE_OVER_IO_URING"
        );
        assert!(neg.accepted, "server did not echo FUSE_OVER_IO_URING");
        assert!(neg.engaged, "ring not engaged");
        assert_eq!(neg.kernel_abi, Some((7, neg.kernel_abi.unwrap().1)));
        let e = env.as_ref().expect("F2 environment");
        assert!(e.num_queues >= 1);
        assert!(e.fuse_abi_minor >= 42);
    }

    // Exercise lookup/getattr/read/write/readdir/create/unlink/rename through
    // ordinary POSIX syscalls.
    let t = apply_ops(&mnt).expect("F2 POSIX ops");
    let stats_after = mount.f2_stats();

    if required {
        let before = stats_before.as_ref().expect("stats before").requests_served;
        let after = stats_after.as_ref().expect("stats after").requests_served;
        assert!(
            after > before,
            "ring served no requests during the transcript ({before} -> {after})"
        );
    }

    let path = manifest_dir().join("evidence/correctness/fuse-uring-f2-engagement.json");
    if let Some(p) = path.parent() {
        let _ = fs::create_dir_all(p);
    }
    let doc = serde_json::json!({
        "schema": "orfs.fuse-uring-engagement.v1",
        "generated_by": "tests/fuse_uring.rs::f2_real_mount_engages_and_carries_requests",
        "init_flags": {
            "kernel_offered_fuse_over_io_uring": neg.kernel_offered,
            "server_accepted": neg.accepted,
            "engaged": neg.engaged,
            "fuse_abi": neg.kernel_abi,
        },
        "environment": env,
        "image_digest": image_digest(),
        "stats_before": stats_before,
        "stats_after": stats_after,
        "transcript_len": t.len(),
    });
    if let Ok(mut s) = serde_json::to_string_pretty(&doc) {
        s.push('\n');
        let _ = fs::write(&path, s);
    }

    let _ = fs::remove_dir_all(&scratch);
    mount.unmount().expect("unmount F2");
}

// ---------------------------------------------------------------------------
// Rigorous paired-run F0 / F1 / F2 court (Phase 26)
//
// Design (see docs/FUSE_URING.md §6.2):
//   * PAIRED runs. Each of `PAIRS` repetitions runs the identical workload under
//     F0, F1, and F2 back to back, so machine drift affects every profile alike.
//   * Per-op samples are recorded (not just batch means), so p50/p95/p99/p99.9 are
//     meaningful; the mean is reported with a two-sided 95% Student-t interval.
//     Significance is judged on the PAIRED differences (F2-F0, F2-F1) with a
//     paired-t interval: a difference is significant only when that interval
//     excludes zero.
//   * Application-level syscall time (what the caller waits for) is reported
//     alongside the number of requests that ACTUALLY REACHED THE DAEMON, from the
//     shared daemon-operation counters (uniform across transports) and, for F2,
//     the native ring's own `requests_served` counter.
// ---------------------------------------------------------------------------

/// Repetitions per (workload, profile).
const PAIRS: usize = 15;
/// 4 MiB bench file, matching the historical court's size.
const BENCH_SIZE: u64 = 4 * 1024 * 1024;

/// Deterministic PRNG so the read workloads are identical across profiles.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Student's t critical value for a two-sided 95% interval, by degrees of freedom.
fn t_crit95(df: usize) -> f64 {
    const T: [f64; 31] = [
        0.0, 12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179,
        2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060,
        2.056, 2.052, 2.048, 2.045, 2.042,
    ];
    if df == 0 {
        f64::INFINITY
    } else if df < T.len() {
        T[df]
    } else {
        1.96
    }
}

fn mean(v: &[f64]) -> f64 {
    if v.is_empty() {
        0.0
    } else {
        v.iter().sum::<f64>() / v.len() as f64
    }
}

fn sd(v: &[f64], m: f64) -> f64 {
    if v.len() < 2 {
        0.0
    } else {
        (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (v.len() as f64 - 1.0)).sqrt()
    }
}

fn ci95(v: &[f64]) -> (f64, f64) {
    let m = mean(v);
    let s = sd(v, m);
    let n = v.len();
    if n < 2 {
        return (m, m);
    }
    let hw = t_crit95(n - 1) * s / (n as f64).sqrt();
    (m - hw, m + hw)
}

fn percentile_of_sorted(s: &[f64], p: f64) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let rank = (p / 100.0 * (s.len() as f64 - 1.0)).round() as usize;
    s[rank.min(s.len() - 1)]
}

/// Per-op summary in microseconds: mean with a 95% CI and the tail percentiles.
fn summarize_us(mut samples: Vec<f64>) -> serde_json::Value {
    if samples.is_empty() {
        return serde_json::json!({ "n": 0 });
    }
    let m = mean(&samples);
    let (lo, hi) = ci95(&samples);
    let s = sd(&samples, m);
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    serde_json::json!({
        "n": samples.len(),
        "mean_us": m,
        "sd_us": s,
        "ci95_low_us": lo,
        "ci95_high_us": hi,
        "p50_us": percentile_of_sorted(&samples, 50.0),
        "p95_us": percentile_of_sorted(&samples, 95.0),
        "p99_us": percentile_of_sorted(&samples, 99.0),
        "p999_us": percentile_of_sorted(&samples, 99.9),
        "min_us": samples.first().copied(),
        "max_us": samples.last().copied(),
    })
}

/// Paired comparison of per-pair means: `b - a`, with a 95% paired-t interval.
/// Significant only when the interval excludes zero. `metric` names the units.
fn paired_compare(a: &[f64], b: &[f64], metric: &str) -> serde_json::Value {
    let n = a.len().min(b.len());
    let d: Vec<f64> = (0..n).map(|i| b[i] - a[i]).collect();
    let m = mean(&d);
    let s = sd(&d, m);
    let (lo, hi) = ci95(&d);
    let significant = n >= 2 && s > 0.0 && (lo > 0.0 || hi < 0.0);
    let t = if s > 0.0 {
        m / (s / (n as f64).sqrt())
    } else {
        0.0
    };
    serde_json::json!({
        "metric": metric,
        "pairs": n,
        "mean_diff": m,
        "ci95_low": lo,
        "ci95_high": hi,
        "t": t,
        "t_crit95": t_crit95(n.saturating_sub(1)),
        "significant": significant,
    })
}

/// A daemon-operation delta: requests that actually reached the daemon, by kind.
#[derive(Debug, Default, Clone, Copy)]
struct DaemonCounts {
    lookups: u64,
    opens: u64,
    reads: u64,
    writes: u64,
    create: u64,
    unlink: u64,
    fsyncs: u64,
}

impl DaemonCounts {
    fn total(&self) -> u64 {
        self.lookups
            + self.opens
            + self.reads
            + self.writes
            + self.create
            + self.unlink
            + self.fsyncs
    }
    fn into_json(self) -> serde_json::Value {
        serde_json::json!({
            "lookups": self.lookups,
            "opens": self.opens,
            "reads": self.reads,
            "writes": self.writes,
            "create": self.create,
            "unlink": self.unlink,
            "fsyncs": self.fsyncs,
            "total": self.total(),
        })
    }
}

fn metrics_counts(m: &Metrics) -> DaemonCounts {
    DaemonCounts {
        lookups: m.lookups,
        opens: m.opens,
        reads: m.reads,
        writes: m.writes,
        create: m.create,
        unlink: m.unlink,
        fsyncs: m.fsyncs,
    }
}

fn delta(before: DaemonCounts, after: DaemonCounts) -> DaemonCounts {
    DaemonCounts {
        lookups: after.lookups.saturating_sub(before.lookups),
        opens: after.opens.saturating_sub(before.opens),
        reads: after.reads.saturating_sub(before.reads),
        writes: after.writes.saturating_sub(before.writes),
        create: after.create.saturating_sub(before.create),
        unlink: after.unlink.saturating_sub(before.unlink),
        fsyncs: after.fsyncs.saturating_sub(before.fsyncs),
    }
}

/// A live mount under test, with its scratch paths and servicing topology.
struct Mounted {
    label: &'static str,
    mount: fuse::OrfsMount,
    root: PathBuf,
    bench: PathBuf,
    servicing: F2Servicing,
    affinity: bool,
}

impl Mounted {
    fn daemon(&self) -> DaemonCounts {
        metrics_counts(&self.mount.daemon_metrics())
    }
    fn ring_requests(&self) -> u64 {
        self.mount
            .f2_stats()
            .map(|s| s.requests_served)
            .unwrap_or(0)
    }
}

fn mount_for(
    scratch: &Path,
    label: &'static str,
    transport: Transport,
    backing: BackingIo,
    servicing: F2Servicing,
    affinity: bool,
) -> Result<Mounted, String> {
    let mnt = scratch.join(format!("{label}-mnt"));
    let back = scratch.join(format!("{label}-backing"));
    fs::create_dir_all(&mnt).map_err(|e| e.to_string())?;
    init_volume(&back)?;
    let opts = MountOptions {
        transport,
        backing_io: backing,
        direct_io: true,
        attr_ttl: Duration::from_millis(0),
        entry_ttl: Duration::from_millis(0),
        f2_servicing: servicing,
        f2_affinity: affinity,
        ..Default::default()
    };
    let mount = fuse::spawn(&back, &mnt, &opts).map_err(|e| e.to_string())?;
    let bench = mnt.join("bench.bin");
    let data: Vec<u8> = (0..BENCH_SIZE).map(|i| (i % 251) as u8).collect();
    let mut h = io_err(File::create(&bench))?;
    io_err(h.write_all(&data))?;
    io_err(h.sync_all())?;
    Ok(Mounted {
        label,
        mount,
        root: mnt,
        bench,
        servicing,
        affinity,
    })
}

/// The single-threaded latency workloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Latency {
    Read1,
    Read64,
    Read4k,
    Read64k,
    Lookup,
    CreateUnlink,
    Fsync,
}

impl Latency {
    fn name(&self) -> &'static str {
        match self {
            Latency::Read1 => "read_1b",
            Latency::Read64 => "read_64b",
            Latency::Read4k => "read_4k",
            Latency::Read64k => "read_64k",
            Latency::Lookup => "lookup",
            Latency::CreateUnlink => "create_unlink",
            Latency::Fsync => "fsync",
        }
    }
    fn ops(&self) -> u64 {
        match self {
            Latency::Read1 | Latency::Read64 | Latency::Read4k | Latency::Lookup => 400,
            Latency::Read64k => 200,
            Latency::CreateUnlink => 80,
            Latency::Fsync => 30,
        }
    }
    fn read_len(&self) -> usize {
        match self {
            Latency::Read1 => 1,
            Latency::Read64 => 64,
            Latency::Read4k => 4096,
            Latency::Read64k => 64 * 1024,
            _ => 0,
        }
    }
    fn all() -> [Latency; 7] {
        [
            Latency::Read1,
            Latency::Read64,
            Latency::Read4k,
            Latency::Read64k,
            Latency::Lookup,
            Latency::CreateUnlink,
            Latency::Fsync,
        ]
    }
}

/// Run one latency workload, returning per-op microsecond samples.
fn latency_samples(m: &Mounted, w: Latency) -> Result<Vec<f64>, String> {
    let n = w.ops();
    let mut rng = Lcg(0x1234_5678_9abc_def0);
    match w {
        Latency::Read1 | Latency::Read64 | Latency::Read4k | Latency::Read64k => {
            let len = w.read_len();
            let f = io_err(File::open(&m.bench))?;
            let mut buf = vec![0u8; len];
            let mut v = Vec::with_capacity(n as usize);
            for _ in 0..n {
                let off = rng.below(BENCH_SIZE - len as u64);
                let t = Instant::now();
                io_err(f.read_exact_at(&mut buf, off))?;
                v.push(t.elapsed().as_secs_f64() * 1e6);
            }
            Ok(v)
        }
        Latency::Lookup => {
            let mut v = Vec::with_capacity(n as usize);
            for _ in 0..n {
                let t = Instant::now();
                io_err(fs::symlink_metadata(&m.bench))?;
                v.push(t.elapsed().as_secs_f64() * 1e6);
            }
            Ok(v)
        }
        Latency::CreateUnlink => {
            let mut v = Vec::with_capacity(n as usize);
            for i in 0..n {
                let p = m.root.join(format!("tmp-{i}"));
                let t = Instant::now();
                {
                    let h = io_err(File::create(&p))?;
                    drop(h);
                }
                io_err(fs::remove_file(&p))?;
                v.push(t.elapsed().as_secs_f64() * 1e6);
            }
            Ok(v)
        }
        Latency::Fsync => {
            let f = io_err(OpenOptions::new().read(true).write(true).open(&m.bench))?;
            let mut v = Vec::with_capacity(n as usize);
            for i in 0..n {
                let off = (i * 4096) % BENCH_SIZE;
                let t = Instant::now();
                io_err(f.write_at(&[0x5a], off))?;
                io_err(f.sync_data())?;
                v.push(t.elapsed().as_secs_f64() * 1e6);
            }
            Ok(v)
        }
    }
}

/// A concurrent run's observations.
struct ConcResult {
    wall: Duration,
    ops: u64,
    latencies: Vec<f64>,
}

impl ConcResult {
    fn ops_per_sec(&self) -> f64 {
        self.ops as f64 / self.wall.as_secs_f64().max(1e-9)
    }
}

/// `threads` concurrent readers of 4 KiB at deterministic offsets.
fn concurrency_readers(
    m: &Mounted,
    threads: usize,
    ops_per_thread: u64,
) -> Result<ConcResult, String> {
    let f = io_err(File::open(&m.bench))?;
    let start = Instant::now();
    let lanes = std::thread::scope(|scope| -> Result<Vec<Vec<f64>>, String> {
        let mut handles = Vec::new();
        for t in 0..threads {
            let f = &f;
            handles.push(scope.spawn(move || -> Result<Vec<f64>, String> {
                let mut rng = Lcg(0x9e37_79b9_7f4a_7c15u64.wrapping_add(t as u64 * 0x100));
                let mut buf = [0u8; 4096];
                let mut v = Vec::with_capacity(ops_per_thread as usize);
                for _ in 0..ops_per_thread {
                    let off = rng.below(BENCH_SIZE - 4096);
                    let s = Instant::now();
                    io_err(f.read_exact_at(&mut buf, off))?;
                    v.push(s.elapsed().as_secs_f64() * 1e6);
                }
                Ok(v)
            }));
        }
        let mut out = Vec::new();
        for h in handles {
            out.push(
                h.join()
                    .map_err(|_| "worker thread panicked".to_string())??,
            );
        }
        Ok(out)
    })?;
    let wall = start.elapsed();
    let mut latencies = Vec::new();
    for mut lane in lanes {
        latencies.append(&mut lane);
    }
    Ok(ConcResult {
        wall,
        ops: threads as u64 * ops_per_thread,
        latencies,
    })
}

/// A sustained mixed workload: `threads` workers each loop a read/lookup/create
/// mix until `dur` elapses. Returns total ops and per-op latencies.
fn mixed_workload(m: &Mounted, threads: usize, dur: Duration) -> Result<ConcResult, String> {
    let start = Instant::now();
    let deadline = start + dur;
    let lanes = std::thread::scope(|scope| -> Result<Vec<(u64, Vec<f64>)>, String> {
        let mut handles = Vec::new();
        for t in 0..threads {
            let bench = m.bench.clone();
            let root = m.root.clone();
            handles.push(scope.spawn(move || -> Result<(u64, Vec<f64>), String> {
                let f = io_err(File::open(&bench))?;
                let mut rng = Lcg(0xc0ff_ee00_1234_5678u64.wrapping_add(t as u64 * 0x1000));
                let mut buf = [0u8; 4096];
                let mut ops = 0u64;
                let mut v = Vec::new();
                loop {
                    if Instant::now() >= deadline {
                        break;
                    }
                    let s = Instant::now();
                    match rng.below(100) {
                        0..=69 => {
                            let off = rng.below(BENCH_SIZE - 4096);
                            io_err(f.read_exact_at(&mut buf, off))?;
                        }
                        70..=89 => {
                            io_err(fs::symlink_metadata(&bench))?;
                        }
                        _ => {
                            let p = root.join(format!("mix-{t}-{ops}"));
                            {
                                let h = io_err(File::create(&p))?;
                                drop(h);
                            }
                            io_err(fs::remove_file(&p))?;
                        }
                    }
                    v.push(s.elapsed().as_secs_f64() * 1e6);
                    ops += 1;
                }
                Ok((ops, v))
            }));
        }
        let mut out = Vec::new();
        for h in handles {
            out.push(
                h.join()
                    .map_err(|_| "mixed worker panicked".to_string())??,
            );
        }
        Ok(out)
    })?;
    let wall = start.elapsed();
    let mut ops = 0u64;
    let mut latencies = Vec::new();
    for (n, mut v) in lanes {
        ops += n;
        latencies.append(&mut v);
    }
    Ok(ConcResult {
        wall,
        ops,
        latencies,
    })
}

fn add_daemon(a: DaemonCounts, b: DaemonCounts) -> DaemonCounts {
    DaemonCounts {
        lookups: a.lookups + b.lookups,
        opens: a.opens + b.opens,
        reads: a.reads + b.reads,
        writes: a.writes + b.writes,
        create: a.create + b.create,
        unlink: a.unlink + b.unlink,
        fsyncs: a.fsyncs + b.fsyncs,
    }
}

fn workload_desc(w: Latency) -> &'static str {
    match w {
        Latency::Read1 => "400 pread of 1 B at deterministic offsets (direct_io)",
        Latency::Read64 => "400 pread of 64 B at deterministic offsets",
        Latency::Read4k => "400 pread of 4096 B at deterministic offsets",
        Latency::Read64k => "200 pread of 64 KiB at deterministic offsets",
        Latency::Lookup => "400 stat() of one file (LOOKUP+GETATTR; TTL=0)",
        Latency::CreateUnlink => "80 create+unlink pairs",
        Latency::Fsync => "30 write(1 B)+fdatasync",
    }
}

#[test]
fn f2_court_f0_f1_f2() {
    let required = fuse_test_required();
    let scratch = unique_scratch("f2court");
    let caps = orfs::capabilities::probe();

    // Mount F0, F1, and F2 (single-loop) once each and keep them alive for the
    // whole court, so every pair sees identical mount state.
    let specs: [(&'static str, Transport, BackingIo, F2Servicing, bool); 3] = [
        (
            "F0",
            Transport::Fuse,
            BackingIo::Sync,
            F2Servicing::Single,
            false,
        ),
        (
            "F1",
            Transport::Fuse,
            BackingIo::Uring,
            F2Servicing::Single,
            false,
        ),
        (
            "F2",
            Transport::FuseUring,
            BackingIo::Uring,
            F2Servicing::Single,
            false,
        ),
    ];
    let mut mounts: Vec<Mounted> = Vec::new();
    for (label, t, b, s, a) in specs {
        match mount_for(&scratch, label, t, b, s, a) {
            Ok(m) => mounts.push(m),
            Err(e) => {
                if required {
                    panic!("{label} mount failed under ORFS_FUSE_TEST=1: {e}");
                }
                eprintln!("f2 court: skipped — {label} mount unavailable: {e}");
                let _ = fs::remove_dir_all(&scratch);
                return;
            }
        }
    }

    let measured_f2 = mounts[2].mount.transport_used() == TransportProfile::F2;
    if required {
        assert!(measured_f2, "F2 must have engaged for the court");
    }
    let labels: Vec<String> = mounts.iter().map(|m| m.label.to_string()).collect();

    // ---- profile metadata ----
    let mut profile_meta = serde_json::Map::new();
    for (i, name) in labels.iter().enumerate() {
        let m = &mounts[i];
        let used = m.mount.transport_used();
        let neg = m.mount.fuse_uring_negotiation();
        let env = m.mount.f2_environment();
        profile_meta.insert(
            name.clone(),
            serde_json::json!({
                "reported_profile": used.name(),
                "servicing": m.servicing.describe(),
                "affinity": m.affinity,
                "f2_engaged": neg.engaged,
                "f2_capabilities": if neg.engaged { Some(neg.capabilities()) } else { None },
                "f2_environment": env,
            }),
        );
    }

    // ---- latency workloads: a cold first-touch pass, then PAIRS warm paired runs ----
    let mut workload_json = serde_json::Map::new();
    for w in Latency::all() {
        // Cold: the first touch after mount, per profile (planner caches cold).
        let mut cold = serde_json::Map::new();
        for m in &mounts {
            let before = m.daemon();
            let ring_before = m.ring_requests();
            let samples = latency_samples(m, w).expect("cold latency run");
            let after = m.daemon();
            cold.insert(
                m.label.to_string(),
                serde_json::json!({
                    "latency": summarize_us(samples),
                    "app_ops": w.ops(),
                    "daemon_requests": delta(before, after).into_json(),
                    "f2_ring_requests": m.ring_requests().saturating_sub(ring_before),
                }),
            );
        }
        // Warm paired runs.
        let mut pair_means: Vec<Vec<f64>> = vec![Vec::new(); mounts.len()];
        let mut pooled: Vec<Vec<f64>> = vec![Vec::new(); mounts.len()];
        let mut daemon_totals = vec![DaemonCounts::default(); mounts.len()];
        let mut ring_totals = vec![0u64; mounts.len()];
        for _ in 0..PAIRS {
            for (pi, m) in mounts.iter().enumerate() {
                let before = m.daemon();
                let ring_before = m.ring_requests();
                let samples = latency_samples(m, w).expect("warm latency run");
                let after = m.daemon();
                daemon_totals[pi] = add_daemon(daemon_totals[pi], delta(before, after));
                ring_totals[pi] += m.ring_requests().saturating_sub(ring_before);
                pair_means[pi].push(mean(&samples));
                pooled[pi].extend_from_slice(&samples);
            }
        }
        let mut warm = serde_json::Map::new();
        for (pi, name) in labels.iter().enumerate() {
            let lat = summarize_us(std::mem::take(&mut pooled[pi]));
            let (lo, hi) = ci95(&pair_means[pi]);
            warm.insert(
                name.clone(),
                serde_json::json!({
                    "latency": lat,
                    "pair_mean_ci95_low_us": lo,
                    "pair_mean_ci95_high_us": hi,
                    "app_ops_total": w.ops() * PAIRS as u64,
                    "daemon_requests_total": daemon_totals[pi].into_json(),
                    "f2_ring_requests_total": ring_totals[pi],
                }),
            );
        }
        let f2f0 = paired_compare(&pair_means[0], &pair_means[2], "us_per_op");
        let f2f1 = paired_compare(&pair_means[1], &pair_means[2], "us_per_op");
        let f1f0 = paired_compare(&pair_means[0], &pair_means[1], "us_per_op");
        let mut paired = serde_json::Map::new();
        paired.insert("F2_minus_F0".into(), f2f0);
        paired.insert("F2_minus_F1".into(), f2f1);
        paired.insert("F1_minus_F0".into(), f1f0);
        workload_json.insert(
            w.name().to_string(),
            serde_json::json!({
                "workload": workload_desc(w),
                "pairs": PAIRS,
                "cold_first_touch": cold,
                "warm_paired": warm,
                "paired_difference_of_pair_means": paired,
            }),
        );
    }

    // ---- concurrency: 1..16 readers, paired ----
    let conc_levels = [1usize, 2, 4, 8, 16];
    let conc_pairs = 8usize;
    let ops_per_thread = 80u64;
    let mut conc_json = serde_json::Map::new();
    for &threads in &conc_levels {
        let mut pair_vals: Vec<Vec<f64>> = vec![Vec::new(); mounts.len()];
        let mut lat_pooled: Vec<Vec<f64>> = vec![Vec::new(); mounts.len()];
        let mut daemon_reads = vec![0u64; mounts.len()];
        let mut ring_totals = vec![0u64; mounts.len()];
        for _ in 0..conc_pairs {
            for (pi, m) in mounts.iter().enumerate() {
                let d0 = m.daemon();
                let r0 = m.ring_requests();
                let r = concurrency_readers(m, threads, ops_per_thread).expect("concurrency run");
                daemon_reads[pi] += delta(d0, m.daemon()).reads;
                ring_totals[pi] += m.ring_requests().saturating_sub(r0);
                pair_vals[pi].push(r.ops_per_sec());
                lat_pooled[pi].extend_from_slice(&r.latencies);
            }
        }
        let mut entry = serde_json::Map::new();
        for (pi, name) in labels.iter().enumerate() {
            let (lo, hi) = ci95(&pair_vals[pi]);
            entry.insert(
                name.clone(),
                serde_json::json!({
                    "threads": threads,
                    "ops_per_thread": ops_per_thread,
                    "pairs": conc_pairs,
                    "ops_per_sec_mean": mean(&pair_vals[pi]),
                    "ops_per_sec_ci95_low": lo,
                    "ops_per_sec_ci95_high": hi,
                    "latency": summarize_us(std::mem::take(&mut lat_pooled[pi])),
                    "daemon_reads_total": daemon_reads[pi],
                    "f2_ring_requests_total": ring_totals[pi],
                }),
            );
        }
        entry.insert(
            "paired_ops_per_sec".into(),
            serde_json::json!({
                "F2_minus_F0": paired_compare(&pair_vals[0], &pair_vals[2], "ops_per_sec"),
                "F2_minus_F1": paired_compare(&pair_vals[1], &pair_vals[2], "ops_per_sec"),
            }),
        );
        conc_json.insert(
            format!("readers_{threads}"),
            serde_json::Value::Object(entry),
        );
    }

    // ---- sustained mixed workload ----
    let mixed_pairs = 5usize;
    let mut mixed_pair_vals: Vec<Vec<f64>> = vec![Vec::new(); mounts.len()];
    let mut mixed_lat: Vec<Vec<f64>> = vec![Vec::new(); mounts.len()];
    for _ in 0..mixed_pairs {
        for (pi, m) in mounts.iter().enumerate() {
            let r = mixed_workload(m, 4, Duration::from_millis(200)).expect("mixed run");
            mixed_pair_vals[pi].push(r.ops_per_sec());
            mixed_lat[pi].extend_from_slice(&r.latencies);
        }
    }
    let mut mixed_json = serde_json::Map::new();
    for (pi, name) in labels.iter().enumerate() {
        let (lo, hi) = ci95(&mixed_pair_vals[pi]);
        mixed_json.insert(
            name.clone(),
            serde_json::json!({
                "threads": 4,
                "duration_ms": 200,
                "pairs": mixed_pairs,
                "ops_per_sec_mean": mean(&mixed_pair_vals[pi]),
                "ops_per_sec_ci95_low": lo,
                "ops_per_sec_ci95_high": hi,
                "latency": summarize_us(std::mem::take(&mut mixed_lat[pi])),
            }),
        );
    }
    mixed_json.insert(
        "paired_ops_per_sec".into(),
        serde_json::json!({
            "F2_minus_F0": paired_compare(&mixed_pair_vals[0], &mixed_pair_vals[2], "ops_per_sec"),
            "F2_minus_F1": paired_compare(&mixed_pair_vals[1], &mixed_pair_vals[2], "ops_per_sec"),
            "F1_minus_F0": paired_compare(&mixed_pair_vals[0], &mixed_pair_vals[1], "ops_per_sec"),
        }),
    );

    // ---- servicing topology benchmark: single vs pool vs pool+affinity ----
    let serv_modes: [(&'static str, F2Servicing, bool); 3] = [
        ("SVC-single", F2Servicing::Single, false),
        ("SVC-pool", F2Servicing::Pool { fast: 2, bulk: 6 }, false),
        ("SVC-pool-aff", F2Servicing::Pool { fast: 2, bulk: 6 }, true),
    ];
    let mut serv: Vec<Mounted> = Vec::new();
    let mut serv_ok = true;
    for (label, s, a) in serv_modes {
        match mount_for(
            &scratch,
            label,
            Transport::FuseUring,
            BackingIo::Uring,
            s,
            a,
        ) {
            Ok(m) => serv.push(m),
            Err(e) => {
                eprintln!("f2 court: servicing mount {label} unavailable: {e}");
                serv_ok = false;
                break;
            }
        }
    }
    let serv_pairs = 8usize;
    let mut serv_json = serde_json::Map::new();
    if serv_ok {
        // Paired across modes: read_4k latency and reader scaling.
        let mut lat_means: Vec<Vec<f64>> = vec![Vec::new(); serv.len()];
        let mut r8: Vec<Vec<f64>> = vec![Vec::new(); serv.len()];
        let mut r16: Vec<Vec<f64>> = vec![Vec::new(); serv.len()];
        for _ in 0..serv_pairs {
            for (pi, m) in serv.iter().enumerate() {
                let s = latency_samples(m, Latency::Read4k).expect("serv latency");
                lat_means[pi].push(mean(&s));
                let a = concurrency_readers(m, 8, ops_per_thread).expect("serv r8");
                r8[pi].push(a.ops_per_sec());
                let b = concurrency_readers(m, 16, ops_per_thread).expect("serv r16");
                r16[pi].push(b.ops_per_sec());
            }
        }
        let mode_name = |m: &Mounted| m.servicing.describe();
        for (pi, m) in serv.iter().enumerate() {
            serv_json.insert(
                mode_name(m),
                serde_json::json!({
                    "affinity": m.affinity,
                    "read_4k_mean_us": mean(&lat_means[pi]),
                    "read_4k_ci95": ci95(&lat_means[pi]),
                    "readers_8_ops_per_sec_mean": mean(&r8[pi]),
                    "readers_8_ci95": ci95(&r8[pi]),
                    "readers_16_ops_per_sec_mean": mean(&r16[pi]),
                    "readers_16_ci95": ci95(&r16[pi]),
                    "f2_stats": m.mount.f2_stats(),
                }),
            );
        }
        // Decide the default topology: the pool is chosen only when it beats the
        // single loop on 16-reader throughput by a significant paired margin.
        let pool_vs_single_r16 = paired_compare(&r16[0], &r16[1], "ops_per_sec");
        let aff_vs_single_r16 = paired_compare(&r16[0], &r16[2], "ops_per_sec");
        let pool_vs_single_lat = paired_compare(&lat_means[0], &lat_means[1], "us_per_op");
        let pool_r16_significant = pool_vs_single_r16["significant"].as_bool().unwrap_or(false)
            && pool_vs_single_r16["mean_diff"].as_f64().unwrap_or(0.0) > 0.0;
        let pool_lat_regression = pool_vs_single_lat["significant"].as_bool().unwrap_or(false)
            && pool_vs_single_lat["mean_diff"].as_f64().unwrap_or(0.0) > 0.0;
        let chosen = if pool_r16_significant && !pool_lat_regression {
            "pool"
        } else {
            "single-loop"
        };
        serv_json.insert(
            "comparisons".into(),
            serde_json::json!({
                "pool_minus_single_readers_16": pool_vs_single_r16,
                "pool_affinity_minus_single_readers_16": aff_vs_single_r16,
                "pool_minus_single_read_4k_latency": pool_vs_single_lat,
            }),
        );
        serv_json.insert("chosen_default".into(), serde_json::json!(chosen));
        serv_json.insert(
            "decision_rule".into(),
            serde_json::json!(
                "pool default only if 16-reader throughput gain is a significant positive \
                 paired margin AND read_4k latency has no significant regression"
            ),
        );
    }

    // ---- write evidence ----
    let doc = serde_json::json!({
        "schema": "orfs.fuse-uring.v3",
        "generated_by": "tests/fuse_uring.rs::f2_court_f0_f1_f2",
        "method": "REPEATED PAIRED runs: each repetition runs the identical workload under F0, \
                   F1 and F2 back to back. direct_io=on and attr/entry TTL=0 so every read and \
                   lookup is a real transport round-trip. Per-op samples are recorded; the mean \
                   carries a two-sided 95% Student-t interval and significance is judged on the \
                   paired difference of per-pair means. Numbers are observations, not models.",
        "statistics": {
            "pairs": PAIRS,
            "mean_interval": "two-sided 95% Student-t (n-1 df)",
            "percentiles": "nearest-rank over pooled per-op samples",
            "significance": "paired-t interval of (F2-F0) and (F2-F1) pair means excluding 0",
        },
        "environment": {
            "kernel_release": caps.kernel_release,
            "machine": caps.machine,
            "container": caps.likely_container,
            "image_digest": image_digest(),
            "orfs_version": orfs::VERSION,
            "cpu_count": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        },
        "profiles": profile_meta,
        "workloads": workload_json,
        "concurrency": conc_json.clone(),
        "mixed_workload": mixed_json.clone(),
        "servicing_benchmark": serv_json.clone(),
        "f2_measured": measured_f2,
        "daemon_reaching_requests": "Each workload reports application-level syscall time AND the \
            requests that actually reached the daemon, from the shared daemon-operation counters \
            (uniform across F0/F1/F2) and, for F2, the native ring's requests_served counter.",
    });
    let path = manifest_dir().join("evidence/performance/fuse-uring.json");
    if let Some(p) = path.parent() {
        let _ = fs::create_dir_all(p);
    }
    if let Ok(mut s) = serde_json::to_string_pretty(&doc) {
        s.push('\n');
        let _ = fs::write(&path, s);
    }

    // A focused concurrency/servicing evidence file.
    let conc_doc = serde_json::json!({
        "schema": "orfs.f2-concurrency.v1",
        "generated_by": "tests/fuse_uring.rs::f2_court_f0_f1_f2",
        "method": "paired F0/F1/F2 reader-scaling (1,2,4,8,16 threads) and a sustained mixed \
                   workload; per-op latency samples and daemon-reaching counts recorded.",
        "environment": {
            "kernel_release": caps.kernel_release,
            "machine": caps.machine,
            "image_digest": image_digest(),
            "cpu_count": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        },
        "concurrency": conc_json,
        "mixed_workload": mixed_json,
        "servicing_benchmark": serv_json,
        "f2_measured": measured_f2,
    });
    let cpath = manifest_dir().join("evidence/performance/f2-concurrency.json");
    if let Some(p) = cpath.parent() {
        let _ = fs::create_dir_all(p);
    }
    if let Ok(mut s) = serde_json::to_string_pretty(&conc_doc) {
        s.push('\n');
        let _ = fs::write(&cpath, s);
    }

    if required {
        // Prove the ring really carried the traffic for the F2 profile.
        let st = mounts[2].mount.f2_stats().expect("F2 stats");
        assert!(
            st.requests_served > 0,
            "the F2 ring must have served requests, got {st:?}"
        );
    }

    // Unmount everything.
    for m in serv.drain(..) {
        let _ = m.mount.unmount();
    }
    for m in mounts.drain(..) {
        let _ = m.mount.unmount();
    }
    let _ = fs::remove_dir_all(&scratch);
}

/// The worker-pool path must be byte-identical to F0. This exercises writes,
/// mkdir, rename, readdir, symlink, hard links, truncate and unlink through the
/// pool, alongside F0, and compares the transcripts.
#[test]
fn f2_pool_servicing_preserves_semantics() {
    let required = fuse_test_required();
    let scratch = unique_scratch("f2pool");
    let mut mounts: Vec<Mounted> = Vec::new();
    for (label, t, b, s, a) in [
        (
            "EV-F0",
            Transport::Fuse,
            BackingIo::Sync,
            F2Servicing::Single,
            false,
        ),
        (
            "EV-pool",
            Transport::FuseUring,
            BackingIo::Uring,
            F2Servicing::Pool { fast: 2, bulk: 6 },
            false,
        ),
    ] {
        match mount_for(&scratch, label, t, b, s, a) {
            Ok(m) => mounts.push(m),
            Err(e) => {
                if required {
                    panic!("{label} mount failed under ORFS_FUSE_TEST=1: {e}");
                }
                eprintln!("f2 pool equivalence: skipped — {e}");
                let _ = fs::remove_dir_all(&scratch);
                return;
            }
        }
    }
    let t0 = apply_ops(&mounts[0].root).expect("F0 ops");
    let tp = apply_ops(&mounts[1].root).expect("F2 pool ops");
    assert_eq!(tp, t0, "F2 worker-pool transcripts differ from F0");
    if required {
        assert_eq!(
            mounts[1].mount.transport_used(),
            TransportProfile::F2,
            "the pool mount must be real F2"
        );
        let st = mounts[1].mount.f2_stats().expect("F2 stats");
        assert!(st.requests_served > 0, "pool served no requests: {st:?}");
        assert!(
            st.workers_fast >= 1 && st.workers_bulk >= 1,
            "the pool must have started both lanes: {st:?}"
        );
        assert_eq!(st.register_failures, 0, "REGISTER must not have failed");
    }
    for m in mounts.drain(..) {
        let _ = m.mount.unmount();
    }
    let _ = fs::remove_dir_all(&scratch);
}
