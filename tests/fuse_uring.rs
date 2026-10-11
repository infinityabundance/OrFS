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
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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
// Measurements: real F0 / F1 / F2 numbers
// ---------------------------------------------------------------------------

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

fn perf_opts(transport: Transport, backing_io: BackingIo) -> MountOptions {
    MountOptions {
        transport,
        backing_io,
        // Bypass the page cache so every read is a real transport round-trip,
        // and disable attribute/entry caching so every lookup reaches the daemon.
        direct_io: true,
        attr_ttl: Duration::from_millis(0),
        entry_ttl: Duration::from_millis(0),
        ..Default::default()
    }
}

/// Measure a fixed workload through `root`; returns microseconds-per-op metrics.
fn measure(root: &Path) -> Result<serde_json::Value, String> {
    let path = root.join("bench.bin");
    let size: usize = 4 * 1024 * 1024;
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    {
        let mut h = io_err(File::create(&path))?;
        io_err(h.write_all(&data))?;
        io_err(h.sync_all())?;
    }

    // Sequential read (2 passes over the whole file in 128 KiB chunks).
    let seq_start = Instant::now();
    let mut seq_bytes: u64 = 0;
    for _ in 0..2 {
        let mut h = io_err(File::open(&path))?;
        let mut buf = vec![0u8; 128 * 1024];
        loop {
            let n = io_err(h.read(&mut buf))?;
            if n == 0 {
                break;
            }
            seq_bytes += n as u64;
        }
    }
    let seq = seq_start.elapsed();

    let mut rng = Lcg(0x1234_5678_9abc_def0);
    let reads_4k: u64 = 1000;
    let r4_start = Instant::now();
    {
        let mut h = io_err(File::open(&path))?;
        let mut buf = [0u8; 4096];
        for _ in 0..reads_4k {
            let off = rng.below((size - 4096) as u64);
            io_err(h.seek(SeekFrom::Start(off)))?;
            io_err(h.read_exact(&mut buf))?;
        }
    }
    let r4 = r4_start.elapsed();

    let reads_1b: u64 = 1000;
    let r1_start = Instant::now();
    {
        let mut h = io_err(File::open(&path))?;
        let mut b = [0u8; 1];
        for _ in 0..reads_1b {
            let off = rng.below((size - 1) as u64);
            io_err(h.seek(SeekFrom::Start(off)))?;
            io_err(h.read_exact(&mut b))?;
        }
    }
    let r1 = r1_start.elapsed();

    // Metadata lookup: stat the file 1000 times (LOOKUP + GETATTR, uncached).
    let lk_n: u64 = 1000;
    let lk_start = Instant::now();
    for _ in 0..lk_n {
        io_err(fs::symlink_metadata(&path))?;
    }
    let lk = lk_start.elapsed();

    // create + unlink.
    let cu_n: u64 = 300;
    let cu_start = Instant::now();
    for i in 0..cu_n {
        let p = root.join(format!("tmp-{i}"));
        {
            let h = io_err(File::create(&p))?;
            drop(h);
        }
        io_err(fs::remove_file(&p))?;
    }
    let cu = cu_start.elapsed();

    // fsync latency: write 1 byte then fsync, 300 times.
    let fs_n: u64 = 300;
    let fs_start = Instant::now();
    {
        let mut h = io_err(OpenOptions::new().read(true).write(true).open(&path))?;
        for i in 0..fs_n {
            io_err(h.seek(SeekFrom::Start((i * 4096) % size as u64)))?;
            io_err(h.write_all(&[0x5a]))?;
            io_err(h.sync_data())?;
        }
    }
    let fsd = fs_start.elapsed();

    let us = |d: Duration, n: u64| (d.as_micros() as f64) / (n as f64);
    Ok(serde_json::json!({
        "sequential_read": {
            "bytes": seq_bytes,
            "seconds": seq.as_secs_f64(),
            "mib_per_s": (seq_bytes as f64 / (1024.0 * 1024.0)) / seq.as_secs_f64().max(1e-9),
        },
        "random_4k_read": { "ops": reads_4k, "us_per_op": us(r4, reads_4k) },
        "random_1b_read": { "ops": reads_1b, "us_per_op": us(r1, reads_1b) },
        "metadata_lookup": { "ops": lk_n, "us_per_op": us(lk, lk_n) },
        "create_unlink": { "ops": cu_n, "us_per_op": us(cu, cu_n) },
        "fsync": { "ops": fs_n, "us_per_op": us(fsd, fs_n) },
    }))
}

#[test]
fn f2_performance_f0_f1_f2() {
    let required = fuse_test_required();
    let scratch = unique_scratch("perf");
    let caps = orfs::capabilities::probe();

    let mut results = serde_json::Map::new();
    let mut profile_meta = serde_json::Map::new();
    let mut measured_f2 = false;

    for (name, opts) in [
        ("F0", perf_opts(Transport::Fuse, BackingIo::Sync)),
        ("F1", perf_opts(Transport::Fuse, BackingIo::Uring)),
        ("F2", perf_opts(Transport::FuseUring, BackingIo::Uring)),
    ] {
        let mnt = scratch.join(format!("{name}-mnt"));
        let backing = scratch.join(format!("{name}-backing"));
        fs::create_dir_all(&mnt).unwrap();
        if let Err(e) = init_volume(&backing) {
            if required {
                panic!("{name} init failed: {e}");
            }
            eprintln!("perf: skipped — {e}");
            let _ = fs::remove_dir_all(&scratch);
            return;
        }
        let mount = match fuse::spawn(&backing, &mnt, &opts) {
            Ok(m) => m,
            Err(e) => {
                if required {
                    panic!("{name} mount failed: {e}");
                }
                eprintln!("perf: skipped — {name} mount unavailable: {e}");
                let _ = fs::remove_dir_all(&scratch);
                return;
            }
        };
        let used = mount.transport_used();
        let neg = mount.fuse_uring_negotiation();
        let env = mount.f2_environment();
        let value = match measure(&mnt) {
            Ok(v) => v,
            Err(e) => {
                let _ = mount.unmount();
                let _ = fs::remove_dir_all(&scratch);
                panic!("{name} measurement failed: {e}");
            }
        };
        let unmount = mount.unmount();
        if name == "F2" {
            measured_f2 = used == TransportProfile::F2;
        }
        results.insert(name.to_string(), value);
        profile_meta.insert(
            name.to_string(),
            serde_json::json!({
                "reported_profile": used.name(),
                "backing_io": format!("{:?}", opts.backing_io),
                "direct_io": opts.direct_io,
                "attr_ttl_ms": opts.attr_ttl.as_millis(),
                "entry_ttl_ms": opts.entry_ttl.as_millis(),
                "f2_engaged": neg.engaged,
                "f2_environment": env,
            }),
        );
        unmount.expect("unmount");
    }

    if required {
        assert!(measured_f2, "F2 must have engaged for the F2 measurements");
    }

    let doc = serde_json::json!({
        "schema": "orfs.fuse-uring.v2",
        "generated_by": "tests/fuse_uring.rs::f2_performance_f0_f1_f2",
        "method": "POSIX syscalls through a real mount; direct_io=on and attr/entry TTL=0 so every \
                   operation is a real transport round-trip. Identical workloads and deterministic \
                   offsets for all three profiles. Numbers are observations, not models.",
        "environment": {
            "kernel_release": caps.kernel_release,
            "machine": caps.machine,
            "container": caps.likely_container,
            "image_digest": image_digest(),
            "orfs_version": orfs::VERSION,
        },
        "workloads": {
            "sequential_read": "2 passes over 4 MiB in 128 KiB reads (page cache bypassed by direct_io)",
            "random_4k_read": "1000 pread of 4096 B at deterministic offsets",
            "random_1b_read": "1000 pread of 1 B at deterministic offsets",
            "metadata_lookup": "1000 stat() of one file (LOOKUP + GETATTR, uncached)",
            "create_unlink": "300 create+unlink pairs",
            "fsync": "300 write(1B)+fdatasync",
        },
        "profiles": profile_meta,
        "measurements": results,
        "f2_measured": measured_f2,
    });
    let path = manifest_dir().join("evidence/performance/fuse-uring.json");
    if let Some(p) = path.parent() {
        let _ = fs::create_dir_all(p);
    }
    if let Ok(mut s) = serde_json::to_string_pretty(&doc) {
        s.push('\n');
        let _ = fs::write(&path, s);
    }

    let _ = fs::remove_dir_all(&scratch);
}
