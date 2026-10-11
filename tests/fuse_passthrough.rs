//! Phase 21 court: kernel-served FUSE passthrough for **immutable snapshot**
//! materializations (research/external-review §2/§9 — "make the fastest read
//! never invoke the handler").
//!
//! These tests **actually mount** a historical snapshot on the native F2 session
//! (the only transport that owns `/dev/fuse`), register a version-qualified
//! backing image with the kernel, and prove:
//!
//! * engagement — the daemon-side read counter does **not** increase across a
//!   read of a passthrough file, and the mount reports `FUSE_PASSTHROUGH`
//!   negotiated plus a registered backing id;
//! * byte-exactness — a kernel-served read equals an independent authoritative
//!   replay of the same committed root, exactly;
//! * fallback — when passthrough is unsupported or denied, reads are served by
//!   the daemon with identical bytes;
//! * version qualification — a different committed version gets a different
//!   backing image and never reuses the old one;
//! * measured latency for passthrough vs. daemon-served vs. a cached ext4 file.
//!
//! Mounting requires `/dev/fuse` + `CAP_SYS_ADMIN` and is expected only under
//! `scripts/container-fuse-test.sh` (`ORFS_FUSE_TEST=1`), where a mount failure
//! is a hard failure — a green run proves real kernel engagement.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use orfs::commit::DurabilityMode;
use orfs::fuse::{self, MountOptions, StatfsMode};
use orfs::fuse_uring::TransportProfile;
use orfs::index::ROOT_INODE;
use orfs::namespace::{Namespace, SetAttr};
use orfs::snapshot::Snapshot;

const FILE_LEN: usize = 256 * 1024;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_scratch(prefix: &str) -> PathBuf {
    let base = manifest_dir().join("target").join("passthrough-it");
    fs::create_dir_all(&base).expect("create base");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = base.join(format!("{prefix}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("create scratch");
    dir
}

fn fuse_test_required() -> bool {
    std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1")
}

fn image_digest() -> String {
    std::env::var("ORFS_IMAGE_DIGEST").unwrap_or_else(|_| "unknown".to_string())
}

/// Deterministic file content for a seed.
fn content(seed: u8) -> Vec<u8> {
    (0..FILE_LEN)
        .map(|i| {
            (i as u8)
                .wrapping_mul(31)
                .wrapping_add(seed)
                .wrapping_add((i >> 8) as u8)
        })
        .collect()
}

/// Initialise a volume with a file `f` holding `v1` at `root_first`, then
/// overwrite it with `v2` and sync to obtain `root_second`.
fn build_fixture(backing: &Path) -> (u64, u64, Vec<u8>, Vec<u8>) {
    let mut ns = Namespace::init(backing, 1 << 20, DurabilityMode::Ordered).expect("init volume");
    // SAFETY: `geteuid`/`getegid` are pure queries.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    ns.setattr(
        ROOT_INODE,
        &SetAttr {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        },
    )
    .expect("chown root");
    let f = ns
        .create(ROOT_INODE, b"f", 0o644, uid, gid)
        .expect("create f");
    let v1 = content(7);
    ns.write_at(f, 0, &v1).expect("write v1");
    ns.sync().expect("sync v1");
    let root_first = ns.root();
    let v2 = content(200);
    ns.write_at(f, 0, &v2).expect("write v2");
    ns.sync().expect("sync v2");
    let root_second = ns.root();
    (root_first, root_second, v1, v2)
}

/// Read `f` at `root` through an independent `Snapshot` (the authoritative
/// replay a daemon-served read would produce).
fn authoritative(backing: &Path, root: u64) -> Vec<u8> {
    let snap = Snapshot::open_dir(backing, root).expect("open snapshot");
    let ino = snap.lookup(ROOT_INODE, b"f").expect("lookup f");
    snap.read_at(ino, 0, FILE_LEN as u32).expect("read_at f")
}

fn snap_opts(passthrough: bool) -> MountOptions {
    MountOptions {
        read_only: true,
        statfs: StatfsMode::PhysicalSafe,
        passthrough,
        ..Default::default()
    }
}

fn mount_native_snapshot(
    backing: &Path,
    mnt: &Path,
    root: u64,
    passthrough: bool,
) -> Result<fuse::OrfsMount, String> {
    fs::create_dir_all(mnt).map_err(|e| e.to_string())?;
    fuse::spawn_snapshot_native(backing, mnt, root, &snap_opts(passthrough))
        .map_err(|e| e.to_string())
}

/// Every materialized backing image (a file named `image`) beneath the
/// concealed `.or_passthrough` area.
fn collect_images(backing: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![backing.join(orfs::passthrough::PASSTHROUGH_DIR)];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().and_then(|n| n.to_str()) == Some("image") {
                out.push(path);
            }
        }
    }
    out
}

/// The image path whose ancestor directory is named after `root`.
fn image_for_root(backing: &Path, root: u64) -> Option<PathBuf> {
    let want = root.to_string();
    collect_images(backing).into_iter().find(|p| {
        p.ancestors()
            .filter_map(|a| a.file_name().and_then(|n| n.to_str()))
            .any(|n| n == want)
    })
}

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut s) = serde_json::to_string_pretty(value) {
        s.push('\n');
        let _ = fs::write(path, s);
    }
}

fn environment() -> serde_json::Value {
    serde_json::to_value(orfs::bench::Environment::capture(Some(image_digest())))
        .unwrap_or(serde_json::Value::Null)
}

// ---------------------------------------------------------------------------
// (a) Engagement + byte-exactness
// ---------------------------------------------------------------------------

#[test]
fn passthrough_reads_are_kernel_served_and_byte_exact() {
    let required = fuse_test_required();
    let scratch = unique_scratch("engage");
    let backing = scratch.join("backing");
    let mnt = scratch.join("mnt");
    let (root_first, _root_second, v1, _v2) = build_fixture(&backing);

    let mount = match mount_native_snapshot(&backing, &mnt, root_first, true) {
        Ok(m) => m,
        Err(e) => {
            if required {
                panic!("native F2 snapshot passthrough mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            eprintln!("passthrough: skipped — mount unavailable: {e}");
            let _ = fs::remove_dir_all(&scratch);
            return;
        }
    };

    let used = mount.transport_used();
    let neg = mount.fuse_uring_negotiation();
    let before = mount.f2_stats().expect("native F2 stats");

    assert_eq!(
        used,
        TransportProfile::F2,
        "passthrough needs the native F2 session"
    );
    assert!(
        neg.engaged,
        "the native F2 ring must be engaged: {}",
        neg.describe()
    );
    assert!(
        before.passthrough_requested,
        "the mount must request passthrough"
    );
    assert!(
        before.passthrough_negotiated,
        "the kernel must offer FUSE_PASSTHROUGH at INIT (ABI {:?})",
        neg.kernel_abi
    );

    // A kernel-served read of the snapshot file, through a handle held open so
    // the registration stays pinned for the next assertion.
    let mut h1 = fs::File::open(mnt.join("f")).expect("open f through the mount");
    let mut bytes = Vec::new();
    h1.read_to_end(&mut bytes)
        .expect("read f through the mount");
    assert_eq!(
        bytes, v1,
        "passthrough bytes differ from the historical content"
    );

    let after = mount.f2_stats().expect("native F2 stats");
    assert!(
        after.passthrough_opens >= 1,
        "no open attached a kernel backing (opens={}, last_error={:?})",
        after.passthrough_opens,
        after.passthrough_last_error
    );
    assert_eq!(
        after.passthrough_registered, 1,
        "the backing must be registered exactly once"
    );
    assert_eq!(
        after.daemon_reads, before.daemon_reads,
        "the daemon served a read on a passthrough file ({} -> {})",
        before.daemon_reads, after.daemon_reads
    );
    assert!(
        after.passthrough_last_error.is_none(),
        "unexpected passthrough fallback: {:?}",
        after.passthrough_last_error
    );

    // Byte-exactness against an independent authoritative replay.
    let auth = authoritative(&backing, root_first);
    assert_eq!(auth, v1, "fixture mismatch");
    assert_eq!(
        bytes, auth,
        "kernel-served bytes differ from the authoritative replay"
    );

    // A second *concurrent* open reuses the registered backing (refcount bump)
    // and is byte-exact without any extra registration.
    let mut h2 = fs::File::open(mnt.join("f")).expect("second concurrent open");
    let mut bytes2 = Vec::new();
    h2.read_to_end(&mut bytes2).expect("second concurrent read");
    assert_eq!(bytes2, v1, "second read differs");
    let after2 = mount.f2_stats().expect("native F2 stats");
    assert_eq!(
        after2.passthrough_registered, 1,
        "a concurrent open must reuse the registration, not register again"
    );
    assert!(
        after2.passthrough_reused >= 1,
        "the second open did not reuse the registered backing"
    );
    assert_eq!(
        after2.daemon_reads, before.daemon_reads,
        "the daemon served the second read too"
    );

    // Closing every handle unpins the backing (the kernel's `RELEASE` is
    // asynchronous, so poll briefly for the unpin).
    drop(h1);
    drop(h2);
    let mut released = false;
    for _ in 0..300 {
        if mount.f2_stats().expect("stats").passthrough_releases >= 1 {
            released = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        released,
        "closing the handles did not release the kernel backing"
    );
    let after3 = mount.f2_stats().expect("native F2 stats");

    let doc = serde_json::json!({
        "schema": "orfs.fuse-passthrough-correctness.v1",
        "generated_by": "tests/fuse_passthrough.rs::passthrough_reads_are_kernel_served_and_byte_exact",
        "claim": "an immutable snapshot read is served by the kernel via FUSE passthrough \
                  and is byte-identical to an independent authoritative replay",
        "environment": environment(),
        "transport": "F2 (native /dev/fuse session)",
        "negotiation": neg,
        "stats_before": before,
        "stats_after_first_read": after,
        "stats_after_second_read": after2,
        "stats_after_release": after3,
        "file_len": FILE_LEN,
        "bytes_equal_authoritative_replay": bytes == auth,
        "daemon_reads_delta": after3.daemon_reads.saturating_sub(before.daemon_reads),
        "backing_images": collect_images(&backing).iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
    });
    write_json(
        &manifest_dir().join("evidence/correctness/fuse-passthrough.json"),
        &doc,
    );

    let result = mount.unmount();
    let _ = fs::remove_dir_all(&scratch);
    result.expect("unmount passthrough snapshot");
}

// ---------------------------------------------------------------------------
// (b) Fallback when passthrough is disabled or denied
// ---------------------------------------------------------------------------

#[test]
fn fallback_paths_are_byte_identical() {
    let required = fuse_test_required();
    let scratch = unique_scratch("fallback");
    let v1;
    let root_first;

    // (b1) Native F2 snapshot mount with passthrough *not requested*: every read
    // is served by the daemon.
    {
        let backing = scratch.join("backing-b1");
        let mnt = scratch.join("mnt-b1");
        let (r, _r2, content1, _c2) = build_fixture(&backing);
        root_first = r;
        v1 = content1;

        let mount = match mount_native_snapshot(&backing, &mnt, root_first, false) {
            Ok(m) => m,
            Err(e) => {
                if required {
                    panic!("native snapshot (no passthrough) mount failed: {e}");
                }
                eprintln!("fallback: skipped — mount unavailable: {e}");
                let _ = fs::remove_dir_all(&scratch);
                return;
            }
        };
        let before = mount.f2_stats().expect("stats");
        assert!(
            !before.passthrough_negotiated,
            "passthrough must not be negotiated here"
        );
        let bytes = fs::read(mnt.join("f")).expect("read f");
        assert_eq!(bytes, v1, "daemon-served bytes differ");
        let after = mount.f2_stats().expect("stats");
        assert!(
            after.daemon_reads > before.daemon_reads,
            "the daemon must have served the read ({} -> {})",
            before.daemon_reads,
            after.daemon_reads
        );
        assert_eq!(
            after.passthrough_opens, 0,
            "no open may attach passthrough here"
        );
        mount.unmount().expect("unmount b1");
    }

    // (b2) Passthrough requested, but materialization/registration is made
    // impossible (the concealed area is a file, not a directory): the open must
    // fall back to the daemon with identical bytes, never fail.
    {
        let backing = scratch.join("backing-b2");
        let mnt = scratch.join("mnt-b2");
        let (r, _r2, content1, _c2) = build_fixture(&backing);
        let _ = &root_first;
        fs::write(
            backing.join(orfs::passthrough::PASSTHROUGH_DIR),
            b"not a directory",
        )
        .unwrap();

        let mount = match mount_native_snapshot(&backing, &mnt, r, true) {
            Ok(m) => m,
            Err(e) => {
                if required {
                    panic!("native passthrough snapshot mount failed: {e}");
                }
                eprintln!("fallback: skipped — mount unavailable: {e}");
                let _ = fs::remove_dir_all(&scratch);
                return;
            }
        };
        let before = mount.f2_stats().expect("stats");
        assert!(
            before.passthrough_negotiated,
            "passthrough should be negotiated"
        );
        let bytes = fs::read(mnt.join("f")).expect("read f");
        assert_eq!(
            bytes, content1,
            "fallback bytes differ from the historical content"
        );
        let after = mount.f2_stats().expect("stats");
        assert!(
            after.passthrough_fallbacks >= 1,
            "the denied materialization must be recorded as a fallback"
        );
        assert_eq!(
            after.passthrough_opens, 0,
            "no backing may attach when denied"
        );
        assert!(
            after.daemon_reads > before.daemon_reads,
            "the daemon must serve the read after a denied passthrough"
        );
        assert_eq!(
            bytes,
            authoritative(&backing, r),
            "fallback bytes differ from replay"
        );
        mount.unmount().expect("unmount b2");
    }

    let _ = fs::remove_dir_all(&scratch);
}

// ---------------------------------------------------------------------------
// (c) Version qualification: no cross-version reuse
// ---------------------------------------------------------------------------

#[test]
fn backing_images_are_version_qualified_and_reused() {
    let required = fuse_test_required();
    let scratch = unique_scratch("versioning");
    let backing = scratch.join("backing");
    let (root_first, root_second, v1, v2) = build_fixture(&backing);
    assert_ne!(v1, v2, "the fixture must produce two distinct versions");
    assert_ne!(root_first, root_second);

    // First mount at root_first.
    let mnt1 = scratch.join("mnt1");
    let m1 = match mount_native_snapshot(&backing, &mnt1, root_first, true) {
        Ok(m) => m,
        Err(e) => {
            if required {
                panic!("passthrough mount failed: {e}");
            }
            eprintln!("versioning: skipped — mount unavailable: {e}");
            let _ = fs::remove_dir_all(&scratch);
            return;
        }
    };
    assert_eq!(fs::read(mnt1.join("f")).unwrap(), v1);
    let img_first = image_for_root(&backing, root_first).expect("image for root_first");
    assert_eq!(
        fs::read(&img_first).unwrap(),
        v1,
        "image bytes must equal the version"
    );
    let mtime_first = fs::metadata(&img_first).unwrap().modified().unwrap();
    m1.unmount().expect("unmount m1");

    // Remount the *same* root: the image is reused, not rewritten.
    std::thread::sleep(std::time::Duration::from_millis(10));
    let mnt2 = scratch.join("mnt2");
    let m2 = mount_native_snapshot(&backing, &mnt2, root_first, true).expect("remount root_first");
    assert_eq!(fs::read(mnt2.join("f")).unwrap(), v1);
    let img_first_again = image_for_root(&backing, root_first).expect("image for root_first");
    assert_eq!(
        img_first, img_first_again,
        "the reused image path must be stable"
    );
    assert_eq!(
        fs::metadata(&img_first).unwrap().modified().unwrap(),
        mtime_first,
        "a reused image must not be rewritten"
    );
    m2.unmount().expect("unmount m2");

    // Mount the *second* root: a distinct backing image, byte-exact to v2.
    let mnt3 = scratch.join("mnt3");
    let m3 = mount_native_snapshot(&backing, &mnt3, root_second, true).expect("mount root_second");
    assert_eq!(fs::read(mnt3.join("f")).unwrap(), v2);
    let img_second = image_for_root(&backing, root_second).expect("image for root_second");
    assert_ne!(
        img_first, img_second,
        "a different committed version must get a different backing image"
    );
    assert_eq!(
        fs::read(&img_second).unwrap(),
        v2,
        "image bytes must equal v2"
    );
    m3.unmount().expect("unmount m3");

    let _ = fs::remove_dir_all(&scratch);
}

// ---------------------------------------------------------------------------
// Measured latency: passthrough vs daemon-served vs cached ext4
// ---------------------------------------------------------------------------

fn read_latencies(path: &Path, iters: usize) -> Vec<u64> {
    // Warm up so page-cache effects are equal across the three arms.
    for _ in 0..3 {
        let _ = fs::read(path).expect("warmup read");
    }
    let mut out = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        let bytes = fs::read(path).expect("read");
        out.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(&bytes);
    }
    out
}

fn summarize(mut xs: Vec<u64>) -> serde_json::Value {
    if xs.is_empty() {
        return serde_json::Value::Null;
    }
    xs.sort_unstable();
    let n = xs.len();
    let sum: u64 = xs.iter().sum();
    let pct = |p: usize| xs[((n - 1) * p) / 100];
    serde_json::json!({
        "iterations": n,
        "min_ns": xs[0],
        "p50_ns": pct(50),
        "p90_ns": pct(90),
        "max_ns": xs[n - 1],
        "mean_ns": sum / n as u64,
    })
}

#[test]
fn measure_passthrough_vs_daemon_vs_ext4() {
    let required = fuse_test_required();
    let scratch = unique_scratch("perf");
    let backing = scratch.join("backing");
    let (root_first, _root_second, v1, _v2) = build_fixture(&backing);
    const ITERS: usize = 200;

    // ext4 (actually the host backing fs) baseline: the same bytes as a plain file.
    let baseline = scratch.join("baseline.bin");
    fs::write(&baseline, &v1).expect("write baseline");
    let ext4 = read_latencies(&baseline, ITERS);

    // Passthrough arm.
    let mnt_pt = scratch.join("mnt-pt");
    let m_pt = match mount_native_snapshot(&backing, &mnt_pt, root_first, true) {
        Ok(m) => m,
        Err(e) => {
            if required {
                panic!("passthrough mount failed: {e}");
            }
            eprintln!("perf: skipped — mount unavailable: {e}");
            let _ = fs::remove_dir_all(&scratch);
            return;
        }
    };
    let pt = read_latencies(&mnt_pt.join("f"), ITERS);
    let pt_stats = m_pt.f2_stats().expect("stats");
    m_pt.unmount().expect("unmount passthrough");

    // Daemon-served arm (native F2, no passthrough).
    let mnt_daemon = scratch.join("mnt-daemon");
    let m_daemon =
        mount_native_snapshot(&backing, &mnt_daemon, root_first, false).expect("daemon mount");
    let daemon = read_latencies(&mnt_daemon.join("f"), ITERS);
    let daemon_stats = m_daemon.f2_stats().expect("stats");
    m_daemon.unmount().expect("unmount daemon");

    let doc = serde_json::json!({
        "schema": "orfs.fuse-passthrough-performance.v1",
        "generated_by": "tests/fuse_passthrough.rs::measure_passthrough_vs_daemon_vs_ext4",
        "claim": "a kernel-served passthrough read of an immutable snapshot file avoids the \
                  userspace daemon; measured against a daemon-served FUSE read and a cached \
                  plain-file read of the same bytes",
        "environment": environment(),
        "file_len": FILE_LEN,
        "iterations": ITERS,
        "caveat": "all three arms are page-cache warm after warmup, so this measures the \
                   per-read dispatch cost, not cold storage; the passthrough arm still avoids \
                   the /dev/fuse round-trip, which is why it is reported separately",
        "passthrough": summarize(pt),
        "daemon_served": summarize(daemon),
        "cached_ext4": summarize(ext4),
        "passthrough_stats": pt_stats,
        "daemon_stats": daemon_stats,
    });
    write_json(
        &manifest_dir().join("evidence/performance/passthrough.json"),
        &doc,
    );

    let _ = fs::remove_dir_all(&scratch);
}
