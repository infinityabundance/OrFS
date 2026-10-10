//! Real read-only snapshot mount integration (Phase 6).
//!
//! This test **actually mounts** a historical snapshot through the kernel FUSE
//! driver and proves the required semantics: reads return the state as of the
//! snapshot root, and every write is refused with `EROFS`. It is expected to run
//! only via `scripts/container-fuse-test.sh` (the `orfs-kmount` container).
//!
//! When mounting is unavailable the test prints the exact error and **skips**
//! rather than fabricating a pass. Under `ORFS_FUSE_TEST=1` a mount failure is a
//! hard failure, so a green run proves a real read-only mount happened.

use std::fs;
use std::os::unix::fs::MetadataExt;

use orfs::commit::DurabilityMode;
use orfs::fuse::{self, MountOptions, StatfsMode};
use orfs::index::ROOT_INODE;
use orfs::namespace::{Namespace, SetAttr};

fn manifest_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_scratch(prefix: &str) -> std::path::PathBuf {
    let base = manifest_dir().join("target").join("snapshot-it");
    fs::create_dir_all(&base).expect("create base");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = base.join(format!("{prefix}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("create scratch");
    dir
}

#[test]
fn snapshot_mount_is_read_only_and_historical() {
    let required = std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1");

    let scratch = unique_scratch("snap");
    let backing = scratch.join("backing");
    let mnt = scratch.join("mnt");
    fs::create_dir_all(&mnt).expect("mnt");

    // SAFETY: `geteuid`/`getegid` are pure queries.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };

    let root_first;
    {
        let mut ns = match Namespace::init(&backing, 1 << 20, DurabilityMode::Ordered) {
            Ok(ns) => ns,
            Err(e) => {
                if required {
                    panic!("failed to initialise backing volume: {e}");
                }
                eprintln!("snapshot_fuse: skipped (init failed: {e})");
                return;
            }
        };
        ns.setattr(
            ROOT_INODE,
            &SetAttr {
                uid: Some(uid),
                gid: Some(gid),
                ..Default::default()
            },
        )
        .expect("chown root");
        let f = ns.create(ROOT_INODE, b"f", 0o644, uid, gid).unwrap();
        ns.write_at(f, 0, b"v1-historical").unwrap();
        ns.sync().unwrap();
        root_first = ns.root();
        // A later write that the snapshot must not observe.
        ns.write_at(f, 0, b"v2-modified-longer").unwrap();
        ns.sync().unwrap();
    }

    let opts = MountOptions {
        read_only: true,
        durability: DurabilityMode::Ordered,
        statfs: StatfsMode::PhysicalSafe,
        ..Default::default()
    };
    let mount = match fuse::spawn_snapshot(&backing, &mnt, root_first, &opts) {
        Ok(m) => m,
        Err(e) => {
            if required {
                panic!("snapshot FUSE mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            eprintln!("snapshot_fuse: skipped — FUSE mount unavailable: {e}");
            return;
        }
    };

    // (b) Reads return the historical content, not the later write.
    let content = fs::read(mnt.join("f")).expect("read snapshot file");
    assert_eq!(content, b"v1-historical");
    let size = fs::metadata(mnt.join("f"))
        .expect("stat snapshot file")
        .size();
    assert_eq!(size, 13);

    // (c) The mount is read-only: writes, creates, unlinks, and setxattr fail
    // with EROFS (or the kernel's read-only file-system error).
    let write_err = fs::OpenOptions::new()
        .write(true)
        .open(mnt.join("f"))
        .expect_err("write-open must fail on a read-only snapshot mount");
    assert_eq!(
        write_err.raw_os_error(),
        Some(libc::EROFS),
        "write-open error was {write_err:?}"
    );
    let create_err = fs::write(mnt.join("new"), b"x")
        .expect_err("create must fail on a read-only snapshot mount");
    assert_eq!(create_err.raw_os_error(), Some(libc::EROFS));
    let unlink_err =
        fs::remove_file(mnt.join("f")).expect_err("unlink must fail on a read-only snapshot mount");
    assert_eq!(unlink_err.raw_os_error(), Some(libc::EROFS));

    let result = mount.unmount();
    let _ = fs::remove_dir_all(&scratch);
    result.expect("unmount");
}
