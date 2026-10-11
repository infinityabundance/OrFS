//! Real FUSE integration test (Phase 4).
//!
//! This test **actually mounts** an OrFS volume through the kernel FUSE driver
//! and drives it with ordinary POSIX syscalls. Each scenario is run twice — once
//! against the OrFS mount, once against a scratch directory on a trusted
//! reference filesystem (the repository's own `target/`, typically ext4) — and
//! the observable results are compared. Where a reference comparison is not
//! meaningful (block-granular `SEEK_DATA`/`SEEK_HOLE`, `fallocate` block layout)
//! the scenario asserts the documented OrFS semantics instead and is recorded as
//! a semantic check.
//!
//! Mounting requires `/dev/fuse` and the CAP_SYS_ADMIN/setuid-mount path. It is
//! expected to be run only via `scripts/container-fuse-test.sh` (the
//! `orfs-kmount` container). When mounting is unavailable (for example under the
//! ordinary unprivileged test container) the test prints the exact error and
//! **skips** rather than fabricating a pass. Under `ORFS_FUSE_TEST=1` a mount
//! failure is a hard failure, so the FUSE test suite can never be green without
//! a real mount.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use orfs::commit::DurabilityMode;
use orfs::fuse::{self, MountOptions, StatfsMode};
use orfs::log::DEFAULT_SEGMENT_SIZE;
use orfs::namespace::{Namespace, SetAttr};

/// A scenario outcome: `Ok(summary)` or `Err(normalised error)`.
type Outcome = Result<String, String>;

fn ioerr() -> String {
    format!("{:?}", std::io::Error::last_os_error().kind())
}

/// A record of one compared or asserted operation.
#[derive(Clone, serde::Serialize)]
struct Check {
    name: String,
    kind: &'static str,
    orfs: String,
    reference: String,
    matched: bool,
}

#[derive(Default)]
struct Recorder {
    checks: Vec<Check>,
}

impl Recorder {
    /// Run `f` against both roots, compare the outcomes, and record the result.
    fn compare(
        &mut self,
        name: &str,
        orfs_root: &Path,
        ref_root: &Path,
        f: impl Fn(&Path) -> Outcome,
    ) {
        let o = f(orfs_root);
        let r = f(ref_root);
        let matched = o == r;
        self.checks.push(Check {
            name: name.to_string(),
            kind: "reference",
            orfs: fmt_outcome(&o),
            reference: fmt_outcome(&r),
            matched,
        });
        assert!(
            matched,
            "{name}: orfs={} reference={}",
            fmt_outcome(&o),
            fmt_outcome(&r)
        );
    }

    /// Assert a documented OrFS semantic directly.
    fn assert_semantic(&mut self, name: &str, expected: &str, got: &str, ok: bool) {
        self.checks.push(Check {
            name: name.to_string(),
            kind: "semantic",
            orfs: got.to_string(),
            reference: expected.to_string(),
            matched: ok,
        });
        assert!(ok, "{name}: expected {expected}, got {got}");
    }
}

fn fmt_outcome(o: &Outcome) -> String {
    match o {
        Ok(s) => format!("ok:{s}"),
        Err(e) => format!("err:{e}"),
    }
}

// ---------------------------------------------------------------------------
// Scenarios (each is self-contained under a fresh subdirectory)
// ---------------------------------------------------------------------------

fn scratch(root: &Path, name: &str) -> PathBuf {
    let p = root.join(name);
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("scratch dir");
    p
}

fn s_create_write_read(root: &Path) -> Outcome {
    let d = scratch(root, "s_create_write_read");
    let f = d.join("f");
    let mut file = File::create(&f).map_err(|e| format!("{:?}", e.kind()))?;
    file.write_all(b"hello world")
        .map_err(|e| format!("{:?}", e.kind()))?;
    file.sync_all().map_err(|e| format!("{:?}", e.kind()))?;
    drop(file);
    let mut s = String::new();
    File::open(&f)
        .and_then(|mut h| h.read_to_string(&mut s))
        .map_err(|e| format!("{:?}", e.kind()))?;
    let md = fs::metadata(&f).map_err(|e| format!("{:?}", e.kind()))?;
    Ok(format!(
        "content={s} size={} isfile={}",
        md.size(),
        md.is_file()
    ))
}

fn s_mkdir_readdir(root: &Path) -> Outcome {
    let d = scratch(root, "s_mkdir_readdir");
    for n in ["b", "a", "c"] {
        fs::create_dir(d.join(n)).map_err(|e| format!("{:?}", e.kind()))?;
    }
    fs::write(d.join("zz"), b"x").map_err(|e| format!("{:?}", e.kind()))?;
    let mut names: Vec<String> = fs::read_dir(&d)
        .map_err(|e| format!("{:?}", e.kind()))?
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok(format!("{names:?}"))
}

fn s_append_and_seek(root: &Path) -> Outcome {
    let d = scratch(root, "s_append_and_seek");
    let f = d.join("f");
    fs::write(&f, b"AAAA").map_err(|e| format!("{:?}", e.kind()))?;
    let mut file = OpenOptions::new()
        .append(true)
        .open(&f)
        .map_err(|e| format!("{:?}", e.kind()))?;
    file.write_all(b"BB")
        .map_err(|e| format!("{:?}", e.kind()))?;
    drop(file);
    let mut file = OpenOptions::new()
        .write(true)
        .open(&f)
        .map_err(|e| format!("{:?}", e.kind()))?;
    file.seek(SeekFrom::Start(2))
        .map_err(|e| format!("{:?}", e.kind()))?;
    file.write_all(b"cc")
        .map_err(|e| format!("{:?}", e.kind()))?;
    drop(file);
    let got = fs::read(&f).map_err(|e| format!("{:?}", e.kind()))?;
    Ok(format!("{:?}", String::from_utf8_lossy(&got)))
}

fn s_sparse(root: &Path) -> Outcome {
    let d = scratch(root, "s_sparse");
    let f = d.join("f");
    let mut file = File::create(&f).map_err(|e| format!("{:?}", e.kind()))?;
    file.seek(SeekFrom::Start(100))
        .map_err(|e| format!("{:?}", e.kind()))?;
    file.write_all(b"X")
        .map_err(|e| format!("{:?}", e.kind()))?;
    drop(file);
    let data = fs::read(&f).map_err(|e| format!("{:?}", e.kind()))?;
    let md = fs::metadata(&f).map_err(|e| format!("{:?}", e.kind()))?;
    let zeros = data[..100].iter().all(|&b| b == 0);
    Ok(format!(
        "size={} zeros={zeros} last={:?}",
        md.size(),
        data.last()
    ))
}

fn s_truncate(root: &Path) -> Outcome {
    let d = scratch(root, "s_truncate");
    let f = d.join("f");
    fs::write(&f, b"0123456789").map_err(|e| format!("{:?}", e.kind()))?;
    let file = OpenOptions::new()
        .write(true)
        .open(&f)
        .map_err(|e| format!("{:?}", e.kind()))?;
    file.set_len(4).map_err(|e| format!("{:?}", e.kind()))?;
    drop(file);
    let short = fs::read(&f).map_err(|e| format!("{:?}", e.kind()))?;
    let file = OpenOptions::new()
        .write(true)
        .open(&f)
        .map_err(|e| format!("{:?}", e.kind()))?;
    file.set_len(8).map_err(|e| format!("{:?}", e.kind()))?;
    drop(file);
    let grown = fs::read(&f).map_err(|e| format!("{:?}", e.kind()))?;
    Ok(format!("short={short:?} grown={grown:?}"))
}

fn s_rename(root: &Path) -> Outcome {
    let d = scratch(root, "s_rename");
    let a = d.join("a");
    let b = d.join("b");
    fs::write(&a, b"payload").map_err(|e| format!("{:?}", e.kind()))?;
    fs::rename(&a, &b).map_err(|e| format!("{:?}", e.kind()))?;
    let old_gone = fs::metadata(&a).is_err();
    let got = fs::read(&b).map_err(|e| format!("{:?}", e.kind()))?;
    Ok(format!(
        "old_gone={old_gone} content={:?}",
        String::from_utf8_lossy(&got)
    ))
}

fn s_hardlink(root: &Path) -> Outcome {
    let d = scratch(root, "s_hardlink");
    let a = d.join("a");
    let b = d.join("b");
    fs::write(&a, b"shared").map_err(|e| format!("{:?}", e.kind()))?;
    fs::hard_link(&a, &b).map_err(|e| format!("{:?}", e.kind()))?;
    let n_before = fs::metadata(&a)
        .map_err(|e| format!("{:?}", e.kind()))?
        .nlink();
    fs::remove_file(&a).map_err(|e| format!("{:?}", e.kind()))?;
    let n_after = fs::metadata(&b)
        .map_err(|e| format!("{:?}", e.kind()))?
        .nlink();
    let got = fs::read(&b).map_err(|e| format!("{:?}", e.kind()))?;
    Ok(format!(
        "n_before={n_before} n_after={n_after} content={:?}",
        String::from_utf8_lossy(&got)
    ))
}

fn s_symlink(root: &Path) -> Outcome {
    let d = scratch(root, "s_symlink");
    let l = d.join("l");
    std::os::unix::fs::symlink("abc", &l).map_err(|e| format!("{:?}", e.kind()))?;
    let target = fs::read_link(&l).map_err(|e| format!("{:?}", e.kind()))?;
    let md = fs::symlink_metadata(&l).map_err(|e| format!("{:?}", e.kind()))?;
    Ok(format!(
        "target={:?} islink={} size={}",
        target.to_string_lossy(),
        md.file_type().is_symlink(),
        md.size()
    ))
}

fn s_unlink_while_open(root: &Path) -> Outcome {
    let d = scratch(root, "s_unlink_while_open");
    let f = d.join("f");
    fs::write(&f, b"live-handle").map_err(|e| format!("{:?}", e.kind()))?;
    let mut handle = File::open(&f).map_err(|e| format!("{:?}", e.kind()))?;
    fs::remove_file(&f).map_err(|e| format!("{:?}", e.kind()))?;
    let mut s = String::new();
    handle
        .read_to_string(&mut s)
        .map_err(|e| format!("{:?}", e.kind()))?;
    let reopen = fs::File::open(&f).map_err(|e| format!("{:?}", e.kind()));
    Ok(format!("via_handle={s:?} reopen={reopen:?}"))
}

fn s_xattr(root: &Path) -> Outcome {
    let d = scratch(root, "s_xattr");
    let f = d.join("f");
    fs::write(&f, b"x").map_err(|e| format!("{:?}", e.kind()))?;
    setxattr(&f, "user.k", b"value")?;
    let got = getxattr(&f, "user.k")?;
    // OrFS additionally exposes derived `user.orfs.*` attributes (research §8);
    // they are intentionally absent from a plain reference filesystem, so the
    // comparison ignores that known namespace.
    let listed: Vec<String> = listxattr(&f)?
        .split(|&b| b == 0)
        .filter(|n| !n.is_empty() && !n.starts_with(b"user.orfs."))
        .map(|n| String::from_utf8_lossy(n).into_owned())
        .collect();
    removexattr(&f, "user.k")?;
    let after = getxattr(&f, "user.k");
    Ok(format!(
        "got={got} listed={listed:?} after={}",
        after.is_err()
    ))
}

fn s_fsync(root: &Path) -> Outcome {
    let d = scratch(root, "s_fsync");
    let f = d.join("f");
    let mut file = File::create(&f).map_err(|e| format!("{:?}", e.kind()))?;
    file.write_all(b"durable")
        .map_err(|e| format!("{:?}", e.kind()))?;
    file.sync_all().map_err(|e| format!("{:?}", e.kind()))?;
    file.sync_data().map_err(|e| format!("{:?}", e.kind()))?;
    drop(file);
    // fsync on a directory handle.
    let dir = File::open(&d).map_err(|e| format!("{:?}", e.kind()))?;
    let dir_sync = dir
        .sync_all()
        .map_err(|e| format!("{:?}", e.kind()))
        .is_ok();
    let got = fs::read(&f).map_err(|e| format!("{:?}", e.kind()))?;
    Ok(format!(
        "dir_sync={dir_sync} content={:?}",
        String::from_utf8_lossy(&got)
    ))
}

fn s_statfs(root: &Path) -> Outcome {
    let d = scratch(root, "s_statfs");
    let md = fs::metadata(&d).map_err(|e| format!("{:?}", e.kind()))?;
    let _ = md;
    let st = statvfs(&d)?;
    Ok(format!("blocks>0={} bsize>0={}", st.0 > 0, st.2 > 0))
}

fn s_rmdir_nonempty(root: &Path) -> Outcome {
    let d = scratch(root, "s_rmdir_nonempty");
    let sub = d.join("sub");
    fs::create_dir(&sub).map_err(|e| format!("{:?}", e.kind()))?;
    fs::write(sub.join("x"), b"x").map_err(|e| format!("{:?}", e.kind()))?;
    let err = fs::remove_dir(&sub).map_err(|e| format!("{:?}", e.kind()));
    Ok(format!("{err:?}"))
}

fn s_unlink_dir(root: &Path) -> Outcome {
    let d = scratch(root, "s_unlink_dir");
    let sub = d.join("sub");
    fs::create_dir(&sub).map_err(|e| format!("{:?}", e.kind()))?;
    let err = fs::remove_file(&sub).map_err(|e| format!("{:?}", e.kind()));
    Ok(format!("{err:?}"))
}

fn s_perm_mode(root: &Path) -> Outcome {
    use std::os::unix::fs::PermissionsExt;
    let d = scratch(root, "s_perm_mode");
    let f = d.join("f");
    fs::write(&f, b"x").map_err(|e| format!("{:?}", e.kind()))?;
    fs::set_permissions(&f, fs::Permissions::from_mode(0o640))
        .map_err(|e| format!("{:?}", e.kind()))?;
    let mode = fs::metadata(&f)
        .map_err(|e| format!("{:?}", e.kind()))?
        .mode()
        & 0o777;
    Ok(format!("{mode:o}"))
}

// ---------------------------------------------------------------------------
// Semantic-only scenarios
// ---------------------------------------------------------------------------

fn s_seek_data_hole(orfs_root: &Path) -> Outcome {
    let d = scratch(orfs_root, "s_seek");
    let f = d.join("f");
    let mut file = File::create(&f).map_err(|e| format!("{:?}", e.kind()))?;
    file.write_all(b"A")
        .map_err(|e| format!("{:?}", e.kind()))?;
    file.seek(SeekFrom::Start(50))
        .map_err(|e| format!("{:?}", e.kind()))?;
    file.write_all(b"B")
        .map_err(|e| format!("{:?}", e.kind()))?;
    file.sync_all().map_err(|e| format!("{:?}", e.kind()))?;
    let fd = file.as_raw_fd();
    let data0 = lseek(fd, 0, libc::SEEK_DATA)?;
    let hole1 = lseek(fd, 1, libc::SEEK_HOLE)?;
    let data1 = lseek(fd, 1, libc::SEEK_DATA)?;
    let hole_end = lseek(fd, 51, libc::SEEK_HOLE)?;
    let data_end = lseek(fd, 51, libc::SEEK_DATA);
    Ok(format!(
        "data0={data0} hole1={hole1} data1={data1} hole_end={hole_end} data_end={data_end:?}"
    ))
}

fn s_fallocate(orfs_root: &Path) -> Outcome {
    let d = scratch(orfs_root, "s_fallocate");
    let f = d.join("f");
    fs::write(&f, [1u8; 64]).map_err(|e| format!("{:?}", e.kind()))?;
    // Punch a 16-byte hole in the middle.
    let file = OpenOptions::new()
        .write(true)
        .open(&f)
        .map_err(|e| format!("{:?}", e.kind()))?;
    let rc = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            16,
            16,
        )
    };
    if rc != 0 {
        return Err(ioerr());
    }
    // Allocate to extend.
    let rc = unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, 128) };
    if rc != 0 {
        return Err(ioerr());
    }
    drop(file);
    let data = fs::read(&f).map_err(|e| format!("{:?}", e.kind()))?;
    let hole_zero = data[16..32].iter().all(|&b| b == 0);
    let head_ok = data[..16].iter().all(|&b| b == 1);
    Ok(format!(
        "len={} hole_zero={hole_zero} head_ok={head_ok}",
        data.len()
    ))
}

fn s_copy_file_range(orfs_root: &Path) -> Outcome {
    let d = scratch(orfs_root, "s_cfr");
    let src = d.join("src");
    let dst = d.join("dst");
    fs::write(&src, b"0123456789").map_err(|e| format!("{:?}", e.kind()))?;
    fs::write(&dst, b"..........").map_err(|e| format!("{:?}", e.kind()))?;
    let sf = File::open(&src).map_err(|e| format!("{:?}", e.kind()))?;
    let df = OpenOptions::new()
        .write(true)
        .open(&dst)
        .map_err(|e| format!("{:?}", e.kind()))?;
    let mut off_in: libc::off64_t = 2;
    let mut off_out: libc::off64_t = 4;
    let n = unsafe {
        libc::copy_file_range(
            sf.as_raw_fd(),
            &mut off_in,
            df.as_raw_fd(),
            &mut off_out,
            4,
            0,
        )
    };
    if n < 0 {
        return Err(ioerr());
    }
    drop(sf);
    drop(df);
    let got = fs::read(&dst).map_err(|e| format!("{:?}", e.kind()))?;
    Ok(format!(
        "copied={n} dst={:?}",
        String::from_utf8_lossy(&got)
    ))
}

// ---------------------------------------------------------------------------
// xattr / statvfs / lseek helpers (libc)
// ---------------------------------------------------------------------------

fn cpath(p: &Path) -> Result<CString, String> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| "path has NUL".to_string())
}

fn setxattr(path: &Path, name: &str, value: &[u8]) -> Result<(), String> {
    let p = cpath(path)?;
    let n = CString::new(name).unwrap();
    // SAFETY: `p`/`n` are valid NUL-terminated strings and `value` is a valid
    // buffer of `value.len()` bytes for the duration of the call.
    let rc = unsafe {
        libc::setxattr(
            p.as_ptr(),
            n.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(ioerr())
    }
}

fn getxattr(path: &Path, name: &str) -> Result<String, String> {
    let p = cpath(path)?;
    let n = CString::new(name).unwrap();
    // SAFETY: querying the size with a null buffer is the documented protocol.
    let size = unsafe { libc::getxattr(p.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(ioerr());
    }
    let mut buf = vec![0u8; size as usize];
    // SAFETY: `buf` has room for `size` bytes as reported above.
    let got = unsafe {
        libc::getxattr(
            p.as_ptr(),
            n.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if got < 0 {
        return Err(ioerr());
    }
    buf.truncate(got as usize);
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn listxattr(path: &Path) -> Result<Vec<u8>, String> {
    let p = cpath(path)?;
    let size = unsafe { libc::listxattr(p.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(ioerr());
    }
    let mut buf = vec![0u8; size as usize];
    let got =
        unsafe { libc::listxattr(p.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if got < 0 {
        return Err(ioerr());
    }
    buf.truncate(got as usize);
    Ok(buf)
}

fn removexattr(path: &Path, name: &str) -> Result<(), String> {
    let p = cpath(path)?;
    let n = CString::new(name).unwrap();
    let rc = unsafe { libc::removexattr(p.as_ptr(), n.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(ioerr())
    }
}

fn lseek(fd: i32, offset: i64, whence: i32) -> Result<i64, String> {
    let rc = unsafe { libc::lseek(fd, offset, whence) };
    if rc < 0 {
        Err(ioerr())
    } else {
        Ok(rc)
    }
}

/// `(f_blocks, f_bfree, f_bsize)`.
fn statvfs(path: &Path) -> Result<(u64, u64, u64), String> {
    let p = cpath(path)?;
    // SAFETY: `p` is a valid path and `st` is a valid, owned buffer.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(p.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(ioerr());
    }
    Ok((st.f_blocks, st.f_bfree, st.f_bsize))
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_scratch(prefix: &str) -> PathBuf {
    let base = manifest_dir().join("target").join("fuse-it");
    fs::create_dir_all(&base).expect("create fuse-it base");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = base.join(format!("{prefix}-{pid}-{nanos}"));
    fs::create_dir_all(&dir).expect("create scratch");
    dir
}

fn run_all(rec: &mut Recorder, orfs_root: &Path, ref_root: &Path) {
    rec.compare(
        "create_write_read",
        orfs_root,
        ref_root,
        s_create_write_read,
    );
    rec.compare("mkdir_readdir", orfs_root, ref_root, s_mkdir_readdir);
    rec.compare("append_and_seek", orfs_root, ref_root, s_append_and_seek);
    rec.compare("sparse", orfs_root, ref_root, s_sparse);
    rec.compare("truncate", orfs_root, ref_root, s_truncate);
    rec.compare("rename", orfs_root, ref_root, s_rename);
    rec.compare("hardlink", orfs_root, ref_root, s_hardlink);
    rec.compare("symlink", orfs_root, ref_root, s_symlink);
    rec.compare(
        "unlink_while_open",
        orfs_root,
        ref_root,
        s_unlink_while_open,
    );
    rec.compare("xattr", orfs_root, ref_root, s_xattr);
    rec.compare("fsync", orfs_root, ref_root, s_fsync);
    rec.compare("statfs", orfs_root, ref_root, s_statfs);
    rec.compare("rmdir_nonempty", orfs_root, ref_root, s_rmdir_nonempty);
    rec.compare("unlink_dir", orfs_root, ref_root, s_unlink_dir);
    rec.compare("perm_mode", orfs_root, ref_root, s_perm_mode);

    // Semantic-only checks on the OrFS mount.
    let seek = s_seek_data_hole(orfs_root);
    let ok = matches!(&seek, Ok(s) if s.contains("data0=0 ") && s.contains("data1=50 ") && s.contains("hole_end=51 "));
    rec.assert_semantic(
        "seek_data_hole",
        "data0=0 data1=50 hole_end=51",
        &fmt_outcome(&seek),
        ok,
    );

    let fall = s_fallocate(orfs_root);
    let ok = matches!(&fall, Ok(s) if s.contains("hole_zero=true") && s.contains("head_ok=true"));
    rec.assert_semantic(
        "fallocate",
        "hole_zero=true head_ok=true",
        &fmt_outcome(&fall),
        ok,
    );

    let cfr = s_copy_file_range(orfs_root);
    let ok = matches!(&cfr, Ok(s) if s.contains("copied=4") && s.contains("dst=\"....2345..\""));
    rec.assert_semantic(
        "copy_file_range",
        "copied=4 dst=....2345..",
        &fmt_outcome(&cfr),
        ok,
    );
}

fn write_evidence(rec: &Recorder, mountpoint: &Path) -> std::io::Result<()> {
    let total = rec.checks.len();
    let passed = rec.checks.iter().filter(|c| c.matched).count();
    let doc = serde_json::json!({
        "generated_by": "tests/fuse_integration.rs",
        "mounted": true,
        "mountpoint": mountpoint.display().to_string(),
        "transport": "fuse (traditional /dev/fuse)",
        "cache_profile": "write-through",
        "operations": rec.checks,
        "summary": { "total": total, "passed": passed, "failed": total - passed },
        "posix33_coverage": {
            "note": "research/OrFS prompt.md §33 lists a POSIX operation set as a *tested target*. \
                     Full POSIX compatibility is not claimed until every listed operation passes an \
                     applicable test. This table records what the court actually exercises today.",
            "covered": [
                "create", "open", "read", "write", "append", "truncate",
                "fallocate", "rename", "unlink", "link", "symlink", "mkdir",
                "rmdir", "stat", "chmod", "xattr", "readdir", "fsync",
                "SEEK_DATA", "SEEK_HOLE",
            ],
            "not_yet_covered": [
                "pwrite (exercised indirectly via append_and_seek; not a dedicated case)",
                "chown (owner is set at setup via setattr; not a compared case)",
                "utimens (mtime update is exercised indirectly; not a compared case)",
                "fdatasync (fsync is covered; fdatasync is not separately asserted)",
                "mmap (not exercised by this court)",
            ],
            "delegated_to_kernel": [
                "POSIX record locks (fcntl F_SETLK/F_GETLK) return ENOSYS and are delegated to the \
                 kernel; see docs/FUSE-SEMANTICS.md",
                "flock (delegated to the kernel)",
            ],
        },
        "notes": [
            "readdirplus is negotiated (FUSE_DO_READDIRPLUS) and exercised by ordinary readdir(3) calls",
            "POSIX record locks and flock are delegated to the kernel (ENOSYS); see docs/FUSE-SEMANTICS.md",
            "SEEK_DATA/SEEK_HOLE and fallocate are byte-granular on OrFS, so they are asserted semantically rather than compared to the reference filesystem",
        ],
    });
    let path = manifest_dir().join("evidence/correctness/posix-results.json");
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let mut s = serde_json::to_string_pretty(&doc)?;
    s.push('\n');
    fs::write(&path, s)
}

#[test]
fn fuse_posix_conformance() {
    let required = std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1");

    let scratch = unique_scratch("it");
    let backing = scratch.join("backing");
    let mnt = scratch.join("mnt");
    let ref_root = scratch.join("reference");
    fs::create_dir_all(&mnt).expect("mnt");
    fs::create_dir_all(&ref_root).expect("reference");

    // Create the volume and give its root to the mounting user so that the
    // daemon's own permission checks admit us.
    {
        let mut ns = match Namespace::init(&backing, DEFAULT_SEGMENT_SIZE, DurabilityMode::Ordered)
        {
            Ok(ns) => ns,
            Err(e) => {
                if required {
                    panic!("failed to initialise backing volume: {e}");
                }
                eprintln!("fuse_integration: skipped (init failed: {e})");
                return;
            }
        };
        // SAFETY: `geteuid`/`getegid` are pure queries.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let attrs = SetAttr {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        };
        ns.setattr(orfs::index::ROOT_INODE, &attrs)
            .expect("chown root inode");
        ns.sync().expect("sync");
    }

    let opts = MountOptions {
        durability: DurabilityMode::Ordered,
        statfs: StatfsMode::PhysicalSafe,
        ..Default::default()
    };

    let mount = match fuse::spawn(&backing, &mnt, &opts) {
        Ok(m) => m,
        Err(e) => {
            if required {
                panic!("FUSE mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            eprintln!("fuse_integration: skipped — FUSE mount unavailable: {e}");
            return;
        }
    };

    let mut rec = Recorder::default();
    run_all(&mut rec, &mnt, &ref_root);

    write_evidence(&rec, &mnt).expect("write evidence");

    // Unmount cleanly; a failure here is a real error.
    let result = mount.unmount();
    let _ = fs::remove_dir_all(&scratch);
    result.expect("unmount");
}

/// Phase 8: a mounted read is served by the measured EKBLOOM read planner when a
/// compatible certified structure exists, and the visible contents are identical
/// with or without it.
#[test]
fn fuse_manifested_reads_match_visible_contents() {
    let required = std::env::var("ORFS_FUSE_TEST").as_deref() == Ok("1");

    let scratch = unique_scratch("manifest-it");
    let backing = scratch.join("backing");
    let mnt = scratch.join("mnt");
    fs::create_dir_all(&mnt).expect("mnt");

    // SAFETY: `geteuid`/`getegid` are pure queries.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    {
        let mut ns = match Namespace::init(&backing, DEFAULT_SEGMENT_SIZE, DurabilityMode::Ordered)
        {
            Ok(ns) => ns,
            Err(e) => {
                if required {
                    panic!("failed to initialise backing volume: {e}");
                }
                eprintln!("fuse_manifested: skipped (init failed: {e})");
                return;
            }
        };
        ns.setattr(
            orfs::index::ROOT_INODE,
            &SetAttr {
                uid: Some(uid),
                gid: Some(gid),
                ..Default::default()
            },
        )
        .expect("chown root inode");
        ns.sync().expect("sync");
    }

    let opts = MountOptions {
        durability: DurabilityMode::Ordered,
        statfs: StatfsMode::PhysicalSafe,
        manifest: Some(orfs::manifestation::ManifestationProfile::Path { depth: 4 }),
        manifest_sync: true,
        manifest_workers: 1,
        ..Default::default()
    };

    let mount = match fuse::spawn(&backing, &mnt, &opts) {
        Ok(m) => m,
        Err(e) => {
            if required {
                panic!("FUSE mount failed under ORFS_FUSE_TEST=1: {e}");
            }
            eprintln!("fuse_manifested: skipped — FUSE mount unavailable: {e}");
            return;
        }
    };

    // Write a file through the mount; synchronous manifestation builds a
    // concealed payload for it.
    let data: Vec<u8> = (0..20_000).map(|i| ((i * 97 + 11) % 251) as u8).collect();
    let f = mnt.join("manifested.bin");
    fs::write(&f, &data).expect("write through mount");

    // Whole-file and positional reads must return exactly the visible contents.
    let whole = fs::read(&f).expect("read back");
    assert_eq!(whole, data, "manifested read changed the visible contents");
    {
        use std::os::unix::fs::FileExt;
        let file = File::open(&f).expect("open");
        let mut buf = [0u8; 100];
        file.read_exact_at(&mut buf, 12_345).expect("pread");
        assert_eq!(&buf[..], &data[12_345..12_445]);
    }

    // A concealed EKBLOOM payload was built (a completed structure exists).
    let payload_dir = backing.join(".or_bloom").join("ekbloom");
    let count = fs::read_dir(&payload_dir)
        .map(|it| it.filter_map(Result::ok).count())
        .unwrap_or(0);
    assert!(
        count >= 1,
        "no concealed EKBLOOM payload was built for the object"
    );

    let result = mount.unmount();
    let _ = fs::remove_dir_all(&scratch);
    result.expect("unmount");
}
