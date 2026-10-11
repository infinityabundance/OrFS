//! Native FUSE-over-`io_uring` (profile **F2**) session that owns the
//! `/dev/fuse` descriptor (research §17 Domain B, §18 F2; directive Phase 15).
//!
//! The classical transport ([`crate::fuse`]) delegates the whole session to the
//! `fuser` crate, which owns the `/dev/fuse` fd and performs the `mount(2)`.
//! `fuser` 0.18 does not expose that fd, so a FUSE-over-`io_uring` ring cannot be
//! attached to a `fuser`-managed mount. This module therefore owns *everything*
//! for the F2 path, and only for the F2 path:
//!
//! 1. opens `/dev/fuse`;
//! 2. performs the `mount(2)` itself (`type=fuse`, `fd=N`);
//! 3. reads the kernel's `FUSE_INIT` request over the classical channel and
//!    replies with `FUSE_OVER_IO_URING` advertised (`flags2`), which is what makes
//!    the kernel hand future requests to an `io_uring` queue;
//! 4. creates an `IORING_SETUP_SQE128` ring bound to the same fd and registers
//!    one entry per CPU queue (`FUSE_IO_URING_CMD_REGISTER`, `sqe->len == 2`);
//! 5. drives the `COMMIT_AND_FETCH` lifecycle, decoding each request from the
//!    registered header/payload buffers and writing the reply back into them;
//! 6. keeps a classical `/dev/fuse` reader for the messages the kernel still
//!    delivers that way — `FORGET`/`BATCH_FORGET` and `INTERRUPT`
//!    (`fs/fuse/dev_uring.c`: `send_forget`/`send_interrupt` remain classical).
//!
//! It reuses the *same* transport-neutral [`OrfsFuse`](crate::fuse::OrfsFuse)
//! adaptor and handle/lookup bookkeeping as the classical path, so F2 and
//! F0/F1 cannot diverge in filesystem semantics: only the way bytes travel
//! differs. If anything prevents F2 from engaging, [`prepare`] returns `Err`
//! with the exact reason and the caller falls back to the classical transport
//! without touching filesystem contents.
//!
//! ## Verified against the running kernel
//!
//! The ABI here is transcribed from this host's kernel source
//! (`fs/fuse/dev_uring.c`, `include/uapi/linux/fuse.h`, FUSE ABI 7.45), which
//! exposes the **baseline** ring interface only: `FUSE_IO_URING_CMD_REGISTER`
//! (1) and `FUSE_IO_URING_CMD_COMMIT_AND_FETCH` (2). There is no `ADD_QUEUE` /
//! `ADD_BUFPOOL` / buffer-pool `offset` on this kernel; queues are created
//! lazily on the first `REGISTER` for each `qid` in `[0, num_possible_cpus())`
//! (`fuse_uring_register` → `fuse_uring_create_queue`) and a queue is only
//! "ready" once *every* queue has at least one registered entry
//! (`is_ring_ready`).

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use crate::buffers::AlignedBuffer;
use crate::error::OrfsError;
use crate::fuse::{MountOptions, OrfsFuse, StatfsMode, Transport};
use crate::fuse_uring::{FuseUringNegotiation, FuseUringRing, RingCompletion};
use crate::inode::{has_permission, InodeStat, InodeType, Timespec};
use crate::namespace::{CoreRead, OrfsCore, RenameMode, SetAttr};

// ---------------------------------------------------------------------------
// UAPI: opcodes and constants (uapi/linux/fuse.h, ABI 7.45)
// ---------------------------------------------------------------------------

const FUSE_LOOKUP: u32 = 1;
const FUSE_FORGET: u32 = 2;
const FUSE_GETATTR: u32 = 3;
const FUSE_SETATTR: u32 = 4;
const FUSE_READLINK: u32 = 5;
const FUSE_SYMLINK: u32 = 6;
const FUSE_MKNOD: u32 = 8;
const FUSE_MKDIR: u32 = 9;
const FUSE_UNLINK: u32 = 10;
const FUSE_RMDIR: u32 = 11;
const FUSE_RENAME: u32 = 12;
const FUSE_RENAME2: u32 = 45;
const FUSE_LINK: u32 = 13;
const FUSE_OPEN: u32 = 14;
const FUSE_READ: u32 = 15;
const FUSE_WRITE: u32 = 16;
const FUSE_STATFS: u32 = 17;
const FUSE_RELEASE: u32 = 18;
const FUSE_FSYNC: u32 = 20;
const FUSE_FLUSH: u32 = 25;
const FUSE_INIT: u32 = 26;
const FUSE_OPENDIR: u32 = 27;
const FUSE_READDIR: u32 = 28;
const FUSE_RELEASEDIR: u32 = 29;
const FUSE_FSYNCDIR: u32 = 30;
const FUSE_ACCESS: u32 = 34;
const FUSE_CREATE: u32 = 35;
const FUSE_INTERRUPT: u32 = 36;
const FUSE_DESTROY: u32 = 38;
const FUSE_BATCH_FORGET: u32 = 42;

/// `FUSE_ROOT_ID`.
const FUSE_ROOT_ID: u64 = 1;

// `fuse_init_out.flags` / `flags2`.
const FUSE_ASYNC_READ: u32 = 1 << 0;
const FUSE_BIG_WRITES: u32 = 1 << 5;
const FUSE_INIT_EXT: u32 = 1 << 30;
/// `FUSE_OVER_IO_URING = 1 << 41` → `flags2` bit 9.
const FUSE_OVER_IO_URING_FLAGS2: u32 = 1 << (41 - 32);

// `fuse_open_out.open_flags`.
const FOPEN_DIRECT_IO: u32 = 1 << 0;
const FOPEN_CACHE_DIR: u32 = 1 << 3;

// `fuse_setattr_in.valid`.
const FATTR_MODE: u32 = 1 << 0;
const FATTR_UID: u32 = 1 << 1;
const FATTR_GID: u32 = 1 << 2;
const FATTR_SIZE: u32 = 1 << 3;
const FATTR_ATIME: u32 = 1 << 4;
const FATTR_MTIME: u32 = 1 << 5;
const FATTR_ATIME_NOW: u32 = 1 << 7;
const FATTR_MTIME_NOW: u32 = 1 << 8;

// `d_type` values.
const DT_DIR: u32 = 4;
const DT_REG: u32 = 8;
const DT_LNK: u32 = 10;

/// Size of each entry's `fuse_uring_req_header` buffer (`>= 288`).
const HEADER_BUF: usize = 4096;
/// Must be `>= ring->max_payload_sz = max(FUSE_MIN_READ_BUFFER, fc->max_write,
/// fc->max_pages * PAGE_SIZE)`. With `max_write` advertised as 128 KiB and an
/// un-negotiated `max_pages` of 32 (`FUSE_DEFAULT_MAX_PAGES_PER_REQ`), that is
/// 128 KiB; we reserve double.
const PAYLOAD_BUF: usize = 256 * 1024;

/// `max_write` advertised in the `INIT` reply (keeps `max_payload_sz` bounded).
const MAX_WRITE: u32 = 128 * 1024;
/// Readahead advertised in the `INIT` reply.
const MAX_READAHEAD: u32 = 128 * 1024;

const IO_URING_DEPTH: u32 = 64;

// ---------------------------------------------------------------------------
// Byte-exact UAPI encoding helpers
// ---------------------------------------------------------------------------

#[inline]
fn put_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_ne_bytes());
}
#[inline]
fn put_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_ne_bytes());
}
#[inline]
fn put_u64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_ne_bytes());
}
#[inline]
fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
}
#[inline]
fn get_u64(b: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(b[off..off + 8].try_into().unwrap())
}

/// The `struct fuse_attr` (88 bytes) we report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Attr {
    ino: u64,
    size: u64,
    blocks: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    atimensec: u32,
    mtimensec: u32,
    ctimensec: u32,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    blksize: u32,
    flags: u32,
}

fn kind_bits(kind: InodeType) -> u32 {
    match kind {
        InodeType::File => libc::S_IFREG,
        InodeType::Directory => libc::S_IFDIR,
        InodeType::Symlink => libc::S_IFLNK,
    }
}

fn attr_from_stat(st: &InodeStat) -> Attr {
    Attr {
        ino: st.id,
        size: st.size,
        blocks: st.blocks,
        atime: st.atime.secs.max(0) as u64,
        mtime: st.mtime.secs.max(0) as u64,
        ctime: st.ctime.secs.max(0) as u64,
        atimensec: st.atime.nanos.min(999_999_999),
        mtimensec: st.mtime.nanos.min(999_999_999),
        ctimensec: st.ctime.nanos.min(999_999_999),
        mode: kind_bits(st.kind) | (st.mode & 0o7777),
        nlink: st.nlink.max(1),
        uid: st.uid,
        gid: st.gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

fn write_attr(v: &mut Vec<u8>, a: &Attr) {
    put_u64(v, a.ino);
    put_u64(v, a.size);
    put_u64(v, a.blocks);
    put_u64(v, a.atime);
    put_u64(v, a.mtime);
    put_u64(v, a.ctime);
    put_u32(v, a.atimensec);
    put_u32(v, a.mtimensec);
    put_u32(v, a.ctimensec);
    put_u32(v, a.mode);
    put_u32(v, a.nlink);
    put_u32(v, a.uid);
    put_u32(v, a.gid);
    put_u32(v, a.rdev);
    put_u32(v, a.blksize);
    put_u32(v, a.flags);
}

fn encode_entry_out(a: &Attr, entry_ttl: Duration, attr_ttl: Duration) -> Vec<u8> {
    let mut v = Vec::with_capacity(128);
    put_u64(&mut v, a.ino); // nodeid
    put_u64(&mut v, 1); // generation (GENERATION)
    put_u64(&mut v, entry_ttl.as_secs()); // entry_valid
    put_u64(&mut v, attr_ttl.as_secs()); // attr_valid
    put_u32(&mut v, entry_ttl.subsec_nanos()); // entry_valid_nsec
    put_u32(&mut v, attr_ttl.subsec_nanos()); // attr_valid_nsec
    write_attr(&mut v, a);
    debug_assert_eq!(v.len(), 128);
    v
}

fn encode_attr_out(a: &Attr, attr_ttl: Duration) -> Vec<u8> {
    let mut v = Vec::with_capacity(104);
    put_u64(&mut v, attr_ttl.as_secs());
    put_u32(&mut v, attr_ttl.subsec_nanos());
    put_u32(&mut v, 0); // dummy
    write_attr(&mut v, a);
    debug_assert_eq!(v.len(), 104);
    v
}

fn encode_open_out(fh: u64, open_flags: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    put_u64(&mut v, fh);
    put_u32(&mut v, open_flags);
    put_u32(&mut v, 0); // backing_id
    debug_assert_eq!(v.len(), 16);
    v
}

fn encode_write_out(n: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    put_u32(&mut v, n);
    put_u32(&mut v, 0);
    v
}

#[allow(clippy::too_many_arguments)]
fn encode_statfs(
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    bsize: u32,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(80);
    put_u64(&mut v, blocks);
    put_u64(&mut v, bfree);
    put_u64(&mut v, bavail);
    put_u64(&mut v, files);
    put_u64(&mut v, ffree);
    put_u32(&mut v, bsize); // bsize
    put_u32(&mut v, 255); // namelen
    put_u32(&mut v, bsize); // frsize
    put_u32(&mut v, 0); // padding
    for _ in 0..6 {
        put_u32(&mut v, 0); // spare[6]
    }
    debug_assert_eq!(v.len(), 80);
    v
}

// ---------------------------------------------------------------------------
// Dispatch: raw FUSE request -> transport-neutral reply
// ---------------------------------------------------------------------------

/// A parsed request as delivered by either transport.
struct Req<'a> {
    unique: u64,
    opcode: u32,
    nodeid: u64,
    uid: u32,
    gid: u32,
    commit_id: u64,
    /// The per-opcode input header (`op_in`, 128 bytes).
    op: &'a [u8],
    /// The variable-length request payload.
    payload: &'a [u8],
}

/// A transport-neutral reply, encoded to `fuse_out_header` + payload by
/// [`Reply::encode`]. Mirrors exactly what the classical adaptor sends.
enum Reply {
    Empty,
    Err(i32),
    Data(Vec<u8>),
    Entry(Attr),
    Attr(Attr),
    Open {
        fh: u64,
        open_flags: u32,
    },
    Write(u32),
    Create {
        attr: Attr,
        fh: u64,
        open_flags: u32,
    },
    Dir(Vec<u8>),
    Statfs {
        blocks: u64,
        bfree: u64,
        bavail: u64,
        files: u64,
        ffree: u64,
        bsize: u32,
    },
}

impl Reply {
    fn encode(self, entry_ttl: Duration, attr_ttl: Duration) -> (i32, Vec<u8>) {
        match self {
            Reply::Empty => (0, Vec::new()),
            Reply::Err(e) => (e, Vec::new()),
            Reply::Data(d) => (0, d),
            Reply::Entry(a) => (0, encode_entry_out(&a, entry_ttl, attr_ttl)),
            Reply::Attr(a) => (0, encode_attr_out(&a, attr_ttl)),
            Reply::Open { fh, open_flags } => (0, encode_open_out(fh, open_flags)),
            Reply::Write(n) => (0, encode_write_out(n)),
            Reply::Create {
                attr,
                fh,
                open_flags,
            } => {
                let mut v = encode_entry_out(&attr, entry_ttl, attr_ttl);
                v.extend_from_slice(&encode_open_out(fh, open_flags));
                (0, v)
            }
            Reply::Dir(d) => (0, d),
            Reply::Statfs {
                blocks,
                bfree,
                bavail,
                files,
                ffree,
                bsize,
            } => (0, encode_statfs(blocks, bfree, bavail, files, ffree, bsize)),
        }
    }
}

fn errno(e: &OrfsError) -> i32 {
    e.errno()
}

fn trim_name(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(i) => &bytes[..i],
        None => bytes,
    }
}

fn split_two(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let mid = bytes.iter().position(|&b| b == 0)?;
    let first = &bytes[..mid];
    let rest = &bytes[mid + 1..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    Some((first, &rest[..end]))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn fuse_kind_code(kind: fuser::FileType) -> u32 {
    match kind {
        fuser::FileType::Directory => DT_DIR,
        fuser::FileType::Symlink => DT_LNK,
        _ => DT_REG,
    }
}

fn statvfs(path: &Path) -> Option<(u64, u64, u64, u64, u64, u32)> {
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c` is a valid NUL-terminated path; `st` is a valid, aligned,
    // fully-owned buffer that `statvfs` initialises. No pointer is retained.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return None;
    }
    Some((
        st.f_blocks as u64,
        st.f_bfree as u64,
        st.f_bavail as u64,
        st.f_files as u64,
        st.f_ffree as u64,
        if st.f_bsize == 0 {
            4096
        } else {
            st.f_bsize as u32
        },
    ))
}

/// The semantic dispatcher; it borrows the exact [`OrfsFuse`] adaptor the
/// classical transport uses, so semantics cannot drift between profiles.
struct Dispatcher<C: OrfsCore + Send + 'static> {
    fs: Arc<OrfsFuse<C>>,
    entry_ttl: Duration,
    attr_ttl: Duration,
    read_only: bool,
    direct_io: bool,
}

impl<C: OrfsCore + Send + 'static> Dispatcher<C> {
    /// Clone the current immutable read view (no core lock).
    fn read_view(&self) -> Arc<dyn CoreRead> {
        self.fs.read_view()
    }

    fn open_flags(&self) -> u32 {
        if self.direct_io {
            FOPEN_DIRECT_IO
        } else {
            0
        }
    }

    fn check_dir_write(
        &self,
        core: &C,
        uid: u32,
        gid: u32,
        parent: u64,
        mask: u32,
    ) -> Result<(), i32> {
        let st = core.getattr(parent, core.root()).map_err(|e| errno(&e))?;
        if st.kind != InodeType::Directory {
            return Err(libc::ENOTDIR);
        }
        if !has_permission(uid, gid, &st, mask) {
            return Err(libc::EACCES);
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn serve(&self, req: &Req<'_>) -> Reply {
        match req.opcode {
            FUSE_LOOKUP => self.lookup(req),
            FUSE_GETATTR => self.getattr(req),
            FUSE_SETATTR => self.setattr(req),
            FUSE_READLINK => self.readlink(req),
            FUSE_SYMLINK => self.symlink(req),
            FUSE_MKNOD => self.mknod(req),
            FUSE_MKDIR => self.mkdir(req),
            FUSE_UNLINK => self.unlink(req),
            FUSE_RMDIR => self.rmdir(req),
            FUSE_RENAME | FUSE_RENAME2 => self.rename(req),
            FUSE_LINK => self.link(req),
            FUSE_OPEN => self.open(req),
            FUSE_READ => self.read(req),
            FUSE_WRITE => self.write(req),
            FUSE_STATFS => self.statfs(),
            FUSE_RELEASE => self.release(req),
            FUSE_FLUSH => Reply::Empty,
            FUSE_FSYNC | FUSE_FSYNCDIR => self.fsync(),
            FUSE_OPENDIR => self.opendir(req),
            FUSE_READDIR => self.readdir(req),
            FUSE_RELEASEDIR => self.releasedir(req),
            FUSE_ACCESS => self.access(req),
            FUSE_CREATE => self.create(req),
            // FORGET arrives on the classical channel; handle it defensively if
            // it ever shows up here.
            FUSE_FORGET => {
                self.fs.inner.record_forget(req.nodeid, get_u64(req.op, 0));
                self.fs.inner.metrics.lock().forgets += 1;
                Reply::Empty
            }
            _ => Reply::Err(libc::ENOSYS),
        }
    }

    fn lookup(&self, req: &Req<'_>) -> Reply {
        let name = trim_name(req.payload);
        let view = self.read_view();
        let root = view.root();
        let directory = match view.getattr(req.nodeid, root) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        if directory.kind != InodeType::Directory {
            return Reply::Err(libc::ENOTDIR);
        }
        if !has_permission(req.uid, req.gid, &directory, 0o1) {
            return Reply::Err(libc::EACCES);
        }
        let resolved = if name == b"." {
            Ok(req.nodeid)
        } else if name == b".." {
            Ok(view.parent_of(req.nodeid).unwrap_or(FUSE_ROOT_ID))
        } else {
            view.lookup(req.nodeid, name, root)
        };
        let ino = match resolved {
            Ok(i) => i,
            Err(e) => return Reply::Err(errno(&e)),
        };
        let st = match view.getattr(ino, root) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        self.fs.inner.record_lookup(ino);
        self.fs.inner.metrics.lock().lookups += 1;
        Reply::Entry(attr_from_stat(&st))
    }

    fn getattr(&self, req: &Req<'_>) -> Reply {
        let view = self.read_view();
        match self.fs.inner.stat(view.as_ref(), req.nodeid) {
            Ok(st) => Reply::Attr(attr_from_stat(&st)),
            Err(e) => Reply::Err(errno(&e)),
        }
    }

    fn setattr(&self, req: &Req<'_>) -> Reply {
        if self.read_only {
            return Reply::Err(libc::EROFS);
        }
        // struct fuse_setattr_in: valid, padding, fh, size, lock_owner, atime,
        // mtime, ctime, atimensec, mtimensec, ctimensec, mode, unused4, uid,
        // gid, unused5.
        let valid = get_u32(req.op, 0);
        let size = get_u64(req.op, 16);
        let atime = get_u64(req.op, 32);
        let mtime = get_u64(req.op, 40);
        let atimensec = get_u32(req.op, 56);
        let mtimensec = get_u32(req.op, 60);
        let mode = get_u32(req.op, 68);
        let uid = get_u32(req.op, 76);
        let gid = get_u32(req.op, 80);

        let mut core = self.fs.inner.core.lock();
        let st = match core.getattr(req.nodeid, core.root()) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        let is_root = req.uid == 0;
        let owner_or_root = is_root || req.uid == st.uid;
        let meta = FATTR_MODE
            | FATTR_UID
            | FATTR_GID
            | FATTR_ATIME
            | FATTR_MTIME
            | FATTR_ATIME_NOW
            | FATTR_MTIME_NOW;
        if valid & meta != 0 && !owner_or_root {
            return Reply::Err(libc::EPERM);
        }
        let uid_changes = valid & FATTR_UID != 0 && uid != st.uid;
        let gid_changes = valid & FATTR_GID != 0 && gid != st.gid;
        if (uid_changes || gid_changes) && !is_root {
            return Reply::Err(libc::EPERM);
        }
        if valid & FATTR_SIZE != 0 && !has_permission(req.uid, req.gid, &st, 0o2) {
            return Reply::Err(libc::EACCES);
        }
        let attrs = SetAttr {
            mode: (valid & FATTR_MODE != 0).then_some(mode & 0o7777),
            uid: (valid & FATTR_UID != 0).then_some(uid),
            gid: (valid & FATTR_GID != 0).then_some(gid),
            size: (valid & FATTR_SIZE != 0).then_some(size),
            atime: if valid & FATTR_ATIME_NOW != 0 {
                Some(Timespec::new(now_secs(), 0))
            } else if valid & FATTR_ATIME != 0 {
                Some(Timespec::new(atime as i64, atimensec))
            } else {
                None
            },
            mtime: if valid & FATTR_MTIME_NOW != 0 {
                Some(Timespec::new(now_secs(), 0))
            } else if valid & FATTR_MTIME != 0 {
                Some(Timespec::new(mtime as i64, mtimensec))
            } else {
                None
            },
        };
        if let Err(e) = core.setattr(req.nodeid, &attrs) {
            return Reply::Err(errno(&e));
        }
        let updated = match core.getattr(req.nodeid, core.root()) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        drop(core);
        self.fs.inner.metrics.lock().setattr += 1;
        Reply::Attr(attr_from_stat(&updated))
    }

    fn readlink(&self, req: &Req<'_>) -> Reply {
        let view = self.read_view();
        let root = view.root();
        match view.readlink(req.nodeid, root) {
            Ok(target) => Reply::Data(target),
            Err(e) => Reply::Err(errno(&e)),
        }
    }

    fn symlink(&self, req: &Req<'_>) -> Reply {
        if self.read_only {
            return Reply::Err(libc::EROFS);
        }
        let (name, target) = match split_two(req.payload) {
            Some(v) => v,
            None => return Reply::Err(libc::EINVAL),
        };
        let mut core = self.fs.inner.core.lock();
        if let Err(e) = self.check_dir_write(&*core, req.uid, req.gid, req.nodeid, 0o3) {
            return Reply::Err(e);
        }
        let ino = match core.symlink(req.nodeid, name, target, req.uid, req.gid) {
            Ok(i) => i,
            Err(e) => return Reply::Err(errno(&e)),
        };
        let st = match core.getattr(ino, core.root()) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        drop(core);
        self.fs.inner.metrics.lock().symlink += 1;
        self.fs.inner.record_lookup(ino);
        Reply::Entry(attr_from_stat(&st))
    }

    fn mknod(&self, req: &Req<'_>) -> Reply {
        if self.read_only {
            return Reply::Err(libc::EROFS);
        }
        let mode = get_u32(req.op, 0);
        let fmt = mode & libc::S_IFMT;
        if fmt != 0 && fmt != libc::S_IFREG {
            return Reply::Err(libc::EOPNOTSUPP);
        }
        let name = trim_name(req.payload);
        let mut core = self.fs.inner.core.lock();
        if let Err(e) = self.check_dir_write(&*core, req.uid, req.gid, req.nodeid, 0o3) {
            return Reply::Err(e);
        }
        let ino = match core.create(req.nodeid, name, mode & 0o7777, req.uid, req.gid) {
            Ok(i) => i,
            Err(e) => return Reply::Err(errno(&e)),
        };
        let st = match core.getattr(ino, core.root()) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        drop(core);
        self.fs.inner.metrics.lock().create += 1;
        self.fs.inner.record_lookup(ino);
        Reply::Entry(attr_from_stat(&st))
    }

    fn mkdir(&self, req: &Req<'_>) -> Reply {
        if self.read_only {
            return Reply::Err(libc::EROFS);
        }
        let mode = get_u32(req.op, 0);
        let name = trim_name(req.payload);
        let mut core = self.fs.inner.core.lock();
        if let Err(e) = self.check_dir_write(&*core, req.uid, req.gid, req.nodeid, 0o3) {
            return Reply::Err(e);
        }
        let ino = match core.mkdir(req.nodeid, name, mode & 0o7777, req.uid, req.gid) {
            Ok(i) => i,
            Err(e) => return Reply::Err(errno(&e)),
        };
        let st = match core.getattr(ino, core.root()) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        drop(core);
        self.fs.inner.metrics.lock().mkdir += 1;
        self.fs.inner.record_lookup(ino);
        Reply::Entry(attr_from_stat(&st))
    }

    fn unlink(&self, req: &Req<'_>) -> Reply {
        if self.read_only {
            return Reply::Err(libc::EROFS);
        }
        let name = trim_name(req.payload);
        let mut core = self.fs.inner.core.lock();
        if let Err(e) = self.check_dir_write(&*core, req.uid, req.gid, req.nodeid, 0o3) {
            return Reply::Err(e);
        }
        match core.unlink(req.nodeid, name) {
            Ok(()) => {
                drop(core);
                self.fs.inner.metrics.lock().unlink += 1;
                Reply::Empty
            }
            Err(e) => Reply::Err(errno(&e)),
        }
    }

    fn rmdir(&self, req: &Req<'_>) -> Reply {
        if self.read_only {
            return Reply::Err(libc::EROFS);
        }
        let name = trim_name(req.payload);
        let mut core = self.fs.inner.core.lock();
        if let Err(e) = self.check_dir_write(&*core, req.uid, req.gid, req.nodeid, 0o3) {
            return Reply::Err(e);
        }
        match core.rmdir(req.nodeid, name) {
            Ok(()) => {
                drop(core);
                self.fs.inner.metrics.lock().rmdir += 1;
                Reply::Empty
            }
            Err(e) => Reply::Err(errno(&e)),
        }
    }

    fn rename(&self, req: &Req<'_>) -> Reply {
        if self.read_only {
            return Reply::Err(libc::EROFS);
        }
        let newdir = get_u64(req.op, 0);
        // Only `RENAME2` carries a flags field (`fuse_rename2_in`); plain
        // `RENAME` is just `fuse_rename_in { newdir }` and the per-op header is
        // NOT zeroed between requests, so reading past the struct would pick up
        // stale bytes from a previous request.
        let flags = if req.opcode == FUSE_RENAME2 {
            get_u32(req.op, 8)
        } else {
            0
        };
        let mode = if flags == 0 {
            RenameMode::Ordinary
        } else if flags == libc::RENAME_NOREPLACE {
            RenameMode::NoReplace
        } else if flags == libc::RENAME_EXCHANGE {
            RenameMode::Exchange
        } else if flags & libc::RENAME_WHITEOUT != 0 {
            return Reply::Err(libc::EOPNOTSUPP);
        } else {
            return Reply::Err(libc::EINVAL);
        };
        let (oldname, newname) = match split_two(req.payload) {
            Some(v) => v,
            None => return Reply::Err(libc::EINVAL),
        };
        let mut core = self.fs.inner.core.lock();
        if let Err(e) = self.check_dir_write(&*core, req.uid, req.gid, req.nodeid, 0o3) {
            return Reply::Err(e);
        }
        if let Err(e) = self.check_dir_write(&*core, req.uid, req.gid, newdir, 0o3) {
            return Reply::Err(e);
        }
        match core.rename(req.nodeid, oldname, newdir, newname, mode) {
            Ok(()) => {
                drop(core);
                self.fs.inner.metrics.lock().rename += 1;
                Reply::Empty
            }
            Err(e) => Reply::Err(errno(&e)),
        }
    }

    fn link(&self, req: &Req<'_>) -> Reply {
        if self.read_only {
            return Reply::Err(libc::EROFS);
        }
        let oldino = get_u64(req.op, 0);
        let newname = trim_name(req.payload);
        let mut core = self.fs.inner.core.lock();
        if let Err(e) = self.check_dir_write(&*core, req.uid, req.gid, req.nodeid, 0o3) {
            return Reply::Err(e);
        }
        if let Err(e) = core.link(oldino, req.nodeid, newname) {
            return Reply::Err(errno(&e));
        }
        let st = match core.getattr(oldino, core.root()) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        drop(core);
        self.fs.inner.metrics.lock().link += 1;
        self.fs.inner.record_lookup(oldino);
        Reply::Entry(attr_from_stat(&st))
    }

    fn open(&self, req: &Req<'_>) -> Reply {
        let flags = get_u32(req.op, 0) as i32;
        let mut core = self.fs.inner.core.lock();
        let root = core.root();
        let st = match core.getattr(req.nodeid, root) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        if st.kind == InodeType::Directory {
            return Reply::Err(libc::EISDIR);
        }
        let mask = match flags & libc::O_ACCMODE {
            libc::O_WRONLY => 0o2,
            libc::O_RDWR => 0o6,
            _ => 0o4,
        };
        if !has_permission(req.uid, req.gid, &st, mask) {
            return Reply::Err(libc::EACCES);
        }
        if self.read_only && mask & 0o2 != 0 {
            return Reply::Err(libc::EROFS);
        }
        if flags & libc::O_TRUNC != 0 && mask & 0o2 != 0 {
            let attrs = SetAttr {
                size: Some(0),
                ..Default::default()
            };
            if let Err(e) = core.setattr(req.nodeid, &attrs) {
                return Reply::Err(errno(&e));
            }
        }
        drop(core);
        let fh = self.fs.inner.register_file(req.nodeid, flags);
        let mut m = self.fs.inner.metrics.lock();
        m.opens += 1;
        m.open_handles += 1;
        drop(m);
        Reply::Open {
            fh,
            open_flags: self.open_flags(),
        }
    }

    fn read(&self, req: &Req<'_>) -> Reply {
        let fh = get_u64(req.op, 0);
        let offset = get_u64(req.op, 8);
        let size = get_u32(req.op, 16);
        match self.fs.inner.handle(fh) {
            Some(h) if !h.is_dir => {}
            _ => return Reply::Err(libc::EBADF),
        }
        let view = self.read_view();
        let root = view.root();
        let st = match view.getattr(req.nodeid, root) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        if !has_permission(req.uid, req.gid, &st, 0o4) {
            return Reply::Err(libc::EACCES);
        }
        match view.read_at(req.nodeid, root, offset, size) {
            Ok(data) => {
                let mut m = self.fs.inner.metrics.lock();
                m.reads += 1;
                m.byte_reads += data.len() as u64;
                drop(m);
                Reply::Data(data)
            }
            Err(e) => Reply::Err(errno(&e)),
        }
    }

    fn write(&self, req: &Req<'_>) -> Reply {
        if self.read_only {
            return Reply::Err(libc::EROFS);
        }
        let fh = get_u64(req.op, 0);
        let offset = get_u64(req.op, 8);
        let size = get_u32(req.op, 16) as usize;
        let handle = match self.fs.inner.handle(fh) {
            Some(h) if !h.is_dir => h,
            _ => return Reply::Err(libc::EBADF),
        };
        let data = &req.payload[..size.min(req.payload.len())];
        let mut core = self.fs.inner.core.lock();
        let root = core.root();
        let st = match core.getattr(req.nodeid, root) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        if !has_permission(req.uid, req.gid, &st, 0o2) {
            return Reply::Err(libc::EACCES);
        }
        let effective = if handle.flags & libc::O_APPEND != 0 {
            st.size
        } else {
            offset
        };
        match core.write_at(req.nodeid, effective, data) {
            Ok(n) => {
                drop(core);
                let mut m = self.fs.inner.metrics.lock();
                m.writes += 1;
                m.byte_writes += n as u64;
                drop(m);
                Reply::Write(n)
            }
            Err(e) => Reply::Err(errno(&e)),
        }
    }

    fn fsync(&self) -> Reply {
        let mut core = self.fs.inner.core.lock();
        match core.sync() {
            Ok(()) => {
                drop(core);
                self.fs.inner.metrics.lock().fsyncs += 1;
                Reply::Empty
            }
            Err(e) => Reply::Err(errno(&e)),
        }
    }

    fn release(&self, req: &Req<'_>) -> Reply {
        let fh = get_u64(req.op, 0);
        let removed = self.fs.inner.remove_handle(fh);
        let mut m = self.fs.inner.metrics.lock();
        m.releases += 1;
        if removed.is_some() {
            m.open_handles = m.open_handles.saturating_sub(1);
        }
        drop(m);
        Reply::Empty
    }

    fn opendir(&self, req: &Req<'_>) -> Reply {
        let view = self.read_view();
        let root = view.root();
        let st = match view.getattr(req.nodeid, root) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        if st.kind != InodeType::Directory {
            return Reply::Err(libc::ENOTDIR);
        }
        if !has_permission(req.uid, req.gid, &st, 0o5) {
            return Reply::Err(libc::EACCES);
        }
        let listing = match self.fs.inner.build_dir_listing(view.as_ref(), req.nodeid) {
            Ok(l) => l,
            Err(e) => return Reply::Err(errno(&e)),
        };
        let fh = self.fs.inner.register_dir(req.nodeid, listing);
        let mut m = self.fs.inner.metrics.lock();
        m.opendirs += 1;
        m.open_handles += 1;
        drop(m);
        Reply::Open {
            fh,
            open_flags: FOPEN_CACHE_DIR,
        }
    }

    fn readdir(&self, req: &Req<'_>) -> Reply {
        let fh = get_u64(req.op, 0);
        let offset = get_u64(req.op, 8) as usize;
        let size = get_u32(req.op, 16) as usize;
        let handle = match self.fs.inner.handle(fh) {
            Some(h) if h.is_dir => h,
            _ => return Reply::Err(libc::EBADF),
        };
        let entries = match handle.dir {
            Some(e) => e,
            None => return Reply::Err(libc::EBADF),
        };
        let mut buf = Vec::new();
        for (idx, entry) in entries.iter().enumerate().skip(offset) {
            let namelen = entry.name.len();
            let entlen = 24 + namelen;
            let padded = (entlen + 7) & !7;
            if buf.len() + padded > size {
                break;
            }
            put_u64(&mut buf, entry.ino);
            put_u64(&mut buf, (idx + 1) as u64);
            put_u32(&mut buf, namelen as u32);
            put_u32(&mut buf, fuse_kind_code(entry.kind));
            buf.extend_from_slice(&entry.name);
            buf.resize(buf.len() + (padded - entlen), 0);
        }
        Reply::Dir(buf)
    }

    fn releasedir(&self, req: &Req<'_>) -> Reply {
        let fh = get_u64(req.op, 0);
        let removed = self.fs.inner.remove_handle(fh);
        let mut m = self.fs.inner.metrics.lock();
        m.releasedirs += 1;
        if removed.is_some() {
            m.open_handles = m.open_handles.saturating_sub(1);
        }
        drop(m);
        Reply::Empty
    }

    fn access(&self, req: &Req<'_>) -> Reply {
        let bits = get_u32(req.op, 0) & 0o7;
        if bits == 0 {
            return Reply::Empty;
        }
        let view = self.read_view();
        let root = view.root();
        let st = match view.getattr(req.nodeid, root) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        if has_permission(req.uid, req.gid, &st, bits) {
            Reply::Empty
        } else {
            Reply::Err(libc::EACCES)
        }
    }

    fn statfs(&self) -> Reply {
        match self.fs.options.statfs {
            StatfsMode::LogicalPlenum => Reply::Statfs {
                blocks: u64::MAX,
                bfree: u64::MAX,
                bavail: u64::MAX,
                files: u64::MAX,
                ffree: u64::MAX,
                bsize: 4096,
            },
            StatfsMode::PhysicalSafe => {
                let backing = self.fs.inner.backing.clone();
                match statvfs(&backing) {
                    Some((blocks, bfree, bavail, files, ffree, bsize)) => Reply::Statfs {
                        blocks,
                        bfree,
                        bavail,
                        files,
                        ffree,
                        bsize,
                    },
                    None => Reply::Err(libc::EIO),
                }
            }
        }
    }

    fn create(&self, req: &Req<'_>) -> Reply {
        if self.read_only {
            return Reply::Err(libc::EROFS);
        }
        let flags = get_u32(req.op, 0) as i32;
        let mode = get_u32(req.op, 4);
        let name = trim_name(req.payload);
        let mut core = self.fs.inner.core.lock();
        if let Err(e) = self.check_dir_write(&*core, req.uid, req.gid, req.nodeid, 0o3) {
            return Reply::Err(e);
        }
        let ino = match core.create(req.nodeid, name, mode & 0o7777, req.uid, req.gid) {
            Ok(i) => i,
            Err(e) => return Reply::Err(errno(&e)),
        };
        let st = match core.getattr(ino, core.root()) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        drop(core);
        let fh = self.fs.inner.register_file(ino, flags);
        let mut m = self.fs.inner.metrics.lock();
        m.create += 1;
        m.open_handles += 1;
        drop(m);
        self.fs.inner.record_lookup(ino);
        Reply::Create {
            attr: attr_from_stat(&st),
            fh,
            open_flags: self.open_flags(),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-entry registered buffers
// ---------------------------------------------------------------------------

/// One registered ring entry: a `fuse_uring_req_header` buffer, a payload
/// buffer, and the 2-element iovec array the kernel imports at `REGISTER`.
///
/// # Lifetime invariant
///
/// The kernel stores `iov[0].iov_base`/`iov[1].iov_base` and dereferences them
/// for every request until the connection is torn down. The buffers are
/// therefore heap-backed [`AlignedBuffer`]s at a stable address, and the iovec
/// array is boxed so moving the `EntryState` inside its `Vec` cannot invalidate
/// the address the kernel was given.
struct EntryState {
    qid: u16,
    ud: u64,
    header: AlignedBuffer,
    payload: AlignedBuffer,
    iov: Box<[libc::iovec; 2]>,
}

// SAFETY: `EntryState` owns its `header`/`payload` allocations; the raw pointers
// in `iov` point into those same allocations, so they stay valid when ownership
// (and the buffers) move to another thread. No thread retains a reference to the
// old location, and the buffers are only accessed through the moved-to owner.
unsafe impl Send for EntryState {}

impl EntryState {
    fn new(qid: u16, ud: u64) -> EntryState {
        let header = AlignedBuffer::new(HEADER_BUF, 4096);
        let payload = AlignedBuffer::new(PAYLOAD_BUF, 4096);
        let iov = crate::buffers::BufferPool::register_iovecs(&header, &payload);
        EntryState {
            qid,
            ud,
            header,
            payload,
            iov,
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence metadata and counters
// ---------------------------------------------------------------------------

/// Environment facts captured at mount time for machine-generated evidence.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NativeEnvironment {
    pub kernel_release: String,
    pub fuse_abi_major: u32,
    pub fuse_abi_minor: u32,
    pub num_queues: usize,
    pub max_write: u32,
    pub payload_buf: usize,
    pub mount_options: String,
}

/// Counters for F2 evidence. Every field is a real observation.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct NativeStats {
    pub requests_served: u64,
    pub reply_bytes: u64,
    pub ring_submits: u64,
    pub ring_completions: u64,
    pub register_sqes: u64,
    pub register_failures: u64,
    pub negative_completions: u64,
    pub forgets_classical: u64,
    pub interrupts_classical: u64,
}

// ---------------------------------------------------------------------------
// Mount(2) / INIT
// ---------------------------------------------------------------------------

fn possible_cpu_count() -> usize {
    if let Ok(s) = std::fs::read_to_string("/sys/devices/system/cpu/possible") {
        let mut total = 0usize;
        for part in s.trim().split(',') {
            if let Some((a, b)) = part.split_once('-') {
                if let (Ok(a), Ok(b)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>()) {
                    if b >= a {
                        total += b - a + 1;
                    }
                }
            } else if part.trim().parse::<usize>().is_ok() {
                total += 1;
            }
        }
        if total > 0 {
            return total;
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn open_dev_fuse() -> io::Result<OwnedFd> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")?;
    Ok(OwnedFd::from(file))
}

/// The FUSE mount options we request, in a form both `mount(2)` and
/// `fusermount3 -o` accept (all of these are on fusermount3's allow-list).
fn mount_option_parts(opts: &MountOptions) -> Vec<String> {
    let mut parts = vec![
        "fsname=orfs".to_string(),
        "subtype=orfs".to_string(),
        format!("max_read={MAX_WRITE}"),
        if opts.read_only { "ro" } else { "rw" }.to_string(),
    ];
    if opts.default_permissions {
        parts.push("default_permissions".into());
    }
    if opts.allow_other {
        parts.push("allow_other".into());
    }
    parts
}

/// Mount directly with the `mount(2)` syscall, passing a `/dev/fuse` fd we own
/// (`fd=N`). Requires `CAP_SYS_ADMIN` (for example a rootful container).
fn direct_mount(mountpoint: &Path, opts: &MountOptions) -> io::Result<(OwnedFd, String)> {
    let fd = open_dev_fuse()?;
    let raw = fd.as_raw_fd();
    // SAFETY: geteuid/getegid are pure queries.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let mut data = format!(
        "fd={raw},rootmode={:o},user_id={uid},group_id={gid}",
        libc::S_IFDIR | 0o755,
    );
    for part in mount_option_parts(opts) {
        data.push(',');
        data.push_str(&part);
    }
    let source = CString::new("orfs").unwrap();
    let target = CString::new(mountpoint.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mountpoint not a C string"))?;
    let fstype = CString::new("fuse.orfs").unwrap();
    let data_c = CString::new(data.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mount options not a C string"))?;
    let mut flags = libc::MS_NOSUID | libc::MS_NODEV;
    if opts.read_only {
        flags |= libc::MS_RDONLY;
    }
    // SAFETY: all pointers are valid NUL-terminated C strings (or a valid data
    // blob) that outlive the call; `mount` retains none of them.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            data_c.as_ptr().cast(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fd, data))
}

/// Mount through the setuid `fusermount3` helper, the unprivileged path.
///
/// `fusermount3` opens `/dev/fuse` itself, performs the `mount(2)`, and **sends
/// the resulting fd back to us** over the `_FUSE_COMMFD` Unix socket
/// (`util/fusermount.c`: `send_fd(cfd, fd)`), which is exactly how `libfuse`
/// gives an unprivileged daemon its `/dev/fuse` descriptor. We therefore receive
/// the descriptor instead of opening it ourselves.
fn fusermount_mount(mountpoint: &Path, opts: &MountOptions) -> io::Result<(OwnedFd, String)> {
    let opts_str = mount_option_parts(opts).join(",");
    let mut fds = [0i32; 2];
    // SAFETY: `socketpair` fills the caller-owned 2-element array on success.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (parent, child) = (fds[0], fds[1]);
    // The child end must survive execve; the parent end must not leak into any
    // future child process.
    // SAFETY: `fcntl` with F_SETFD only sets descriptor flags on a valid fd.
    unsafe {
        libc::fcntl(parent, libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(child, libc::F_SETFD, 0);
    }

    let spawn = Command::new("fusermount3")
        .arg("-o")
        .arg(&opts_str)
        .arg("--")
        .arg(mountpoint)
        .env("_FUSE_COMMFD", child.to_string())
        .spawn();
    // The child has inherited its end; close our copy regardless of the outcome.
    // SAFETY: `child` is a valid fd owned by this process.
    unsafe {
        libc::close(child);
    }
    let mut process = match spawn {
        Ok(p) => p,
        Err(e) => {
            // SAFETY: `parent` is a valid fd owned by this process.
            unsafe {
                libc::close(parent);
            }
            return Err(e);
        }
    };

    let received = recv_fd(parent);
    // SAFETY: `parent` is a valid fd owned by this process.
    unsafe {
        libc::close(parent);
    }
    let status = process.wait();
    match received {
        Ok(fd) => {
            if let Ok(st) = status {
                if !st.success() {
                    return Err(io::Error::other(format!("fusermount3 exited with {st}")));
                }
            }
            Ok((fd, opts_str))
        }
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("fusermount3 did not hand back a /dev/fuse fd: {e}"),
        )),
    }
}

/// Receive a file descriptor over a Unix socket (`SCM_RIGHTS`).
fn recv_fd(sock: RawFd) -> io::Result<OwnedFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0u8; 64];
    // SAFETY: `msghdr` is a plain C struct; zeroing it is a valid initial state
    // that we immediately overwrite with valid pointers into owned locals.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();
    // SAFETY: `sock` is a valid connected Unix socket; `msg` describes valid,
    // aligned, owned buffers.
    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "control socket closed without a descriptor",
        ));
    }
    // SAFETY: `msg` was populated by `recvmsg`; the cmsg helpers walk its
    // control buffer, which is within `control`.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg);
                let fd = std::ptr::read_unaligned(data as *const i32);
                if fd < 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "negative fd"));
                }
                return Ok(OwnedFd::from_raw_fd(fd));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "no SCM_RIGHTS descriptor received",
    ))
}

/// Open `/dev/fuse` and mount it at `mountpoint`, preferring a direct
/// `mount(2)` and falling back to the setuid `fusermount3` helper.
fn open_and_mount(mountpoint: &Path, opts: &MountOptions) -> io::Result<(OwnedFd, String)> {
    match direct_mount(mountpoint, opts) {
        Ok(v) => Ok(v),
        Err(direct_err) => match fusermount_mount(mountpoint, opts) {
            Ok(v) => Ok(v),
            Err(helper_err) => Err(io::Error::new(
                helper_err.kind(),
                format!("direct mount(2): {direct_err}; fusermount3: {helper_err}"),
            )),
        },
    }
}

fn detach_mount(mountpoint: &Path) {
    // Prefer the setuid helper (works unprivileged); fall back to a direct lazy
    // detach for the privileged case.
    let _ = Command::new("fusermount3")
        .arg("-u")
        .arg("-z")
        .arg("-q")
        .arg(mountpoint)
        .status();
    if let Ok(c) = CString::new(mountpoint.as_os_str().as_bytes()) {
        // SAFETY: `c` is a valid NUL-terminated path; `umount2` performs a lazy
        // detach and retains no pointer.
        unsafe {
            libc::umount2(c.as_ptr(), libc::MNT_DETACH);
        }
    }
}

fn read_init(fd: RawFd) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 65536];
    loop {
        // SAFETY: `fd` is a valid open /dev/fuse fd; `buf` is a valid writable
        // region of `buf.len()` bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        buf.truncate(n as usize);
        return Ok(buf);
    }
}

fn write_all(fd: RawFd, buf: &[u8]) -> io::Result<()> {
    let mut off = 0usize;
    while off < buf.len() {
        // SAFETY: `fd` is valid; `buf[off..]` is a valid readable region.
        let n = unsafe { libc::write(fd, buf[off..].as_ptr().cast(), buf.len() - off) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short /dev/fuse write",
            ));
        }
        off += n as usize;
    }
    Ok(())
}

/// Encode the `FUSE_INIT` reply (out header + `fuse_init_out`, 64 bytes).
fn encode_init_reply(unique: u64, minor: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 64);
    put_u32(&mut out, 16 + 64);
    put_u32(&mut out, 0);
    put_u64(&mut out, unique);
    // struct fuse_init_out
    put_u32(&mut out, 7); // major
    put_u32(&mut out, minor); // minor
    put_u32(&mut out, MAX_READAHEAD); // max_readahead
    put_u32(&mut out, FUSE_INIT_EXT | FUSE_ASYNC_READ | FUSE_BIG_WRITES); // flags
    put_u16(&mut out, 12); // max_background
    put_u16(&mut out, 9); // congestion_threshold
    put_u32(&mut out, MAX_WRITE); // max_write
    put_u32(&mut out, 1); // time_gran
    put_u16(&mut out, 32); // max_pages
    put_u16(&mut out, 0); // map_alignment
    put_u32(&mut out, FUSE_OVER_IO_URING_FLAGS2); // flags2
    put_u32(&mut out, 0); // max_stack_depth
    put_u16(&mut out, 0); // request_timeout
    for _ in 0..11 {
        put_u16(&mut out, 0); // unused[11]
    }
    debug_assert_eq!(out.len(), 16 + 64);
    out
}

// ---------------------------------------------------------------------------
// The prepared (pre-core) F2 transport
// ---------------------------------------------------------------------------

/// A F2 transport that has completed `mount(2)`, the `INIT` handshake, and ring
/// registration, but has not yet been given an [`OrfsFuse`] to dispatch with.
///
/// Splitting this out lets the caller build the filesystem core only *after* F2
/// is proven to engage, so a failure never consumes the core.
pub struct Prepared {
    fd: OwnedFd,
    mountpoint: PathBuf,
    options: MountOptions,
    kernel_minor: u32,
    environment: Arc<Mutex<NativeEnvironment>>,
    stats: Arc<Mutex<NativeStats>>,
    stop: Arc<AtomicBool>,
}

/// Perform the whole F2 setup *except* dispatch: open, mount, `INIT`, ring,
/// `REGISTER`, and a short probe that catches an immediate `REGISTER` failure.
///
/// Returns `Err(reason)` with the mount already detached on every failure path.
pub fn prepare(mountpoint: &Path, opts: &MountOptions) -> Result<Prepared, String> {
    if !opts.transport.requests_uring_fuse() {
        return Err("F2 not requested".into());
    }
    let (fd, mount_options) =
        open_and_mount(mountpoint, opts).map_err(|e| format!("mount failed: {e}"))?;
    let raw = fd.as_raw_fd();

    // Every failure from here on must detach the mount.
    let fail = |reason: String| -> String {
        detach_mount(mountpoint);
        reason
    };

    let init = read_init(raw).map_err(|e| fail(format!("read FUSE_INIT: {e}")))?;
    if init.len() < 40 + 64 {
        return Err(fail(format!("short FUSE_INIT: {} bytes", init.len())));
    }
    let opcode = get_u32(&init, 4);
    let unique = get_u64(&init, 8);
    if opcode != FUSE_INIT {
        return Err(fail(format!(
            "first request is not FUSE_INIT (opcode {opcode})"
        )));
    }
    let kernel_minor = get_u32(&init, 44);
    let in_flags = get_u32(&init, 52);
    let in_flags2 = get_u32(&init, 56);
    let offered = ((in_flags as u64) | ((in_flags2 as u64) << 32))
        & crate::fuse_uring::FUSE_OVER_IO_URING
        != 0;
    if !offered {
        return Err(fail(format!(
            "kernel did not offer FUSE_OVER_IO_URING at INIT (FUSE ABI 7.{kernel_minor}); \
             fuse_uring_enabled() is false for this connection"
        )));
    }
    let reply = encode_init_reply(unique, kernel_minor);
    write_all(raw, &reply).map_err(|e| fail(format!("write FUSE_INIT reply: {e}")))?;

    let num_queues = possible_cpu_count();
    let environment = Arc::new(Mutex::new(NativeEnvironment {
        kernel_release: crate::capabilities::probe().kernel_release,
        fuse_abi_major: 7,
        fuse_abi_minor: kernel_minor,
        num_queues,
        max_write: MAX_WRITE,
        payload_buf: PAYLOAD_BUF,
        mount_options,
    }));
    Ok(Prepared {
        fd,
        mountpoint: mountpoint.to_path_buf(),
        options: *opts,
        kernel_minor,
        environment,
        stats: Arc::new(Mutex::new(NativeStats::default())),
        stop: Arc::new(AtomicBool::new(false)),
    })
}

/// Attempt a real FUSE-over-`io_uring` negotiation on a throwaway mount: open,
/// `mount(2)`/`fusermount3`, the `FUSE_INIT` handshake, and ring registration,
/// then tear everything down. Used by `orfs doctor` to report the *live* result
/// rather than a static prediction.
///
/// Returns `Err(reason)` with the mount already detached on any failure. The
/// negotiation's `engaged` is true only when ring registration succeeded.
pub fn negotiate_live() -> Result<FuseUringNegotiation, String> {
    let dir = std::env::temp_dir().join(format!("orfs-f2-doctor-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create probe mountpoint: {e}"))?;
    let opts = MountOptions {
        transport: Transport::FuseUring,
        ..Default::default()
    };
    let result = (|| -> Result<FuseUringNegotiation, String> {
        let prepared = prepare(&dir, &opts)?;
        let raw = prepared.fd.as_raw_fd();
        let (_ring, _entries, _probe, num_queues) = register_all_entries(raw)?;
        Ok(FuseUringNegotiation {
            kernel_offered: true,
            kernel_offered_bufpool: false,
            kernel_abi: Some((7, prepared.kernel_minor)),
            accepted: true,
            engaged: true,
            reason: Some(format!(
                "live probe: INIT offered FUSE_OVER_IO_URING and {num_queues} ring entries registered"
            )),
        })
    })();
    detach_mount(&dir);
    let _ = std::fs::remove_dir(&dir);
    result
}

/// The live F2 mount handle returned once the session thread is running.
pub struct NativeMount {
    mountpoint: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    negotiation: Arc<Mutex<FuseUringNegotiation>>,
    stats: Arc<Mutex<NativeStats>>,
    environment: Arc<Mutex<NativeEnvironment>>,
}

impl NativeMount {
    /// The live negotiation result (always `engaged == true` for a native mount).
    pub fn negotiation(&self) -> FuseUringNegotiation {
        self.negotiation.lock().clone()
    }

    /// The shared negotiation cell, so the mount can report live updates.
    pub fn negotiation_cell(&self) -> Arc<Mutex<FuseUringNegotiation>> {
        Arc::clone(&self.negotiation)
    }

    /// The session's stop flag (set to request an orderly shutdown).
    pub fn stop_cell(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// A snapshot of the F2 counters.
    pub fn stats(&self) -> NativeStats {
        self.stats.lock().clone()
    }

    /// The environment facts captured at mount time.
    pub fn environment(&self) -> NativeEnvironment {
        self.environment.lock().clone()
    }

    /// Tear the session down: signal the loop, detach the mount, and join.
    pub fn unmount(mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::SeqCst);
        detach_mount(&self.mountpoint);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        Ok(())
    }

    /// Wait for the session to end (for example after an external unmount).
    pub fn join(mut self) -> io::Result<()> {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        Ok(())
    }
}

impl Prepared {
    /// Build the dispatch adaptor and launch the F2 request loop on a background
    /// thread, returning a handle the mount can join/unmount.
    ///
    /// The `io_uring` instance and every `REGISTER`/`COMMIT_AND_FETCH` SQE are
    /// created and submitted *by this thread*, because `io_uring` delivers
    /// URING_CMD completions as task-work to the task that submitted the command
    /// (`io_uring_cmd_complete_in_task`). That task must be the one parked waiting
    /// for completions, so `prepare` deliberately does not create the ring.
    pub fn launch<C: OrfsCore + Send + 'static>(
        self,
        core: C,
        backing: PathBuf,
    ) -> Result<NativeMount, String> {
        let options = self.options;
        let fs = Arc::new(OrfsFuse::new(core, backing, options));
        let negotiation = fs.negotiation_cell();
        let dispatcher = Arc::new(Dispatcher {
            fs: Arc::clone(&fs),
            entry_ttl: options.entry_ttl,
            attr_ttl: options.attr_ttl,
            read_only: options.read_only,
            direct_io: options.direct_io,
        });
        let stop = Arc::clone(&self.stop);
        let stats = Arc::clone(&self.stats);
        let environment = Arc::clone(&self.environment);
        let mountpoint = self.mountpoint.clone();
        let reader_fd = dup_fd(self.fd.as_raw_fd());
        let (setup_tx, setup_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let session = SessionLoop {
            fd: self.fd,
            dispatcher,
            stats: Arc::clone(&stats),
            stop: Arc::clone(&stop),
            kernel_minor: self.kernel_minor,
            environment: Arc::clone(&environment),
            ring: None,
            entries: Vec::new(),
            pending: Vec::new(),
            reader_fd,
            setup_tx: Some(setup_tx),
        };
        let thread = std::thread::Builder::new()
            .name("orfs-f2".to_string())
            .spawn(move || {
                let _ = session.run();
            })
            .map_err(|e| format!("spawn F2 session thread: {e}"))?;

        match setup_rx.recv_timeout(Duration::from_secs(15)) {
            Ok(Ok(())) => Ok(NativeMount {
                mountpoint,
                stop,
                thread: Some(thread),
                negotiation,
                stats,
                environment,
            }),
            Ok(Err(e)) => {
                stop.store(true, Ordering::SeqCst);
                detach_mount(&mountpoint);
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                stop.store(true, Ordering::SeqCst);
                detach_mount(&mountpoint);
                let _ = thread.join();
                Err("F2 ring registration timed out".into())
            }
        }
    }
}

fn dup_fd(fd: RawFd) -> Option<RawFd> {
    // SAFETY: `dup` duplicates a valid fd; the returned fd is owned by the caller.
    let n = unsafe { libc::dup(fd) };
    if n < 0 {
        None
    } else {
        Some(n)
    }
}

/// Create the SQE128 ring bound to `fd`, register one entry per CPU queue, and
/// probe for an immediate `REGISTER` rejection.
///
/// Must be called on the thread that will wait for completions: the kernel
/// delivers `URING_CMD` completions as task-work to the task that submitted the
/// command, so the submitting and waiting tasks must be the same.
fn register_all_entries(
    fd: RawFd,
) -> Result<(FuseUringRing, Vec<EntryState>, Vec<RingCompletion>, usize), String> {
    let num_queues = possible_cpu_count();
    let mut ring =
        FuseUringRing::new(fd, IO_URING_DEPTH).map_err(|e| format!("io_uring setup: {e}"))?;
    let mut entries: Vec<EntryState> = Vec::with_capacity(num_queues);
    for qid in 0..num_queues {
        entries.push(EntryState::new(qid as u16, (qid + 1) as u64));
    }
    // Register one entry per queue: the kernel creates each queue lazily and
    // only starts routing requests once every queue has an available entry
    // (`is_ring_ready`).
    for e in &entries {
        ring.submit_register(e.qid, e.iov.as_ptr() as u64, e.ud)
            .map_err(|err| format!("queue REGISTER SQE for qid {}: {err}", e.qid))?;
    }
    ring.submit()?;
    // A rejected REGISTER completes immediately with a negative result
    // (`sqe->len != 2` → -EINVAL; disabled → -EOPNOTSUPP). A successful REGISTER
    // produces no completion until a request arrives, so an empty probe is the
    // success case.
    let probe = ring.submit_and_wait_timeout(1, Duration::from_millis(500))?;
    let failures = probe.iter().filter(|c| c.result < 0).count();
    if failures > 0 {
        let sample = probe
            .iter()
            .find(|c| c.result < 0)
            .map(|c| -c.result)
            .unwrap_or(0);
        return Err(format!(
            "FUSE_IO_URING_CMD_REGISTER was rejected by the kernel ({failures} of {num_queues} \
             SQEs failed; first errno {sample}); the raw-SQE iovec path (`sqe->len == 2`) did not take"
        ));
    }
    Ok((ring, entries, probe, num_queues))
}

// ---------------------------------------------------------------------------
// The request loop
// ---------------------------------------------------------------------------

struct SessionLoop<C: OrfsCore + Send + 'static> {
    /// Owns the `/dev/fuse` descriptor for the session's lifetime.
    fd: OwnedFd,
    /// The io_uring ring, created on this thread so completions (delivered as
    /// task-work to the submitting task) are run by this thread's waits.
    ring: Option<FuseUringRing>,
    entries: Vec<EntryState>,
    pending: Vec<RingCompletion>,
    dispatcher: Arc<Dispatcher<C>>,
    stats: Arc<Mutex<NativeStats>>,
    stop: Arc<AtomicBool>,
    kernel_minor: u32,
    environment: Arc<Mutex<NativeEnvironment>>,
    reader_fd: Option<RawFd>,
    setup_tx: Option<std::sync::mpsc::Sender<Result<(), String>>>,
}

impl<C: OrfsCore + Send + 'static> SessionLoop<C> {
    /// Create the ring, register one entry per CPU queue, and probe for an
    /// immediate `REGISTER` rejection. Runs on the session thread.
    fn setup(&mut self) -> Result<(), String> {
        let raw = self.fd.as_raw_fd();
        let (ring, entries, probe, num_queues) = register_all_entries(raw)?;
        self.stats.lock().register_sqes = num_queues as u64;
        {
            let mut env = self.environment.lock();
            env.num_queues = num_queues;
        }
        self.dispatcher.fs.record_negotiation(FuseUringNegotiation {
            kernel_offered: true,
            kernel_offered_bufpool: false,
            kernel_abi: Some((7, self.kernel_minor)),
            accepted: true,
            engaged: true,
            reason: None,
        });
        self.ring = Some(ring);
        self.entries = entries;
        self.pending = probe;
        Ok(())
    }

    fn run(mut self) -> Result<(), String> {
        let setup = self.setup();
        let ok = setup.is_ok();
        if let Some(tx) = self.setup_tx.take() {
            let _ = tx.send(setup);
        }
        if !ok {
            return Ok(());
        }
        // Only now (ring ready) start the classical reader for FORGET/INTERRUPT.
        if let Some(reader_fd) = self.reader_fd.take() {
            let stop = Arc::clone(&self.stop);
            let stats = Arc::clone(&self.stats);
            let fs = Arc::clone(&self.dispatcher.fs);
            let _ = std::thread::Builder::new()
                .name("orfs-f2-classical".to_string())
                .spawn(move || classical_reader(reader_fd, stop, stats, fs));
        }

        loop {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            let comps = if !self.pending.is_empty() {
                std::mem::take(&mut self.pending)
            } else {
                let ring = self.ring.as_mut().expect("ring initialized");
                match ring.submit_and_wait_timeout(1, Duration::from_millis(200)) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("orfs: F2 ring wait failed: {e}");
                        break;
                    }
                }
            };
            if comps.is_empty() {
                continue;
            }
            for c in comps {
                if let Err(e) = self.handle_completion(c) {
                    eprintln!("orfs: F2 request handling failed: {e}");
                }
            }
            if let Some(ring) = self.ring.as_mut() {
                if let Err(e) = ring.submit() {
                    eprintln!("orfs: F2 submit failed: {e}");
                    break;
                }
            }
        }
        if let Some(ring) = self.ring.as_mut() {
            ring.shutdown();
        }
        // `self.fd` drops here, closing /dev/fuse.
        Ok(())
    }

    fn handle_completion(&mut self, c: RingCompletion) -> Result<(), String> {
        self.stats.lock().ring_completions += 1;
        let idx = match (c.user_data as usize).checked_sub(1) {
            Some(i) if i < self.entries.len() => i,
            _ => return Ok(()),
        };
        if c.result < 0 {
            // A negative completion means the kernel tore the entry down (for
            // example when the connection aborts at unmount). The entry is no
            // longer usable; count it and keep draining the rest.
            self.stats.lock().negative_completions += 1;
            return Ok(());
        }
        self.serve_entry(idx)
    }

    fn serve_entry(&mut self, idx: usize) -> Result<(), String> {
        let (qid, ud, commit_id, unique, destroy, reply) = {
            let e = &self.entries[idx];
            let hdr = e.header.as_slice();
            let payload_sz = (get_u32(hdr, 272) as usize).min(e.payload.len());
            let req = Req {
                unique: get_u64(hdr, 8),
                opcode: get_u32(hdr, 4),
                nodeid: get_u64(hdr, 16),
                uid: get_u32(hdr, 24),
                gid: get_u32(hdr, 28),
                commit_id: get_u64(hdr, 264),
                op: &hdr[128..256],
                payload: &e.payload.as_slice()[..payload_sz],
            };
            let destroy = req.opcode == FUSE_DESTROY;
            let reply = if destroy {
                Reply::Empty
            } else {
                self.dispatcher.serve(&req)
            };
            (e.qid, e.ud, req.commit_id, req.unique, destroy, reply)
        };

        let (err, data) = reply.encode(self.dispatcher.entry_ttl, self.dispatcher.attr_ttl);
        {
            let e = &mut self.entries[idx];
            write_reply(e, unique, err, &data);
        }
        {
            let mut s = self.stats.lock();
            s.requests_served += 1;
            s.reply_bytes += data.len() as u64;
        }
        self.ring
            .as_mut()
            .ok_or_else(|| "F2 ring not initialized".to_string())?
            .submit_commit_and_fetch(qid, commit_id, ud)
            .map_err(|e| format!("queue COMMIT_AND_FETCH for qid {qid}: {e}"))?;
        self.stats.lock().ring_submits += 1;

        if destroy {
            self.stop.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
}

/// Write a reply into an entry's header and payload buffers, exactly as the
/// kernel's `fuse_uring_commit`/`fuse_uring_copy_from_ring` read them: the
/// `fuse_out_header` at the start of `in_out`, the reply data in the payload
/// buffer, and its length in `ring_ent_in_out.payload_sz` (offset 272).
fn write_reply(e: &mut EntryState, unique: u64, err: i32, data: &[u8]) {
    let hdr = e.header.as_mut_slice();
    let len = (16 + data.len()) as u32;
    hdr[0..4].copy_from_slice(&len.to_ne_bytes());
    let wire = if err == 0 { 0 } else { -err };
    hdr[4..8].copy_from_slice(&wire.to_ne_bytes());
    hdr[8..16].copy_from_slice(&unique.to_ne_bytes());
    hdr[272..276].copy_from_slice(&(data.len() as u32).to_ne_bytes());
    let payload = e.payload.as_mut_slice();
    payload[..data.len()].copy_from_slice(data);
}

// ---------------------------------------------------------------------------
// Classical channel: FORGET / BATCH_FORGET / INTERRUPT
// ---------------------------------------------------------------------------

fn classical_reader<C: OrfsCore + Send + 'static>(
    fd: RawFd,
    stop: Arc<AtomicBool>,
    stats: Arc<Mutex<NativeStats>>,
    fs: Arc<OrfsFuse<C>>,
) {
    let mut buf = vec![0u8; 256 * 1024];
    while !stop.load(Ordering::SeqCst) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a valid, owned pollfd describing `fd`.
        let rc = unsafe { libc::poll(&mut pfd, 1, 200) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if rc == 0 || pfd.revents & libc::POLLIN == 0 {
            continue;
        }
        // SAFETY: `fd` is a valid open fd; `buf` is a valid writable region.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted || e.kind() == io::ErrorKind::WouldBlock {
                continue;
            }
            break;
        }
        let n = n as usize;
        if n < 40 {
            continue;
        }
        match get_u32(&buf, 4) {
            FUSE_FORGET => {
                if n >= 48 {
                    let nodeid = get_u64(&buf, 16);
                    let nlookup = get_u64(&buf, 40);
                    fs.inner.record_forget(nodeid, nlookup);
                    fs.inner.metrics.lock().forgets += 1;
                    stats.lock().forgets_classical += 1;
                }
            }
            FUSE_BATCH_FORGET => {
                if n >= 48 {
                    let count = get_u32(&buf, 40) as usize;
                    let mut off = 48;
                    for _ in 0..count {
                        if off + 16 > n {
                            break;
                        }
                        let nodeid = get_u64(&buf, off);
                        let nlookup = get_u64(&buf, off + 8);
                        fs.inner.record_forget(nodeid, nlookup);
                        fs.inner.metrics.lock().forgets += 1;
                        off += 16;
                    }
                    stats.lock().forgets_classical += 1;
                }
            }
            FUSE_INTERRUPT => {
                // Interrupts need no reply; cancellation is inherent to the
                // kernel aborting the interrupted request.
                stats.lock().interrupts_classical += 1;
            }
            other => {
                eprintln!(
                    "orfs: F2 classical channel received opcode {other} ({} bytes) — the ring is not ready",
                    n
                );
            }
        }
    }
    // SAFETY: the fd was produced by `dup` in `launch` and is owned by this thread.
    unsafe {
        libc::close(fd);
    }
}
