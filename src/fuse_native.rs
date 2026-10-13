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

use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

use crate::buffers::AlignedBuffer;
use crate::error::OrfsError;
use crate::fuse::{F2Servicing, MountOptions, OrfsFuse, StatfsMode, Transport};
use crate::fuse_uring::{FuseUringNegotiation, FuseUringRing, QueuePlan, RingCompletion};
use crate::inode::{has_permission_grouped, InodeStat, InodeType, Timespec};
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
/// `FUSE_HANDLE_KILLPRIV` (`1 << 19`): the daemon clears suid/sgid on write.
const FUSE_HANDLE_KILLPRIV: u32 = 1 << 19;
/// `FUSE_HANDLE_KILLPRIV_V2` (`1 << 28`): as above, and the kernel carries the
/// precise `FUSE_WRITE_KILL_SUIDGID` signal on the write request.
const FUSE_HANDLE_KILLPRIV_V2: u32 = 1 << 28;
const FUSE_INIT_EXT: u32 = 1 << 30;
/// `FUSE_OVER_IO_URING = 1 << 41` → `flags2` bit 9.
const FUSE_OVER_IO_URING_FLAGS2: u32 = 1 << (41 - 32);

// `fuse_open_out.open_flags`.
const FOPEN_DIRECT_IO: u32 = 1 << 0;
const FOPEN_CACHE_DIR: u32 = 1 << 3;
/// `FOPEN_PASSTHROUGH = 1 << 7` (ABI 7.40+): read/write bypass the daemon.
const FOPEN_PASSTHROUGH: u32 = 1 << 7;

// FUSE ABI 7.40+ passthrough negotiation (`uapi/linux/fuse.h`).
/// `FUSE_PASSTHROUGH = 1 << 37` → `flags2` bit 5.
const FUSE_PASSTHROUGH_FLAGS2: u32 = 1 << (37 - 32);
/// The 64-bit `FUSE_PASSTHROUGH` capability bit, as it appears in the 64-bit
/// `INIT` flags (low word `flags` + high word `flags2`).
const FUSE_PASSTHROUGH: u64 = 1u64 << 37;
/// The `max_stack_depth` advertised in the `INIT` reply when passthrough is
/// negotiated. It must be `> 0` for passthrough to be enabled and
/// `<= FILESYSTEM_MAX_STACK_DEPTH` (2 on Linux); `2` admits a backing file on a
/// plain or single-layer stacked filesystem.
const PASSTHROUGH_MAX_STACK_DEPTH: u32 = 2;

/// `FUSE_DEV_IOC_MAGIC` (`uapi/linux/fuse.h`).
const FUSE_DEV_IOC_MAGIC: u32 = 229;
/// `_IOW(FUSE_DEV_IOC_MAGIC, 1, struct fuse_backing_map)`.
const FUSE_DEV_IOC_BACKING_OPEN: libc::c_ulong = iow(
    FUSE_DEV_IOC_MAGIC,
    1,
    std::mem::size_of::<FuseBackingMap>() as u32,
);
/// `_IOW(FUSE_DEV_IOC_MAGIC, 2, uint32_t)`.
const FUSE_DEV_IOC_BACKING_CLOSE: libc::c_ulong = iow(FUSE_DEV_IOC_MAGIC, 2, 4);

/// `_IOW(type, nr, size)`: the little-endian-independent ioctl request number
/// used on x86_64 (`_IOC_WRITE == 1`). Kept as a `const fn` so a unit test can
/// recompute it and fail if the transcribed magic ever drifts.
const fn iow(type_: u32, nr: u32, size: u32) -> libc::c_ulong {
    ((1u32 << 30) | (size << 16) | (type_ << 8) | nr) as libc::c_ulong
}

/// `struct fuse_backing_map` (`uapi/linux/fuse.h`, ABI 7.40+): the argument to
/// `FUSE_DEV_IOC_BACKING_OPEN`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseBackingMap {
    fd: i32,
    flags: u32,
    padding: u64,
}

// `fuse_setattr_in.valid`.
const FATTR_MODE: u32 = 1 << 0;
const FATTR_UID: u32 = 1 << 1;
const FATTR_GID: u32 = 1 << 2;
const FATTR_SIZE: u32 = 1 << 3;
const FATTR_ATIME: u32 = 1 << 4;
const FATTR_MTIME: u32 = 1 << 5;
const FATTR_FH: u32 = 1 << 6;
const FATTR_ATIME_NOW: u32 = 1 << 7;
const FATTR_MTIME_NOW: u32 = 1 << 8;

// `fuse_write_in.write_flags`.
const FUSE_WRITE_KILL_SUIDGID: u32 = 1 << 2;

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

const IO_URING_DEPTH: u32 = 128;

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
        nlink: st.nlink,
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

fn write_entry_out(v: &mut Vec<u8>, a: &Attr, entry_ttl: Duration, attr_ttl: Duration) {
    put_u64(v, a.ino); // nodeid
    put_u64(v, 1); // generation (GENERATION)
    put_u64(v, entry_ttl.as_secs()); // entry_valid
    put_u64(v, attr_ttl.as_secs()); // attr_valid
    put_u32(v, entry_ttl.subsec_nanos()); // entry_valid_nsec
    put_u32(v, attr_ttl.subsec_nanos()); // attr_valid_nsec
    write_attr(v, a);
}

fn write_attr_out(v: &mut Vec<u8>, a: &Attr, attr_ttl: Duration) {
    put_u64(v, attr_ttl.as_secs());
    put_u32(v, attr_ttl.subsec_nanos());
    put_u32(v, 0); // dummy
    write_attr(v, a);
}

fn write_open_out(v: &mut Vec<u8>, fh: u64, open_flags: u32, backing_id: i32) {
    put_u64(v, fh);
    put_u32(v, open_flags);
    put_u32(v, backing_id as u32);
}

fn write_write_out(v: &mut Vec<u8>, n: u32) {
    put_u32(v, n);
    put_u32(v, 0);
}

#[allow(clippy::too_many_arguments)]
fn write_statfs(
    v: &mut Vec<u8>,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    bsize: u32,
) {
    put_u64(v, blocks);
    put_u64(v, bfree);
    put_u64(v, bavail);
    put_u64(v, files);
    put_u64(v, ffree);
    put_u32(v, bsize); // bsize
    put_u32(v, 255); // namelen
    put_u32(v, bsize); // frsize
    put_u32(v, 0); // padding
    for _ in 0..6 {
        put_u32(v, 0); // spare[6]
    }
}

// ---------------------------------------------------------------------------
// Dispatch: raw FUSE request -> transport-neutral reply
// ---------------------------------------------------------------------------

/// A parsed request as delivered by either transport.
struct Req<'a> {
    opcode: u32,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
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
        /// The registered kernel backing id when `FOPEN_PASSTHROUGH` is set.
        backing_id: i32,
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
    /// Encode the reply body into `out` (cleared first), returning the wire error
    /// code.
    ///
    /// This writes into a caller-owned, reusable buffer instead of allocating a
    /// fresh `Vec` per request. For `Data` replies the buffer takes ownership of
    /// the core's `Vec` when it is large enough that copying would be wasteful,
    /// and otherwise reuses the existing capacity. Byte-for-byte identical to the
    /// previous per-reply allocation.
    fn encode_into(self, out: &mut Vec<u8>, entry_ttl: Duration, attr_ttl: Duration) -> i32 {
        out.clear();
        match self {
            Reply::Empty => 0,
            Reply::Err(e) => e,
            Reply::Data(d) => {
                // Reuse capacity when possible; otherwise take the core's buffer
                // wholesale (no second copy for a large read).
                if out.capacity() >= d.len() {
                    out.extend_from_slice(&d);
                } else {
                    *out = d;
                }
                0
            }
            Reply::Entry(a) => {
                let before = out.len();
                write_entry_out(out, &a, entry_ttl, attr_ttl);
                debug_assert_eq!(out.len() - before, 128);
                0
            }
            Reply::Attr(a) => {
                let before = out.len();
                write_attr_out(out, &a, attr_ttl);
                debug_assert_eq!(out.len() - before, 104);
                0
            }
            Reply::Open {
                fh,
                open_flags,
                backing_id,
            } => {
                write_open_out(out, fh, open_flags, backing_id);
                0
            }
            Reply::Write(n) => {
                write_write_out(out, n);
                0
            }
            Reply::Create {
                attr,
                fh,
                open_flags,
            } => {
                write_entry_out(out, &attr, entry_ttl, attr_ttl);
                write_open_out(out, fh, open_flags, 0);
                0
            }
            Reply::Dir(d) => {
                if out.capacity() >= d.len() {
                    out.extend_from_slice(&d);
                } else {
                    *out = d;
                }
                0
            }
            Reply::Statfs {
                blocks,
                bfree,
                bavail,
                files,
                ffree,
                bsize,
            } => {
                write_statfs(out, blocks, bfree, bavail, files, ffree, bsize);
                0
            }
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
    /// The passthrough controller, present only when the mount requested kernel
    /// passthrough on the native session.
    passthrough: Option<Arc<PassthroughControl>>,
    /// Shared native counters (bumped when the daemon serves a read).
    stats: Arc<Mutex<NativeStats>>,
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
        if !has_permission_grouped(
            req.uid,
            req.gid,
            &crate::fuse::caller_groups(req.pid),
            &directory,
            0o1,
        ) {
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
        let fh = get_u64(req.op, 8);
        let size = get_u64(req.op, 16);
        let atime = get_u64(req.op, 32);
        let mtime = get_u64(req.op, 40);
        let atimensec = get_u32(req.op, 56);
        let mtimensec = get_u32(req.op, 60);
        let mode = get_u32(req.op, 68);
        let uid = get_u32(req.op, 76);
        let gid = get_u32(req.op, 80);

        // The permission model reads the authoritative inode, and the change must be
        // decided against the same state it commits against, so the whole check +
        // mutate runs inside one job under the core lock. Routing through
        // `Inner::mutate` also lets a truncate share a group-commit batch's barrier.
        let ino_raw = req.nodeid;
        let actor_uid = req.uid;
        let actor_gid = req.gid;
        let actor_pid = req.pid;
        let groups = crate::fuse::caller_groups(actor_pid);
        let is_root = actor_uid == 0;
        let writable_fh = valid & FATTR_FH != 0
            && self
                .fs
                .inner
                .handle(fh)
                .is_some_and(|h| !h.is_dir && (h.flags & libc::O_ACCMODE) != libc::O_RDONLY);
        let res = self.fs.inner.mutate(move |core| {
            let st = core.getattr(ino_raw, core.root())?;
            let owner_or_root = is_root || actor_uid == st.uid;
            let meta_change = valid & (FATTR_MODE | FATTR_UID | FATTR_GID) != 0;
            let time_change = valid & (FATTR_ATIME | FATTR_MTIME) != 0;
            // Linux `ATTR_TOUCH` (both times `UTIME_NOW`, e.g. `utimes(path, NULL)`)
            // needs only write permission for a non-owner; every other time form
            // requires ownership (mirrors the classical transport).
            let touch_like =
                !meta_change && valid & FATTR_ATIME_NOW != 0 && valid & FATTR_MTIME_NOW != 0;
            if touch_like {
                if !owner_or_root
                    && !has_permission_grouped(actor_uid, actor_gid, &groups, &st, 0o2)
                {
                    return Err(OrfsError::PermissionDenied);
                }
            } else if (meta_change || time_change) && !owner_or_root {
                return Err(OrfsError::NotPermitted);
            }
            let uid_changes = valid & FATTR_UID != 0 && uid != st.uid;
            if uid_changes && !is_root {
                return Err(OrfsError::NotPermitted);
            }
            let gid_changes = valid & FATTR_GID != 0 && gid != st.gid;
            if gid_changes
                && !is_root
                && (!owner_or_root || !crate::fuse::caller_in_group(actor_pid, actor_gid, gid))
            {
                return Err(OrfsError::NotPermitted);
            }
            if valid & FATTR_SIZE != 0
                && !writable_fh
                && !has_permission_grouped(actor_uid, actor_gid, &groups, &st, 0o2)
            {
                return Err(OrfsError::PermissionDenied);
            }
            let mut effective_mode = (valid & FATTR_MODE != 0).then_some(mode & 0o7777);
            if valid & FATTR_SIZE != 0 && !is_root {
                let cleared = st.mode & !(libc::S_ISUID | libc::S_ISGID);
                if cleared != st.mode {
                    effective_mode =
                        Some(effective_mode.unwrap_or(st.mode) & !(libc::S_ISUID | libc::S_ISGID));
                }
            }
            let attrs = SetAttr {
                mode: effective_mode,
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
            core.setattr(ino_raw, &attrs)?;
            Ok(0)
        });
        if let Err(e) = res {
            return Reply::Err(errno(&e));
        }
        let view = self.read_view();
        let updated = match view.getattr(ino_raw, view.root()) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
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
        let nodeid = req.nodeid;
        let actor_uid = req.uid;
        let actor_gid = req.gid;
        let groups = crate::fuse::caller_groups(req.pid);
        let name = name.to_vec();
        let target = target.to_vec();
        let res = self.fs.inner.mutate(move |core| {
            crate::fuse::check_create_uid(core, actor_uid, actor_gid, &groups, nodeid, 0o3)?;
            let ino = core.symlink(nodeid, &name, &target, actor_uid, actor_gid)?;
            Ok(ino as i64)
        });
        let ino = match res {
            Ok(i) => i as u64,
            Err(e) => return Reply::Err(errno(&e)),
        };
        let view = self.read_view();
        let st = match view.getattr(ino, view.root()) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
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
        let nodeid = req.nodeid;
        let actor_uid = req.uid;
        let actor_gid = req.gid;
        let groups = crate::fuse::caller_groups(req.pid);
        let name = name.to_vec();
        let perm = mode & 0o7777;
        let res = self.fs.inner.mutate(move |core| {
            crate::fuse::check_create_uid(core, actor_uid, actor_gid, &groups, nodeid, 0o3)?;
            let ino = core.create(nodeid, &name, perm, actor_uid, actor_gid)?;
            Ok(ino as i64)
        });
        let ino = match res {
            Ok(i) => i as u64,
            Err(e) => return Reply::Err(errno(&e)),
        };
        let view = self.read_view();
        let st = match view.getattr(ino, view.root()) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
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
        let nodeid = req.nodeid;
        let actor_uid = req.uid;
        let actor_gid = req.gid;
        let groups = crate::fuse::caller_groups(req.pid);
        let name = name.to_vec();
        let perm = mode & 0o7777;
        let res = self.fs.inner.mutate(move |core| {
            crate::fuse::check_create_uid(core, actor_uid, actor_gid, &groups, nodeid, 0o3)?;
            let ino = core.mkdir(nodeid, &name, perm, actor_uid, actor_gid)?;
            Ok(ino as i64)
        });
        let ino = match res {
            Ok(i) => i as u64,
            Err(e) => return Reply::Err(errno(&e)),
        };
        let view = self.read_view();
        let st = match view.getattr(ino, view.root()) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        self.fs.inner.metrics.lock().mkdir += 1;
        self.fs.inner.record_lookup(ino);
        Reply::Entry(attr_from_stat(&st))
    }

    fn unlink(&self, req: &Req<'_>) -> Reply {
        if self.read_only {
            return Reply::Err(libc::EROFS);
        }
        let name = trim_name(req.payload);
        let nodeid = req.nodeid;
        let actor_uid = req.uid;
        let actor_gid = req.gid;
        let groups = crate::fuse::caller_groups(req.pid);
        let name = name.to_vec();
        let res = self.fs.inner.mutate(move |core| {
            crate::fuse::check_dir_write_uid(core, actor_uid, actor_gid, &groups, nodeid, 0o3)?;
            core.unlink(nodeid, &name)?;
            Ok(0)
        });
        match res {
            Ok(_) => {
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
        let nodeid = req.nodeid;
        let actor_uid = req.uid;
        let actor_gid = req.gid;
        let groups = crate::fuse::caller_groups(req.pid);
        let name = name.to_vec();
        let res = self.fs.inner.mutate(move |core| {
            crate::fuse::check_dir_write_uid(core, actor_uid, actor_gid, &groups, nodeid, 0o3)?;
            core.rmdir(nodeid, &name)?;
            Ok(0)
        });
        match res {
            Ok(_) => {
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
        let nodeid = req.nodeid;
        let actor_uid = req.uid;
        let actor_gid = req.gid;
        let groups = crate::fuse::caller_groups(req.pid);
        let oldname = oldname.to_vec();
        let newname = newname.to_vec();
        let res = self.fs.inner.mutate(move |core| {
            crate::fuse::check_dir_write_uid(core, actor_uid, actor_gid, &groups, nodeid, 0o3)?;
            crate::fuse::check_dir_write_uid(core, actor_uid, actor_gid, &groups, newdir, 0o3)?;
            core.rename(nodeid, &oldname, newdir, &newname, mode)?;
            Ok(0)
        });
        match res {
            Ok(_) => {
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
        let nodeid = req.nodeid;
        let actor_uid = req.uid;
        let actor_gid = req.gid;
        let groups = crate::fuse::caller_groups(req.pid);
        let newname = newname.to_vec();
        let res = self.fs.inner.mutate(move |core| {
            crate::fuse::check_dir_write_uid(core, actor_uid, actor_gid, &groups, nodeid, 0o3)?;
            core.link(oldino, nodeid, &newname)?;
            Ok(0)
        });
        if let Err(e) = res {
            return Reply::Err(errno(&e));
        }
        let view = self.read_view();
        let st = match view.getattr(oldino, view.root()) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
        self.fs.inner.metrics.lock().link += 1;
        self.fs.inner.record_lookup(oldino);
        Reply::Entry(attr_from_stat(&st))
    }

    fn open(&self, req: &Req<'_>) -> Reply {
        let flags = get_u32(req.op, 0) as i32;
        let view = self.read_view();
        let root = view.root();
        let st = match view.getattr(req.nodeid, root) {
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
        if !has_permission_grouped(
            req.uid,
            req.gid,
            &crate::fuse::caller_groups(req.pid),
            &st,
            mask,
        ) {
            return Reply::Err(libc::EACCES);
        }
        if self.read_only && mask & 0o2 != 0 {
            return Reply::Err(libc::EROFS);
        }
        if flags & libc::O_TRUNC != 0 && mask & 0o2 != 0 {
            // A truncating open is the only mutating part; route it through the
            // coordinator so it can share a batch's durability barrier.
            let attrs = SetAttr {
                size: Some(0),
                ..Default::default()
            };
            let ino_raw = req.nodeid;
            if let Err(e) = self.fs.inner.mutate(move |core| {
                core.setattr(ino_raw, &attrs)?;
                Ok(0)
            }) {
                return Reply::Err(errno(&e));
            }
        }
        let fh = self.fs.inner.register_file(req.nodeid, flags);
        let (open_flags, backing_id) = self.attach_passthrough(req.nodeid, flags, fh);
        let mut m = self.fs.inner.metrics.lock();
        m.opens += 1;
        m.open_handles += 1;
        drop(m);
        Reply::Open {
            fh,
            open_flags,
            backing_id,
        }
    }

    /// Decide whether this open can be served by the kernel and, if so, register
    /// a version-qualified backing image with the kernel and pin it to the file
    /// handle. Returns `(open_flags, backing_id)`: `FOPEN_PASSTHROUGH` with a
    /// positive backing id on success, or the ordinary open flags with `0`.
    ///
    /// Passthrough is deliberately conservative: it is offered only by a
    /// read-only historical core (whose files no ordinary descriptor can mutate),
    /// only for clean read-only opens, and never alongside direct I/O.
    fn attach_passthrough(&self, inode: u64, flags: i32, fh: u64) -> (u32, i32) {
        let ctrl = match &self.passthrough {
            Some(c) if c.enabled() => c,
            _ => return (self.open_flags(), 0),
        };
        if self.direct_io || (flags & libc::O_ACCMODE) != libc::O_RDONLY {
            return (self.open_flags(), 0);
        }
        let image = {
            let mut core = self.fs.inner.core.lock();
            match core.passthrough_backing(inode) {
                Ok(Some(image)) => image,
                Ok(None) => return (self.open_flags(), 0),
                Err(e) => {
                    ctrl.note_error(format!("materialize passthrough backing: {e}"));
                    return (self.open_flags(), 0);
                }
            }
        };
        match ctrl.attach(&image) {
            Some(id) => {
                self.fs.inner.set_handle_backing(fh, image.path.clone());
                self.stats.lock().passthrough_opens += 1;
                (FOPEN_PASSTHROUGH, id)
            }
            None => (self.open_flags(), 0),
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
        if !has_permission_grouped(
            req.uid,
            req.gid,
            &crate::fuse::caller_groups(req.pid),
            &st,
            0o4,
        ) {
            return Reply::Err(libc::EACCES);
        }
        match view.read_at(req.nodeid, root, offset, size) {
            Ok(data) => {
                let mut m = self.fs.inner.metrics.lock();
                m.reads += 1;
                m.byte_reads += data.len() as u64;
                drop(m);
                // A passthrough-served read never reaches here; this counter is
                // the daemon-side proof that a read did (or did not) engage the
                // handler.
                self.stats.lock().daemon_reads += 1;
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
        let write_flags = get_u32(req.op, 20);
        let handle = match self.fs.inner.handle(fh) {
            Some(h) if !h.is_dir => h,
            _ => return Reply::Err(libc::EBADF),
        };
        let nodeid = req.nodeid;
        let actor_uid = req.uid;
        let actor_gid = req.gid;
        let groups = crate::fuse::caller_groups(req.pid);
        let append = handle.flags & libc::O_APPEND != 0;
        let kill_flag = write_flags & FUSE_WRITE_KILL_SUIDGID != 0;
        // The payload is owned by the kernel for the duration of this call; the
        // job outlives the call, so it must own its bytes.
        let data = req.payload[..size.min(req.payload.len())].to_vec();
        // Everything that depends on the authoritative state — the permission
        // check, the O_APPEND end-of-file and the killpriv decision — is resolved
        // *inside* the job, under the core lock, so a concurrent append can never
        // observe a stale end-of-file. Routing through `Inner::mutate` also lets a
        // write share a group-commit batch's durability barrier.
        let res = self.fs.inner.mutate(move |core| {
            let root = core.root();
            let st = core.getattr(nodeid, root)?;
            if !has_permission_grouped(actor_uid, actor_gid, &groups, &st, 0o2) {
                return Err(OrfsError::PermissionDenied);
            }
            let effective = if append { st.size } else { offset };
            let kill_setid = kill_flag
                || (actor_uid != 0
                    && actor_uid != st.uid
                    && st.mode & (libc::S_ISUID | libc::S_ISGID) != 0);
            let n = core.write_at_killpriv(nodeid, effective, &data, kill_setid)?;
            Ok(n as i64)
        });
        match res {
            Ok(n) => {
                let mut m = self.fs.inner.metrics.lock();
                m.writes += 1;
                m.byte_writes += n as u64;
                drop(m);
                Reply::Write(n as u32)
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
        if let Some(h) = &removed {
            if let (Some(path), Some(ctrl)) = (&h.backing, &self.passthrough) {
                ctrl.release(path);
            }
        }
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
        if !has_permission_grouped(
            req.uid,
            req.gid,
            &crate::fuse::caller_groups(req.pid),
            &st,
            0o5,
        ) {
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
            backing_id: 0,
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
        if has_permission_grouped(
            req.uid,
            req.gid,
            &crate::fuse::caller_groups(req.pid),
            &st,
            bits,
        ) {
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
        let nodeid = req.nodeid;
        let actor_uid = req.uid;
        let actor_gid = req.gid;
        let groups = crate::fuse::caller_groups(req.pid);
        let name = name.to_vec();
        let perm = mode & 0o7777;
        let res = self.fs.inner.mutate(move |core| {
            crate::fuse::check_create_uid(core, actor_uid, actor_gid, &groups, nodeid, 0o3)?;
            let ino = core.create(nodeid, &name, perm, actor_uid, actor_gid)?;
            Ok(ino as i64)
        });
        let ino = match res {
            Ok(i) => i as u64,
            Err(e) => return Reply::Err(errno(&e)),
        };
        let view = self.read_view();
        let st = match view.getattr(ino, view.root()) {
            Ok(st) => st,
            Err(e) => return Reply::Err(errno(&e)),
        };
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
    /// The chosen queue-servicing topology (`single-loop` or `pool(...)`).
    pub servicing: String,
    /// Whether F2 threads were pinned to a dedicated CPU set.
    pub affinity: bool,
    /// The exact negotiated F2 capability set (ABI boundary included).
    pub capabilities: crate::fuse_uring::F2Capabilities,
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

    // -- queue servicing (Phase 26) ----------------------------------------
    /// Requests routed to the latency lane (metadata + small reads).
    pub fast_routed: u64,
    /// Requests routed to the bulk lane (large reads/writes).
    pub bulk_routed: u64,
    /// Worker threads in the latency lane (`0` for single-loop).
    pub workers_fast: u64,
    /// Worker threads in the bulk lane (`0` for single-loop).
    pub workers_bulk: u64,

    // -- concurrency instrumentation (Phase 47) ----------------------------
    /// Blocking ring waits issued by the servicing threads (`io_uring_enter`
    /// with `min_complete >= 1`). One per loop pass that had no buffered
    /// completion; the syscall count the transport really pays.
    pub wait_calls: u64,
    /// Cumulative nanoseconds parked inside those blocking ring waits.
    pub wait_ns: u64,
    /// Requests dispatched on a servicing thread (one per served request).
    pub dispatch_calls: u64,
    /// Cumulative nanoseconds spent inside the filesystem dispatch
    /// (`Dispatcher::serve`), excluding reply encoding and ring submission.
    pub dispatch_ns: u64,
    /// The largest number of completions reaped in a single `reap()`. This is
    /// the ring's observed pipeline depth: how many requests were already
    /// waiting when the servicer next looked at the completion queue.
    pub completions_max_per_reap: u64,
    /// Buffer/request ownership transfers between threads: jobs handed to a
    /// dispatch worker through the pool queue. `0` for the inline topologies
    /// (single-loop and queue-affine), which keep each entry local to one
    /// thread.
    pub handoffs: u64,
    /// Per-queue-group observations of the opt-in queue-affine topology: which
    /// queues each ring-owning thread serviced and how many requests it served.
    /// Empty for every other topology.
    pub queue_groups: Vec<QueueGroupStat>,

    // -- FUSE passthrough (Phase 21) ---------------------------------------
    /// The mount requested kernel passthrough (`--passthrough`).
    pub passthrough_requested: bool,
    /// The kernel offered `FUSE_PASSTHROUGH` at `INIT` and it was negotiated.
    pub passthrough_negotiated: bool,
    /// Opens that attached a kernel backing (`FOPEN_PASSTHROUGH` + a backing id).
    pub passthrough_opens: u64,
    /// Backing files registered with the kernel via `FUSE_DEV_IOC_BACKING_OPEN`.
    pub passthrough_registered: u64,
    /// Attaches that reused an already-registered backing (refcount bump).
    pub passthrough_reused: u64,
    /// Opens that fell back to daemon-served reads.
    pub passthrough_fallbacks: u64,
    /// Backing registrations released via `FUSE_DEV_IOC_BACKING_CLOSE`.
    pub passthrough_releases: u64,
    /// Total logical bytes materialized into backing images.
    pub passthrough_bytes: u64,
    /// `FUSE_READ` requests actually served by the daemon (a passthrough-served
    /// read never increments this).
    pub daemon_reads: u64,
    /// The most recent passthrough fallback reason, if any.
    pub passthrough_last_error: Option<String>,
}

/// One queue-affine servicer's observed share of the traffic.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct QueueGroupStat {
    /// The servicer thread's index.
    pub group: usize,
    /// The system queue ids this ring-owning thread registered and serviced.
    pub qids: Vec<u16>,
    /// Requests this group served over the mount's lifetime.
    pub served: u64,
}

/// The kernel FUSE-passthrough controller for one native session.
///
/// It owns a duplicate of the session's `/dev/fuse` descriptor (an ioctl on any
/// descriptor referring to the same connection is equivalent), registers backing
/// images with `FUSE_DEV_IOC_BACKING_OPEN`, and refcount-pins each registration
/// for the open-file lifetime, releasing the kernel reference on the last
/// `RELEASE` via `FUSE_DEV_IOC_BACKING_CLOSE`.
struct PassthroughControl {
    /// A duplicate of the session's `/dev/fuse` fd, used for the ioctls.
    fd: OwnedFd,
    /// Whether `FUSE_PASSTHROUGH` was negotiated for this connection.
    enabled: bool,
    /// Live registrations keyed by backing-image path, with open refcounts.
    cache: Mutex<HashMap<PathBuf, BackingEntry>>,
    /// Shared native counters (also read by the court as engagement proof).
    stats: Arc<Mutex<NativeStats>>,
}

struct BackingEntry {
    backing_id: i32,
    /// The userspace descriptor used at registration. The kernel holds its own
    /// `struct file` reference; keeping ours pinned mirrors the open lifetime.
    #[allow(dead_code)]
    image_fd: OwnedFd,
    refs: usize,
}

impl PassthroughControl {
    fn new(fd: OwnedFd, enabled: bool, stats: Arc<Mutex<NativeStats>>) -> PassthroughControl {
        PassthroughControl {
            fd,
            enabled,
            cache: Mutex::new(HashMap::new()),
            stats,
        }
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    /// Register (or reuse) a backing image and pin it for one open. Returns the
    /// kernel `backing_id` on success, or `None` (recording the reason) so the
    /// caller falls back to ordinary daemon-served reads.
    fn attach(&self, image: &crate::passthrough::BackingImage) -> Option<i32> {
        let mut cache = self.cache.lock();
        if let Some(entry) = cache.get_mut(&image.path) {
            entry.refs += 1;
            self.stats.lock().passthrough_reused += 1;
            return Some(entry.backing_id);
        }
        let file = match OpenOptions::new().read(true).open(&image.path) {
            Ok(f) => f,
            Err(e) => {
                self.note_error(format!("open backing image {}: {e}", image.path.display()));
                return None;
            }
        };
        let image_fd: OwnedFd = file.into();
        let mut map = FuseBackingMap {
            fd: image_fd.as_raw_fd(),
            flags: 0,
            padding: 0,
        };
        // SAFETY: `self.fd` is a live `/dev/fuse` descriptor owned by this
        // controller; `map` is a `#[repr(C)]` POD matching `struct
        // fuse_backing_map`; the request number is transcribed from the running
        // kernel's `linux/fuse.h` and checked by a unit test. The ioctl copies
        // the map in and returns the backing id (>= 1) or a negative errno.
        let rc = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                FUSE_DEV_IOC_BACKING_OPEN,
                &mut map as *mut FuseBackingMap,
            )
        };
        if rc < 1 {
            let err = io::Error::last_os_error();
            self.note_error(format!(
                "FUSE_DEV_IOC_BACKING_OPEN failed for {}: {err}",
                image.path.display()
            ));
            return None;
        }
        let backing_id = rc as i32;
        cache.insert(
            image.path.clone(),
            BackingEntry {
                backing_id,
                image_fd,
                refs: 1,
            },
        );
        {
            let mut s = self.stats.lock();
            s.passthrough_registered += 1;
            s.passthrough_bytes = s.passthrough_bytes.saturating_add(image.size);
        }
        Some(backing_id)
    }

    /// Release one open's pin; when the last pin goes, release the kernel
    /// registration so the backing file is no longer held by the kernel.
    fn release(&self, path: &Path) {
        let mut cache = self.cache.lock();
        let drop_it = match cache.get_mut(path) {
            Some(entry) => {
                entry.refs = entry.refs.saturating_sub(1);
                entry.refs == 0
            }
            None => false,
        };
        if drop_it {
            if let Some(entry) = cache.remove(path) {
                self.close_id(entry.backing_id);
                self.stats.lock().passthrough_releases += 1;
            }
        }
    }

    fn close_id(&self, backing_id: i32) {
        let mut id = backing_id;
        // SAFETY: `self.fd` is live; the request number is transcribed from the
        // running kernel's `linux/fuse.h`. The kernel reads a `uint32_t` id.
        let _ = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                FUSE_DEV_IOC_BACKING_CLOSE,
                &mut id as *mut i32,
            )
        };
    }

    /// Release every live registration (called as the session shuts down, while
    /// the connection is still open).
    fn close_all(&self) {
        let mut cache = self.cache.lock();
        for (_, entry) in cache.drain() {
            self.close_id(entry.backing_id);
        }
    }

    fn note_error(&self, msg: String) {
        let mut s = self.stats.lock();
        s.passthrough_fallbacks += 1;
        s.passthrough_last_error = Some(msg);
    }
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
///
/// `FUSE_INIT_EXT` must be set in `flags` for the kernel to read `flags2`
/// (`process_init_reply`). When `passthrough` is requested we additionally set
/// `FUSE_PASSTHROUGH` in `flags2` and advertise a `max_stack_depth > 0`; the
/// kernel then enables `fc->passthrough`. We never set `FUSE_WRITEBACK_CACHE`,
/// which cannot coexist with passthrough.
fn encode_init_reply(unique: u64, minor: u32, passthrough: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 64);
    put_u32(&mut out, 16 + 64);
    put_u32(&mut out, 0);
    put_u64(&mut out, unique);
    // struct fuse_init_out
    put_u32(&mut out, 7); // major
    put_u32(&mut out, minor); // minor
    put_u32(&mut out, MAX_READAHEAD); // max_readahead
    put_u32(
        &mut out,
        FUSE_INIT_EXT
            | FUSE_ASYNC_READ
            | FUSE_BIG_WRITES
            | FUSE_HANDLE_KILLPRIV
            | FUSE_HANDLE_KILLPRIV_V2,
    ); // flags
    put_u16(&mut out, 12); // max_background
    put_u16(&mut out, 9); // congestion_threshold
    put_u32(&mut out, MAX_WRITE); // max_write
    put_u32(&mut out, 1); // time_gran
    put_u16(&mut out, 32); // max_pages
    put_u16(&mut out, 0); // map_alignment
    put_u32(
        &mut out,
        FUSE_OVER_IO_URING_FLAGS2
            | if passthrough {
                FUSE_PASSTHROUGH_FLAGS2
            } else {
                0
            },
    ); // flags2
    put_u32(
        &mut out,
        if passthrough {
            PASSTHROUGH_MAX_STACK_DEPTH
        } else {
            0
        },
    ); // max_stack_depth
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
    /// The mount requested FUSE passthrough.
    passthrough: bool,
    /// The kernel offered `FUSE_PASSTHROUGH` at `INIT`, so passthrough is usable.
    passthrough_enabled: bool,
    /// The kernel offered `FUSE_HAS_IO_URING_BUFPOOL` at `INIT` (FUSE ABI 7.46+).
    /// This is the runtime gate for the forward-compatible `ADD_QUEUE`/
    /// `ADD_BUFPOOL`/zero-copy commands.
    kernel_offered_bufpool: bool,
    /// Whether the process holds `CAP_SYS_ADMIN` (needed for zero-copy).
    cap_sys_admin: bool,
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
    let offered_flags = (in_flags as u64) | ((in_flags2 as u64) << 32);
    let offered = offered_flags & crate::fuse_uring::FUSE_OVER_IO_URING != 0;
    if !offered {
        return Err(fail(format!(
            "kernel did not offer FUSE_OVER_IO_URING at INIT (FUSE ABI 7.{kernel_minor}); \
             fuse_uring_enabled() is false for this connection"
        )));
    }
    // Forward-compat capability (Phase 26): the buffer-pool extension is present
    // iff the kernel sets FUSE_HAS_IO_URING_BUFPOOL at INIT. When it is absent
    // (FUSE ABI 7.45 does not set it) the ADD_QUEUE / ADD_BUFPOOL / zero-copy
    // commands stay inert and are never reported as available.
    let kernel_offered_bufpool = offered_flags & crate::fuse_uring::FUSE_HAS_IO_URING_BUFPOOL != 0;
    let cap_sys_admin = crate::fuse_uring::has_cap_sys_admin();
    // FUSE passthrough (Phase 21): engage only when requested and offered. The
    // kernel sets the capability bit iff CONFIG_FUSE_PASSTHROUGH is enabled.
    let passthrough = opts.passthrough;
    let passthrough_enabled = passthrough && (offered_flags & FUSE_PASSTHROUGH != 0);
    if passthrough && !passthrough_enabled {
        eprintln!(
            "orfs: kernel did not offer FUSE_PASSTHROUGH at INIT (FUSE ABI \
             7.{kernel_minor}); passthrough disabled, reads fall back to the daemon"
        );
    }
    let reply = encode_init_reply(unique, kernel_minor, passthrough_enabled);
    write_all(raw, &reply).map_err(|e| fail(format!("write FUSE_INIT reply: {e}")))?;

    let num_queues = possible_cpu_count();
    let capabilities = FuseUringNegotiation {
        kernel_offered: true,
        kernel_offered_bufpool,
        kernel_abi: Some((7, kernel_minor)),
        accepted: true,
        engaged: false,
        cap_sys_admin,
        num_queues,
        ..Default::default()
    }
    .capabilities();
    let environment = Arc::new(Mutex::new(NativeEnvironment {
        kernel_release: crate::capabilities::probe().kernel_release,
        fuse_abi_major: 7,
        fuse_abi_minor: kernel_minor,
        num_queues,
        max_write: MAX_WRITE,
        payload_buf: PAYLOAD_BUF,
        mount_options,
        servicing: opts.f2_servicing.describe(),
        affinity: opts.f2_affinity,
        capabilities,
    }));
    Ok(Prepared {
        fd,
        mountpoint: mountpoint.to_path_buf(),
        options: *opts,
        kernel_minor,
        environment,
        stats: Arc::new(Mutex::new(NativeStats {
            passthrough_requested: passthrough,
            passthrough_negotiated: passthrough_enabled,
            ..NativeStats::default()
        })),
        stop: Arc::new(AtomicBool::new(false)),
        passthrough,
        passthrough_enabled,
        kernel_offered_bufpool,
        cap_sys_admin,
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
        // Probe-only negotiation: build the capability view, pick the queue plan,
        // and register over the plan the kernel actually offered.
        let probe_neg = FuseUringNegotiation {
            kernel_offered: true,
            kernel_offered_bufpool: prepared.kernel_offered_bufpool,
            kernel_abi: Some((7, prepared.kernel_minor)),
            accepted: true,
            engaged: true,
            cap_sys_admin: prepared.cap_sys_admin,
            ..Default::default()
        };
        let plan = crate::fuse_uring::plan_queues(&probe_neg, false);
        let (_ring, _entries, _probe, num_queues) = register_all_entries(raw, plan)?;
        Ok(FuseUringNegotiation {
            kernel_offered: true,
            kernel_offered_bufpool: prepared.kernel_offered_bufpool,
            kernel_abi: Some((7, prepared.kernel_minor)),
            accepted: true,
            engaged: true,
            cap_sys_admin: prepared.cap_sys_admin,
            num_queues,
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
    metrics: Arc<Mutex<crate::fuse::Metrics>>,
    /// The group-commit instrumentation cell, when the mount enabled grouping.
    group_commit: Option<Arc<crate::group_commit::GcCounters>>,
}

impl NativeMount {
    /// The live negotiation result (always `engaged == true` for a native mount).
    pub fn negotiation(&self) -> FuseUringNegotiation {
        self.negotiation.lock().clone()
    }

    /// The shared daemon-operation counters (same ones the classical transport
    /// uses), so the mount can report daemon-reaching requests uniformly.
    pub fn metrics_cell(&self) -> Arc<Mutex<crate::fuse::Metrics>> {
        Arc::clone(&self.metrics)
    }

    /// The group-commit instrumentation cell, when the mount enabled grouping.
    pub(crate) fn group_commit_cell(&self) -> Option<Arc<crate::group_commit::GcCounters>> {
        self.group_commit.clone()
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
        let metrics = fs.metrics_cell();
        let group_commit = fs.group_commit_counters();
        let stats = Arc::clone(&self.stats);
        // The passthrough controller holds its own `/dev/fuse` duplicate so the
        // ioctls do not race with the session's reads on the original fd.
        let passthrough = if self.passthrough {
            match dup_owned(self.fd.as_raw_fd()) {
                Ok(fd) => Some(Arc::new(PassthroughControl::new(
                    fd,
                    self.passthrough_enabled,
                    Arc::clone(&stats),
                ))),
                Err(e) => {
                    eprintln!("orfs: passthrough controller fd dup failed: {e}");
                    None
                }
            }
        } else {
            None
        };
        let dispatcher = Arc::new(Dispatcher {
            fs: Arc::clone(&fs),
            entry_ttl: options.entry_ttl,
            attr_ttl: options.attr_ttl,
            read_only: options.read_only,
            direct_io: options.direct_io,
            passthrough,
            stats: Arc::clone(&stats),
        });
        let stop = Arc::clone(&self.stop);
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
            servicing: options.f2_servicing,
            affinity: options.f2_affinity,
            inflight: Vec::new(),
            pool: None,
            scratch: Vec::new(),
            kernel_offered_bufpool: self.kernel_offered_bufpool,
            cap_sys_admin: self.cap_sys_admin,
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
                metrics,
                group_commit,
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

/// Duplicate a raw fd into an [`OwnedFd`] (closed when dropped).
fn dup_owned(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `dup` duplicates a valid fd; the result is a fresh owned fd.
    let n = unsafe { libc::dup(fd) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `n` is a fresh, valid descriptor we now exclusively own.
        Ok(unsafe { OwnedFd::from_raw_fd(n) })
    }
}

/// Create the SQE128 ring bound to `fd`, register one entry per CPU queue, and
/// probe for an immediate `REGISTER` rejection.
///
/// `plan` selects the queue-creation interface. On FUSE ABI 7.45 the kernel never
/// offers the buffer-pool extension, so `plan` is always [`QueuePlan::Baseline`]
/// and the single-entry-per-queue `REGISTER` path below is the only one executed.
/// The [`QueuePlan::Modern`] branch issues `ADD_QUEUE`/`ADD_BUFPOOL` and **degrades
/// to the baseline** on any rejection, so a mis-detected capability can never
/// break a mount and can never silently claim zero-copy.
///
/// Must be called on the thread that will wait for completions: the kernel
/// delivers `URING_CMD` completions as task-work to the task that submitted the
/// command, so the submitting and waiting tasks must be the same.
fn register_all_entries(
    fd: RawFd,
    plan: QueuePlan,
) -> Result<(FuseUringRing, Vec<EntryState>, Vec<RingCompletion>, usize), String> {
    let num_queues = possible_cpu_count();
    let qids: Vec<u16> = (0..num_queues as u16).collect();
    let (ring, entries, probe) = register_qids(fd, plan, &qids)?;
    Ok((ring, entries, probe, num_queues))
}

/// Register one ring entry per queue in `qids` on a fresh `io_uring` instance.
///
/// `qids` is the exact set of queues this ring services. The all-queues caller
/// passes `0..possible_cpu_count()`; the opt-in queue-affine topology passes a
/// disjoint subset so each ring-owning thread services only its own queues. The
/// `user_data` tag is the entry's position within this ring (`i + 1`), which is
/// what [`SessionLoop::handle_completion`]/[`QueueGroup::handle_completion`]
/// decode back into an index, so a subset is indexed independently of the
/// global qid numbering.
fn register_qids(
    fd: RawFd,
    plan: QueuePlan,
    qids: &[u16],
) -> Result<(FuseUringRing, Vec<EntryState>, Vec<RingCompletion>), String> {
    let mut ring =
        FuseUringRing::new(fd, IO_URING_DEPTH).map_err(|e| format!("io_uring setup: {e}"))?;
    // The baseline interface allows several registered entries per queue, which
    // raises the number of requests the kernel can keep in flight on a queue
    // (and therefore the pipeline depth available to a servicer). The modern
    // buffer-pool interface keeps one entry per queue.
    let per_queue = if matches!(plan, QueuePlan::Baseline) {
        entries_per_queue()
    } else {
        1
    };
    // Never build more entries than the submission ring can hold at once (every
    // entry costs one `REGISTER` SQE at setup).
    let per_queue = per_queue.min((IO_URING_DEPTH as usize / qids.len().max(1)).max(1));
    let mut entries: Vec<EntryState> = Vec::with_capacity(qids.len() * per_queue);
    let mut ud = 1u64;
    for &qid in qids {
        for _ in 0..per_queue {
            entries.push(EntryState::new(qid, ud));
            ud += 1;
        }
    }
    // Forward-compat (guarded): only a kernel that offered FUSE_HAS_IO_URING_BUFPOOL
    // reaches this branch. Every command is runtime-checked; a rejection degrades
    // to the baseline path below rather than failing the mount.
    if let QueuePlan::Modern { zero_copy } = plan {
        let mut ok = true;
        for e in &entries {
            match ring.add_queue(e.qid, zero_copy) {
                Ok(res) if res >= 0 => {}
                _ => {
                    ok = false;
                    break;
                }
            }
            if zero_copy {
                // The payload buffer backs the per-queue buffer pool.
                let base = e.payload.as_ptr() as u64;
                match ring.add_bufpool(e.qid, base, e.payload.len() as u32, None) {
                    Ok(res) if res >= 0 => {}
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
        }
        if !ok {
            eprintln!(
                "orfs: forward-compat ADD_QUEUE/ADD_BUFPOOL was rejected by the kernel; \
                 degrading to the baseline REGISTER interface"
            );
        }
    }
    // Baseline register: one entry per queue (the kernel creates each queue lazily
    // and only starts routing requests once every queue has an available entry,
    // `is_ring_ready`).
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
            "FUSE_IO_URING_CMD_REGISTER was rejected by the kernel ({failures} of {} \
             SQEs failed; first errno {sample}); the raw-SQE iovec path (`sqe->len == 2`) did not take",
            qids.len()
        ));
    }
    Ok((ring, entries, probe))
}

/// The number of registered entries per queue for the baseline interface, read
/// from `ORFS_F2_ENTRIES_PER_QUEUE` (default `1`). More entries per queue raise
/// the ring's in-flight depth; `1` preserves the measured Phase-15..26
/// behaviour exactly.
fn entries_per_queue() -> usize {
    std::env::var("ORFS_F2_ENTRIES_PER_QUEUE")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .map(|n| n.clamp(1, 32))
        .unwrap_or(1)
}

/// The number of ring-owning servicer threads for the opt-in **queue-affine**
/// topology, read from `ORFS_F2_RINGS`. `0`, absent, or unparseable disables it
/// (the default), leaving the measured `single-loop` / `pool` behaviour intact.
/// Values above the queue count are clamped to it by the caller.
fn affine_ring_count() -> usize {
    std::env::var("ORFS_F2_RINGS")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Queue servicing: a bounded, workload-aware dispatch worker pool (Phase 26)
// ---------------------------------------------------------------------------

/// The route a request takes through the pool: the *latency* lane (metadata and
/// small reads) or the *bulk* lane (large reads and writes). The lanes have
/// dedicated workers, so a small metadata op never queues behind a large read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    Fast,
    Bulk,
}

/// A read or write at least this large is routed to the bulk lane.
const BULK_THRESHOLD: usize = 64 * 1024;

/// A stable pointer to one registered ring entry, handed to a dispatch worker.
///
/// # Safety invariant
///
/// The pointed-to `EntryState` lives in the session's `entries: Vec<EntryState>`
/// for the whole mount; the `Vec` is never resized after setup, so its buffer
/// address is stable (as are the `AlignedBuffer` allocations it owns). A pointer
/// is handed out **only** while `inflight[idx]` is `true`, and the session thread
/// then neither reads nor writes `entries[idx]` — and never submits
/// `COMMIT_AND_FETCH` for it — until the matching [`Done`] returns. The kernel
/// does not touch the entry's buffers again until that `COMMIT_AND_FETCH`, so the
/// worker has exclusive access for the whole job. The `mpsc` handoff of `Done`
/// supplies the happens-before edge for the worker's reply writes.
struct EntryPtr(*mut EntryState);
// SAFETY: see the type-level invariant. The session transfers exclusive access
// for the duration of one job and reclaims it only after the job returns.
unsafe impl Send for EntryPtr {}

/// One unit of dispatch work: which entry, and the lane it runs on.
struct Job {
    idx: usize,
    entry: EntryPtr,
    lane: Lane,
}

/// What a worker hands back: everything the session thread needs to re-arm the
/// entry after the reply has been staged into its registered buffers.
struct Done {
    idx: usize,
    qid: u16,
    ud: u64,
    commit_id: u64,
    destroy: bool,
    reply_len: u64,
}

/// One lane's jobs and its shutdown flag, guarded together by a single mutex.
///
/// Keeping `closed` *inside* the locked state is what makes the condition
/// variable lossless: a waiter checks the queue and `closed` under the same lock
/// it will `wait` on, and [`JobQueue::close`] flips `closed` and notifies while
/// holding that lock. A worker therefore cannot observe `closed == false` and
/// then park after the wakeup has already been sent.
#[derive(Default)]
struct LaneState {
    jobs: VecDeque<Job>,
    closed: bool,
}

/// Two-lane job queues with condition variables (one waiter set per lane).
struct JobQueue {
    fast: Mutex<LaneState>,
    bulk: Mutex<LaneState>,
    fast_cv: Condvar,
    bulk_cv: Condvar,
}

impl JobQueue {
    fn new() -> JobQueue {
        JobQueue {
            fast: Mutex::new(LaneState::default()),
            bulk: Mutex::new(LaneState::default()),
            fast_cv: Condvar::new(),
            bulk_cv: Condvar::new(),
        }
    }

    /// The locked state and condition variable belonging to `lane`.
    fn lane(&self, lane: Lane) -> (&Mutex<LaneState>, &Condvar) {
        match lane {
            Lane::Fast => (&self.fast, &self.fast_cv),
            Lane::Bulk => (&self.bulk, &self.bulk_cv),
        }
    }

    fn push(&self, job: Job) {
        let (state, cv) = self.lane(job.lane);
        let mut guard = state.lock();
        guard.jobs.push_back(job);
        // Notify while still holding the lock: the queue-nonempty predicate and
        // the wakeup are observed through the same mutex, so a worker that saw an
        // empty queue is always woken (it holds the lock until it parks).
        cv.notify_one();
    }

    /// Block until a job is available on `lane`, or `None` once the queue closes.
    fn pop(&self, lane: Lane) -> Option<Job> {
        let (state, cv) = self.lane(lane);
        let mut guard = state.lock();
        loop {
            if let Some(job) = guard.jobs.pop_front() {
                return Some(job);
            }
            if guard.closed {
                return None;
            }
            cv.wait(&mut guard);
        }
    }

    fn close(&self) {
        // Flip `closed` and wake every waiter while holding the lane mutex. A
        // worker that observed `closed == false` still holds the lock until it
        // parks in `wait`, and `close` cannot notify until it acquires that same
        // lock — by which point the worker is parked and the wakeup is delivered.
        // This closes the lost-wakeup window the HEAD audit recorded.
        for (state, cv) in [(&self.fast, &self.fast_cv), (&self.bulk, &self.bulk_cv)] {
            let mut guard = state.lock();
            guard.closed = true;
            cv.notify_all();
        }
    }
}

/// A bounded pool of dispatch workers. The workers run the filesystem dispatch
/// and stage the reply into the entry's registered buffers; they never touch the
/// ring (the session thread alone submits SQEs, because the kernel delivers
/// URING_CMD completions as task-work to the submitting task).
struct WorkerPool<C: OrfsCore + Send + 'static> {
    queue: Arc<JobQueue>,
    done_rx: Receiver<Done>,
    threads: Vec<std::thread::JoinHandle<()>>,
    _marker: std::marker::PhantomData<C>,
}

impl<C: OrfsCore + Send + 'static> WorkerPool<C> {
    fn try_done(&self) -> Option<Done> {
        self.done_rx.try_recv().ok()
    }

    fn wait_done(&self, timeout: Duration) -> Option<Done> {
        self.done_rx.recv_timeout(timeout).ok()
    }
}

impl<C: OrfsCore + Send + 'static> Drop for WorkerPool<C> {
    fn drop(&mut self) {
        // Close the queues (waking every worker) and wait for in-flight jobs to
        // finish, so no worker still holds an `EntryPtr` when the session tears
        // the ring and entries down.
        self.queue.close();
        for h in self.threads.drain(..) {
            let _ = h.join();
        }
    }
}

/// The dispatch worker entry point: pop jobs for `lane` until the queue closes,
/// serving each and reporting the result on `done_tx`.
fn worker_loop<C: OrfsCore + Send + 'static>(
    lane: Lane,
    queue: Arc<JobQueue>,
    done_tx: Sender<Done>,
    dispatcher: Arc<Dispatcher<C>>,
    affinity: Option<usize>,
) {
    if let Some(cpu) = affinity {
        pin_to_cpu(cpu);
    }
    // Reused across jobs so reply encoding allocates at most once per worker.
    let mut scratch = Vec::with_capacity(8 * 1024);
    while let Some(job) = queue.pop(lane) {
        let done = serve_job(&dispatcher, &job, &mut scratch);
        if done_tx.send(done).is_err() {
            break;
        }
    }
}

/// Serve one job: parse the request out of the entry's registered buffers,
/// dispatch it, encode the reply into a reusable buffer, and write it back into
/// the entry — byte-for-byte as the single-loop path does.
fn serve_job<C: OrfsCore + Send + 'static>(
    dispatcher: &Dispatcher<C>,
    job: &Job,
    scratch: &mut Vec<u8>,
) -> Done {
    // SAFETY: the session handed us exclusive access to this entry for the whole
    // job (see `EntryPtr`); no other thread touches it until `Done` returns.
    let e = unsafe { &mut *job.entry.0 };
    let (qid, ud, commit_id, unique, opcode, payload_sz) = {
        let hdr = e.header.as_slice();
        (
            e.qid,
            e.ud,
            get_u64(hdr, 264),
            get_u64(hdr, 8),
            get_u32(hdr, 4),
            (clamp_payload_sz(get_u32(hdr, 272), e.payload.len())),
        )
    };
    let destroy = opcode == FUSE_DESTROY;
    let reply = if destroy {
        Reply::Empty
    } else {
        let hdr = e.header.as_slice();
        let req = Req {
            opcode,
            nodeid: get_u64(hdr, 16),
            uid: get_u32(hdr, 24),
            gid: get_u32(hdr, 28),
            pid: get_u32(hdr, 32),
            op: &hdr[128..256],
            payload: &e.payload.as_slice()[..payload_sz],
        };
        dispatcher.serve(&req)
    };
    let err = reply.encode_into(scratch, dispatcher.entry_ttl, dispatcher.attr_ttl);
    let reply_len = scratch.len() as u64;
    write_reply(e, unique, err, scratch);
    Done {
        idx: job.idx,
        qid,
        ud,
        commit_id,
        destroy,
        reply_len,
    }
}

/// Pin the calling thread to `cpu` (best-effort; failures are ignored). Used to
/// dedicate a CPU set to F2 so background manifestation does not share it.
fn pin_to_cpu(cpu: usize) {
    // A CPU mask covers `MAX_CPUS` bits (the kernel's `CPU_SETSIZE`); the byte
    // array below is exactly that size, so the kernel accepts it as a `cpu_set_t`.
    const MAX_CPUS: usize = 1024;
    if cpu >= MAX_CPUS {
        return;
    }
    let mut mask = [0u8; MAX_CPUS / 8];
    mask[cpu / 8] |= 1 << (cpu % 8);
    // SAFETY: `mask` is a live, fully-owned byte array of exactly `MAX_CPUS / 8`
    // bytes; the kernel interprets it as a little-endian bitmask of that size and
    // never retains the pointer past the call. `sched_setaffinity` reads only
    // `mask.len()` bytes.
    unsafe {
        let _ = libc::sched_setaffinity(0, mask.len(), mask.as_ptr().cast::<libc::cpu_set_t>());
    }
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
    /// The chosen queue-servicing topology (single loop vs bounded worker pool).
    servicing: F2Servicing,
    /// Whether to pin the F2 session/worker threads to a dedicated CPU set.
    affinity: bool,
    /// Per-entry busy flag: `true` while a dispatch worker owns the entry.
    inflight: Vec<bool>,
    /// The dispatch worker pool (absent for [`F2Servicing::Single`]).
    pool: Option<WorkerPool<C>>,
    /// A reusable reply-encoding buffer for the single-loop path.
    scratch: Vec<u8>,
    /// Whether the kernel offered the buffer-pool extension (`FUSE_HAS_IO_URING_BUFPOOL`).
    kernel_offered_bufpool: bool,
    /// Whether the process holds `CAP_SYS_ADMIN`.
    cap_sys_admin: bool,
}

impl<C: OrfsCore + Send + 'static> SessionLoop<C> {
    /// Create the ring, register one entry per CPU queue, and probe for an
    /// immediate `REGISTER` rejection. Runs on the session thread.
    fn setup(&mut self) -> Result<(), String> {
        let raw = self.fd.as_raw_fd();
        // Decide the queue-creation interface from the negotiated capabilities.
        // At FUSE ABI 7.45 the buffer-pool extension is absent, so this is always
        // the baseline interface; `ADD_QUEUE`/`ADD_BUFPOOL` stay inert.
        let plan_neg = FuseUringNegotiation {
            kernel_offered: true,
            kernel_offered_bufpool: self.kernel_offered_bufpool,
            kernel_abi: Some((7, self.kernel_minor)),
            accepted: true,
            engaged: true,
            cap_sys_admin: self.cap_sys_admin,
            ..Default::default()
        };
        let plan = crate::fuse_uring::plan_queues(&plan_neg, self.dispatcher.fs.options.zero_copy);
        let (ring, entries, probe, num_queues) = register_all_entries(raw, plan)?;
        let negotiation = FuseUringNegotiation {
            kernel_offered: true,
            kernel_offered_bufpool: self.kernel_offered_bufpool,
            kernel_abi: Some((7, self.kernel_minor)),
            accepted: true,
            engaged: true,
            reason: None,
            cap_sys_admin: self.cap_sys_admin,
            num_queues,
        };
        let capabilities = negotiation.capabilities();
        self.stats.lock().register_sqes = entries.len() as u64;
        {
            let mut env = self.environment.lock();
            env.num_queues = num_queues;
            env.capabilities = capabilities.clone();
            env.servicing = self.servicing.describe();
            env.affinity = self.affinity;
        }
        self.dispatcher.fs.record_negotiation(negotiation);
        self.inflight = vec![false; entries.len()];
        self.ring = Some(ring);
        self.entries = entries;
        self.pending = probe;
        Ok(())
    }

    /// Start the dispatch worker pool, if the chosen topology uses one.
    fn start_pool(&mut self) {
        let (fast, bulk) = match self.servicing {
            F2Servicing::Single => return,
            F2Servicing::Pool { fast, bulk } => {
                let nq = self.entries.len().max(1);
                (fast.clamp(1, nq), bulk.clamp(1, nq))
            }
        };
        let queue = Arc::new(JobQueue::new());
        let (done_tx, done_rx) = std::sync::mpsc::channel::<Done>();
        let cpus = possible_cpu_count().max(1);
        let mut cpu = 0usize;
        let mut threads = Vec::new();
        for (lane, count) in [(Lane::Fast, fast), (Lane::Bulk, bulk)] {
            for _ in 0..count {
                let q = Arc::clone(&queue);
                let tx = done_tx.clone();
                let dispatcher = Arc::clone(&self.dispatcher);
                let affinity = if self.affinity {
                    let c = cpu % cpus;
                    cpu += 1;
                    Some(c)
                } else {
                    None
                };
                let name = match lane {
                    Lane::Fast => "orfs-f2-fast",
                    Lane::Bulk => "orfs-f2-bulk",
                };
                if let Ok(h) = std::thread::Builder::new()
                    .name(name.to_string())
                    .spawn(move || worker_loop(lane, q, tx, dispatcher, affinity))
                {
                    threads.push(h);
                }
            }
        }
        drop(done_tx);
        {
            let mut s = self.stats.lock();
            s.workers_fast = fast as u64;
            s.workers_bulk = bulk as u64;
        }
        self.pool = Some(WorkerPool {
            queue,
            done_rx,
            threads,
            _marker: std::marker::PhantomData,
        });
    }

    fn run(mut self) -> Result<(), String> {
        // Opt-in queue-affine topology: one ring-owning servicer thread per queue
        // group, above the ring's own queue interface. It is inert unless
        // `ORFS_F2_RINGS` names >1 rings, so the measured `single-loop` (and the
        // selectable `pool`) remain the default.
        let rings = affine_ring_count();
        if rings > 1 && matches!(self.servicing, F2Servicing::Single) {
            return self.run_affine(rings);
        }
        let setup = self.setup();
        let ok = setup.is_ok();
        if let Some(tx) = self.setup_tx.take() {
            let _ = tx.send(setup);
        }
        if !ok {
            return Ok(());
        }
        if self.affinity {
            pin_to_cpu(0);
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
        self.start_pool();

        loop {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            // 1. Reap ring completions and route them (non-blocking when a pool
            //    is active, so the session thread stays responsive to workers).
            let routed = match self.pump_ring() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("orfs: F2 ring wait failed: {e}");
                    break;
                }
            };
            // 2. Collect finished jobs and re-arm their entries.
            let finished = match self.drain_done() {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("orfs: F2 re-arm failed: {e}");
                    break;
                }
            };
            // 3. Submit any queued SQEs (REGISTER / COMMIT_AND_FETCH).
            if let Some(ring) = self.ring.as_mut() {
                if let Err(e) = ring.submit() {
                    eprintln!("orfs: F2 submit failed: {e}");
                    break;
                }
            }
            // 4. Block appropriately when the pass made no progress.
            if self.pool.is_none() || routed || finished {
                continue;
            }
            if self.inflight_count() > 0 {
                // Entries are busy in workers: wait briefly for one to finish,
                // then loop to pick up the result and any new ring completion.
                if let Some(pool) = self.pool.as_ref() {
                    if let Some(d) = pool.wait_done(Duration::from_micros(250)) {
                        if let Err(e) = self.finish(d) {
                            eprintln!("orfs: F2 commit failed: {e}");
                            break;
                        }
                    }
                }
            } else {
                // Nothing in flight: block on the ring for the next request.
                let comps = match self
                    .ring
                    .as_mut()
                    .expect("ring initialized")
                    .submit_and_wait_timeout(1, Duration::from_millis(200))
                {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("orfs: F2 ring wait failed: {e}");
                        break;
                    }
                };
                for c in comps {
                    if let Err(e) = self.handle_completion(c) {
                        eprintln!("orfs: F2 request handling failed: {e}");
                    }
                }
            }
        }

        // Dropping the pool closes the queues and joins the workers before the
        // ring and entries are torn down (so no worker still holds an EntryPtr).
        self.pool = None;
        if let Some(ring) = self.ring.as_mut() {
            ring.shutdown();
        }
        // Release every live passthrough registration while the connection is
        // still open, so the kernel drops its backing-file references cleanly.
        if let Some(ctrl) = &self.dispatcher.passthrough {
            ctrl.close_all();
        }
        // `self.fd` drops here, closing /dev/fuse.
        Ok(())
    }

    /// Submit and reap ring completions, routing each. Non-blocking when a worker
    /// pool is active; otherwise blocks up to 200 ms for the next request.
    /// Returns whether any completion was observed.
    fn pump_ring(&mut self) -> Result<bool, String> {
        let comps = if !self.pending.is_empty() {
            std::mem::take(&mut self.pending)
        } else {
            let timeout = if self.pool.is_some() {
                Duration::ZERO
            } else {
                Duration::from_millis(200)
            };
            let t0 = Instant::now();
            let comps = self
                .ring
                .as_mut()
                .expect("ring initialized")
                .submit_and_wait_timeout(1, timeout)?;
            {
                let mut s = self.stats.lock();
                s.wait_calls += 1;
                s.wait_ns += t0.elapsed().as_nanos() as u64;
            }
            comps
        };
        let n = comps.len() as u64;
        {
            let mut s = self.stats.lock();
            if n > s.completions_max_per_reap {
                s.completions_max_per_reap = n;
            }
        }
        if comps.is_empty() {
            return Ok(false);
        }
        for c in comps {
            self.handle_completion(c)?;
        }
        Ok(true)
    }

    /// Drain finished dispatch jobs, re-arming each entry. Returns whether any
    /// completed.
    fn drain_done(&mut self) -> Result<bool, String> {
        // Collect first (immutable borrow of the pool), then re-arm (mutable
        // borrow of the ring), so the two borrows never overlap.
        let dones: Vec<Done> = match self.pool.as_ref() {
            Some(pool) => std::iter::from_fn(|| pool.try_done()).collect(),
            None => Vec::new(),
        };
        let mut any = false;
        for done in dones {
            self.finish(done)?;
            any = true;
        }
        Ok(any)
    }

    fn inflight_count(&self) -> usize {
        self.inflight.iter().filter(|b| **b).count()
    }

    /// The lane a request on entry `idx` runs on: large reads and writes go to
    /// the bulk lane, everything else (metadata, small reads) to the latency lane.
    fn lane_for(&self, idx: usize) -> Lane {
        let e = &self.entries[idx];
        let hdr = e.header.as_slice();
        let opcode = get_u32(hdr, 4);
        let big = match opcode {
            FUSE_READ => get_u32(hdr, 128 + 16) as usize >= BULK_THRESHOLD,
            FUSE_WRITE => (get_u32(hdr, 272) as usize).min(e.payload.len()) >= BULK_THRESHOLD,
            _ => false,
        };
        if big {
            Lane::Bulk
        } else {
            Lane::Fast
        }
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
        if self.pool.is_some() {
            let lane = self.lane_for(idx);
            // Mark the entry busy BEFORE handing its pointer to a worker; the
            // session will not touch it again until `finish` re-arms it.
            self.inflight[idx] = true;
            let entry = EntryPtr(&mut self.entries[idx] as *mut EntryState);
            if let Some(pool) = self.pool.as_ref() {
                pool.queue.push(Job { idx, entry, lane });
            }
            let mut s = self.stats.lock();
            match lane {
                Lane::Fast => s.fast_routed += 1,
                Lane::Bulk => s.bulk_routed += 1,
            }
            s.handoffs += 1;
            Ok(())
        } else {
            self.serve_entry(idx)
        }
    }

    /// Re-arm a finished job's entry with `COMMIT_AND_FETCH` and account for it.
    fn finish(&mut self, d: Done) -> Result<(), String> {
        self.inflight[d.idx] = false;
        {
            let mut s = self.stats.lock();
            s.requests_served += 1;
            s.reply_bytes += d.reply_len;
            s.ring_submits += 1;
        }
        self.ring
            .as_mut()
            .ok_or_else(|| "F2 ring not initialized".to_string())?
            .submit_commit_and_fetch(d.qid, d.commit_id, d.ud)
            .map_err(|e| format!("queue COMMIT_AND_FETCH for qid {}: {e}", d.qid))?;
        if d.destroy {
            self.stop.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    /// Single-loop path: dispatch the request on this thread and re-arm the entry
    /// inline, using a reusable reply buffer (no per-request allocation).
    fn serve_entry(&mut self, idx: usize) -> Result<(), String> {
        let (qid, ud, commit_id, destroy, reply_len, dispatch_ns) = {
            let (qid, ud, commit_id, unique, opcode) = {
                let e = &self.entries[idx];
                let hdr = e.header.as_slice();
                (
                    e.qid,
                    e.ud,
                    get_u64(hdr, 264),
                    get_u64(hdr, 8),
                    get_u32(hdr, 4),
                )
            };
            let destroy = opcode == FUSE_DESTROY;
            let t0 = Instant::now();
            let reply = if destroy {
                Reply::Empty
            } else {
                let e = &self.entries[idx];
                let hdr = e.header.as_slice();
                let payload_sz = clamp_payload_sz(get_u32(hdr, 272), e.payload.len());
                let req = Req {
                    opcode,
                    nodeid: get_u64(hdr, 16),
                    uid: get_u32(hdr, 24),
                    gid: get_u32(hdr, 28),
                    pid: get_u32(hdr, 32),
                    op: &hdr[128..256],
                    payload: &e.payload.as_slice()[..payload_sz],
                };
                self.dispatcher.serve(&req)
            };
            let dispatch_ns = t0.elapsed().as_nanos() as u64;
            let err = reply.encode_into(
                &mut self.scratch,
                self.dispatcher.entry_ttl,
                self.dispatcher.attr_ttl,
            );
            let reply_len = self.scratch.len() as u64;
            write_reply(&mut self.entries[idx], unique, err, &self.scratch);
            (qid, ud, commit_id, destroy, reply_len, dispatch_ns)
        };
        {
            let mut s = self.stats.lock();
            s.requests_served += 1;
            s.reply_bytes += reply_len;
            s.ring_submits += 1;
            s.dispatch_calls += 1;
            s.dispatch_ns += dispatch_ns;
        }
        self.ring
            .as_mut()
            .ok_or_else(|| "F2 ring not initialized".to_string())?
            .submit_commit_and_fetch(qid, commit_id, ud)
            .map_err(|e| format!("queue COMMIT_AND_FETCH for qid {qid}: {e}"))?;
        if destroy {
            self.stop.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    /// Opt-in **queue-affine** topology (see `docs/CONCURRENCY.md`): split the
    /// CPU queues across `rings` servicer threads, each owning its own
    /// `io_uring` instance and the registered entries for exactly its queues.
    ///
    /// This is the one topology that realises F2's parallel potential on this
    /// ABI. The kernel delivers a `URING_CMD` completion as task-work to the
    /// task that submitted it, so a single ring can only ever be reaped by one
    /// thread; splitting the *queues* across *rings* gives each queue a stable
    /// owner that keeps its buffers, completion handling and reply commit local
    /// to one CPU — no `EntryPtr` handoff, no shared ring lock, no cross-core
    /// buffer ownership transfer. It is inert unless the kernel routes a queue
    /// to the ring that registered its entry, which the acceptance court
    /// measures rather than assumes.
    fn run_affine(mut self, rings: usize) -> Result<(), String> {
        let num_queues = possible_cpu_count().max(1);
        let rings = rings.clamp(1, num_queues);
        let cpus = possible_cpu_count().max(1);
        let raw = self.fd.as_raw_fd();
        // Round-robin disjoint queue assignment: group g owns qids g, g+rings, …
        let mut assignments: Vec<Vec<u16>> = vec![Vec::new(); rings];
        for q in 0..num_queues {
            assignments[q % rings].push(q as u16);
        }
        let (setup_tx, setup_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        // Pre-size the live per-group observation record *before* any group can
        // serve: each group increments its own slot under the same lock it
        // already takes per request, so the distribution is readable at any time.
        {
            let mut s = self.stats.lock();
            s.queue_groups = (0..rings)
                .map(|g| QueueGroupStat {
                    group: g,
                    qids: assignments[g].clone(),
                    served: 0,
                })
                .collect();
        }
        let mut handles = Vec::new();
        for (g, qids) in assignments.into_iter().enumerate() {
            if qids.is_empty() {
                continue;
            }
            let group = QueueGroup {
                fd: raw,
                qids,
                ring: None,
                entries: Vec::new(),
                pending: Vec::new(),
                dispatcher: Arc::clone(&self.dispatcher),
                stats: Arc::clone(&self.stats),
                stop: Arc::clone(&self.stop),
                kernel_minor: self.kernel_minor,
                kernel_offered_bufpool: self.kernel_offered_bufpool,
                cap_sys_admin: self.cap_sys_admin,
                affinity: if self.affinity { Some(g % cpus) } else { None },
                scratch: Vec::with_capacity(8 * 1024),
                group_idx: g,
            };
            let tx = setup_tx.clone();
            let h = std::thread::Builder::new()
                .name(format!("orfs-f2-q{g}"))
                .spawn(move || {
                    let mut group = group;
                    match group.setup() {
                        Ok(()) => {
                            let _ = tx.send(Ok(()));
                            if let Err(e) = group.serve_loop() {
                                eprintln!("orfs: F2 queue-group {g} loop failed: {e}");
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(Err(e));
                        }
                    }
                })
                .map_err(|e| format!("spawn F2 queue-group thread: {e}"))?;
            handles.push(h);
        }
        drop(setup_tx);

        // Every group must register its queues: the kernel only starts routing
        // requests once every queue has an available entry (`is_ring_ready`).
        let mut first_err: Option<String> = None;
        for _ in 0..handles.len() {
            match setup_rx.recv_timeout(Duration::from_secs(15)) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
                Err(_) => {
                    if first_err.is_none() {
                        first_err = Some("F2 queue-group registration timed out".into());
                    }
                }
            }
        }
        if let Some(e) = first_err {
            self.stop.store(true, Ordering::SeqCst);
            for h in handles {
                let _ = h.join();
            }
            if let Some(tx) = self.setup_tx.take() {
                let _ = tx.send(Err(e));
            }
            return Ok(());
        }

        let negotiation = FuseUringNegotiation {
            kernel_offered: true,
            kernel_offered_bufpool: self.kernel_offered_bufpool,
            kernel_abi: Some((7, self.kernel_minor)),
            accepted: true,
            engaged: true,
            reason: None,
            cap_sys_admin: self.cap_sys_admin,
            num_queues,
        };
        let capabilities = negotiation.capabilities();
        self.stats.lock().register_sqes = (num_queues * entries_per_queue()) as u64;
        {
            let mut env = self.environment.lock();
            env.num_queues = num_queues;
            env.capabilities = capabilities;
            env.servicing = format!("queue-affine(rings={rings})");
            env.affinity = self.affinity;
        }
        self.dispatcher.fs.record_negotiation(negotiation);
        if let Some(tx) = self.setup_tx.take() {
            let _ = tx.send(Ok(()));
        }

        // The classical channel (FORGET/INTERRUPT) is served once, on its own
        // thread, exactly as in the single-loop topology.
        if let Some(reader_fd) = self.reader_fd.take() {
            let stop = Arc::clone(&self.stop);
            let stats = Arc::clone(&self.stats);
            let fs = Arc::clone(&self.dispatcher.fs);
            let _ = std::thread::Builder::new()
                .name("orfs-f2-classical".to_string())
                .spawn(move || classical_reader(reader_fd, stop, stats, fs));
        }

        // Park until unmount/DESTROY asks every group to stop, then join them
        // (no group still holds an entry) before the `/dev/fuse` fd drops.
        while !self.stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(20));
        }
        for h in handles {
            let _ = h.join();
        }
        if let Some(ctrl) = &self.dispatcher.passthrough {
            ctrl.close_all();
        }
        Ok(())
    }
}

/// One ring-owning servicer for a disjoint subset of queues: the unit of
/// execution of the opt-in queue-affine topology.
///
/// It mirrors the single-loop servicer of [`SessionLoop`] but owns its own
/// [`FuseUringRing`] and its own registered [`EntryState`]s, so a request's
/// buffers, reply commit and completion handling never leave one thread. It is
/// deliberately *not* pooled: the point of the topology is a stable owner per
/// queue, not a larger thread pool.
struct QueueGroup<C: OrfsCore + Send + 'static> {
    /// The session's `/dev/fuse` descriptor (borrowed as a raw value; the
    /// session owns the `OwnedFd` for the whole mount).
    fd: RawFd,
    /// The queues this group services, registered on its own ring.
    qids: Vec<u16>,
    ring: Option<FuseUringRing>,
    entries: Vec<EntryState>,
    pending: Vec<RingCompletion>,
    dispatcher: Arc<Dispatcher<C>>,
    stats: Arc<Mutex<NativeStats>>,
    stop: Arc<AtomicBool>,
    kernel_minor: u32,
    kernel_offered_bufpool: bool,
    cap_sys_admin: bool,
    affinity: Option<usize>,
    scratch: Vec<u8>,
    /// This group's index (into `NativeStats::queue_groups`).
    group_idx: usize,
}

impl<C: OrfsCore + Send + 'static> QueueGroup<C> {
    /// Create this group's ring and register one entry per owned queue. Runs on
    /// the group's own thread (the ring must be created where it is waited on).
    fn setup(&mut self) -> Result<(), String> {
        let neg = FuseUringNegotiation {
            kernel_offered: true,
            kernel_offered_bufpool: self.kernel_offered_bufpool,
            kernel_abi: Some((7, self.kernel_minor)),
            accepted: true,
            engaged: true,
            cap_sys_admin: self.cap_sys_admin,
            ..Default::default()
        };
        let plan = crate::fuse_uring::plan_queues(&neg, self.dispatcher.fs.options.zero_copy);
        let (ring, entries, probe) = register_qids(self.fd, plan, &self.qids)?;
        self.ring = Some(ring);
        self.entries = entries;
        self.pending = probe;
        Ok(())
    }

    /// Service this group's queues inline until `stop` is set.
    fn serve_loop(mut self) -> Result<(), String> {
        if let Some(cpu) = self.affinity {
            pin_to_cpu(cpu);
        }
        while !self.stop.load(Ordering::SeqCst) {
            let comps = if !self.pending.is_empty() {
                std::mem::take(&mut self.pending)
            } else {
                let t0 = Instant::now();
                let comps = match self
                    .ring
                    .as_mut()
                    .expect("ring initialized")
                    .submit_and_wait_timeout(1, Duration::from_millis(200))
                {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("orfs: F2 queue-group ring wait failed: {e}");
                        break;
                    }
                };
                {
                    let mut s = self.stats.lock();
                    s.wait_calls += 1;
                    s.wait_ns += t0.elapsed().as_nanos() as u64;
                }
                comps
            };
            let n = comps.len() as u64;
            {
                let mut s = self.stats.lock();
                if n > s.completions_max_per_reap {
                    s.completions_max_per_reap = n;
                }
            }
            for c in comps {
                if let Err(e) = self.handle_completion(c) {
                    eprintln!("orfs: F2 queue-group request handling failed: {e}");
                }
            }
        }
        if let Some(ring) = self.ring.as_mut() {
            ring.shutdown();
        }
        Ok(())
    }

    fn handle_completion(&mut self, c: RingCompletion) -> Result<(), String> {
        self.stats.lock().ring_completions += 1;
        let idx = match (c.user_data as usize).checked_sub(1) {
            Some(i) if i < self.entries.len() => i,
            _ => return Ok(()),
        };
        if c.result < 0 {
            self.stats.lock().negative_completions += 1;
            return Ok(());
        }
        self.serve_entry(idx)
    }

    /// Dispatch the request on this thread and re-arm the entry inline, using a
    /// reusable reply buffer — byte-for-byte identical to the single-loop path.
    fn serve_entry(&mut self, idx: usize) -> Result<(), String> {
        let (qid, ud, commit_id, destroy, reply_len, dispatch_ns) = {
            let (qid, ud, commit_id, unique, opcode) = {
                let e = &self.entries[idx];
                let hdr = e.header.as_slice();
                (
                    e.qid,
                    e.ud,
                    get_u64(hdr, 264),
                    get_u64(hdr, 8),
                    get_u32(hdr, 4),
                )
            };
            let destroy = opcode == FUSE_DESTROY;
            let t0 = Instant::now();
            let reply = if destroy {
                Reply::Empty
            } else {
                let e = &self.entries[idx];
                let hdr = e.header.as_slice();
                let payload_sz = clamp_payload_sz(get_u32(hdr, 272), e.payload.len());
                let req = Req {
                    opcode,
                    nodeid: get_u64(hdr, 16),
                    uid: get_u32(hdr, 24),
                    gid: get_u32(hdr, 28),
                    pid: get_u32(hdr, 32),
                    op: &hdr[128..256],
                    payload: &e.payload.as_slice()[..payload_sz],
                };
                self.dispatcher.serve(&req)
            };
            let dispatch_ns = t0.elapsed().as_nanos() as u64;
            let err = reply.encode_into(
                &mut self.scratch,
                self.dispatcher.entry_ttl,
                self.dispatcher.attr_ttl,
            );
            let reply_len = self.scratch.len() as u64;
            write_reply(&mut self.entries[idx], unique, err, &self.scratch);
            (qid, ud, commit_id, destroy, reply_len, dispatch_ns)
        };
        {
            let mut s = self.stats.lock();
            s.requests_served += 1;
            s.reply_bytes += reply_len;
            s.ring_submits += 1;
            s.dispatch_calls += 1;
            s.dispatch_ns += dispatch_ns;
            s.queue_groups[self.group_idx].served += 1;
        }
        self.ring
            .as_mut()
            .ok_or_else(|| "F2 ring not initialized".to_string())?
            .submit_commit_and_fetch(qid, commit_id, ud)
            .map_err(|e| format!("queue COMMIT_AND_FETCH for qid {qid}: {e}"))?;
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
    // Safety invariant (memory, not just `unsafe`): the kernel copies exactly
    // `ring_ent_in_out.payload_sz` bytes out of the registered payload buffer, and
    // that buffer is exactly `PAYLOAD_BUF` bytes. A reply must therefore never
    // claim (or copy) more than the buffer holds. Clamp defensively: a request
    // whose `size` field is out of range (a hostile or buggy client asking for a
    // read/readdir larger than the registered buffer) must not panic the session
    // thread and must not make the kernel over-read adjacent heap. Legitimate
    // requests are always ≤ `max_read`/`max_write` (128 KiB), so the clamp is a
    // no-op for them. Asserted by
    // `reply_larger_than_the_registered_buffer_is_clamped_not_panicking`.
    let n = data.len().min(e.payload.len());
    let hdr = e.header.as_mut_slice();
    let len = (16 + n) as u32;
    hdr[0..4].copy_from_slice(&len.to_ne_bytes());
    let wire = if err == 0 { 0 } else { -err };
    hdr[4..8].copy_from_slice(&wire.to_ne_bytes());
    hdr[8..16].copy_from_slice(&unique.to_ne_bytes());
    hdr[272..276].copy_from_slice(&(n as u32).to_ne_bytes());
    let payload = e.payload.as_mut_slice();
    payload[..n].copy_from_slice(&data[..n]);
}

/// The payload size a registered entry actually holds: the kernel-reported
/// `payload_sz`, capped at the registered payload buffer's length.
///
/// A hostile or out-of-range `payload_sz` (for example `u32::MAX`) can therefore
/// never index past the buffer; the two call sites (`serve_job`, `serve_entry`)
/// both go through this one function, so the clamp cannot drift. Asserted by
/// `payload_size_is_clamped_to_the_registered_buffer`.
fn clamp_payload_sz(raw: u32, cap: usize) -> usize {
    (raw as usize).min(cap)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_uapi_matches_the_kernel_headers() {
        // `struct fuse_backing_map` is 16 bytes on x86_64 (`int32`, `uint32`,
        // `uint64`).
        assert_eq!(std::mem::size_of::<FuseBackingMap>(), 16);
        // `_IOW(229, 1, struct fuse_backing_map)` and `_IOW(229, 2, uint32_t)` as
        // computed by the kernel's `asm-generic/ioctl.h` on x86_64
        // (`_IOC_WRITE == 1`, `_IOC_SIZEBITS == 14`). Verified against the
        // running kernel's `linux/fuse.h` (ABI 7.45).
        assert_eq!(FUSE_DEV_IOC_BACKING_OPEN, 0x4010_E501);
        assert_eq!(FUSE_DEV_IOC_BACKING_CLOSE, 0x4004_E502);
        // The direction/size/type/number fields decode to the documented values.
        assert_eq!((FUSE_DEV_IOC_BACKING_OPEN >> 30) & 0x3, 1);
        assert_eq!((FUSE_DEV_IOC_BACKING_OPEN >> 16) & 0x3fff, 16);
        assert_eq!((FUSE_DEV_IOC_BACKING_OPEN >> 8) & 0xff, 229);
        assert_eq!(FUSE_DEV_IOC_BACKING_OPEN & 0xff, 1);
        assert_eq!(FUSE_DEV_IOC_BACKING_CLOSE & 0xff, 2);
        // Capability/open-flag bit positions.
        assert_eq!(FUSE_PASSTHROUGH, 1u64 << 37);
        assert_eq!(FUSE_PASSTHROUGH_FLAGS2, 1 << 5);
        assert_eq!(FOPEN_PASSTHROUGH, 1 << 7);
    }

    /// Cross-transport regression (Phase 33): `stat` must report the true link
    /// count through **both** adapters, including `nlink == 0` for an inode that
    /// has been unlinked but is still open (POSIX). The native adapter previously
    /// clamped with `.max(1)` and so reported `1` where the classical adapter
    /// correctly reported `0`.
    #[test]
    fn both_transports_report_the_true_link_count() {
        for nlink in [0u32, 1, 2, 4096] {
            let st = InodeStat {
                id: 7,
                kind: InodeType::File,
                mode: 0o644,
                uid: 0,
                gid: 0,
                nlink,
                size: 0,
                atime: Timespec::ZERO,
                mtime: Timespec::ZERO,
                ctime: Timespec::ZERO,
                version: 1,
                blocks: 0,
            };
            let native = attr_from_stat(&st).nlink;
            let classical = crate::fuse::file_attr(&st).nlink;
            assert_eq!(native, nlink, "native adapter must pass nlink through");
            assert_eq!(
                classical, nlink,
                "classical adapter must pass nlink through"
            );
            assert_eq!(native, classical, "the adapters must agree");
        }
    }

    #[test]
    fn init_reply_advertises_passthrough_only_when_requested() {
        let plain = encode_init_reply(1, 45, false);
        // flags2 is at offset 16 (out header) + 32 (init_out) = 48, and
        // max_stack_depth is the next u32 (offset 52).
        assert_eq!(get_u32(&plain, 48), FUSE_OVER_IO_URING_FLAGS2);
        assert_eq!(get_u32(&plain, 52), 0);
        let pt = encode_init_reply(1, 45, true);
        assert_eq!(
            get_u32(&pt, 48),
            FUSE_OVER_IO_URING_FLAGS2 | FUSE_PASSTHROUGH_FLAGS2
        );
        assert_eq!(get_u32(&pt, 52), PASSTHROUGH_MAX_STACK_DEPTH);
    }

    #[test]
    fn open_out_carries_the_backing_id() {
        let mut bytes = Vec::new();
        write_open_out(&mut bytes, 7, FOPEN_PASSTHROUGH, 42);
        assert_eq!(get_u64(&bytes, 0), 7);
        assert_eq!(get_u32(&bytes, 8), FOPEN_PASSTHROUGH);
        assert_eq!(get_u32(&bytes, 12), 42);
    }

    #[test]
    fn reply_encode_into_reuses_one_buffer() {
        // The reused-buffer encoding is byte-identical to a fresh encoding and
        // leaves no trailing bytes from a previous, larger reply.
        let mut buf = Vec::new();
        let a = Attr {
            ino: 3,
            mode: libc::S_IFREG | 0o644,
            nlink: 1,
            blksize: 4096,
            ..Default::default()
        };
        let err =
            Reply::Attr(a).encode_into(&mut buf, Duration::from_secs(1), Duration::from_secs(2));
        assert_eq!(err, 0);
        assert_eq!(buf.len(), 104, "fuse_attr_out is 104 bytes");
        let first = buf.clone();
        // A second, smaller reply must replace (not append to) the buffer.
        let err = Reply::Err(libc::EACCES).encode_into(
            &mut buf,
            Duration::from_secs(1),
            Duration::from_secs(2),
        );
        assert_eq!(err, libc::EACCES);
        assert!(buf.is_empty(), "an error reply carries no body");
        let err =
            Reply::Attr(a).encode_into(&mut buf, Duration::from_secs(1), Duration::from_secs(2));
        assert_eq!(err, 0);
        assert_eq!(buf, first, "reusing the buffer is byte-identical");
    }

    // -----------------------------------------------------------------------
    // Completion ownership + buffer-lifetime invariants (Phase 28)
    //
    // Each test names the safety invariant its corresponding `unsafe`/code
    // comment claims and asserts it directly, rather than restating the comment.
    // -----------------------------------------------------------------------

    /// A reply body of `i` selects a different `Reply` shape; used to interleave
    /// many encodings through one reused buffer.
    fn make_reply(i: usize) -> Reply {
        match i {
            0 => Reply::Empty,
            1 => Reply::Err(libc::ENOENT),
            2 => Reply::Write(1234),
            3 => Reply::Data(vec![0x11; 8 * 1024]),
            4 => Reply::Dir(vec![0x22; 64]),
            5 => Reply::Open {
                fh: 9,
                open_flags: FOPEN_PASSTHROUGH,
                backing_id: 3,
            },
            6 => Reply::Statfs {
                blocks: 1,
                bfree: 2,
                bavail: 3,
                files: 4,
                ffree: 5,
                bsize: 4096,
            },
            7 => Reply::Attr(Attr {
                ino: 5,
                mode: libc::S_IFREG | 0o644,
                nlink: 1,
                blksize: 4096,
                size: 999,
                ..Default::default()
            }),
            _ => Reply::Entry(Attr::default()),
        }
    }

    /// **Invariant (d): reply / reused-buffer correctness under interleaving.**
    /// `encode_into` reuses one caller buffer and must be byte-identical to a
    /// fresh encoding every time, with no trailing bytes surviving from a larger
    /// earlier reply (`out.clear()` at the top). Reuse is only sound because each
    /// reply is staged and read back before the next request reuses the buffer.
    #[test]
    fn reply_encode_into_interleaved_reuse_is_byte_identical() {
        let ttl = Duration::from_secs(1);
        let mut reused = Vec::new();
        for round in 0..4 {
            for i in 0..9 {
                let mut fresh = Vec::new();
                let e_fresh = make_reply(i).encode_into(&mut fresh, ttl, ttl);
                let e_reused = make_reply(i).encode_into(&mut reused, ttl, ttl);
                assert_eq!(e_fresh, e_reused, "round {round} reply {i}");
                assert_eq!(
                    fresh, reused,
                    "round {round} reply {i}: reuse must be byte-identical"
                );
            }
        }
    }

    /// **Invariant: the kernel-reported `payload_sz` is clamped to the registered
    /// buffer length.** A hostile/out-of-range size can never index past the
    /// buffer.
    #[test]
    fn payload_size_is_clamped_to_the_registered_buffer() {
        let cap = 4096;
        assert_eq!(clamp_payload_sz(u32::MAX, cap), cap);
        assert_eq!(clamp_payload_sz(0, cap), 0);
        assert_eq!(clamp_payload_sz(4096, cap), 4096);
        assert_eq!(clamp_payload_sz(4097, cap), 4096);
    }

    /// **Invariant: `write_reply` stages the reply exactly where the kernel reads
    /// it** — `fuse_out_header` at the start of `in_out` (len@0, error@4,
    /// unique@8) and the body length at `ring_ent_in_out.payload_sz` (offset 272),
    /// with the bytes copied into the payload buffer.
    #[test]
    fn write_reply_stages_header_and_payload_at_documented_offsets() {
        let mut e = EntryState::new(0, 1);
        write_reply(&mut e, 0x1122_3344_5566_7788, 0, &[0xAB; 300]);
        let hdr = e.header.as_slice();
        assert_eq!(get_u32(hdr, 0), 16 + 300, "out_header.len");
        assert_eq!(get_u32(hdr, 4), 0, "out_header.error");
        assert_eq!(get_u64(hdr, 8), 0x1122_3344_5566_7788, "out_header.unique");
        assert_eq!(get_u32(hdr, 272), 300, "ring_ent_in_out.payload_sz");
        assert_eq!(&e.payload.as_slice()[..300], &[0xAB; 300][..]);

        // An error reply negates the errno on the wire and carries no body.
        write_reply(&mut e, 7, libc::ENOENT, &[]);
        let hdr = e.header.as_slice();
        assert_eq!(get_u32(hdr, 0), 16);
        assert_eq!(
            i32::from_ne_bytes(hdr[4..8].try_into().unwrap()),
            -libc::ENOENT
        );
    }

    /// **Invariant (buffer lifetime): a reply larger than the registered payload
    /// buffer is clamped, never a panic and never an over-claim.** Regression test
    /// for the hostile `read`/`readdir` `size` field: before the clamp,
    /// `write_reply` sliced `payload[..data.len()]` out of bounds (panic / DoS) and
    /// would have told the kernel to copy past the registered buffer.
    #[test]
    fn reply_larger_than_the_registered_buffer_is_clamped_not_panicking() {
        let mut e = EntryState::new(0, 1);
        let cap = e.payload.len();
        write_reply(&mut e, 7, 0, &vec![0x5A; cap + 4096]);
        let hdr = e.header.as_slice();
        assert_eq!(
            get_u32(hdr, 272),
            cap as u32,
            "payload_sz must be clamped to the registered buffer"
        );
        assert_eq!(get_u32(hdr, 0), (16 + cap) as u32);
        assert!(e.payload.as_slice().iter().all(|&b| b == 0x5A));
    }

    /// **Invariant (buffer lifetime): the registered entry's buffers are at a
    /// stable address and its `iovec` array points into them, even after
    /// ownership moves to another thread.** The kernel is handed `iov[0]`/`iov[1]`
    /// once at `REGISTER` and dereferences them for the entry's whole lifetime, so
    /// this must hold across the `unsafe impl Send for EntryState`.
    #[test]
    fn entry_state_buffers_are_stable_under_ownership_move() {
        let e = EntryState::new(3, 9);
        let header_ptr = e.header.as_ptr() as usize;
        let payload_ptr = e.payload.as_ptr() as usize;
        assert_eq!(e.iov[0].iov_base as usize, header_ptr, "iov[0] = header");
        assert_eq!(e.iov[1].iov_base as usize, payload_ptr, "iov[1] = payload");
        assert_eq!(e.iov[0].iov_len, e.header.len());
        assert_eq!(e.iov[1].iov_len, e.payload.len());
        // Move the entry to another thread and back (the `Send` transfer the
        // registration relies on); the addresses must not change.
        let e = std::thread::spawn(move || e).join().expect("worker");
        assert_eq!(e.header.as_ptr() as usize, header_ptr);
        assert_eq!(e.payload.as_ptr() as usize, payload_ptr);
        assert_eq!(e.iov[0].iov_base as usize, header_ptr);
        assert_eq!(e.iov[1].iov_base as usize, payload_ptr);
    }

    /// **Invariant (a/c): a closed `JobQueue` wakes every waiter and drains to
    /// `None`.** A sentinel job whose entry is heap-owned (so its raw pointer stays
    /// valid) documents that a queued `EntryPtr` is only handed out while the
    /// session keeps the entry alive.
    #[test]
    fn job_queue_close_wakes_waiters_and_drains_cleanly() {
        let q = JobQueue::new();
        let mut entry = Box::new(EntryState::new(1, 1));
        let ptr = &mut *entry as *mut EntryState;
        q.push(Job {
            idx: 0,
            entry: EntryPtr(ptr),
            lane: Lane::Fast,
        });
        q.push(Job {
            idx: 1,
            entry: EntryPtr(ptr),
            lane: Lane::Bulk,
        });
        assert_eq!(q.pop(Lane::Fast).map(|j| j.idx), Some(0));
        assert_eq!(q.pop(Lane::Bulk).map(|j| j.idx), Some(1));
        q.close();
        assert!(q.pop(Lane::Fast).is_none(), "closed queue drains to None");
        assert!(q.pop(Lane::Bulk).is_none());
        drop(entry);
    }

    /// **Invariant (c): `WorkerPool` shutdown with outstanding requests joins
    /// every worker before returning.** This is the ownership guarantee that no
    /// worker still holds an `EntryPtr` when the session tears the ring and the
    /// entries down.
    #[test]
    fn worker_pool_drop_joins_workers_with_outstanding_jobs() {
        use std::sync::atomic::{AtomicUsize, Ordering as O};
        use std::sync::mpsc::channel;

        let queue = Arc::new(JobQueue::new());
        let (_tx, rx) = channel::<Done>();
        let processed = Arc::new(AtomicUsize::new(0));
        // The entry outlives the pool, so the queued raw pointers stay valid.
        let entry = Box::new(EntryState::new(0, 1));
        let ptr = &*entry as *const EntryState as *mut EntryState;
        let mut threads = Vec::new();
        for _ in 0..2 {
            let q = Arc::clone(&queue);
            let c = Arc::clone(&processed);
            threads.push(std::thread::spawn(move || {
                while let Some(_job) = q.pop(Lane::Fast) {
                    c.fetch_add(1, O::SeqCst);
                }
            }));
        }
        for i in 0..8 {
            queue.push(Job {
                idx: i,
                entry: EntryPtr(ptr),
                lane: Lane::Fast,
            });
        }
        let pool = WorkerPool::<crate::namespace::Namespace> {
            queue,
            done_rx: rx,
            threads,
            _marker: std::marker::PhantomData,
        };
        // Dropping the pool closes the queues and joins both workers.
        drop(pool);
        assert_eq!(
            processed.load(O::SeqCst),
            8,
            "every outstanding job must have been served before Drop returns"
        );
        drop(entry);
    }

    /// **Regression (phase 61): `close` must acquire the lane mutex before it
    /// notifies.** If it notified without the lock, a worker could check
    /// `closed == false`, then `close` could flip the flag and call `notify_all`
    /// while no waiter is parked yet (the notify is dropped), and only then would
    /// the worker park in `wait` — a lost wakeup that can hang `WorkerPool::drop`
    /// forever. Holding the lane mutex here forces `close` to block until the
    /// worker that is about to park has released it, which cannot happen *after* a
    /// wakeup it missed. The pre-fix code notified without the lock, so `close`
    /// returns immediately and the first assertion fires.
    #[test]
    fn job_queue_close_acquires_the_lane_mutex_before_notifying() {
        use std::sync::atomic::{AtomicBool as AB, Ordering as AO};
        use std::sync::{Arc as A, Barrier};

        let q = A::new(JobQueue::new());
        let barrier = A::new(Barrier::new(2));
        // Stand in for a worker that has observed an empty queue and
        // `closed == false` and still holds the lane lock — the instant before it
        // parks in `wait`.
        let guard = q.fast.lock();

        let done = A::new(AB::new(false));
        let closer = {
            let q = A::clone(&q);
            let barrier = A::clone(&barrier);
            let done = A::clone(&done);
            std::thread::spawn(move || {
                barrier.wait();
                q.close();
                done.store(true, AO::SeqCst);
            })
        };
        barrier.wait();
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !done.load(AO::SeqCst),
            "close() must acquire the lane mutex before notifying waiters"
        );
        drop(guard);
        closer.join().unwrap();
        assert!(
            done.load(AO::SeqCst),
            "close() returns once the lock is free"
        );
    }

    /// **Regression (phase 61): repeatedly tearing a worker pool down with jobs
    /// still outstanding must join every worker within a bounded time.** A lost
    /// wakeup in `JobQueue::close` leaves a worker parked in `wait` forever, so
    /// `WorkerPool::drop` never returns; the bounded `recv_timeout` turns that
    /// hang into a deterministic test failure instead of a wedged suite.
    ///
    /// The default sweep is bounded so it fits the gate; set
    /// `ORFS_JOBQUEUE_STRESS_ITERS=<n>` to run a longer sweep.
    #[test]
    fn worker_pool_drop_repeatedly_joins_within_bounded_time() {
        use std::sync::mpsc::channel;

        let iterations: usize = std::env::var("ORFS_JOBQUEUE_STRESS_ITERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2_000);

        for i in 0..iterations {
            let queue = Arc::new(JobQueue::new());
            let (_tx, rx) = channel::<Done>();
            // The entry outlives the pool, so queued raw pointers stay valid.
            let entry = Box::new(EntryState::new(0, 1));
            let ptr = &*entry as *const EntryState as *mut EntryState;

            let mut threads = Vec::new();
            for _ in 0..2 {
                let q = Arc::clone(&queue);
                threads.push(std::thread::spawn(
                    move || {
                        while q.pop(Lane::Fast).is_some() {}
                    },
                ));
            }
            for j in 0..8 {
                queue.push(Job {
                    idx: j,
                    entry: EntryPtr(ptr),
                    lane: Lane::Fast,
                });
            }

            let pool = WorkerPool::<crate::namespace::Namespace> {
                queue,
                done_rx: rx,
                threads,
                _marker: std::marker::PhantomData,
            };
            // Drop (which closes and joins) on another thread so the wait here is
            // bounded: if a worker is stranded in `wait`, the deadline fires.
            let (joined_tx, joined_rx) = channel();
            let joiner = std::thread::spawn(move || {
                drop(pool);
                let _ = joined_tx.send(());
            });
            assert!(
                joined_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
                "WorkerPool::drop hung on iteration {i} (lost wakeup in JobQueue::close)"
            );
            joiner.join().unwrap();
            drop(entry);
        }
    }

    /// **Regression (phase 61): concurrent `push`/`pop`/`close` never loses a
    /// wakeup.** Many workers on both lanes race a pusher and a closer; every
    /// worker must observe `close` and exit within a bounded time.
    #[test]
    fn job_queue_concurrent_push_pop_close_joins_promptly() {
        use std::sync::atomic::{AtomicUsize as AU, Ordering as AO};
        use std::time::Instant;

        let iterations: usize = std::env::var("ORFS_JOBQUEUE_STRESS_ITERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200);

        for i in 0..iterations {
            let queue = Arc::new(JobQueue::new());
            let entry = Box::new(EntryState::new(0, 1));
            let addr = &*entry as *const EntryState as usize;
            let worker_count = 8;
            let exited = Arc::new(AU::new(0));

            let mut workers = Vec::new();
            for k in 0..worker_count {
                let q = Arc::clone(&queue);
                let exited = Arc::clone(&exited);
                let lane = if k % 2 == 0 { Lane::Fast } else { Lane::Bulk };
                workers.push(std::thread::spawn(move || {
                    while let Some(job) = q.pop(lane) {
                        std::hint::black_box(job.idx);
                    }
                    exited.fetch_add(1, AO::SeqCst);
                }));
            }

            // Build the jobs up front (a `Vec<Job>` is `Send`), then push them
            // concurrently with `close`.
            let jobs: Vec<Job> = (0..128)
                .map(|j| Job {
                    idx: j,
                    entry: EntryPtr(addr as *mut EntryState),
                    lane: if j % 2 == 0 { Lane::Fast } else { Lane::Bulk },
                })
                .collect();
            let pusher = {
                let q = Arc::clone(&queue);
                std::thread::spawn(move || {
                    for job in jobs {
                        q.push(job);
                    }
                })
            };

            // Close while the pusher is still running, widening the race window.
            std::thread::yield_now();
            queue.close();

            let deadline = Instant::now() + Duration::from_secs(5);
            while exited.load(AO::SeqCst) < worker_count {
                assert!(
                    Instant::now() < deadline,
                    "worker stranded after close on iteration {i} (lost wakeup)"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            for w in workers {
                w.join().unwrap();
            }
            pusher.join().unwrap();
            drop(entry);
        }
    }
}
