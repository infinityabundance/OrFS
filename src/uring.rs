//! A safe wrapper over `io-uring` 0.7.15 for OrFS's backing-store I/O
//! (research §17 Domain A, §20 Rings W/R, §21, §22, §26).
//!
//! This module is the *only* place in OrFS that talks to `io_uring` directly.
//! It provides:
//!
//! * a bounded ring (`IoUring::new(depth)`) with capability probing;
//! * submit-and-wait with **per-operation `user_data`** so every completion is
//!   validated and matched to the operation that produced it;
//! * positional `read`/`write`/`fsync` primitives that handle negative results,
//!   short writes, partial reads, cancellation, `EINTR`, and queue saturation;
//! * an **explicit ordering primitive** ([`UringEngine::write_then_fsync_ordered`])
//!   built from `IOSQE_IO_DRAIN`, plus an ordered durability barrier
//!   ([`UringEngine::fsync_order_barrier`]);
//! * registered-buffer staging via [`crate::buffers`], with the buffer kept pinned
//!   until its completion has been collected;
//! * a teardown path ([`UringEngine::drain`]) that reaps outstanding completions;
//! * honest fallback: if `io_uring` is unavailable at runtime, ring creation fails
//!   with a *reason*, and the caller keeps using the synchronous path.
//!
//! # The ordering rule (non-negotiable)
//!
//! Submitting a write SQE before an `fsync` SQE does **not** order them: io_uring
//! is free to execute them concurrently, and the `fsync` may complete before the
//! write is even issued (this is stated verbatim in the `io-uring` crate's own
//! `Fsync` documentation). OrFS therefore never relies on submission order. When
//! a durable ordering is required it is established by one of:
//!
//! * an explicit **completion barrier** — wait for the write's CQE before
//!   submitting the `fsync` (the default commit-sequencer path); or
//! * **`IOSQE_IO_DRAIN`** — the `fsync` SQE is not started until every earlier
//!   SQE has completed (used by [`UringEngine::write_then_fsync_ordered`] and
//!   [`UringEngine::fsync_order_barrier`]).
//!
//! `IOSQE_IO_HARDLINK` is deliberately **not** used as a substitute for
//! failure-sensitive dependency handling: it continues a link even after a
//! failure, which would mask a failed dependent write. Where a failure must
//! cancel the dependent operation, ordering is achieved by completion barriers.
//!
//! # `unsafe`
//!
//! All `unsafe` here is confined to the `io-uring` FFI contract: pushing an SQE
//! whose buffer pointer must outlive the operation, registering buffers, and
//! taking a raw pointer into a caller-owned slice. Every block carries a safety
//! comment stating the invariant. The engine's public API is synchronous
//! (submit-and-wait), so no pointer it hands to the kernel outlives the call that
//! created it.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::os::unix::io::RawFd;

use io_uring::{opcode, squeue, types, IoUring};

use crate::buffers::BufferPool;
use crate::error::{OrfsError, Result};

/// Measured starting configuration (research §20: "do not use a fixed number of
/// rings or workers without measurement"). The write ring only ever needs a few
/// slots because the commit sequencer submits synchronously; the read ring is
/// sized for concurrent immutable-segment reads. See `docs/IO_URING.md`.
pub const DEFAULT_WRITE_DEPTH: u32 = 32;
/// Read-ring depth.
pub const DEFAULT_READ_DEPTH: u32 = 64;
/// Number of staging buffers in the write ring's registered pool.
pub const STAGING_BUFFERS: usize = 4;
/// Size of each staging buffer (larger than the largest record OrFS writes).
pub const STAGING_BUFFER_SIZE: usize = 256 * 1024;
/// Largest chunk used by the ordered write+fsync primitive.
const MAX_ORDERED_CHUNK: usize = 1024 * 1024;

/// Runtime configuration for engaging the io_uring backing engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UringConfig {
    /// Whether the caller asked for io_uring at all.
    pub enabled: bool,
    /// Write-ring (Ring W) queue depth.
    pub write_depth: u32,
    /// Read-ring (Ring R) queue depth.
    pub read_depth: u32,
    /// Whether to stage writes through a registered buffer pool.
    pub stage_writes: bool,
}

impl Default for UringConfig {
    fn default() -> Self {
        UringConfig {
            enabled: true,
            write_depth: DEFAULT_WRITE_DEPTH,
            read_depth: DEFAULT_READ_DEPTH,
            stage_writes: true,
        }
    }
}

/// A truthful account of whether io_uring actually engaged.
///
/// `engaged` is `true` **only** when a real ring was created and every required
/// opcode probed as supported. When it is `false`, `reason` explains why and the
/// caller is using the synchronous path.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UringReport {
    /// Whether the caller requested io_uring.
    pub requested: bool,
    /// Whether io_uring is actually in use.
    pub engaged: bool,
    /// Requested write-ring depth.
    pub depth: u32,
    /// Requested read-ring depth.
    pub read_depth: u32,
    /// Number of buffers actually registered with the write ring.
    pub registered_buffers: usize,
    /// Why io_uring could not be engaged (only when `engaged` is `false`).
    pub reason: Option<String>,
}

impl UringReport {
    /// A report for a caller that did not request io_uring.
    pub fn disabled() -> UringReport {
        UringReport {
            requested: false,
            engaged: false,
            depth: 0,
            read_depth: 0,
            registered_buffers: 0,
            reason: None,
        }
    }

    /// A one-line honest description of the outcome.
    pub fn describe(&self) -> String {
        if self.engaged {
            format!(
                "io_uring engaged (write_depth={}, read_depth={}, registered_buffers={})",
                self.depth, self.read_depth, self.registered_buffers
            )
        } else if self.requested {
            format!(
                "io_uring requested but NOT engaged; using synchronous backing I/O: {}",
                self.reason.as_deref().unwrap_or("unavailable")
            )
        } else {
            "synchronous backing I/O (io_uring not requested)".to_string()
        }
    }
}

/// Cumulative operation counters for evidence.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct UringStats {
    /// Ring depth.
    pub depth: u32,
    /// SQEs submitted.
    pub submits: u64,
    /// CQEs drained.
    pub completions: u64,
    /// Positive-but-short writes observed and retried.
    pub short_writes: u64,
    /// Positive-but-short reads observed and retried.
    pub short_reads: u64,
    /// Completions that arrived for a different operation than the one awaited.
    pub orphan_completions: u64,
}

/// The classification of a single completion result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// A non-negative result (bytes transferred, or 0 for `fsync`).
    Done(i32),
    /// The kernel was interrupted before completing; the operation must be retried.
    Retry,
    /// The operation was canceled (`-ECANCELED`).
    Cancelled,
    /// A negative errno other than `EINTR`/`ECANCELED`.
    Failed(i32),
}

/// Classify a raw `io_uring` completion result.
///
/// A positive-but-short result is a *complete CQE* whose payload is smaller than
/// requested; it is reported as [`Completion::Done`] and the caller must loop to
/// transfer the remainder.
pub fn classify_completion(res: i32) -> Completion {
    if res >= 0 {
        Completion::Done(res)
    } else {
        match -res {
            libc::EINTR => Completion::Retry,
            libc::ECANCELED => Completion::Cancelled,
            e => Completion::Failed(e),
        }
    }
}

fn errno_error(e: i32) -> OrfsError {
    OrfsError::Io(io::Error::from_raw_os_error(e))
}

/// Advance a write loop given a completion.
///
/// `done` is the number of bytes already written toward `total`; returns the new
/// `done`. A short write advances by the number of bytes actually written while
/// **preserving the original reservation** — the caller re-submits the remainder
/// at `offset + done`, never rewriting the completed prefix.
pub fn advance_write(done: usize, total: usize, res: i32) -> Result<usize> {
    match classify_completion(res) {
        Completion::Done(0) => Err(OrfsError::Io(io::Error::new(
            io::ErrorKind::WriteZero,
            "short write made no progress",
        ))),
        Completion::Done(n) => {
            let nd = done + n as usize;
            if nd > total {
                Err(OrfsError::Corrupt(
                    "write reported more bytes than were submitted".into(),
                ))
            } else {
                Ok(nd)
            }
        }
        Completion::Retry => Ok(done),
        Completion::Cancelled => Err(errno_error(libc::ECANCELED)),
        Completion::Failed(e) => Err(errno_error(e)),
    }
}

/// Advance a read loop given a completion. A zero-length read is an unexpected
/// end of file and is an error (matching `RecordReader`'s contract).
pub fn advance_read(done: usize, total: usize, res: i32) -> Result<usize> {
    match classify_completion(res) {
        Completion::Done(0) => Err(OrfsError::Corrupt(format!(
            "unexpected end of file after {done} of {total} bytes"
        ))),
        Completion::Done(n) => {
            let nd = done + n as usize;
            if nd > total {
                Err(OrfsError::Corrupt(
                    "read reported more bytes than were requested".into(),
                ))
            } else {
                Ok(nd)
            }
        }
        Completion::Retry => Ok(done),
        Completion::Cancelled => Err(errno_error(libc::ECANCELED)),
        Completion::Failed(e) => Err(errno_error(e)),
    }
}

fn is_short(c: Completion, submitted: usize) -> bool {
    matches!(c, Completion::Done(n) if (n as usize) < submitted)
}

/// Counters and orphan-completion bookkeeping for one ring.
#[derive(Default)]
struct EngineState {
    next_user_data: u64,
    submits: u64,
    completions: u64,
    short_writes: u64,
    short_reads: u64,
    orphan_completions: u64,
    /// `user_data` of nowait operations whose completion has not yet been
    /// collected. `drain` waits for exactly these.
    nowait_outstanding: HashSet<u64>,
    orphans: HashMap<u64, i32>,
}

impl EngineState {
    fn alloc_ud(&mut self) -> u64 {
        // user_data is opaque to the kernel; a monotonic counter makes every
        // completion trivially associable with its operation.
        self.next_user_data += 1;
        self.next_user_data
    }
}

/// A single positional read performed by [`UringEngine::read_batch`].
pub struct ReadJob<'a> {
    /// The file descriptor to read from.
    pub fd: RawFd,
    /// The file offset to read at.
    pub offset: u64,
    /// The destination buffer.
    pub buf: &'a mut [u8],
    /// Bytes transferred so far (advanced across retry rounds).
    pub done: usize,
}

impl<'a> ReadJob<'a> {
    /// Create a job that fills `buf` from `fd` at `offset`.
    pub fn new(fd: RawFd, offset: u64, buf: &'a mut [u8]) -> ReadJob<'a> {
        ReadJob {
            fd,
            offset,
            buf,
            done: 0,
        }
    }
}

/// A single positional write performed by [`UringEngine::write_batch`].
///
/// The referenced bytes must stay valid until `write_batch` returns, which it
/// guarantees (it collects every completion it submits).
pub struct WriteJob<'a> {
    /// The file descriptor to write to.
    pub fd: RawFd,
    /// The file offset to write at.
    pub offset: u64,
    /// The bytes to write.
    pub buf: &'a [u8],
    /// Bytes written so far (advanced across retry rounds).
    pub done: usize,
}

impl<'a> WriteJob<'a> {
    /// Create a job that writes `buf` to `fd` at `offset`.
    pub fn new(fd: RawFd, offset: u64, buf: &'a [u8]) -> WriteJob<'a> {
        WriteJob {
            fd,
            offset,
            buf,
            done: 0,
        }
    }
}

/// Evidence returned by the ordered write+fsync primitive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OrderedReport {
    /// Bytes written in total.
    pub bytes_written: u64,
    /// Number of submit rounds.
    pub rounds: u64,
    /// Whether, in every round, the `fsync` completion arrived *after* the write
    /// completion. This is the machine-checked ordering verdict.
    pub fsync_after_write_every_round: bool,
    /// Number of short writes retried.
    pub short_writes: u64,
}

/// A bounded, capability-probed `io_uring` engine for one logical ring.
pub struct UringEngine {
    ring: IoUring,
    depth: u32,
    state: EngineState,
    pool: Option<BufferPool>,
    registered: bool,
}

/// The opcodes OrFS requires of a backing ring.
fn required_ops() -> [u8; 3] {
    [opcode::Read::CODE, opcode::Write::CODE, opcode::Fsync::CODE]
}

fn describe_setup_error(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::ENOSYS) => "io_uring_setup: ENOSYS (kernel lacks io_uring)".into(),
        Some(libc::EPERM) => "io_uring_setup: EPERM (blocked by seccomp or rlimit)".into(),
        Some(libc::EACCES) => "io_uring_setup: EACCES (disabled by sysctl or LSM)".into(),
        Some(libc::EMFILE) | Some(libc::ENFILE) => "io_uring_setup: too many open files".into(),
        Some(libc::ENOMEM) => "io_uring_setup: ENOMEM (out of memory)".into(),
        _ => format!("io_uring_setup: {e}"),
    }
}

/// Probe whether a usable `io_uring` is available in the current environment.
///
/// Returns `Ok(())` only if a ring can be created *and* every required opcode is
/// supported. This does not cache: it is a genuine runtime probe used by `doctor`,
/// the CLI, and the fallback decisions.
pub fn probe_available() -> std::result::Result<(), String> {
    let ring = IoUring::new(8).map_err(|e| describe_setup_error(&e))?;
    let mut probe = io_uring::Probe::new();
    ring.submitter()
        .register_probe(&mut probe)
        .map_err(|e| format!("io_uring probe failed: {e}"))?;
    for op in required_ops() {
        if !probe.is_supported(op) {
            return Err(format!("required io_uring opcode {op} is not supported"));
        }
    }
    Ok(())
}

impl UringEngine {
    /// Try to create a ring of at least `depth` entries with a probed opcode set.
    ///
    /// On failure the returned `String` is a human-readable reason suitable for
    /// the fallback report.
    pub fn try_new(depth: u32, stage: bool) -> std::result::Result<UringEngine, String> {
        let depth = depth.max(2).next_power_of_two();
        let ring = IoUring::new(depth).map_err(|e| describe_setup_error(&e))?;
        {
            let mut probe = io_uring::Probe::new();
            ring.submitter()
                .register_probe(&mut probe)
                .map_err(|e| format!("io_uring probe failed: {e}"))?;
            for op in required_ops() {
                if !probe.is_supported(op) {
                    return Err(format!("required io_uring opcode {op} is not supported"));
                }
            }
        }
        let pool = if stage {
            Some(BufferPool::new(STAGING_BUFFERS, STAGING_BUFFER_SIZE))
        } else {
            None
        };
        Ok(UringEngine {
            ring,
            depth,
            state: EngineState::default(),
            pool,
            registered: false,
        })
    }

    /// Register the staging buffers with the ring. Returns whether registration
    /// succeeded; failure is non-fatal (writes then submit plain `WRITE` SQEs from
    /// the same buffers).
    pub fn register_buffers(&mut self) -> bool {
        let iov = match &self.pool {
            Some(p) => p.iovecs(),
            None => return false,
        };
        if iov.is_empty() {
            return false;
        }
        // SAFETY: the iovecs point at page-aligned buffers owned by `self.pool`,
        // which lives at least as long as `self` (the ring). We unregister in
        // `Drop` before the pool is released, so no buffer is freed while the
        // kernel may still reference it.
        let ok = unsafe { self.ring.submitter().register_buffers(&iov) }.is_ok();
        self.registered = ok;
        ok
    }

    /// The configured ring depth.
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// Whether the staging buffers are registered.
    pub fn buffers_registered(&self) -> bool {
        self.registered
    }

    /// Snapshot the operation counters.
    pub fn stats(&self) -> UringStats {
        UringStats {
            depth: self.depth,
            submits: self.state.submits,
            completions: self.state.completions,
            short_writes: self.state.short_writes,
            short_reads: self.state.short_reads,
            orphan_completions: self.state.orphan_completions,
        }
    }

    /// Write all of `buf` at `offset` on `fd`, retrying short writes.
    ///
    /// The engine is synchronous: every submitted operation's completion is
    /// validated before this returns, so `buf` is valid for the whole call.
    pub fn write_at_all(&mut self, fd: RawFd, offset: u64, buf: &[u8]) -> Result<u64> {
        if self.pool.is_some() {
            self.write_staged(fd, offset, buf)
        } else {
            self.write_direct(fd, offset, buf)
        }
    }

    fn write_direct(&mut self, fd: RawFd, offset: u64, buf: &[u8]) -> Result<u64> {
        let total = buf.len();
        let mut done = 0usize;
        while done < total {
            let ud = self.state.alloc_ud();
            let ptr = buf[done..].as_ptr();
            let submitted = total - done;
            let entry = opcode::Write::new(types::Fd(fd), ptr, submitted as u32)
                .offset(offset + done as u64)
                .build()
                .user_data(ud);
            let order = run_entries(&mut self.ring, &mut self.state, vec![entry], 1)?;
            let res = take_result(&order, ud)?;
            let c = classify_completion(res);
            if is_short(c, submitted) {
                self.state.short_writes += 1;
            }
            done = advance_write(done, total, res)?;
        }
        Ok(done as u64)
    }

    fn write_staged(&mut self, fd: RawFd, offset: u64, buf: &[u8]) -> Result<u64> {
        let UringEngine {
            ring,
            state,
            pool,
            registered,
            ..
        } = self;
        let pool = pool
            .as_ref()
            .expect("write_staged is only called when a pool exists");
        let registered = *registered;
        let total = buf.len();
        let mut done = 0usize;
        while done < total {
            // A pin borrows the pool: the buffer cannot be released (nor the pool
            // dropped) while the operation referencing it is in flight.
            let mut pin = pool.pin().ok_or_else(|| {
                OrfsError::Unsupported("io_uring staging buffer pool exhausted".into())
            })?;
            let submitted = (total - done).min(pin.capacity());
            pin.buffer_mut()[..submitted].copy_from_slice(&buf[done..done + submitted]);
            let ud = state.alloc_ud();
            let ptr = pin.as_ptr();
            let index = pin.index() as u16;
            let entry = if registered {
                opcode::WriteFixed::new(types::Fd(fd), ptr as *const u8, submitted as u32, index)
                    .offset(offset + done as u64)
                    .build()
                    .user_data(ud)
            } else {
                opcode::Write::new(types::Fd(fd), ptr as *const u8, submitted as u32)
                    .offset(offset + done as u64)
                    .build()
                    .user_data(ud)
            };
            let order = run_entries(&mut *ring, state, vec![entry], 1)?;
            let res = take_result(&order, ud)?;
            let c = classify_completion(res);
            if is_short(c, submitted) {
                state.short_writes += 1;
            }
            done = advance_write(done, done + submitted, res)?;
            // The completion has been collected; only now is it safe to release.
            drop(pin);
        }
        Ok(done as u64)
    }

    /// Read exactly `buf.len()` bytes at `offset` on `fd`, retrying partial reads.
    pub fn read_exact_at(&mut self, fd: RawFd, offset: u64, buf: &mut [u8]) -> Result<()> {
        let total = buf.len();
        let mut done = 0usize;
        while done < total {
            let ud = self.state.alloc_ud();
            let ptr = buf[done..].as_mut_ptr();
            let submitted = total - done;
            let entry = opcode::Read::new(types::Fd(fd), ptr, submitted as u32)
                .offset(offset + done as u64)
                .build()
                .user_data(ud);
            let order = run_entries(&mut self.ring, &mut self.state, vec![entry], 1)?;
            let res = take_result(&order, ud)?;
            let c = classify_completion(res);
            if is_short(c, submitted) {
                self.state.short_reads += 1;
            }
            done = advance_read(done, total, res)?;
        }
        Ok(())
    }

    /// Submit a batch of positional reads concurrently (Ring R) and advance each
    /// job until it is complete. This is the concurrent immutable-segment read
    /// primitive; short reads are retried round by round.
    pub fn read_batch(&mut self, jobs: &mut [ReadJob<'_>]) -> Result<()> {
        loop {
            let mut mapping: Vec<(u64, usize)> = Vec::new();
            let mut entries: Vec<squeue::Entry> = Vec::new();
            for (j, job) in jobs.iter_mut().enumerate() {
                if job.done >= job.buf.len() {
                    continue;
                }
                let ud = self.state.alloc_ud();
                let submitted = job.buf.len() - job.done;
                // SAFETY: `job.buf` is a `&mut [u8]` owned by the caller and stays
                // borrowed (and thus unmoved and valid) until `read_batch` returns;
                // every submitted completion is collected before then.
                let ptr = unsafe { job.buf.as_mut_ptr().add(job.done) };
                let entry = opcode::Read::new(types::Fd(job.fd), ptr, submitted as u32)
                    .offset(job.offset + job.done as u64)
                    .build()
                    .user_data(ud);
                mapping.push((ud, j));
                entries.push(entry);
            }
            if entries.is_empty() {
                return Ok(());
            }
            let order = run_entries(&mut self.ring, &mut self.state, entries, mapping.len())?;
            for (ud, res) in order {
                let Some(&(_, j)) = mapping.iter().find(|(u, _)| *u == ud) else {
                    continue;
                };
                let job = &mut jobs[j];
                let submitted = job.buf.len() - job.done;
                if is_short(classify_completion(res), submitted) {
                    self.state.short_reads += 1;
                }
                job.done = advance_read(job.done, job.buf.len(), res)?;
            }
        }
    }

    /// Submit a batch of positional writes concurrently (Ring W batching) and
    /// advance each job until complete. Batches are capped at the ring depth so
    /// the submission queue can never saturate.
    ///
    /// This is the "multiple requests may be batched" path of research §20; it
    /// changes nothing about *visibility* — the caller still publishes only after
    /// every completion has been validated.
    pub fn write_batch(&mut self, jobs: &mut [WriteJob<'_>]) -> Result<()> {
        let max_batch = self.depth as usize;
        loop {
            let mut mapping: Vec<(u64, usize)> = Vec::new();
            let mut entries: Vec<squeue::Entry> = Vec::new();
            for (j, job) in jobs.iter_mut().enumerate() {
                if job.done >= job.buf.len() || entries.len() >= max_batch {
                    continue;
                }
                let ud = self.state.alloc_ud();
                let submitted = job.buf.len() - job.done;
                // SAFETY: `job.buf` is a `&[u8]` owned by the caller and stays
                // borrowed (and valid) until `write_batch` returns; every
                // submitted completion is collected before then.
                let ptr = unsafe { job.buf.as_ptr().add(job.done) };
                let entry = opcode::Write::new(types::Fd(job.fd), ptr, submitted as u32)
                    .offset(job.offset + job.done as u64)
                    .build()
                    .user_data(ud);
                mapping.push((ud, j));
                entries.push(entry);
            }
            if entries.is_empty() {
                return Ok(());
            }
            let order = run_entries(&mut self.ring, &mut self.state, entries, mapping.len())?;
            for (ud, res) in order {
                let Some(&(_, j)) = mapping.iter().find(|(u, _)| *u == ud) else {
                    continue;
                };
                let job = &mut jobs[j];
                let submitted = job.buf.len() - job.done;
                if is_short(classify_completion(res), submitted) {
                    self.state.short_writes += 1;
                }
                job.done = advance_write(job.done, job.buf.len(), res)?;
            }
        }
    }

    /// `fsync` `fd` and wait for completion.
    pub fn fsync(&mut self, fd: RawFd) -> Result<()> {
        let ud = self.state.alloc_ud();
        let entry = opcode::Fsync::new(types::Fd(fd)).build().user_data(ud);
        let order = run_entries(&mut self.ring, &mut self.state, vec![entry], 1)?;
        let res = take_result(&order, ud)?;
        match classify_completion(res) {
            Completion::Done(_) | Completion::Retry => Ok(()),
            Completion::Cancelled => Err(errno_error(libc::ECANCELED)),
            Completion::Failed(e) => Err(errno_error(e)),
        }
    }

    /// An **ordered durability barrier**: `fsync` `fd`, flagged `IOSQE_IO_DRAIN`,
    /// so the kernel does not start it until every previously submitted SQE on
    /// this ring has completed. This is the explicit mechanism used when a durable
    /// point must be clamped after a set of writes that were submitted together.
    pub fn fsync_order_barrier(&mut self, fd: RawFd) -> Result<()> {
        let ud = self.state.alloc_ud();
        let entry = opcode::Fsync::new(types::Fd(fd))
            .build()
            .flags(squeue::Flags::IO_DRAIN)
            .user_data(ud);
        let order = run_entries(&mut self.ring, &mut self.state, vec![entry], 1)?;
        let res = take_result(&order, ud)?;
        match classify_completion(res) {
            Completion::Done(_) | Completion::Retry => Ok(()),
            Completion::Cancelled => Err(errno_error(libc::ECANCELED)),
            Completion::Failed(e) => Err(errno_error(e)),
        }
    }

    /// Write `buf` at `offset`, then `fsync` **with an `IOSQE_IO_DRAIN` barrier**,
    /// in a single submission round, and verify from the completion order that the
    /// `fsync` did not complete before the write.
    ///
    /// This is the demonstration that ordering is explicit: the write and the
    /// `fsync` are submitted together, yet the drain flag forces the `fsync` to
    /// wait. Short writes are retried in further rounds (each also drained).
    pub fn write_then_fsync_ordered(
        &mut self,
        fd: RawFd,
        offset: u64,
        buf: &[u8],
    ) -> Result<OrderedReport> {
        let mut report = OrderedReport {
            bytes_written: 0,
            rounds: 0,
            fsync_after_write_every_round: true,
            short_writes: 0,
        };
        let total = buf.len();
        let mut done = 0usize;
        while done < total {
            let n = (total - done).min(MAX_ORDERED_CHUNK);
            let w_ud = self.state.alloc_ud();
            let f_ud = self.state.alloc_ud();
            let wentry = opcode::Write::new(types::Fd(fd), buf[done..].as_ptr(), n as u32)
                .offset(offset + done as u64)
                .build()
                .user_data(w_ud);
            let fentry = opcode::Fsync::new(types::Fd(fd))
                .build()
                .flags(squeue::Flags::IO_DRAIN)
                .user_data(f_ud);
            let order = run_entries(&mut self.ring, &mut self.state, vec![wentry, fentry], 2)?;
            let wres = take_result(&order, w_ud)?;
            let fres = take_result(&order, f_ud)?;

            let wpos = order.iter().position(|(u, _)| *u == w_ud);
            let fpos = order.iter().position(|(u, _)| *u == f_ud);
            report.fsync_after_write_every_round &=
                matches!((wpos, fpos), (Some(a), Some(b)) if b > a);
            report.rounds += 1;

            match classify_completion(fres) {
                Completion::Done(_) | Completion::Retry => {}
                Completion::Cancelled => return Err(errno_error(libc::ECANCELED)),
                Completion::Failed(e) => return Err(errno_error(e)),
            }
            if is_short(classify_completion(wres), n) {
                report.short_writes += 1;
                self.state.short_writes += 1;
            }
            done = advance_write(done, done + n, wres)?;
        }
        // A final barrier makes the whole write durable.
        self.fsync(fd)?;
        report.bytes_written = done as u64;
        Ok(report)
    }

    /// Submit a read **without waiting** and return its `user_data`. The buffer
    /// pointed at by `buf` must remain valid until [`UringEngine::wait_for`] or
    /// [`UringEngine::drain`] collects the completion.
    pub fn submit_read_nowait(&mut self, fd: RawFd, buf: &mut [u8]) -> Result<u64> {
        let ud = self.state.alloc_ud();
        let entry = opcode::Read::new(types::Fd(fd), buf.as_mut_ptr(), buf.len() as u32)
            .offset(0)
            .build()
            .user_data(ud);
        {
            let mut sq = self.ring.submission();
            // SAFETY: `buf` outlives the completion; the caller holds it until the
            // completion is collected, per this function's contract.
            if unsafe { sq.push(&entry) }.is_err() {
                return Err(OrfsError::Io(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "io_uring submission queue full",
                )));
            }
        }
        self.ring.submit().map_err(OrfsError::Io)?;
        self.state.submits += 1;
        self.state.nowait_outstanding.insert(ud);
        Ok(ud)
    }

    /// Request cancellation of the in-flight operation identified by `target`.
    ///
    /// Cancellation is best-effort: the target's own completion (`-ECANCELED`) is
    /// observed through [`UringEngine::wait_for`]. A canceled operation is **not**
    /// proof that its buffer is immediately safe to release; the caller must still
    /// wait for the completion.
    pub fn cancel(&mut self, target: u64) -> Result<()> {
        let ud = self.state.alloc_ud();
        let entry = opcode::AsyncCancel::new(target).build().user_data(ud);
        let order = run_entries(&mut self.ring, &mut self.state, vec![entry], 1)?;
        // Success (0) or -ENOENT (already completed) are both acceptable; the
        // target's own completion is the authority.
        let _ = take_result(&order, ud);
        Ok(())
    }

    /// Wait for the completion of a specific previously-submitted operation.
    /// Completions for other operations are stashed and returned by later waits.
    pub fn wait_for(&mut self, ud: u64) -> Result<i32> {
        if let Some(r) = self.state.orphans.remove(&ud) {
            return Ok(r);
        }
        loop {
            match self.ring.submit_and_wait(1) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(OrfsError::Io(e)),
            }
            let mut cq = self.ring.completion();
            let mut found: Option<i32> = None;
            let mut drained = 0u64;
            for cqe in &mut cq {
                let u = cqe.user_data();
                let r = cqe.result();
                drained += 1;
                self.state.nowait_outstanding.remove(&u);
                if u == ud {
                    found = Some(r);
                } else {
                    self.state.orphans.insert(u, r);
                    self.state.orphan_completions += 1;
                }
            }
            cq.sync();
            self.state.completions += drained;
            if let Some(r) = found {
                return Ok(r);
            }
        }
    }

    /// Drain every outstanding (nowait) operation to completion.
    ///
    /// This is the teardown path: it does not assume a canceled operation is
    /// complete — it waits for the CQE. It blocks until outstanding operations
    /// complete, so the caller must ensure they *can* complete (e.g. by cancelling
    /// a blocking request first).
    pub fn drain(&mut self) -> Result<()> {
        self.ring.submit().map_err(OrfsError::Io)?;
        while !self.state.nowait_outstanding.is_empty() {
            match self.ring.submit_and_wait(1) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(OrfsError::Io(e)),
            }
            let mut cq = self.ring.completion();
            let mut drained = 0u64;
            for cqe in &mut cq {
                let u = cqe.user_data();
                self.state.nowait_outstanding.remove(&u);
                self.state.orphans.insert(u, cqe.result());
                drained += 1;
            }
            cq.sync();
            self.state.completions += drained;
        }
        Ok(())
    }

    /// A borrowed view of the staging pool, if any (for tests/evidence).
    pub fn pool(&self) -> Option<&BufferPool> {
        self.pool.as_ref()
    }

    /// Take a raw mutable reference to the underlying ring, for tests that must
    /// inspect ring state. Not part of the safe surface.
    #[doc(hidden)]
    pub fn ring_mut(&mut self) -> &mut IoUring {
        &mut self.ring
    }
}

impl Drop for UringEngine {
    fn drop(&mut self) {
        // Submit anything queued, then reap what has already completed without
        // blocking. Our public API is submit-and-wait, so a normally-used engine
        // has nothing outstanding here; an aborted test might, and we must not
        // free a buffer the kernel could still touch. Because the engine owns the
        // pool and is dropped together with it, we unregister the buffers first.
        let _ = self.ring.submit();
        let mut cq = self.ring.completion();
        cq.sync();
        let pending = cq.len();
        for cqe in &mut cq {
            self.state.orphans.insert(cqe.user_data(), cqe.result());
        }
        cq.sync();
        let _ = pending;
        drop(cq);
        if self.registered {
            // Best-effort: ignore errors during teardown.
            let _ = self.ring.submitter().unregister_buffers();
        }
    }
}

/// Push `entries`, submit, and return completions in arrival order.
///
/// Every completion carries its operation's `user_data`. Completions for
/// operations that are not part of this batch are stashed as orphans.
fn run_entries(
    ring: &mut IoUring,
    state: &mut EngineState,
    entries: Vec<squeue::Entry>,
    want: usize,
) -> Result<Vec<(u64, i32)>> {
    if want == 0 {
        return Ok(Vec::new());
    }
    {
        let mut sq = ring.submission();
        for e in &entries {
            // SAFETY: the caller guarantees every buffer referenced by `e` stays
            // valid until this function returns, and this function collects every
            // requested completion before returning.
            if unsafe { sq.push(e) }.is_err() {
                return Err(OrfsError::Io(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "io_uring submission queue full",
                )));
            }
        }
    }
    let expected: HashSet<u64> = entries.iter().map(|e| e.get_user_data()).collect();
    let mut got: HashSet<u64> = HashSet::new();
    let mut order: Vec<(u64, i32)> = Vec::with_capacity(want);
    while got.len() < want {
        match ring.submit_and_wait(want - got.len()) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(OrfsError::Io(e)),
        }
        let mut cq = ring.completion();
        let mut drained = 0u64;
        for cqe in &mut cq {
            let ud = cqe.user_data();
            let res = cqe.result();
            drained += 1;
            order.push((ud, res));
            state.nowait_outstanding.remove(&ud);
            if expected.contains(&ud) {
                got.insert(ud);
            } else {
                state.orphans.insert(ud, res);
                state.orphan_completions += 1;
            }
        }
        cq.sync();
        state.completions += drained;
    }
    state.submits += entries.len() as u64;
    Ok(order)
}

fn take_result(order: &[(u64, i32)], ud: u64) -> Result<i32> {
    order
        .iter()
        .find(|(u, _)| *u == ud)
        .map(|(_, r)| *r)
        .ok_or_else(|| OrfsError::Corrupt("io_uring completion missing for operation".into()))
}

/// Ring W (authoritative writes) + Ring R (concurrent reads) as one owned unit.
pub struct BackingRings {
    write: RefCell<UringEngine>,
    read: RefCell<UringEngine>,
}

impl BackingRings {
    /// Create both rings, registering the write ring's staging buffers if possible.
    pub fn try_new(
        write_depth: u32,
        read_depth: u32,
        stage_writes: bool,
    ) -> std::result::Result<BackingRings, String> {
        let mut write = UringEngine::try_new(write_depth, stage_writes)?;
        if stage_writes {
            let _ = write.register_buffers();
        }
        let read = UringEngine::try_new(read_depth, false)?;
        Ok(BackingRings {
            write: RefCell::new(write),
            read: RefCell::new(read),
        })
    }

    /// The write ring.
    pub fn write(&self) -> &RefCell<UringEngine> {
        &self.write
    }

    /// The read ring.
    pub fn read(&self) -> &RefCell<UringEngine> {
        &self.read
    }

    /// Write-ring depth.
    pub fn write_depth(&self) -> u32 {
        self.write.borrow().depth()
    }

    /// Read-ring depth.
    pub fn read_depth(&self) -> u32 {
        self.read.borrow().depth()
    }

    /// Number of registered staging buffers (0 if not registered).
    pub fn registered_buffers(&self) -> usize {
        if self.write.borrow().buffers_registered() {
            self.write
                .borrow()
                .pool()
                .map(|p| p.capacity())
                .unwrap_or(0)
        } else {
            0
        }
    }

    /// Combined stats for evidence.
    pub fn stats(&self) -> (UringStats, UringStats) {
        (self.write.borrow().stats(), self.read.borrow().stats())
    }
}

/// The backing-I/O engine a [`crate::log::Log`] uses.
pub enum BackingEngine {
    /// Synchronous positional `pread`/`pwrite` + `fsync`.
    Sync,
    /// `io_uring` Rings W and R (boxed: the two rings are much larger than the
    /// `Sync` variant).
    Uring(Box<BackingRings>),
}

impl BackingEngine {
    /// Attempt to engage io_uring. On failure, returns the reason and the caller
    /// keeps [`BackingEngine::Sync`].
    pub fn engage(cfg: &UringConfig) -> std::result::Result<BackingEngine, String> {
        if !cfg.enabled {
            return Ok(BackingEngine::Sync);
        }
        let rings = BackingRings::try_new(cfg.write_depth, cfg.read_depth, cfg.stage_writes)?;
        Ok(BackingEngine::Uring(Box::new(rings)))
    }

    /// Whether the engine is actually io_uring.
    pub fn is_uring(&self) -> bool {
        matches!(self, BackingEngine::Uring(_))
    }

    /// The rings, if engaged.
    pub fn rings(&self) -> Option<&BackingRings> {
        match self {
            BackingEngine::Sync => None,
            BackingEngine::Uring(r) => Some(&**r),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_handles_short_retry_cancel_and_error() {
        assert_eq!(classify_completion(5), Completion::Done(5));
        assert_eq!(classify_completion(0), Completion::Done(0));
        assert_eq!(classify_completion(-libc::EINTR), Completion::Retry);
        assert_eq!(classify_completion(-libc::ECANCELED), Completion::Cancelled);
        assert_eq!(
            classify_completion(-libc::EIO),
            Completion::Failed(libc::EIO)
        );
    }

    #[test]
    fn short_writes_are_retried_while_preserving_the_reservation() {
        // Scripted completions for a 10-byte write: 3, 3, 4.
        let mut script = [3, 3, 4].into_iter();
        let total = 10usize;
        let mut done = 0usize;
        while done < total {
            let res = script.next().expect("script exhausted");
            done = advance_write(done, total, res).expect("advance");
        }
        assert_eq!(done, 10);
        assert!(script.next().is_none());
    }

    #[test]
    fn write_loop_offsets_never_rewrite_the_prefix() {
        // Reconstruct the offsets the loop would submit for 3,3,4.
        let mut observed = Vec::new();
        let mut done = 0usize;
        for res in [3, 3, 4] {
            observed.push(done);
            done = advance_write(done, 10, res).unwrap();
        }
        assert_eq!(observed, vec![0, 3, 6]);
    }

    #[test]
    fn zero_progress_write_is_an_error() {
        assert!(advance_write(0, 10, 0).is_err());
    }

    #[test]
    fn short_read_is_retried_and_eof_is_an_error() {
        let mut done = 0usize;
        for res in [2, 0, 3] {
            match advance_read(done, 5, res) {
                Ok(next) => done = next,
                Err(_) => {
                    // The 0 in the middle is EOF and must be an error; continue is
                    // impossible, so assert that exactly this happens.
                    assert_eq!(done, 2);
                    return;
                }
            }
        }
        panic!("EOF (a zero-length read) must terminate the loop with an error");
    }

    #[test]
    fn probe_reports_a_reason_without_panicking() {
        // Either io_uring works, or we get a human-readable reason; never a panic.
        match probe_available() {
            Ok(()) => {}
            Err(reason) => assert!(!reason.is_empty()),
        }
    }
}
