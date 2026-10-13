//! Minimal hardware-PMU access over `perf_event_open(2)` (Phase 50 PMU court).
//!
//! `libc` exposes `SYS_perf_event_open` but neither `struct perf_event_attr` nor
//! the `PERF_*` constants, so the ABI struct and the constants used here are
//! declared directly from `include/uapi/linux/perf_event.h`.
//!
//! # The blocker this corrects
//!
//! `perf_event_paranoid=2` does **not** disable user-space counters: it denies
//! *kernel* profiling to an unprivileged caller. A user-space, per-thread event
//! (`pid=0`, `cpu=-1`, `exclude_kernel=1`, `exclude_hv=1`) is still permitted.
//! The real blocker is usually the container's seccomp profile, which denies the
//! syscall outright with `EPERM` — the same default profile that denies
//! `io_uring_setup`. Every failure path here carries the errno name, so a caller
//! never has to infer availability from `/proc/sys/kernel/perf_event_paranoid`.
//!
//! # Contents
//!
//! * [`PmuGroup`] — a group reader over the six generic hardware events
//!   (cycles, instructions, cache-references, cache-misses, branch-instructions,
//!   branch-misses) with reset/enable/disable/read.
//! * [`Sampler`] — a sampling reader over a `perf_event_open` ring buffer that
//!   records the instruction pointer and (when unwindable) the call chain, for
//!   the flamegraph.

#![allow(dead_code)]

use std::os::unix::io::RawFd;

// ---------------------------------------------------------------------------
// perf_event ABI (declared from include/uapi/linux/perf_event.h)
// ---------------------------------------------------------------------------

const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_TYPE_SOFTWARE: u32 = 1;

const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
const PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
const PERF_COUNT_HW_BRANCH_INSTRUCTIONS: u64 = 4;
const PERF_COUNT_HW_BRANCH_MISSES: u64 = 5;

/// `PERF_TYPE_SOFTWARE` / `PERF_COUNT_SW_CPU_CLOCK` — a timer-driven sampling
/// event. Used for the flamegraph because it is robust across (virtualised) CPUs
/// where the hardware cycle event's overflow interrupt is unreliable.
const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;

// Attribute flag-word bit positions (declaration order in the header).
const PERF_ATTR_DISABLED: u64 = 1 << 0;
const PERF_ATTR_EXCLUDE_KERNEL: u64 = 1 << 5;
const PERF_ATTR_EXCLUDE_HV: u64 = 1 << 6;

// `sample_type` bits.
const PERF_SAMPLE_IP: u64 = 1 << 0;
const PERF_SAMPLE_TID: u64 = 1 << 1;

/// `PERF_RECORD_SAMPLE` (`enum perf_event_type`).
const PERF_RECORD_SAMPLE: u32 = 9;

// ioctl requests: `_IO('$', n)` with `$` = 0x24 on x86_64.
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
const PERF_EVENT_IOC_RESET: libc::c_ulong = 0x2403;
const PERF_IOC_FLAG_GROUP: libc::c_ulong = 1;

/// The prefix of `struct perf_event_attr` published as ABI version 0
/// (`PERF_ATTR_SIZE_VER0`, 64 bytes). Every field used by this module fits in
/// that prefix, and the kernel accepts exactly this size.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    /// The `bp_addr`/`config1` union tail, present so the struct is 64 bytes.
    config1: u64,
}

const _: () = assert!(std::mem::size_of::<PerfEventAttr>() == 64);

/// The `perf_event_mmap_page` metadata header (the first mmap page). Only the
/// record-ring fields are named; the shape and offsets are the stable kernel ABI
/// (`include/uapi/linux/perf_event.h`), with `data_head` at byte offset 1024.
#[repr(C)]
struct PerfEventMmapPage {
    version: u32,
    compat_version: u32,
    lock: u32,
    index: u32,
    offset: i64,
    time_enabled: u64,
    time_running: u64,
    capabilities: u64,
    pmc_width: u16,
    time_shift: u16,
    time_mult: u32,
    time_offset: u64,
    time_zero: u64,
    size: u32,
    _reserved_1: u32,
    time_cycles: u64,
    time_mask: u64,
    __reserved: [u8; 928],
    data_head: u64,
    data_tail: u64,
    data_offset: u64,
    data_size: u64,
}

// ---------------------------------------------------------------------------
// errno helpers
// ---------------------------------------------------------------------------

/// The name of an errno value, from `errno.h`. Falls back to `ERRNO`.
pub fn errno_name(errno: i32) -> &'static str {
    match errno {
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ESRCH => "ESRCH",
        libc::EINTR => "EINTR",
        libc::EIO => "EIO",
        libc::ENXIO => "ENXIO",
        libc::EBADF => "EBADF",
        libc::EACCES => "EACCES",
        libc::EBUSY => "EBUSY",
        libc::EINVAL => "EINVAL",
        libc::EMFILE => "EMFILE",
        libc::ENFILE => "ENFILE",
        libc::ENODEV => "ENODEV",
        libc::ENOSYS => "ENOSYS",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        _ => "ERRNO",
    }
}

/// Format the current `errno` as `NAME (os error N)`.
fn errno_string() -> String {
    let e = std::io::Error::last_os_error();
    let n = e.raw_os_error().unwrap_or(0);
    format!("{} (os error {})", errno_name(n), n)
}

// ---------------------------------------------------------------------------
// The counter set
// ---------------------------------------------------------------------------

/// A generic hardware counter (`PERF_TYPE_HARDWARE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Counter {
    Cycles,
    Instructions,
    CacheReferences,
    CacheMisses,
    BranchInstructions,
    BranchMisses,
}

impl Counter {
    /// Every counter the group reader attempts to open, leader first.
    pub const ALL: [Counter; 6] = [
        Counter::Cycles,
        Counter::Instructions,
        Counter::CacheReferences,
        Counter::CacheMisses,
        Counter::BranchInstructions,
        Counter::BranchMisses,
    ];

    /// The stable evidence name.
    pub fn name(self) -> &'static str {
        match self {
            Counter::Cycles => "cycles",
            Counter::Instructions => "instructions",
            Counter::CacheReferences => "cache_references",
            Counter::CacheMisses => "cache_misses",
            Counter::BranchInstructions => "branch_instructions",
            Counter::BranchMisses => "branch_misses",
        }
    }

    fn config(self) -> u64 {
        match self {
            Counter::Cycles => PERF_COUNT_HW_CPU_CYCLES,
            Counter::Instructions => PERF_COUNT_HW_INSTRUCTIONS,
            Counter::CacheReferences => PERF_COUNT_HW_CACHE_REFERENCES,
            Counter::CacheMisses => PERF_COUNT_HW_CACHE_MISSES,
            Counter::BranchInstructions => PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
            Counter::BranchMisses => PERF_COUNT_HW_BRANCH_MISSES,
        }
    }
}

/// A user-space-only, per-thread, disabled-by-default hardware attribute.
fn hardware_attr(config: u64) -> PerfEventAttr {
    PerfEventAttr {
        type_: PERF_TYPE_HARDWARE,
        size: std::mem::size_of::<PerfEventAttr>() as u32,
        config,
        flags: PERF_ATTR_DISABLED | PERF_ATTR_EXCLUDE_KERNEL | PERF_ATTR_EXCLUDE_HV,
        ..Default::default()
    }
}

fn syscall_open(attr: &mut PerfEventAttr, group_fd: RawFd) -> Result<RawFd, String> {
    // SAFETY: `attr` is a valid, fully initialised ABI struct for the duration of
    // the call; `syscall` is invoked with the exact `perf_event_open(2)` layout
    // and the return value is checked before use.
    let attr_ptr: *mut PerfEventAttr = attr;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            attr_ptr,
            0,  // pid 0: the calling thread
            -1, // cpu -1: no CPU-wide event (the unprivileged-permitted form)
            group_fd,
            0, // flags
        )
    };
    if fd < 0 {
        return Err(errno_string());
    }
    Ok(fd as RawFd)
}

// ---------------------------------------------------------------------------
// The group reader
// ---------------------------------------------------------------------------

/// A group of user-space hardware counters for the calling thread.
///
/// All counters are created disabled, then enabled and disabled together through
/// the group leader. `read_all` reads every live counter.
pub struct PmuGroup {
    /// `(counter, fd)`, the cycle-counter leader first.
    events: Vec<(Counter, RawFd)>,
    /// Counters the kernel could not provide on this microarchitecture
    /// (skipped, never fatal).
    missing: Vec<Counter>,
    enabled: bool,
}

impl PmuGroup {
    /// Open the group. On failure the error names the errno (typically `EPERM`
    /// when a seccomp profile blocks `perf_event_open`, or `ENOSYS`/`EINVAL`).
    /// A single unsupported *member* event is skipped, not fatal; only the cycle
    /// leader failing is an error.
    pub fn open() -> Result<PmuGroup, String> {
        let leader = {
            let mut attr = hardware_attr(Counter::Cycles.config());
            syscall_open(&mut attr, -1)?
        };
        let mut events = vec![(Counter::Cycles, leader)];
        let mut missing = Vec::new();
        for &counter in &Counter::ALL {
            if counter == Counter::Cycles {
                continue;
            }
            let mut attr = hardware_attr(counter.config());
            match syscall_open(&mut attr, leader) {
                Ok(fd) => events.push((counter, fd)),
                // E.g. a virtualised CPU without generic cache/branch counters.
                Err(_) => missing.push(counter),
            }
        }
        Ok(PmuGroup {
            events,
            missing,
            enabled: false,
        })
    }

    /// The counters the kernel granted.
    pub fn counters(&self) -> Vec<Counter> {
        self.events.iter().map(|(c, _)| *c).collect()
    }

    /// The counters the kernel refused (best-effort members only).
    pub fn missing(&self) -> &[Counter] {
        &self.missing
    }

    /// Whether a counter is live.
    pub fn has(&self, counter: Counter) -> bool {
        self.events.iter().any(|(c, _)| *c == counter)
    }

    fn leader(&self) -> RawFd {
        // The constructor always inserts the leader first.
        self.events[0].1
    }

    fn group_ioctl(&self, request: libc::c_ulong) -> Result<(), String> {
        // SAFETY: `leader()` is a live perf fd; a control ioctl dereferences no
        // user memory.
        let rc = unsafe { libc::ioctl(self.leader(), request, PERF_IOC_FLAG_GROUP) };
        if rc < 0 {
            Err(errno_string())
        } else {
            Ok(())
        }
    }

    /// Reset every counter in the group to zero.
    pub fn reset(&self) -> Result<(), String> {
        self.group_ioctl(PERF_EVENT_IOC_RESET)
    }

    /// Enable the whole group.
    pub fn enable(&mut self) -> Result<(), String> {
        self.group_ioctl(PERF_EVENT_IOC_ENABLE)?;
        self.enabled = true;
        Ok(())
    }

    /// Disable the whole group.
    pub fn disable(&mut self) -> Result<(), String> {
        self.group_ioctl(PERF_EVENT_IOC_DISABLE)?;
        self.enabled = false;
        Ok(())
    }

    /// Whether the group is currently enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Read every live counter as `(counter, value)`.
    pub fn read_all(&self) -> Vec<(Counter, u64)> {
        self.events
            .iter()
            .map(|&(counter, fd)| (counter, read_counter(fd)))
            .collect()
    }

    /// Read one counter, if it is live.
    pub fn read(&self, counter: Counter) -> Option<u64> {
        self.events
            .iter()
            .find(|(c, _)| *c == counter)
            .map(|&(_, fd)| read_counter(fd))
    }
}

impl Drop for PmuGroup {
    fn drop(&mut self) {
        for &(_, fd) in &self.events {
            // SAFETY: each fd was opened by this module and is owned here.
            unsafe { libc::close(fd) };
        }
    }
}

/// Read one counter fd (a single `u64`, because `read_format` is 0).
fn read_counter(fd: RawFd) -> u64 {
    let mut value: u64 = 0;
    // SAFETY: `fd` is a live perf counter fd and a single-u64 read is the
    // documented form for a counter opened without `PERF_FORMAT_GROUP`.
    let n = unsafe {
        libc::read(
            fd,
            &mut value as *mut u64 as *mut libc::c_void,
            std::mem::size_of::<u64>(),
        )
    };
    if n as usize == std::mem::size_of::<u64>() {
        value
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// The sampling reader (ring buffer)
// ---------------------------------------------------------------------------

/// One sampled instruction pointer. Leaf-only: `PERF_SAMPLE_IP` records the
/// exact interrupted instruction, which is the robust attribution this court
/// uses (a full call chain would need reliable user-stack unwinding).
#[derive(Debug, Clone)]
pub struct Sample {
    pub ip: u64,
}

/// A per-thread sampling event over a `perf_event_open` record ring.
pub struct Sampler {
    fd: RawFd,
    mmap: *mut u8,
    mmap_len: usize,
    data_offset: usize,
    data_size: usize,
    tail: u64,
}

fn page_size() -> usize {
    // SAFETY: `sysconf(_SC_PAGESIZE)` returns a positive page size or -1.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 {
        n as usize
    } else {
        4096
    }
}

impl Sampler {
    /// Open a sampling event on the software CPU clock.
    ///
    /// `period_ns` is the nanosecond interval between samples (a period of
    /// 200000 ns is 5 kHz). Each sample records the interrupted instruction
    /// pointer (`PERF_SAMPLE_IP`) — a flat, reliable attribution. The software
    /// clock is used instead of a hardware event because its overflow interrupt
    /// is dependable on this virtualised AMD host.
    pub fn open(period_ns: u64) -> Result<Sampler, String> {
        let mut attr = hardware_attr(PERF_COUNT_SW_CPU_CLOCK);
        attr.type_ = PERF_TYPE_SOFTWARE;
        attr.sample_period = period_ns.max(1);
        attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID;
        attr.wakeup_events = 1;
        let fd = syscall_open(&mut attr, -1)?;

        let page = page_size();
        // One metadata page plus eight data pages.
        let mmap_len = (1 + 8) * page;
        // SAFETY: `mmap` maps the kernel-provided ring for `fd`; length and flags
        // are the documented ones for a perf record ring.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            let e = errno_string();
            // SAFETY: `fd` was opened above and is not otherwise owned.
            unsafe { libc::close(fd) };
            return Err(format!("mmap: {e}"));
        }
        let meta = ptr as *const PerfEventMmapPage;
        // SAFETY: the kernel filled the metadata page; these fields are the
        // documented ring layout.
        let (data_offset, data_size) =
            unsafe { ((*meta).data_offset as usize, (*meta).data_size as usize) };
        Ok(Sampler {
            fd,
            mmap: ptr as *mut u8,
            mmap_len,
            data_offset,
            data_size,
            tail: 0,
        })
    }

    /// Start sampling.
    pub fn enable(&mut self) -> Result<(), String> {
        // SAFETY: `fd` is a live perf fd; the group flag is not needed.
        let rc = unsafe { libc::ioctl(self.fd, PERF_EVENT_IOC_ENABLE, 0) };
        if rc < 0 {
            Err(errno_string())
        } else {
            Ok(())
        }
    }

    /// Stop sampling.
    pub fn disable(&mut self) -> Result<(), String> {
        // SAFETY: as `enable`.
        let rc = unsafe { libc::ioctl(self.fd, PERF_EVENT_IOC_DISABLE, 0) };
        if rc < 0 {
            Err(errno_string())
        } else {
            Ok(())
        }
    }

    /// Drain the ring of every record produced since the last call.
    pub fn collect(&mut self) -> Vec<Sample> {
        if self.mmap.is_null() || self.data_size == 0 {
            return Vec::new();
        }
        let meta = self.mmap as *mut PerfEventMmapPage;
        // Observe everything the kernel wrote before `data_head`.
        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
        let head = unsafe { (*meta).data_head };
        let data = unsafe { self.mmap.add(self.data_offset) };
        let mut tail = self.tail;
        let mut out = Vec::new();
        while tail + 8 <= head {
            let off = (tail % self.data_size as u64) as usize;
            let mut header = [0u8; 8];
            copy_ring(data, self.data_size, off, &mut header);
            let size = u16::from_ne_bytes([header[6], header[7]]) as usize;
            let record_type = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]);
            if size < 8 || tail + size as u64 > head {
                break;
            }
            if record_type == PERF_RECORD_SAMPLE {
                let mut record = vec![0u8; size];
                copy_ring(data, self.data_size, off, &mut record);
                if let Some(sample) = parse_sample(&record) {
                    out.push(sample);
                }
            }
            tail += size as u64;
        }
        self.tail = tail;
        // SAFETY: `data_tail` is the ring's consume pointer; publishing it lets
        // the kernel reuse those slots.
        unsafe { (*meta).data_tail = tail };
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        out
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        if !self.mmap.is_null() {
            // SAFETY: the mapping was created in `open` with `mmap_len`.
            unsafe { libc::munmap(self.mmap as *mut libc::c_void, self.mmap_len) };
        }
        // SAFETY: `fd` was opened in `open` and is owned here.
        unsafe { libc::close(self.fd) };
    }
}

/// Copy `out.len()` bytes of the ring buffer starting at `off`, wrapping at
/// `data_size`.
fn copy_ring(data: *const u8, data_size: usize, off: usize, out: &mut [u8]) {
    let len = out.len();
    let first = len.min(data_size - off);
    // SAFETY: `off < data_size` and `out` is a valid destination of `len` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(data.add(off), out.as_mut_ptr(), first);
        if first < len {
            std::ptr::copy_nonoverlapping(data, out.as_mut_ptr().add(first), len - first);
        }
    }
}

/// Parse a `PERF_RECORD_SAMPLE` whose `sample_type` is
/// `PERF_SAMPLE_IP | PERF_SAMPLE_TID`: the payload is `ip(u64)` then
/// `ptid(u32), tid(u32)`.
fn parse_sample(record: &[u8]) -> Option<Sample> {
    // header(8) + ip(8) + ptid/tid(8).
    if record.len() < 16 {
        return None;
    }
    let ip = u64::from_ne_bytes(record[8..16].try_into().ok()?);
    Some(Sample { ip })
}
