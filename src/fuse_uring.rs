//! FUSE-over-`io_uring` transport (research §17 Domain B, §18 profile F2, §19
//! implementation boundary; directive §16).
//!
//! This module is the native-Rust **transport adapter** for the documented Linux
//! FUSE-over-`io_uring` UAPI. It is deliberately split from [`crate::fuse`]: the
//! filesystem core and every POSIX semantic are transport-neutral, and this
//! module only moves bytes between the kernel and the core. Turning the transport
//! on or off therefore cannot change filesystem contents.
//!
//! # What is implemented here
//!
//! * **UAPI model** — the exact wire structures and command opcodes, transcribed
//!   from the running kernel's own headers (`include/uapi/linux/fuse.h`) and from
//!   the kernel's documented UAPI, *not* from the container's (older) system
//!   headers:
//!   * `struct fuse_uring_cmd_req` (80-byte SQE command area),
//!   * `struct fuse_uring_ent_in_out`,
//!   * `struct fuse_uring_req_header`,
//!   * `enum fuse_uring_cmd` (`FUSE_IO_URING_CMD_REGISTER`,
//!     `FUSE_IO_URING_CMD_COMMIT_AND_FETCH`, `FUSE_IO_URING_CMD_ADD_QUEUE`,
//!     `FUSE_IO_URING_CMD_ADD_BUFPOOL`).
//! * **Discovery** ([`Discovery`]) — runtime facts about the running kernel, with
//!   an explicit, decisive *kernel gate* (the `fuse.enable_uring` module
//!   parameter) rather than a guess.
//! * **Negotiation** ([`FuseUringNegotiation`]) — the runtime result of the FUSE
//!   `INIT` handshake, which is the only authoritative statement of whether the
//!   kernel actually enabled `io_uring` on this connection.
//! * **Request/reply codec** ([`RingRequest`], [`RingReply`]) — transport-neutral
//!   decoding of a ring request header and encoding of a reply, with the ring
//!   `commit_id` and payload `offset`/`payload_sz` carried through unchanged.
//! * **The `io_uring` command layer** ([`FuseUringRing`]) — queue creation
//!   (`ADD_QUEUE`), buffer-pool registration (`ADD_BUFPOOL`), entry registration
//!   (`REGISTER`), reply commit and fetch-next (`COMMIT_AND_FETCH`), completion
//!   handling, request cancellation, and a safe shutdown/drain.
//! * **Fallback** ([`TransportProfile`], [`FuseUringReport`]) — a truthful
//!   decision of F0/F1/F2 that can never claim F2 unless a real ring negotiated.
//!
//! # Honest status on this host (Phase 15)
//!
//! A **real F2 mount is achieved here**: the kernel gate is open
//! (`fuse.enable_uring=Y`), the raw-SQE path below supplies the `sqe->len == 2`
//! that `FUSE_IO_URING_CMD_REGISTER` requires, and [`crate::fuse_native`] owns the
//! `/dev/fuse` fd and drives the ring. See `docs/FUSE_URING.md`.
//!
//! This module remains the *UAPI codec + ring command layer*: it is deliberately
//! transport-boundary code, so the filesystem core and every POSIX semantic stay
//! transport-neutral. It is used by [`crate::fuse_native`] and is exercised both
//! against a live mount and against a non-`fuse` fd (where the kernel rejects
//! `URING_CMD` with `-EOPNOTSUPP`, the honest result).

use std::fs;
use std::io;
use std::os::unix::io::RawFd;
use std::time::Duration;

use io_uring::{opcode, squeue, types, IoUring};

/// FUSE protocol major version implemented here.
pub const FUSE_KERNEL_VERSION: u32 = 7;

/// The FUSE ABI minor version at which `FUSE_OVER_IO_URING` and the baseline
/// two-command ring interface (`REGISTER` + `COMMIT_AND_FETCH`) appeared.
pub const FUSE_KERNEL_MINOR_OVER_IO_URING: u32 = 42;

/// The FUSE ABI minor version at which the modern interface appeared:
/// `FUSE_IO_URING_CMD_ADD_QUEUE`, `FUSE_IO_URING_CMD_ADD_BUFPOOL`, the buffer
/// pool, the payload `offset` field, and the zero-copy flags.
pub const FUSE_KERNEL_MINOR_ADD_QUEUE: u32 = 46;

/// The FUSE ABI minor version of the running development kernel (`7.2.x`,
/// `include/uapi/linux/fuse.h` = 45): the baseline interface only.
pub const FUSE_KERNEL_MINOR_BASELINE: u32 = 45;

/// Size of the request/response header area in `struct fuse_uring_req_header`.
pub const FUSE_URING_IN_OUT_HEADER_SZ: usize = 128;
/// Size of the per-opcode header area in `struct fuse_uring_req_header`.
pub const FUSE_URING_OP_IN_OUT_SZ: usize = 128;
/// Size of `struct fuse_uring_ent_in_out`.
pub const FUSE_URING_ENT_IN_OUT_SZ: usize = 32;
/// Full size of `struct fuse_uring_req_header` (288 bytes).
pub const FUSE_URING_REQ_HEADER_SZ: usize =
    FUSE_URING_IN_OUT_HEADER_SZ + FUSE_URING_OP_IN_OUT_SZ + FUSE_URING_ENT_IN_OUT_SZ;
/// Number of iovecs a `REGISTER` SQE carries: header, then payload.
pub const FUSE_URING_IOV_SEGS: u32 = 2;

/// `enum fuse_uring_cmd` — invalid/placeholder value.
pub const FUSE_IO_URING_CMD_INVALID: u32 = 0;
/// `enum fuse_uring_cmd` — register the request buffer and fetch a request.
pub const FUSE_IO_URING_CMD_REGISTER: u32 = 1;
/// `enum fuse_uring_cmd` — commit a reply and fetch the next request.
pub const FUSE_IO_URING_CMD_COMMIT_AND_FETCH: u32 = 2;
/// `enum fuse_uring_cmd` — create a queue (FUSE ABI 7.46+).
pub const FUSE_IO_URING_CMD_ADD_QUEUE: u32 = 3;
/// `enum fuse_uring_cmd` — add a buffer pool to a queue (FUSE ABI 7.46+).
pub const FUSE_IO_URING_CMD_ADD_BUFPOOL: u32 = 4;

/// `FUSE_URING_ZERO_COPY` — `fuse_uring_cmd_req.flags` for `ADD_QUEUE`.
pub const FUSE_URING_ZERO_COPY: u64 = 1 << 0;
/// `FUSE_URING_ENT_ZERO_COPY` — `fuse_uring_ent_in_out.flags`.
pub const FUSE_URING_ENT_ZERO_COPY: u64 = 1 << 0;
/// `FOPEN_IO_URING_ZERO_COPY` — `fuse_open_out.open_flags`.
pub const FOPEN_IO_URING_ZERO_COPY: u32 = 1 << 8;
/// `FUSE_OVER_IO_URING` — `fuse_init_out.flags` / `fuse_init_in.flags`.
pub const FUSE_OVER_IO_URING: u64 = 1 << 41;
/// `FUSE_HAS_IO_URING_BUFPOOL` — `fuse_init_out.flags` (FUSE ABI 7.46+).
pub const FUSE_HAS_IO_URING_BUFPOOL: u64 = 1 << 43;

/// The kernel's FUSE-over-`io_uring` module parameter (built-in `fuse`).
pub const ENABLE_URING_PARAM: &str = "/sys/module/fuse/parameters/enable_uring";
/// The `fuse` character device.
pub const DEV_FUSE: &str = "/dev/fuse";

// ---------------------------------------------------------------------------
// UAPI structures
// ---------------------------------------------------------------------------

/// `struct fuse_in_header` (40 bytes) — the fixed FUSE request header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FuseInHeader {
    /// Total length of the request (header + body).
    pub len: u32,
    /// The operation code.
    pub opcode: u32,
    /// Unique request id, echoed in the reply.
    pub unique: u64,
    /// The inode the operation targets.
    pub nodeid: u64,
    /// Caller uid.
    pub uid: u32,
    /// Caller gid.
    pub gid: u32,
    /// Caller pid.
    pub pid: u32,
    /// Total length of the extension header (ABI 7.38+).
    pub total_extlen: u16,
    /// Padding.
    pub padding: u16,
}

/// Byte length of [`FuseInHeader`].
pub const FUSE_IN_HEADER_SZ: usize = 40;
/// Byte length of `struct fuse_out_header`.
pub const FUSE_OUT_HEADER_SZ: usize = 16;

impl FuseInHeader {
    /// Decode a request header from `bytes`. Returns `None` if `bytes` is short.
    pub fn from_bytes(bytes: &[u8]) -> Option<FuseInHeader> {
        if bytes.len() < FUSE_IN_HEADER_SZ {
            return None;
        }
        Some(FuseInHeader {
            len: u32::from_ne_bytes(bytes[0..4].try_into().ok()?),
            opcode: u32::from_ne_bytes(bytes[4..8].try_into().ok()?),
            unique: u64::from_ne_bytes(bytes[8..16].try_into().ok()?),
            nodeid: u64::from_ne_bytes(bytes[16..24].try_into().ok()?),
            uid: u32::from_ne_bytes(bytes[24..28].try_into().ok()?),
            gid: u32::from_ne_bytes(bytes[28..32].try_into().ok()?),
            pid: u32::from_ne_bytes(bytes[32..36].try_into().ok()?),
            total_extlen: u16::from_ne_bytes(bytes[36..38].try_into().ok()?),
            padding: u16::from_ne_bytes(bytes[38..40].try_into().ok()?),
        })
    }
}

/// `struct fuse_uring_ent_in_out` (32 bytes).
///
/// In FUSE ABI 7.45 the fourth field is named `padding`; from 7.46 it is the
/// buffer-pool payload `offset` (see the kernel's `uapi/fuse-uapi-io-uring.rst`).
/// The layout is identical, so a single structure models both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FuseUringEntInOut {
    /// `FUSE_URING_ENT_ZERO_COPY` when the payload was zero-copied.
    pub flags: u64,
    /// The commit id to echo back in `COMMIT_AND_FETCH`.
    pub commit_id: u64,
    /// Total payload size in bytes.
    pub payload_sz: u32,
    /// Payload byte offset within the buffer pool (padding in ABI 7.45).
    pub offset: u32,
    /// Reserved (0).
    pub reserved: u64,
}

impl FuseUringEntInOut {
    /// Decode from the trailing 32 bytes of a request header.
    pub fn from_bytes(bytes: &[u8]) -> Option<FuseUringEntInOut> {
        if bytes.len() < FUSE_URING_ENT_IN_OUT_SZ {
            return None;
        }
        Some(FuseUringEntInOut {
            flags: u64::from_ne_bytes(bytes[0..8].try_into().ok()?),
            commit_id: u64::from_ne_bytes(bytes[8..16].try_into().ok()?),
            payload_sz: u32::from_ne_bytes(bytes[16..20].try_into().ok()?),
            offset: u32::from_ne_bytes(bytes[20..24].try_into().ok()?),
            reserved: u64::from_ne_bytes(bytes[24..32].try_into().ok()?),
        })
    }

    /// Whether the kernel marked this payload as zero-copied.
    pub fn is_zero_copy(&self) -> bool {
        self.flags & FUSE_URING_ENT_ZERO_COPY != 0
    }
}

/// `struct fuse_uring_bufpool` (16 bytes) — the union arm used by `ADD_BUFPOOL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FuseUringBufpool {
    /// Base address of the contiguous pool region.
    pub uaddr: u64,
    /// Length of the pool region in bytes.
    pub len: u32,
    /// Reserved (0).
    pub reserved: u32,
}

/// `struct fuse_uring_cmd_req` — the 80-byte command area of a 128-byte SQE.
///
/// The final field is a C union in the UAPI. It is modelled as a raw 16-byte
/// array here so that encoding is entirely safe (no `unsafe` union access) while
/// remaining byte-for-byte identical to the kernel's layout. Use
/// [`FuseUringCmdReq::set_bufpool`]/[`FuseUringCmdReq::set_zero_copy_buf_index`]
/// and their readers to interpret it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FuseUringCmdReq {
    /// Command-specific flags.
    pub flags: u64,
    /// Request id, for `COMMIT_AND_FETCH`.
    pub commit_id: u64,
    /// Queue index.
    pub qid: u16,
    /// Padding.
    pub padding: [u8; 6],
    /// The union arm: `{ bufpool { uaddr, len, reserved } }` or
    /// `{ ent_zero_copy_buf_index: u16 }`.
    pub aux: [u8; 16],
}

/// Byte length of [`FuseUringCmdReq`] as consumed by the kernel.
pub const FUSE_URING_CMD_REQ_SZ: usize = 40;
/// Size of the 80-byte SQE command area (`struct io_uring_sqe.cmd[0]`).
pub const URING_CMD_AREA_SZ: usize = 80;

impl FuseUringCmdReq {
    /// A command request for `qid` with no other fields set.
    pub fn for_queue(qid: u16) -> FuseUringCmdReq {
        FuseUringCmdReq {
            qid,
            ..Default::default()
        }
    }

    /// Set the `bufpool` union arm.
    pub fn set_bufpool(&mut self, pool: FuseUringBufpool) {
        self.aux[0..8].copy_from_slice(&pool.uaddr.to_ne_bytes());
        self.aux[8..12].copy_from_slice(&pool.len.to_ne_bytes());
        self.aux[12..16].copy_from_slice(&pool.reserved.to_ne_bytes());
    }

    /// Read the `bufpool` union arm.
    pub fn bufpool(&self) -> FuseUringBufpool {
        FuseUringBufpool {
            uaddr: u64::from_ne_bytes(self.aux[0..8].try_into().unwrap()),
            len: u32::from_ne_bytes(self.aux[8..12].try_into().unwrap()),
            reserved: u32::from_ne_bytes(self.aux[12..16].try_into().unwrap()),
        }
    }

    /// Set the `ent_zero_copy_buf_index` union arm (for `REGISTER`).
    pub fn set_zero_copy_buf_index(&mut self, index: u16) {
        self.aux = [0u8; 16];
        self.aux[0..2].copy_from_slice(&index.to_ne_bytes());
    }

    /// Read the `ent_zero_copy_buf_index` union arm.
    pub fn zero_copy_buf_index(&self) -> u16 {
        u16::from_ne_bytes(self.aux[0..2].try_into().unwrap())
    }

    /// Encode into the 80-byte `io_uring` command area. Bytes after the 40-byte
    /// structure are zero, matching the kernel's expectations.
    pub fn to_sqe_cmd(&self) -> [u8; URING_CMD_AREA_SZ] {
        let mut out = [0u8; URING_CMD_AREA_SZ];
        out[0..8].copy_from_slice(&self.flags.to_ne_bytes());
        out[8..16].copy_from_slice(&self.commit_id.to_ne_bytes());
        out[16..18].copy_from_slice(&self.qid.to_ne_bytes());
        out[18..24].copy_from_slice(&self.padding);
        out[24..40].copy_from_slice(&self.aux);
        out
    }

    /// Decode from an 80-byte command area (inverse of [`Self::to_sqe_cmd`]).
    pub fn from_sqe_cmd(cmd: &[u8; URING_CMD_AREA_SZ]) -> FuseUringCmdReq {
        let mut padding = [0u8; 6];
        padding.copy_from_slice(&cmd[18..24]);
        let mut aux = [0u8; 16];
        aux.copy_from_slice(&cmd[24..40]);
        FuseUringCmdReq {
            flags: u64::from_ne_bytes(cmd[0..8].try_into().unwrap()),
            commit_id: u64::from_ne_bytes(cmd[8..16].try_into().unwrap()),
            qid: u16::from_ne_bytes(cmd[16..18].try_into().unwrap()),
            padding,
            aux,
        }
    }
}

/// `struct fuse_uring_req_header` (288 bytes) — the per-request ring header.
#[derive(Debug, Clone)]
pub struct FuseUringReqHeader {
    /// `struct fuse_in_header` (request) / `struct fuse_out_header` (reply).
    pub in_out: [u8; FUSE_URING_IN_OUT_HEADER_SZ],
    /// Per-opcode header.
    pub op_in: [u8; FUSE_URING_OP_IN_OUT_SZ],
    /// Kernel-reported entry bookkeeping.
    pub ring_ent_in_out: FuseUringEntInOut,
}

impl FuseUringReqHeader {
    /// Decode a full request header from its raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<FuseUringReqHeader> {
        if bytes.len() < FUSE_URING_REQ_HEADER_SZ {
            return None;
        }
        let mut in_out = [0u8; FUSE_URING_IN_OUT_HEADER_SZ];
        in_out.copy_from_slice(&bytes[0..FUSE_URING_IN_OUT_HEADER_SZ]);
        let mut op_in = [0u8; FUSE_URING_OP_IN_OUT_SZ];
        op_in.copy_from_slice(
            &bytes[FUSE_URING_IN_OUT_HEADER_SZ
                ..FUSE_URING_IN_OUT_HEADER_SZ + FUSE_URING_OP_IN_OUT_SZ],
        );
        let ring_ent_in_out = FuseUringEntInOut::from_bytes(
            &bytes[FUSE_URING_IN_OUT_HEADER_SZ + FUSE_URING_OP_IN_OUT_SZ..],
        )?;
        Some(FuseUringReqHeader {
            in_out,
            op_in,
            ring_ent_in_out,
        })
    }

    /// The FUSE request header, or `None` if the framing is too short.
    pub fn request(&self) -> Option<FuseInHeader> {
        FuseInHeader::from_bytes(&self.in_out)
    }
}

// ---------------------------------------------------------------------------
// Request / reply codec (transport-neutral)
// ---------------------------------------------------------------------------

/// A decoded ring request. This is the transport-neutral shape handed to the
/// same dispatch logic the classical `/dev/fuse` transport uses; it carries no
/// transport-specific state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingRequest {
    /// Unique request id.
    pub unique: u64,
    /// FUSE opcode.
    pub opcode: u32,
    /// Target inode.
    pub nodeid: u64,
    /// Caller uid.
    pub uid: u32,
    /// Caller gid.
    pub gid: u32,
    /// Caller pid.
    pub pid: u32,
    /// Payload size in bytes.
    pub payload_sz: u32,
    /// Payload offset within the buffer pool (0 when no pool is used).
    pub payload_offset: u32,
    /// The commit id the reply must echo.
    pub commit_id: u64,
    /// Entry flags (`FUSE_URING_ENT_ZERO_COPY` when zero-copied).
    pub flags: u64,
}

impl RingRequest {
    /// Decode a ring request from a per-request header.
    pub fn decode(hdr: &FuseUringReqHeader) -> Option<RingRequest> {
        let in_hdr = hdr.request()?;
        Some(RingRequest {
            unique: in_hdr.unique,
            opcode: in_hdr.opcode,
            nodeid: in_hdr.nodeid,
            uid: in_hdr.uid,
            gid: in_hdr.gid,
            pid: in_hdr.pid,
            payload_sz: hdr.ring_ent_in_out.payload_sz,
            payload_offset: hdr.ring_ent_in_out.offset,
            commit_id: hdr.ring_ent_in_out.commit_id,
            flags: hdr.ring_ent_in_out.flags,
        })
    }

    /// Whether this request was zero-copied.
    pub fn is_zero_copy(&self) -> bool {
        self.flags & FUSE_URING_ENT_ZERO_COPY != 0
    }
}

/// A reply to be committed through `COMMIT_AND_FETCH`.
///
/// The `commit_id` must be the value the kernel reported for the matching
/// request; the kernel uses it to route the reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingReply {
    /// The request being answered.
    pub unique: u64,
    /// The matching commit id.
    pub commit_id: u64,
    /// `0` on success, or a negative errno.
    pub error: i32,
    /// Reply payload (already opcode-encoded by the caller).
    pub payload: Vec<u8>,
}

impl RingReply {
    /// A success reply with no payload.
    pub fn ok(req: &RingRequest) -> RingReply {
        RingReply {
            unique: req.unique,
            commit_id: req.commit_id,
            error: 0,
            payload: Vec::new(),
        }
    }

    /// An error reply carrying `errno` (a positive errno; negated on the wire).
    pub fn error(req: &RingRequest, errno: i32) -> RingReply {
        RingReply {
            unique: req.unique,
            commit_id: req.commit_id,
            error: errno,
            payload: Vec::new(),
        }
    }

    /// Encode the `struct fuse_out_header` + payload exactly as the classical
    /// transport does, so the two transports are byte-compatible.
    pub fn encode(&self) -> Vec<u8> {
        let len = (FUSE_OUT_HEADER_SZ + self.payload.len()) as u32;
        let mut out = Vec::with_capacity(len as usize);
        out.extend_from_slice(&len.to_ne_bytes());
        // The wire error is `-errno` (`0` stays `0`).
        let wire_error = if self.error == 0 { 0 } else { -self.error };
        out.extend_from_slice(&wire_error.to_ne_bytes());
        out.extend_from_slice(&self.unique.to_ne_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

// ---------------------------------------------------------------------------
// Discovery — what the running kernel actually offers
// ---------------------------------------------------------------------------

/// Runtime facts about FUSE-over-`io_uring` support. Every field is read from the
/// live system; nothing is cached or assumed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Discovery {
    /// `uname -r`.
    pub kernel_release: String,
    /// Whether `/dev/fuse` exists and is a character device.
    pub dev_fuse_present: bool,
    /// Whether a usable `io_uring` is available in this environment.
    pub io_uring_available: bool,
    /// Why `io_uring` is unavailable, if it is.
    pub io_uring_reason: Option<String>,
    /// `CONFIG_FUSE_IO_URING` from the kernel config, if readable.
    pub config_fuse_io_uring: Option<bool>,
    /// `CONFIG_IO_URING` from the kernel config, if readable.
    pub config_io_uring: Option<bool>,
    /// The value of `/sys/module/fuse/parameters/enable_uring`, if readable.
    /// This is the kernel's own, decisive gate for FUSE-over-`io_uring`.
    pub enable_uring_param: Option<bool>,
    /// Whether the process holds `CAP_SYS_ADMIN` (needed for zero-copy).
    pub cap_sys_admin: bool,
}

impl Discovery {
    /// Probe the live system.
    pub fn probe() -> Discovery {
        let caps = crate::capabilities::probe();
        let (io_uring_available, io_uring_reason) = match probe_io_uring() {
            Ok(()) => (true, None),
            Err(reason) => (false, Some(reason)),
        };
        Discovery {
            kernel_release: caps.kernel_release,
            dev_fuse_present: caps.dev_fuse_present,
            io_uring_available,
            io_uring_reason,
            config_fuse_io_uring: caps.config_fuse_io_uring,
            config_io_uring: caps.config_io_uring,
            enable_uring_param: read_enable_uring_param(),
            cap_sys_admin: has_cap_sys_admin(),
        }
    }

    /// Whether every *necessary* condition for FUSE-over-`io_uring` holds.
    ///
    /// This is a necessary condition only: the decisive statement is the runtime
    /// `INIT` negotiation ([`FuseUringNegotiation`]). When this returns `Err`, F2
    /// is provably impossible and the reason is exact.
    pub fn preconditions(&self) -> Result<(), String> {
        if self.config_fuse_io_uring == Some(false) {
            return Err("kernel built without CONFIG_FUSE_IO_URING".into());
        }
        if !self.dev_fuse_present {
            return Err(format!("{DEV_FUSE} is not present"));
        }
        if !self.io_uring_available {
            return Err(format!(
                "io_uring unavailable: {}",
                self.io_uring_reason.as_deref().unwrap_or("unknown")
            ));
        }
        match self.enable_uring_param {
            Some(false) => Err(format!(
                "fuse-io-uring is disabled by the kernel module parameter \
                 (fuse.enable_uring=0 in {ENABLE_URING_PARAM}); the kernel does not \
                 even offer FUSE_OVER_IO_URING at INIT while it is off"
            )),
            // `None` means the parameter is unreadable (for example `fuse` is not
            // loaded or the path is absent). That is not proof of availability, so
            // negotiation at mount time remains decisive.
            Some(true) | None => Ok(()),
        }
    }
}

fn read_enable_uring_param() -> Option<bool> {
    let text = fs::read_to_string(ENABLE_URING_PARAM).ok()?;
    match text.trim() {
        "Y" | "y" | "1" => Some(true),
        "N" | "n" | "0" => Some(false),
        _ => None,
    }
}

/// `true` when the effective capability set includes `CAP_SYS_ADMIN` (bit 21).
///
/// Read from `/proc/self/status`, which reflects the *effective* set, so no
/// `unsafe` syscall is needed.
pub fn has_cap_sys_admin() -> bool {
    const CAP_SYS_ADMIN_BIT: u64 = 21;
    if let Ok(text) = fs::read_to_string("/proc/self/status") {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("CapEff:") {
                let hex = rest.trim();
                if let Ok(bits) = u64::from_str_radix(hex, 16) {
                    return bits & (1 << CAP_SYS_ADMIN_BIT) != 0;
                }
            }
        }
    }
    false
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

/// Create an SQE128 ring (the ring shape FUSE-over-`io_uring` requires).
///
/// The kernel rejects an `IORING_OP_URING_CMD` whose SQE lacks the 128-byte
/// extension (`IO_URING_F_SQE128`), so the ability to create an `Entry128` ring is
/// itself the relevant capability probe.
fn probe_io_uring() -> Result<(), String> {
    let ring: IoUring<squeue::Entry128> = IoUring::builder()
        .build(8)
        .map_err(|e| describe_setup_error(&e))?;
    drop(ring);
    Ok(())
}

// ---------------------------------------------------------------------------
// Negotiation — the authoritative runtime result
// ---------------------------------------------------------------------------

/// The result of the FUSE `INIT` handshake with respect to FUSE-over-`io_uring`.
///
/// Produced inside [`crate::fuse::OrfsFuse::init`]. `kernel_offered` is the only
/// authoritative statement that the kernel would enable `io_uring` for this
/// connection: the kernel sets `FUSE_OVER_IO_URING` in the `INIT` flags **only**
/// when `fuse_uring_enabled()` is true.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FuseUringNegotiation {
    /// Whether the kernel offered `FUSE_OVER_IO_URING` in the `INIT` handshake.
    pub kernel_offered: bool,
    /// Whether the kernel offered `FUSE_HAS_IO_URING_BUFPOOL` (FUSE ABI 7.46+),
    /// which is the signal that `ADD_QUEUE`/`ADD_BUFPOOL` are available.
    pub kernel_offered_bufpool: bool,
    /// The negotiated FUSE ABI version `(major, minor)`, if known.
    pub kernel_abi: Option<(u32, u32)>,
    /// Whether the server accepted `FUSE_OVER_IO_URING` in its reply.
    pub accepted: bool,
    /// Whether a real ring is actually running for this mount (never optimistic).
    pub engaged: bool,
    /// A human-readable reason when F2 did not engage.
    pub reason: Option<String>,
    /// Whether the process holds `CAP_SYS_ADMIN` (required for zero-copy).
    pub cap_sys_admin: bool,
    /// The number of baseline queue entries registered over the ring.
    pub num_queues: usize,
}

/// The **exact** F2 feature set negotiated for one live mount.
///
/// Everything here is derived from the `INIT` flags and the process's own capability
/// set; nothing is assumed from the compile-time UAPI model. Zero-copy in particular
/// is `true` only when the kernel offered the buffer-pool extension *and* the process
/// holds `CAP_SYS_ADMIN`; at FUSE ABI 7.45 it is always `false`.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct F2Capabilities {
    /// `FUSE_OVER_IO_URING` was offered by the kernel and accepted by the server.
    pub over_io_uring: bool,
    /// The negotiated FUSE ABI minor version.
    pub abi_minor: Option<u32>,
    /// The baseline two-command interface (`REGISTER` + `COMMIT_AND_FETCH`) is in force.
    pub baseline_register: bool,
    /// `FUSE_IO_URING_CMD_ADD_QUEUE` is available (requires the buffer-pool extension).
    pub add_queue: bool,
    /// `FUSE_IO_URING_CMD_ADD_BUFPOOL` is available (requires the buffer-pool extension).
    pub add_bufpool: bool,
    /// The process holds `CAP_SYS_ADMIN`.
    pub cap_sys_admin: bool,
    /// Zero-copy is actually available (`add_bufpool && cap_sys_admin`).
    pub zero_copy: bool,
    /// Queue entries registered over the baseline interface.
    pub num_queues: usize,
    /// The ABI boundary in words, for `orfs doctor`.
    pub boundary: String,
}

impl FuseUringNegotiation {
    /// A negotiation that never ran (for example a non-`fuse-uring` mount).
    pub fn not_requested() -> FuseUringNegotiation {
        FuseUringNegotiation {
            reason: Some("F2 was not requested for this mount".into()),
            ..Default::default()
        }
    }

    /// The negotiated FUSE ABI minor version, when known.
    pub fn abi_minor(&self) -> Option<u32> {
        self.kernel_abi.map(|(_, minor)| minor)
    }

    /// Whether the modern `ADD_QUEUE`/`ADD_BUFPOOL` interface was negotiated.
    ///
    /// This is the *runtime* gate for the forward-compatible commands: the kernel
    /// must have offered `FUSE_HAS_IO_URING_BUFPOOL` (its own signal that the
    /// extension exists) **and** a real ring must be engaged. On FUSE ABI 7.45 the
    /// kernel never sets that flag, so the modern commands stay inert.
    pub fn add_queue_available(&self) -> bool {
        self.engaged && self.kernel_offered_bufpool && self.kernel_offered
    }

    /// The exact negotiated capability set (the authority for `orfs doctor` and
    /// for deciding whether the zero-copy / buffer-pool commands may be used).
    pub fn capabilities(&self) -> F2Capabilities {
        let add_queue = self.add_queue_available();
        let zero_copy = add_queue && self.cap_sys_admin;
        let abi_minor = self.abi_minor();
        let boundary = if add_queue {
            format!(
                "FUSE ABI 7.{} exposes ADD_QUEUE/ADD_BUFPOOL (buffer pools); zero-copy {}",
                abi_minor.unwrap_or(0),
                if zero_copy {
                    "available (CAP_SYS_ADMIN held)"
                } else {
                    "unavailable (CAP_SYS_ADMIN not held)"
                }
            )
        } else {
            format!(
                "FUSE ABI 7.{} exposes only the baseline REGISTER + COMMIT_AND_FETCH \
                 interface; ADD_QUEUE/ADD_BUFPOOL and zero-copy are inert (not offered)",
                abi_minor.unwrap_or(0)
            )
        };
        F2Capabilities {
            over_io_uring: self.engaged && self.kernel_offered && self.accepted,
            abi_minor,
            baseline_register: self.engaged,
            add_queue,
            add_bufpool: add_queue,
            cap_sys_admin: self.cap_sys_admin,
            zero_copy,
            num_queues: self.num_queues,
            boundary,
        }
    }

    /// A one-line honest description.
    pub fn describe(&self) -> String {
        if self.engaged {
            "FUSE-over-io_uring engaged".to_string()
        } else if let Some(reason) = &self.reason {
            format!("FUSE-over-io_uring not active: {reason}")
        } else {
            "FUSE-over-io_uring not active".to_string()
        }
    }
}

/// Which queue-creation interface a session may use, decided from the negotiated
/// capability set. `Modern` is reachable only on a kernel that offers the buffer
/// pool; the baseline path is the only one executed at FUSE ABI 7.45.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueuePlan {
    /// Register one entry per CPU queue with `FUSE_IO_URING_CMD_REGISTER` (ABI 7.45).
    Baseline,
    /// Create queues with `ADD_QUEUE`, allocate pools with `ADD_BUFPOOL`, and
    /// (when `zero_copy`) request the zero-copy flag (ABI 7.46+).
    Modern { zero_copy: bool },
}

/// Decide the queue-creation plan from the negotiated capabilities and the mount's
/// zero-copy request. Never returns `Modern` unless the kernel truly offered the
/// buffer-pool extension.
pub fn plan_queues(neg: &FuseUringNegotiation, zero_copy_requested: bool) -> QueuePlan {
    if neg.add_queue_available() {
        QueuePlan::Modern {
            zero_copy: zero_copy_requested && neg.cap_sys_admin,
        }
    } else {
        QueuePlan::Baseline
    }
}

/// A truthful report of whether F2 is usable, combining discovery and the live
/// negotiation. Surfaced by `orfs doctor` and the mount command.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FuseUringReport {
    /// The kernel/runtime discovery facts.
    pub discovery: Discovery,
    /// `Ok` when all necessary preconditions hold; `Err(reason)` otherwise.
    pub preconditions: Result<(), String>,
    /// The live `INIT` negotiation, when a mount performed one.
    pub negotiation: Option<FuseUringNegotiation>,
}

impl FuseUringReport {
    /// The decisive answer: is F2 actually usable?
    pub fn usable(&self) -> bool {
        self.preconditions.is_ok()
            && self
                .negotiation
                .as_ref()
                .map(|n| n.engaged)
                .unwrap_or(false)
    }

    /// The precise reason F2 is not usable, combining both sources.
    pub fn reason(&self) -> String {
        if let Err(r) = &self.preconditions {
            return r.clone();
        }
        match &self.negotiation {
            Some(n) if n.engaged => "F2 active".to_string(),
            Some(n) => n
                .reason
                .clone()
                .unwrap_or_else(|| "kernel did not enable FUSE-over-io_uring".into()),
            None => "FUSE-over-io_uring was not negotiated (no mount performed)".to_string(),
        }
    }

    /// A one-line description for CLI output.
    pub fn describe(&self) -> String {
        if self.usable() {
            "usable".to_string()
        } else {
            format!("not usable: {}", self.reason())
        }
    }
}

/// Probe FUSE-over-`io_uring` availability without mounting. Static discovery
/// only; the decisive `INIT` negotiation happens during a mount.
pub fn discover_report() -> FuseUringReport {
    let discovery = Discovery::probe();
    let preconditions = discovery.preconditions();
    FuseUringReport {
        discovery,
        preconditions,
        negotiation: None,
    }
}

// ---------------------------------------------------------------------------
// Transport profiles F0/F1/F2
// ---------------------------------------------------------------------------

/// The three transport profiles (research §18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum TransportProfile {
    /// Traditional `/dev/fuse` with conventional (synchronous) backing I/O.
    F0,
    /// Traditional `/dev/fuse` with `io_uring` backing I/O.
    F1,
    /// FUSE-over-`io_uring` with `io_uring` backing I/O.
    F2,
}

impl TransportProfile {
    /// The profile name used in evidence and diagnostics.
    pub fn name(&self) -> &'static str {
        match self {
            TransportProfile::F0 => "F0",
            TransportProfile::F1 => "F1",
            TransportProfile::F2 => "F2",
        }
    }

    /// A description including what physically happened.
    pub fn describe(&self, backing_uring: bool) -> String {
        let backing = if backing_uring { "io_uring" } else { "sync" };
        match self {
            TransportProfile::F0 => format!("F0 (traditional /dev/fuse, {backing} backing)"),
            TransportProfile::F1 => format!("F1 (traditional /dev/fuse, {backing} backing)"),
            TransportProfile::F2 => format!("F2 (FUSE-over-io_uring, {backing} backing)"),
        }
    }
}

/// Decide the transport profile that is *actually* in force.
///
/// F2 is returned **only** when the negotiation reports a running ring
/// (`engaged`). Backing `io_uring` never implies F2: that is F1.
pub fn classify(
    requested_f2: bool,
    backing_uring: bool,
    negotiation: Option<&FuseUringNegotiation>,
) -> TransportProfile {
    let f2 = requested_f2
        && negotiation
            .map(|n| n.engaged && n.kernel_offered)
            .unwrap_or(false);
    if f2 {
        TransportProfile::F2
    } else if backing_uring {
        TransportProfile::F1
    } else {
        TransportProfile::F0
    }
}

// ---------------------------------------------------------------------------
// The io_uring command layer
// ---------------------------------------------------------------------------

/// A completion observed on the FUSE ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingCompletion {
    /// The `user_data` the SQE was submitted with.
    pub user_data: u64,
    /// The raw completion result (bytes, `0`, or a negative errno).
    pub result: i32,
}

/// Cumulative counters for evidence.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct RingStats {
    /// SQEs submitted.
    pub submits: u64,
    /// CQEs reaped.
    pub completions: u64,
    /// Control commands that completed.
    pub control_completions: u64,
    /// Cancellations issued.
    pub cancels: u64,
    /// Completions observed for operations not currently awaited.
    pub orphan_completions: u64,
    /// Times an SQE could not be pushed because the submission queue was full
    /// (SQ backpressure). This is the F2 analogue of the backing `UringEngine`'s
    /// `sq_full_events` (`docs/PERFORMANCE.md` §21): the same SQ-pressure signal,
    /// measured on the FUSE-over-`io_uring` ring instead of the backing ring.
    /// The servicer submits after every push, so in the shipped topologies this
    /// is expected to stay 0 — reported as measured, not assumed.
    pub sq_full_events: u64,
    /// The largest number of CQEs drained in a single `reap()`. A value at the
    /// ring's CQ capacity is direct evidence of CQ-overflow pressure (the F2
    /// analogue of §21's `cq_max_len`).
    pub cq_max_len: u64,
}

/// A native FUSE-over-`io_uring` ring bound to a `/dev/fuse` file descriptor.
///
/// The ring is created with `IORING_SETUP_SQE128`, because the kernel rejects a
/// `IORING_OP_URING_CMD` whose SQE lacks the 128-byte extension
/// (`if (!(issue_flags & IO_URING_F_SQE128)) return -EINVAL;`).
///
/// # Lifetimes and safety
///
/// The ring holds only `user_data` bookkeeping; it does not retain pointers to
/// caller buffers. The two places that hand the kernel a pointer — entry
/// registration (iovecs) and buffer-pool registration — are documented at their
/// call sites and require the caller to keep the buffers alive for as long as the
/// entry/pool is registered.
pub struct FuseUringRing {
    ring: IoUring<squeue::Entry128>,
    fd: RawFd,
    next_user_data: u64,
    stats: RingStats,
}

/// Write the raw `sqe->len` ABI field of an `Entry128`.
///
/// `FUSE_IO_URING_CMD_REGISTER` is the one command that needs it: the kernel
/// requires `sqe->len == FUSE_URING_IOV_SEGS (2)`, the number of iovecs at
/// `sqe->addr` (`fuse_uring_get_iovec_from_sqe`: `if (sqe->len !=
/// FUSE_URING_IOV_SEGS) return -EINVAL;`). The pinned `io-uring` 0.7.15 crate
/// exposes no setter for `len`, so the ABI field is written directly.
///
/// # Safety
///
/// `squeue::Entry128` is `#[repr(C)]` and exactly 128 bytes: a 64-byte
/// `struct io_uring_sqe` followed by the 64-byte command area (the crate's own
/// `test_entry_sizes` asserts `size_of::<Entry128>() == 128`). In the kernel's
/// `struct io_uring_sqe` — and in the crate's bindgen of it — the fields up to
/// `len` are `opcode@0 u8`, `flags@1 u8`, `ioprio@2 u16`, `fd@4 s32`,
/// `off/addr2@8 u64`, `addr@16 u64`, `len@24 u32`, so byte offset 24 is
/// unambiguous on every supported architecture. This writes only within the
/// 128-byte value owned by `entry`, through a raw pointer derived from a unique
/// `&mut`, using an unaligned store because the field's alignment is not
/// guaranteed by the byte-slice view. `entry` is consumed and returned by value.
fn entry128_set_len(mut entry: squeue::Entry128, len: u32) -> squeue::Entry128 {
    const _: () = assert!(std::mem::size_of::<squeue::Entry128>() == 128);
    const SQE_LEN_OFFSET: usize = 24;
    // SAFETY: see the function-level invariant above. `entry` is a live, unique,
    // `repr(C)` `Entry128` of at least 28 bytes; offset 24 holds `sqe->len`.
    unsafe {
        let base = (&mut entry as *mut squeue::Entry128).cast::<u8>();
        base.add(SQE_LEN_OFFSET)
            .cast::<[u8; 4]>()
            .write_unaligned(len.to_ne_bytes());
    }
    entry
}

impl FuseUringRing {
    /// Create an SQE128 ring for `fd`. `depth` is rounded up to a power of two.
    pub fn new(fd: RawFd, depth: u32) -> Result<FuseUringRing, String> {
        let depth = depth.max(2).next_power_of_two();
        let ring: IoUring<squeue::Entry128> = IoUring::builder()
            .build(depth)
            .map_err(|e| describe_setup_error(&e))?;
        Ok(FuseUringRing {
            ring,
            fd,
            next_user_data: 1,
            stats: RingStats::default(),
        })
    }

    /// The backing file descriptor.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Snapshot the counters.
    pub fn stats(&self) -> RingStats {
        self.stats
    }

    fn alloc_ud(&mut self) -> u64 {
        let ud = self.next_user_data;
        self.next_user_data += 1;
        ud
    }

    /// Push an `IORING_OP_URING_CMD` SQE carrying `req` for `cmd_op`.
    ///
    /// `len` sets the raw `sqe->len` ABI field (see [`entry128_set_len`]);
    /// `None` leaves it zero, which every command except `REGISTER` requires.
    fn push_cmd(
        &mut self,
        cmd_op: u32,
        req: &FuseUringCmdReq,
        buf_index: Option<u16>,
        addr: Option<u64>,
        len: Option<u32>,
        user_data: u64,
    ) -> Result<(), String> {
        let mut entry = opcode::UringCmd80::new(types::Fd(self.fd), cmd_op).cmd(req.to_sqe_cmd());
        if let Some(idx) = buf_index {
            entry = entry.buf_index(Some(idx));
        }
        if let Some(addr) = addr {
            entry = entry.addr(Some(addr));
        }
        let mut entry = entry.build().user_data(user_data);
        if let Some(len) = len {
            entry = entry128_set_len(entry, len);
        }
        // SAFETY: the SQE references only `req`'s encoded bytes (copied into the
        // SQE) and, when `addr` is set, a caller-owned buffer whose lifetime the
        // caller guarantees for the whole operation. This function copies the
        // command into the SQE before returning.
        if unsafe { self.ring.submission().push(&entry) }.is_err() {
            self.stats.sq_full_events += 1;
            return Err("io_uring submission queue full".into());
        }
        self.stats.submits += 1;
        Ok(())
    }

    /// Submit everything pushed so far and wait for at least `wait` completions.
    pub fn submit_and_wait(&mut self, wait: usize) -> Result<Vec<RingCompletion>, String> {
        loop {
            match self.ring.submit_and_wait(wait.max(1)) {
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("io_uring submit_and_wait: {e}")),
            }
        }
        self.reap()
    }

    /// Drain every completion currently available without blocking.
    pub fn reap(&mut self) -> Result<Vec<RingCompletion>, String> {
        let mut out = Vec::new();
        let mut cq = self.ring.completion();
        for cqe in &mut cq {
            out.push(RingCompletion {
                user_data: cqe.user_data(),
                result: cqe.result(),
            });
        }
        cq.sync();
        self.stats.completions += out.len() as u64;
        let drained = out.len() as u64;
        if drained > self.stats.cq_max_len {
            self.stats.cq_max_len = drained;
        }
        Ok(out)
    }

    /// Issue a control command and wait for **its** completion.
    ///
    /// Completions for other operations (for example a previously registered
    /// entry delivering a request) are returned to the caller as `orphans` rather
    /// than dropped.
    fn control(
        &mut self,
        cmd_op: u32,
        req: &FuseUringCmdReq,
        buf_index: Option<u16>,
        addr: Option<u64>,
    ) -> Result<(i32, Vec<RingCompletion>), String> {
        let ud = self.alloc_ud();
        self.push_cmd(cmd_op, req, buf_index, addr, None, ud)?;
        let mut orphans = Vec::new();
        loop {
            for c in self.submit_and_wait(1)? {
                if c.user_data == ud {
                    self.stats.control_completions += 1;
                    return Ok((c.result, orphans));
                }
                self.stats.orphan_completions += 1;
                orphans.push(c);
            }
        }
    }

    /// `FUSE_IO_URING_CMD_ADD_QUEUE` — create queue `qid` (FUSE ABI 7.46+).
    ///
    /// `zero_copy` sets `FUSE_URING_ZERO_COPY`, which additionally requires
    /// `CAP_SYS_ADMIN` and a buffer pool added with [`Self::add_bufpool`].
    pub fn add_queue(&mut self, qid: u16, zero_copy: bool) -> Result<i32, String> {
        let mut req = FuseUringCmdReq::for_queue(qid);
        if zero_copy {
            req.flags = FUSE_URING_ZERO_COPY;
        }
        let (res, _) = self.control(FUSE_IO_URING_CMD_ADD_QUEUE, &req, None, None)?;
        Ok(res)
    }

    /// `FUSE_IO_URING_CMD_ADD_BUFPOOL` — register `len` bytes at `base` as the
    /// payload pool for `qid`.
    ///
    /// When `registered_index` is `Some`, the SQE carries `IORING_URING_CMD_FIXED`
    /// and the pool must already have been registered with `io_uring_register`.
    /// The caller guarantees `base`/`len` describe a live, stable region for the
    /// whole time the pool is registered.
    pub fn add_bufpool(
        &mut self,
        qid: u16,
        base: u64,
        len: u32,
        registered_index: Option<u16>,
    ) -> Result<i32, String> {
        let mut req = FuseUringCmdReq::for_queue(qid);
        req.set_bufpool(FuseUringBufpool {
            uaddr: base,
            len,
            reserved: 0,
        });
        let (res, _) = self.control(FUSE_IO_URING_CMD_ADD_BUFPOOL, &req, registered_index, None)?;
        Ok(res)
    }

    /// `FUSE_IO_URING_CMD_REGISTER` — register a ring entry for `qid`.
    ///
    /// `headers` must point at a `fuse_uring_req_header` (288 bytes) and `payload`
    /// at a payload buffer of at least the negotiated maximum payload size; the
    /// kernel pins both for the entry's lifetime. They are passed as a 2-element
    /// `iovec` array at `iov_addr`.
    ///
    /// The kernel requires `sqe->len == FUSE_URING_IOV_SEGS (2)` for this command
    /// (`fuse_uring_get_iovec_from_sqe`). The pinned `io-uring` 0.7.15 crate exposes
    /// no setter for `sqe->len`, so this uses the raw-SQE path
    /// (`entry128_set_len`) to write the ABI field directly. Everything else —
    /// reply commit and fetch, cancellation — leaves `len` zero.
    pub fn register_entry(
        &mut self,
        qid: u16,
        iov_addr: u64,
        zero_copy_buf_index: Option<u16>,
    ) -> Result<i32, String> {
        let mut req = FuseUringCmdReq::for_queue(qid);
        if let Some(idx) = zero_copy_buf_index {
            req.set_zero_copy_buf_index(idx);
        }
        let ud = self.alloc_ud();
        self.push_cmd(
            FUSE_IO_URING_CMD_REGISTER,
            &req,
            None,
            Some(iov_addr),
            Some(FUSE_URING_IOV_SEGS),
            ud,
        )?;
        // The entry's completion arrives only when a request is delivered to it,
        // so registration is fire-and-forget here; the caller observes later
        // completions through `reap`/`wait_event`.
        Ok(ud as i32)
    }

    /// `FUSE_IO_URING_CMD_COMMIT_AND_FETCH` — commit `reply` for `request` and
    /// ask the kernel for the next request on `qid`.
    pub fn commit_and_fetch(&mut self, qid: u16, commit_id: u64) -> Result<i32, String> {
        let mut req = FuseUringCmdReq::for_queue(qid);
        req.commit_id = commit_id;
        let (res, _) = self.control(FUSE_IO_URING_CMD_COMMIT_AND_FETCH, &req, None, None)?;
        Ok(res)
    }

    /// Submit every queued SQE without waiting for any completion.
    pub fn submit(&mut self) -> Result<(), String> {
        self.ring
            .submit()
            .map(|_| ())
            .map_err(|e| format!("io_uring submit: {e}"))
    }

    /// Submit queued SQEs and wait up to `timeout` for at least one completion.
    ///
    /// Returns whatever is on the completion queue (possibly empty on timeout),
    /// so a driver can periodically check a stop flag while blocked on an idle
    /// mount without busy-waiting. `ETIME` (the kernel's "timeout expired") and
    /// `EINTR` are treated as "no completion yet".
    pub fn submit_and_wait_timeout(
        &mut self,
        wait: usize,
        timeout: Duration,
    ) -> Result<Vec<RingCompletion>, String> {
        let ts = types::Timespec::from(timeout);
        let args = types::SubmitArgs::new().timespec(&ts);
        match self.ring.submitter().submit_with_args(wait.max(1), &args) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::ETIME) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("io_uring submit_with_args: {e}")),
        }
        self.reap()
    }

    /// Queue a `REGISTER` SQE for `qid` carrying the 2-element iovec array at
    /// `iov_addr`, tagged with `user_data`.
    ///
    /// This is the raw-SQE path: unlike every other command, `REGISTER` requires
    /// `sqe->len == 2` (see [`entry128_set_len`]), which the `io-uring` crate
    /// cannot express. `user_data` doubles as the entry identity: the SQE's
    /// completion is not posted until the kernel delivers a request into the
    /// registered buffers, so the CQE's `user_data` tells the driver which entry
    /// received work.
    ///
    /// The caller guarantees that the iovec array is valid for the duration of
    /// the syscall and that the two buffers it points at stay allocated, at a
    /// stable address, for the entry's whole lifetime (the kernel retains the
    /// base pointers across requests).
    pub fn submit_register(
        &mut self,
        qid: u16,
        iov_addr: u64,
        user_data: u64,
    ) -> Result<(), String> {
        let req = FuseUringCmdReq::for_queue(qid);
        self.push_cmd(
            FUSE_IO_URING_CMD_REGISTER,
            &req,
            None,
            Some(iov_addr),
            Some(FUSE_URING_IOV_SEGS),
            user_data,
        )
    }

    /// Queue a `COMMIT_AND_FETCH` SQE committing the reply for `commit_id` on
    /// `qid`, tagged with `user_data` (the entry whose buffers hold the reply).
    ///
    /// The SQE is not waited on: its completion *is* the next request delivered
    /// into that entry's buffers, which may not arrive until the filesystem is
    /// next used.
    pub fn submit_commit_and_fetch(
        &mut self,
        qid: u16,
        commit_id: u64,
        user_data: u64,
    ) -> Result<(), String> {
        let mut req = FuseUringCmdReq::for_queue(qid);
        req.commit_id = commit_id;
        self.push_cmd(
            FUSE_IO_URING_CMD_COMMIT_AND_FETCH,
            &req,
            None,
            None,
            None,
            user_data,
        )
    }

    /// Wait for the next event (a delivered request) and return its completion.
    pub fn wait_event(&mut self) -> Result<RingCompletion, String> {
        loop {
            let mut completions = self.submit_and_wait(1)?;
            if let Some(c) = completions.pop() {
                return Ok(c);
            }
        }
    }

    /// Cancel the in-flight operation identified by `target` (`user_data`).
    pub fn cancel(&mut self, target: u64) -> Result<(), String> {
        let ud = self.alloc_ud();
        let entry: squeue::Entry128 = opcode::AsyncCancel::new(target)
            .build()
            .user_data(ud)
            .into();
        // SAFETY: `AsyncCancel` references no user buffer; the target is identified
        // purely by `user_data`.
        if unsafe { self.ring.submission().push(&entry) }.is_err() {
            return Err("io_uring submission queue full".into());
        }
        self.stats.cancels += 1;
        let _ = self.submit_and_wait(1);
        Ok(())
    }

    /// Safely shut the ring down: submit anything queued, then reap every
    /// completion without blocking. The ring's `Drop` releases the kernel
    /// resources.
    pub fn shutdown(&mut self) {
        let _ = self.ring.submit();
        let _ = self.reap();
    }
}

impl std::fmt::Debug for FuseUringRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuseUringRing")
            .field("fd", &self.fd)
            .field("stats", &self.stats)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uapi_sizes_match_the_kernel_headers() {
        assert_eq!(FUSE_IN_HEADER_SZ, 40);
        assert_eq!(FUSE_OUT_HEADER_SZ, 16);
        assert_eq!(FUSE_URING_IN_OUT_HEADER_SZ, 128);
        assert_eq!(FUSE_URING_OP_IN_OUT_SZ, 128);
        assert_eq!(FUSE_URING_ENT_IN_OUT_SZ, 32);
        assert_eq!(FUSE_URING_REQ_HEADER_SZ, 288);
        assert_eq!(FUSE_URING_CMD_REQ_SZ, 40);
        assert_eq!(URING_CMD_AREA_SZ, 80);
        assert_eq!(
            std::mem::size_of::<FuseInHeader>(),
            FUSE_IN_HEADER_SZ,
            "FuseInHeader must be exactly 40 bytes"
        );
        assert_eq!(
            std::mem::size_of::<FuseUringEntInOut>(),
            FUSE_URING_ENT_IN_OUT_SZ,
            "FuseUringEntInOut must be exactly 32 bytes"
        );
    }

    #[test]
    fn command_opcodes_match_the_documented_uapi() {
        assert_eq!(FUSE_IO_URING_CMD_INVALID, 0);
        assert_eq!(FUSE_IO_URING_CMD_REGISTER, 1);
        assert_eq!(FUSE_IO_URING_CMD_COMMIT_AND_FETCH, 2);
        assert_eq!(FUSE_IO_URING_CMD_ADD_QUEUE, 3);
        assert_eq!(FUSE_IO_URING_CMD_ADD_BUFPOOL, 4);
        assert_eq!(FUSE_OVER_IO_URING, 1 << 41);
        assert_eq!(FUSE_HAS_IO_URING_BUFPOOL, 1 << 43);
        assert_eq!(FOPEN_IO_URING_ZERO_COPY, 1 << 8);
        assert_eq!(FUSE_URING_ZERO_COPY, 1);
        assert_eq!(FUSE_URING_ENT_ZERO_COPY, 1);
    }

    #[test]
    fn cmd_req_encodes_at_the_documented_offsets() {
        let mut req = FuseUringCmdReq::for_queue(7);
        assert_eq!(req.qid, 7);
        req.commit_id = 0x1122_3344_5566_7788;
        req.set_bufpool(FuseUringBufpool {
            uaddr: 0xdead_beef_0000_1000,
            len: 0x0002_0000,
            reserved: 0,
        });
        let bytes = req.to_sqe_cmd();
        // flags @0, commit_id @8, qid @16, padding @18, union @24.
        assert_eq!(
            u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
            req.commit_id
        );
        assert_eq!(u16::from_ne_bytes(bytes[16..18].try_into().unwrap()), 7);
        assert_eq!(&bytes[18..24], &[0u8; 6]);
        assert_eq!(
            u64::from_ne_bytes(bytes[24..32].try_into().unwrap()),
            0xdead_beef_0000_1000
        );
        assert_eq!(
            u32::from_ne_bytes(bytes[32..36].try_into().unwrap()),
            0x0002_0000
        );
        assert!(bytes[40..].iter().all(|&b| b == 0), "tail must be zeroed");

        let back = FuseUringCmdReq::from_sqe_cmd(&bytes);
        assert_eq!(back, req);
        assert_eq!(back.bufpool().uaddr, 0xdead_beef_0000_1000);
        assert_eq!(back.bufpool().len, 0x0002_0000);
    }

    #[test]
    fn zero_copy_union_arm_round_trips() {
        let mut req = FuseUringCmdReq::for_queue(0);
        req.set_zero_copy_buf_index(9);
        assert_eq!(req.zero_copy_buf_index(), 9);
        // The bufpool arm now reads back as the first 8 bytes of `aux`.
        assert_eq!(req.bufpool().uaddr, 9);
        let back = FuseUringCmdReq::from_sqe_cmd(&req.to_sqe_cmd());
        assert_eq!(back.zero_copy_buf_index(), 9);
    }

    #[test]
    fn request_header_decodes_into_a_ring_request() {
        let mut hdr_bytes = vec![0u8; FUSE_URING_REQ_HEADER_SZ];
        // struct fuse_in_header
        hdr_bytes[0..4].copy_from_slice(&96u32.to_ne_bytes()); // len
        hdr_bytes[4..8].copy_from_slice(&1u32.to_ne_bytes()); // opcode = FUSE_LOOKUP
        hdr_bytes[8..16].copy_from_slice(&42u64.to_ne_bytes()); // unique
        hdr_bytes[16..24].copy_from_slice(&1u64.to_ne_bytes()); // nodeid (root)
        hdr_bytes[24..28].copy_from_slice(&1000u32.to_ne_bytes()); // uid
        hdr_bytes[28..32].copy_from_slice(&1000u32.to_ne_bytes()); // gid
        hdr_bytes[32..36].copy_from_slice(&1234u32.to_ne_bytes()); // pid
                                                                   // struct fuse_uring_ent_in_out
        let base = FUSE_URING_IN_OUT_HEADER_SZ + FUSE_URING_OP_IN_OUT_SZ;
        hdr_bytes[base..base + 8].copy_from_slice(&FUSE_URING_ENT_ZERO_COPY.to_ne_bytes());
        hdr_bytes[base + 8..base + 16].copy_from_slice(&77u64.to_ne_bytes());
        hdr_bytes[base + 16..base + 20].copy_from_slice(&4096u32.to_ne_bytes());
        hdr_bytes[base + 20..base + 24].copy_from_slice(&256u32.to_ne_bytes());

        let hdr = FuseUringReqHeader::from_bytes(&hdr_bytes).expect("header");
        let req = RingRequest::decode(&hdr).expect("request");
        assert_eq!(req.unique, 42);
        assert_eq!(req.opcode, 1);
        assert_eq!(req.nodeid, 1);
        assert_eq!(req.uid, 1000);
        assert_eq!(req.pid, 1234);
        assert_eq!(req.commit_id, 77);
        assert_eq!(req.payload_sz, 4096);
        assert_eq!(req.payload_offset, 256);
        assert!(req.is_zero_copy());
    }

    #[test]
    fn reply_encoding_matches_the_classical_out_header() {
        let req = RingRequest {
            unique: 42,
            opcode: 1,
            nodeid: 1,
            uid: 0,
            gid: 0,
            pid: 0,
            payload_sz: 0,
            payload_offset: 0,
            commit_id: 77,
            flags: 0,
        };
        let ok = RingReply::ok(&req).encode();
        assert_eq!(ok.len(), FUSE_OUT_HEADER_SZ);
        assert_eq!(u32::from_ne_bytes(ok[0..4].try_into().unwrap()), 16);
        assert_eq!(i32::from_ne_bytes(ok[4..8].try_into().unwrap()), 0);
        assert_eq!(u64::from_ne_bytes(ok[8..16].try_into().unwrap()), 42);

        let err = RingReply::error(&req, libc::ENOENT).encode();
        assert_eq!(
            i32::from_ne_bytes(err[4..8].try_into().unwrap()),
            -libc::ENOENT
        );

        let mut with_payload = RingReply::ok(&req);
        with_payload.payload = vec![1, 2, 3, 4];
        let encoded = with_payload.encode();
        assert_eq!(encoded.len(), FUSE_OUT_HEADER_SZ + 4);
        assert_eq!(
            u32::from_ne_bytes(encoded[0..4].try_into().unwrap()),
            (FUSE_OUT_HEADER_SZ + 4) as u32
        );
    }

    #[test]
    fn classify_never_claims_f2_without_a_running_ring() {
        // Backing io_uring alone is F1, never F2.
        assert_eq!(classify(false, true, None), TransportProfile::F1);
        assert_eq!(classify(false, false, None), TransportProfile::F0);

        // Requesting F2 without a negotiated, running ring stays F1/F0.
        let not_running = FuseUringNegotiation {
            kernel_offered: false,
            engaged: false,
            reason: Some("gate off".into()),
            ..Default::default()
        };
        assert_eq!(
            classify(true, true, Some(&not_running)),
            TransportProfile::F1
        );
        assert_eq!(
            classify(true, false, Some(&not_running)),
            TransportProfile::F0
        );

        // F2 only with a really running ring.
        let running = FuseUringNegotiation {
            kernel_offered: true,
            engaged: true,
            ..Default::default()
        };
        assert_eq!(classify(true, true, Some(&running)), TransportProfile::F2);
    }

    #[test]
    fn discover_report_is_honest_and_never_panics() {
        let report = discover_report();
        // Either usable, or it must carry a concrete reason.
        if !report.usable() {
            assert!(!report.reason().is_empty());
        }
        // `usable()` must agree with its constituents.
        assert_eq!(
            report.usable(),
            report.preconditions.is_ok()
                && report
                    .negotiation
                    .as_ref()
                    .map(|n| n.engaged)
                    .unwrap_or(false)
        );
    }

    #[test]
    fn negotiation_reports_add_queue_availability_truthfully() {
        let legacy = FuseUringNegotiation {
            kernel_offered: true,
            kernel_offered_bufpool: false,
            engaged: true,
            kernel_abi: Some((7, FUSE_KERNEL_MINOR_BASELINE)),
            num_queues: 16,
            ..Default::default()
        };
        assert!(!legacy.add_queue_available(), "ABI 7.45 has no ADD_QUEUE");
        let caps = legacy.capabilities();
        assert!(caps.baseline_register);
        assert!(!caps.add_queue && !caps.add_bufpool && !caps.zero_copy);
        assert_eq!(plan_queues(&legacy, true), QueuePlan::Baseline);

        // A modern kernel that offers the buffer pool: the commands become usable,
        // and zero-copy is still gated on CAP_SYS_ADMIN.
        let modern_no_cap = FuseUringNegotiation {
            kernel_offered: true,
            kernel_offered_bufpool: true,
            engaged: true,
            kernel_abi: Some((7, FUSE_KERNEL_MINOR_ADD_QUEUE)),
            cap_sys_admin: false,
            ..Default::default()
        };
        assert!(modern_no_cap.add_queue_available());
        assert!(!modern_no_cap.capabilities().zero_copy, "no CAP_SYS_ADMIN");
        assert_eq!(
            plan_queues(&modern_no_cap, true),
            QueuePlan::Modern { zero_copy: false }
        );

        let modern_cap = FuseUringNegotiation {
            kernel_offered: true,
            kernel_offered_bufpool: true,
            engaged: true,
            cap_sys_admin: true,
            ..Default::default()
        };
        assert!(modern_cap.capabilities().zero_copy);
        assert_eq!(
            plan_queues(&modern_cap, true),
            QueuePlan::Modern { zero_copy: true }
        );
        // Requesting zero-copy never changes the plan on a baseline kernel.
        assert_eq!(plan_queues(&legacy, true), QueuePlan::Baseline);
    }

    // -----------------------------------------------------------------------
    // Raw 128-byte SQE layout (Phase 28)
    //
    // `entry128_set_len` is the one place OrFS writes an `io_uring` ABI field
    // through a raw pointer (the pinned crate exposes no `sqe->len` setter). These
    // tests assert the exact layout the safety argument depends on.
    // -----------------------------------------------------------------------

    /// **Invariant (e): the raw entry is exactly 128 bytes and `entry128_set_len`
    /// writes only the 4-byte `sqe->len` field at byte offset 24, for any value.**
    #[test]
    fn raw_sqe_len_field_is_written_at_the_documented_offset() {
        assert_eq!(
            std::mem::size_of::<squeue::Entry128>(),
            128,
            "Entry128 is the 64-byte SQE plus the 64-byte command area"
        );
        for len in [0u32, 1, 2, 0xDEAD_BEEF, u32::MAX] {
            let entry = opcode::UringCmd80::new(types::Fd(0), FUSE_IO_URING_CMD_REGISTER)
                .cmd([0u8; URING_CMD_AREA_SZ])
                .build()
                .user_data(0xABCD);
            let entry = entry128_set_len(entry, len);
            assert_eq!(
                read_entry128_len(&entry),
                len,
                "sqe->len must land at byte {SQE_LEN_OFFSET}"
            );
            // A second write is idempotent and overwrites the first.
            let entry = entry128_set_len(entry, 2);
            assert_eq!(read_entry128_len(&entry), 2);
        }
    }

    /// Byte offset of the ABI `sqe->len` field within a 128-byte `Entry128`.
    const SQE_LEN_OFFSET: usize = 24;

    /// Read the raw `sqe->len` field of an [`squeue::Entry128`] (test-only).
    fn read_entry128_len(entry: &squeue::Entry128) -> u32 {
        // SAFETY: `Entry128` is `#[repr(C)]` and exactly 128 bytes (asserted
        // above); byte offset 24 is the ABI `sqe->len` field. `entry128_set_len`
        // has already initialised those four bytes, so this reads initialised
        // memory owned by `entry`, reading no padding and aliasing nothing.
        let got = unsafe {
            std::ptr::read_unaligned(
                (entry as *const squeue::Entry128)
                    .cast::<u8>()
                    .add(SQE_LEN_OFFSET)
                    .cast::<[u8; 4]>(),
            )
        };
        u32::from_ne_bytes(got)
    }

    /// **Invariant: the 80-byte SQE command area decodes totally over arbitrary
    /// bytes.** `from_sqe_cmd` takes a fixed-size array, so it has no length to
    /// validate and cannot panic or allocate; the field offsets it reads
    /// (flags@0, commit_id@8, qid@16, padding@18, union@24) are asserted to
    /// round-trip, with the unused tail zeroed on encode.
    #[test]
    fn cmd_area_decode_is_total_over_arbitrary_bytes() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        };
        for _ in 0..4096 {
            let mut cmd = [0u8; URING_CMD_AREA_SZ];
            for b in cmd[..FUSE_URING_CMD_REQ_SZ].iter_mut() {
                *b = next();
            }
            let req = FuseUringCmdReq::from_sqe_cmd(&cmd);
            let back = req.to_sqe_cmd();
            assert_eq!(
                &back[..FUSE_URING_CMD_REQ_SZ],
                &cmd[..FUSE_URING_CMD_REQ_SZ]
            );
            assert!(
                back[FUSE_URING_CMD_REQ_SZ..].iter().all(|&b| b == 0),
                "the SQE command area tail must be zeroed on encode"
            );
            // The union accessors are total and cannot panic on any input.
            let _ = req.bufpool();
            let _ = req.zero_copy_buf_index();
        }
    }
}
