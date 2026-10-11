# OrFS FUSE-over-io_uring transport (Phase 10)

**Status:** the native-Rust FUSE-over-`io_uring` transport adapter is implemented
and its discovery, negotiation, codec, and `io_uring` command layer are tested.
A **real F2 mount is not achievable on the development host**, for three
independent reasons documented below (§7). Requesting F2 therefore falls back
cleanly to F1/F0 with byte-identical contents. No success is fabricated.

Sources: `src/fuse_uring.rs` (the adapter, the sole place that speaks the
FUSE-over-`io_uring` UAPI), `src/fuse.rs` (transport-neutral cores + the live
`INIT` negotiation), `src/uring.rs` (backing I/O, Domain A), `tests/fuse_uring.rs`
(equivalence, negotiation/fallback, cancellation/shutdown).

This document is normative for transport profiles F0/F1/F2 (research §17–§19,
directive §16/§17).

---

## 1. Two `io_uring` domains, three profiles

Research §17 separates two uses of `io_uring`; they are independent and OrFS
never conflates them.

| Domain | What it accelerates | Where |
|--------|---------------------|-------|
| **A — backing store** | authoritative writes, immutable reads, `fsync` | `src/uring.rs` (Phase 5) |
| **B — FUSE transport** | kernel↔userspace request delivery | `src/fuse_uring.rs` (this phase) |

Turning on Domain A does **not** turn on Domain B. The transport profiles
(research §18) are:

| Profile | Request transport | Backing I/O | How OrFS reports it |
|---------|-------------------|-------------|---------------------|
| **F0** | `/dev/fuse` (fuser) | synchronous `pread`/`pwrite` | `transport_used() == F0` |
| **F1** | `/dev/fuse` (fuser) | `io_uring` rings W/R | `transport_used() == F1` |
| **F2** | FUSE-over-`io_uring` | `io_uring` rings W/R | `transport_used() == F2` **only** when a ring really negotiated |

`--transport fuse|fuse-uring` selects the *requested* transport;
`--backing-io sync|uring` selects the backing engine. The profile actually in
force is computed by `fuse_uring::classify`: **F2 is returned only when the
negotiation reports a running ring.** Backing `io_uring` alone is F1, never F2.
`OrfsMount::backing_io_used` and `OrfsMount::transport_used()` are the
authoritative, non-optimistic answers.

---

## 2. UAPI: structures and commands

The container image (Debian bookworm) ships **older** headers than the running
kernel, so OrFS does **not** include any system `fuse.h`. The structures and
commands are transcribed from the running kernel's own headers and the
documented UAPI, with byte-exact layouts:

* `/usr/include/linux/fuse.h` and `/usr/src/linux-cachyos/include/uapi/linux/fuse.h`
  (kernel `7.2.9-2-cachyos`, FUSE ABI **7.45**), and
* a full Linux **7.3.0-rc4** source tree (`v7.2` and `v7.3-rc4` tags) whose
  `include/uapi/linux/fuse.h`, `fs/fuse/dev_uring.c`, and
  `Documentation/filesystems/fuse/{fuse-io-uring,uapi/fuse-uapi-io-uring}.rst`
  give the modern (**7.46**) interface and the driver semantics.

### 2.1 Command opcodes (`enum fuse_uring_cmd`)

All are carried through `IORING_OP_URING_CMD` as the 80-byte command area of a
128-byte SQE (`IORING_SETUP_SQE128`; the kernel rejects an SQE without the
extension: `if (!(issue_flags & IO_URING_F_SQE128)) return -EINVAL;`).

| Constant | Value | Available since |
|----------|------:|-----------------|
| `FUSE_IO_URING_CMD_INVALID` | 0 | — |
| `FUSE_IO_URING_CMD_REGISTER` | 1 | ABI 7.42 |
| `FUSE_IO_URING_CMD_COMMIT_AND_FETCH` | 2 | ABI 7.42 |
| `FUSE_IO_URING_CMD_ADD_QUEUE` | 3 | **ABI 7.46** |
| `FUSE_IO_URING_CMD_ADD_BUFPOOL` | 4 | **ABI 7.46** |

No outdated/experimental command names are used.

### 2.2 `struct fuse_uring_cmd_req` (80-byte SQE command area)

| Offset | Field | Notes |
|-------:|-------|-------|
| 0 | `u64 flags` | command-specific (`FUSE_URING_ZERO_COPY` for `ADD_QUEUE`) |
| 8 | `u64 commit_id` | for `COMMIT_AND_FETCH` |
| 16 | `u16 qid` | queue index |
| 18 | `u8[6] padding` | |
| 24 | union (16 bytes) | `{ bufpool { u64 uaddr; u32 len; u32 reserved } }` or `{ u16 ent_zero_copy_buf_index }` |

The union is modelled as a raw 16-byte array with typed accessors
(`set_bufpool`/`bufpool`, `set_zero_copy_buf_index`/`zero_copy_buf_index`) so
encoding is entirely **safe** while remaining byte-identical.

### 2.3 `struct fuse_uring_ent_in_out` (32 bytes)

| Offset | Field | Notes |
|-------:|-------|-------|
| 0 | `u64 flags` | `FUSE_URING_ENT_ZERO_COPY` when zero-copied |
| 8 | `u64 commit_id` | echo back in `COMMIT_AND_FETCH` |
| 16 | `u32 payload_sz` | payload bytes |
| 20 | `u32 offset` | payload offset within the buffer pool (**7.46**); `padding` in **7.45** |
| 24 | `u64 reserved` | |

The layout is identical across 7.45/7.46 (only field *4* is renamed), so one
structure models both.

### 2.4 `struct fuse_uring_req_header` (288 bytes)

`char in_out[128]` + `char op_in[128]` + `struct fuse_uring_ent_in_out` (32).
`in_out` holds a `struct fuse_in_header` (request) — the same header the
classical transport uses.

### 2.5 Other constants

| Constant | Value |
|----------|-------|
| `FUSE_OVER_IO_URING` | `1 << 41` |
| `FUSE_HAS_IO_URING_BUFPOOL` | `1 << 43` (ABI 7.46) |
| `FOPEN_IO_URING_ZERO_COPY` | `1 << 8` |
| `FUSE_URING_ZERO_COPY` | `1 << 0` |
| `FUSE_URING_ENT_ZERO_COPY` | `1 << 0` |
| `FUSE_URING_IOV_SEGS` | 2 (header, payload) |

In-crate tests assert every size and opcode value, and round-trip the codec, so
a drift from the UAPI is a test failure, not a silent mismatch.

---

## 3. Lifecycle

```mermaid
sequenceDiagram
    participant U as OrFS (userspace)
    participant K as FUSE kernel
    U->>K: FUSE_INIT (server offers FUSE_OVER_IO_URING if offered)
    K-->>U: init reply (FUSE_OVER_IO_URING only if fuse_uring_enabled())
    Note over U: negotiate_fuse_uring() records the real result
    U->>K: ADD_QUEUE (qid, flags) [ABI 7.46]
    U->>K: ADD_BUFPOOL (qid, uaddr, len) [ABI 7.46, optional]
    U->>K: REGISTER (entry iovecs; one entry per queue)
    K-->>U: CQE carrying fuse_uring_req_header (a request)
    U->>K: COMMIT_AND_FETCH (commit_id, qid) -> next request
    U->>K: IORING_OP_ASYNC_CANCEL (cancel a stalled request)
    U->>U: shutdown(): submit, reap, drop
```

The adapter implements each step:

1. **Capability discovery** — `Discovery::probe()` reads `uname`, `/dev/fuse`,
   an `io_uring` probe, the kernel config where available, the
   `fuse.enable_uring` module parameter, and `CAP_SYS_ADMIN` (`/proc/self/status`
   `CapEff`).
2. **Queue creation** — `FuseUringRing::add_queue(qid, zero_copy)`.
3. **Buffer-pool registration** — `FuseUringRing::add_bufpool(qid, base, len, fixed_index)`.
4. **Entry registration** — `FuseUringRing::register_entry(qid, iov_addr, zero_copy_index)`.
5. **CQE request handling** — `wait_event()`, plus `reap()`; requests decode via
   `RingRequest::decode(&FuseUringReqHeader)`.
6. **Reply commit** — `RingReply::encode()` produces the exact `fuse_out_header`
   + payload, byte-compatible with the classical transport.
7. **Fetch-next lifecycle** — `commit_and_fetch(qid, commit_id)` re-submits the
   entry, which is how the kernel returns the next request.
8. **Cancellation** — `cancel(user_data)` issues `IORING_OP_ASYNC_CANCEL`; a
   canceled request never counts as success.
9. **Safe shutdown** — `shutdown()` submits, reaps without blocking, and the
   ring's `Drop` releases kernel resources.
10. **Automatic fallback** — §6.

The classical `/dev/fuse` path (`src/fuse.rs`, `fuser`) is retained for
everything F2 does not deliver: **notifications and interrupts still require the
conventional interface**, exactly as the kernel documentation states.

### 3.1 The implicit-queue legacy path (ABI 7.45)

The running kernel (`7.2.9`, ABI 7.45) has **no** `ADD_QUEUE`: the driver creates
a queue lazily on the first `REGISTER` whose `qid` is in `[0, nr_queues)`, where
`nr_queues` is the CPU count (`fuse_uring_register` → `fuse_uring_create_queue`).
The adapter therefore treats `ADD_QUEUE` as optional and availability is decided
by the negotiated ABI (`FUSE_HAS_IO_URING_BUFPOOL` ⇒ 7.46+).

---

## 4. Buffer pools and zero-copy (§17)

* A queue may be given one contiguous payload region with `ADD_BUFPOOL`. The
  kernel then reports, per request, `ring_ent_in_out.offset` and `payload_sz`;
  the server locates the payload at `pool_base + offset`. This decouples entries
  from payload buffers.
* Registering the pool with `io_uring` and issuing `ADD_BUFPOOL` with
  `IORING_URING_CMD_FIXED` + `sqe->buf_index` pins the pool pages once. The same
  registered region can back the server's own `READ_FIXED`/`WRITE_FIXED` file
  I/O — the shared-buffer idea of research §17.
* **Zero-copy** is opt-in only (`--zero-copy` requires `--transport fuse-uring`
  *and* `CAP_SYS_ADMIN`); it is capability-checked at the CLI, never required for
  ordinary mounts. The open-file flag `FOPEN_IO_URING_ZERO_COPY` selects it per
  open. Because F2 does not engage here (§7), zero-copy is inert and is *not*
  benchmarked; §8 states this plainly rather than inventing numbers.

---

## 5. Negotiation and fallback

Negotiation is a **live `INIT` handshake**, not a guess. Inside
`OrfsFuse::init` (`src/fuse.rs`), when `--transport fuse-uring` is requested:

* `config.capabilities()` is the kernel's offered set. The kernel sets
  `FUSE_OVER_IO_URING` **only** when `fuse_uring_enabled()` is true
  (`fs/fuse/inode.c`), so the presence of that bit is the authoritative answer.
* The server echoes the capability only when offered
  (`config.add_capabilities(FUSE_OVER_IO_URING)`).
* `FUSE_HAS_IO_URING_BUFPOOL` (`1 << 43`, retained by the fuser crate via
  `from_bits_retain`) reports the modern `ADD_QUEUE`/`ADD_BUFPOOL` interface.
* The result is stored in `FuseUringNegotiation { kernel_offered,
  kernel_offered_bufpool, kernel_abi, accepted, engaged, reason }` and surfaced
  by `OrfsMount::fuse_uring_negotiation()` / `transport_description()` /
  `fuse_uring_report()`.

`classify()` turns that into F0/F1/F2. The fallback changes **no** filesystem
contents: F2 is purely a request-delivery path; the authoritative log, extents,
and EKBLOOM integration are untouched.

`orfs doctor` performs the static discovery (including the decisive
`fuse.enable_uring` gate) and reports `fuse_over_io_uring_usable` with the exact
reason — never merely "plausible".

---

## 6. What is verified

| Test (`tests/fuse_uring.rs`) | Requires | Checks |
|------------------------------|----------|--------|
| `ring_control_cancel_and_shutdown_are_safe` | `io_uring` | `ADD_QUEUE`/`ADD_BUFPOOL`/`COMMIT_AND_FETCH` submission, `ASYNC_CANCEL`, `shutdown()` against a non-`fuse` fd (kernel rejects `URING_CMD` with `-EOPNOTSUPP` for a file with no `uring_cmd`); counters and no panic |
| `transport_equivalence_and_f2_fallback` | mount | identical logical transcripts for F0, F1, and a requested-F2 mount; `F0`/`F1`/non-F2 profiles; negotiation recorded with a reason; contents identical |
| `f2_negotiation_records_a_real_reason` | mount | a requested-F2 mount records `engaged == false` and a non-empty reason, and never reports F2 |

In-crate unit tests (`src/fuse_uring.rs`) pin the UAPI sizes/opcodes, the
command encoding offsets, the zero-copy union arm, the request/reply codec, and
the profile-classification rule.

---

## 7. Why a real F2 mount is not achievable here (three blockers)

Both are *honest, documented* outcomes; neither is worked around by faking
success.

### 7.1 `fuse.enable_uring=0` (kernel policy / privilege)

The running kernel exposes the module parameter
`/sys/module/fuse/parameters/enable_uring` and `fuse_uring_enabled()` returns it.
It gates **both** the `FUSE_OVER_IO_URING` `INIT` flag and the connection's
`io_uring` enablement (`fs/fuse/inode.c`:

```c
if (flags & FUSE_OVER_IO_URING && fuse_uring_enabled())
        fuse_chan_io_uring_enable(fc->chan);
```

and `fs/fuse/dev_uring.c`: `if (!enable_uring && !fch->io_uring) return -EOPNOTSUPP;`).
On this host it is **`N`**. The parameter is `root:root 0644`; the container runs
as an unprivileged uid, so it cannot be changed, and changing a host-global
kernel parameter would be an out-of-scope host mutation. The observed result is
recorded verbatim in the evidence: *"kernel did not offer FUSE_OVER_IO_URING at
INIT (FUSE ABI 7.45)"*.

### 7.2 The pinned `io-uring` 0.7.15 cannot set `sqe->len`

`FUSE_IO_URING_CMD_REGISTER` requires `sqe->len == FUSE_URING_IOV_SEGS (2)`
(`fuse_uring_get_iovec_from_sqe`: `if (sqe->len != FUSE_URING_IOV_SEGS) return
-EINVAL;`). The `io-uring` 0.7.15 crate's `UringCmd80` builder exposes
`cmd_op`/`cmd`/`addr`/`buf_index` but **no `len` setter**, and neither `Entry`
nor `Entry128` exposes one. The control commands (`ADD_QUEUE`, `ADD_BUFPOOL`,
`COMMIT_AND_FETCH`, cancellation) do not use `len` and are unaffected. Closing
this gap needs a raw-SQE path (or a crate that exposes `len`); that is listed as
follow-up and deliberately not attempted as untested `unsafe` here.

### 7.3 fuser owns the `/dev/fuse` fd

Even with §7.1 enabled, a running F2 request loop must issue `URING_CMD` on the
mount's `/dev/fuse` fd. This build uses the `fuser` crate for the session, and
`fuser` 0.18 does not expose that descriptor, so a native ring cannot attach to
a `fuser`-managed mount. A full F2 driver would own the session (mount + `INIT` +
ring); the adapter here is the ring/codec/negotiation layer such a driver uses.

---

## 8. Measured results and evidence (honest interpretation)

Machine-generated evidence:

* `evidence/performance/fuse-uring.json` — environment, kernel, UAPI version,
  the per-profile reported status, the live F2 negotiation, and the *reason* F2
  throughput is not measured (`"f2": "not measured (F2 unavailable)"`).
* `evidence/correctness/fuse-uring-equivalence.json` — the operation transcript
  shared by F0, F1, and the requested-F2 fallback (`contents_identical: true`).
* `evidence/correctness/fuse-uring-ring.json` — the ring layer's submission,
  completion, cancellation, and shutdown counters, and the `-EOPNOTSUPP` the
  kernel returns for `URING_CMD` on a non-`fuse` fd.

What these **do not** claim: no F2 throughput number is reported, because F2 did
not engage. Backing-I/O micro-benchmarks remain in
`evidence/performance/backing-uring.json` (Phase 5).

---

## 9. `unsafe` inventory

All `unsafe` in `src/fuse_uring.rs` is confined to the `io_uring` FFI contract,
each with a stated invariant:

| Location | Invariant |
|----------|-----------|
| `FuseUringRing::push_cmd` (`squeue::SubmissionQueue::push`) | the SQE references only bytes copied into it and, when `addr` is set, a caller-owned buffer the caller keeps alive for the operation's lifetime |
| `FuseUringRing::cancel` (`push` of `AsyncCancel`) | `AsyncCancel` references no user buffer; the target is identified by `user_data` |

No raw ring setup, `mmap`, or `unsafe` transmute is used; the command/reply
structs are encoded and decoded with checked byte arithmetic.

---

## 10. Explicit non-claims

* F2 is **not** active on this host; `orfs doctor` and the evidence say so.
* Zero-copy is implemented at the CLI/negotiation level but not exercised; no
  zero-copy performance number is claimed.
* FUSE passthrough (research §28.2) is not implemented in this phase.
* The `REGISTER` iovec path is implemented but cannot be expressed through the
  pinned `io-uring` crate (§7.2).
