# OrFS — Security Model, Hardening, and Unsafe Audit (Phase 11; native-FUSE hardening, Phase 28)

This document is normative for Phase 11 (research directive §28 *filesystem
security*, §29 *non-withdrawal privacy implications*, §34 *fault injection*) and
extended in Phase 28 with the native FUSE-over-`io_uring` threat/fuzzing analysis,
the raw-SQE layout assertions, the completion-ownership and buffer-lifetime
tests, and the reconciled `unsafe` audit (§3.13, §4.1).
Every claim below is backed by a test in this repository, a build-time check, or
a machine-generated evidence file under `evidence/security/`. Where a guarantee
is **not** provided, it is stated as a limitation rather than implied.

---

## 1. Threat model

OrFS treats **every authoritative backing record and every FUSE request as
potentially hostile**. The adversaries considered are:

| Adversary | Capability | Where handled |
|---|---|---|
| **Hostile backing data** | Arbitrary bytes in `or_log/*.seg`, a forged but correctly-framed record, a tampered or truncated committed segment, an unsupported format version. | `src/record.rs`, `src/segment.rs`, `src/log.rs`, every payload decoder |
| **Hostile FUSE client** | Arbitrary request fields: opcodes, nodeids, names, offsets, sizes, xattr names, access masks, handles. | `src/fuse.rs`, `src/fuse_uring.rs`, `src/namespace.rs`, `src/index.rs` |
| **Unprivileged local user** | Mounts the filesystem (possibly with `default_permissions`) and issues ordinary POSIX operations. | `src/fuse.rs` permission helpers, `src/inode.rs::has_permission_grouped` |
| **Tampered derived structure** | A process able to read/write the backing directory forges a concealed structure (e.g. a FUSE-passthrough backing image) and rewrites its manifest to match. | §3.14, `src/passthrough.rs`, the read planner's certification/identity checks |
| **Hostile backing directory contents** | A hostile or curious process that can read the backing directory, or plant files/symlinks in it. | §5 namespace↔backend separation, `src/manifestation.rs::dir_bytes` |
| **Process crash / torn writes** | The process is killed mid-write; the page cache survives but no destructor runs. | `tests/crash_recovery.rs`, `tests/recovery_adversarial.rs`, `docs/RECOVERY.md` |

Out of scope (explicitly): a compromised kernel, a privileged attacker who can
read the raw device, and **power-loss/device-cache reordering** — the last is a
separate, identified proof obligation (`docs/TRANSACTIONS.md`; a process kill is
*not* a power-loss simulation).

---

## 2. Non-withdrawal privacy statement (§29)

> **Logical deletion is *not* secure erasure.**

OrFS is an **append-only, non-withdrawal** filesystem. `unlink`, `rmdir`,
`truncate`-down, rename-over, and every other logical removal write a *new*
record that changes the *visible* namespace; they **never physically remove,
overwrite, or reclaim the underlying historical bytes**. Consequently:

* A path that has been unlinked remains physically present in the authoritative
  log, byte-for-byte, forever (by design — this is invariant I1).
* **OrFS is inappropriate for any workflow that requires reliable physical
  deletion** (for example, "right to erasure", secret destruction, or
  declassification) **unless a separately specified data-retention and
  cryptographic policy is applied on top of it.** Cryptographic key destruction
  in particular changes the *effective* recoverability of the retained bytes and
  may not satisfy the strongest non-withdrawal interpretation
  (research OrFS §31).
* Revoking a namespace path **does not** make the underlying historical bytes
  unrecoverable: any party who can read the backing store, or who can mount an
  earlier committed root, can still read them.
* **Historical access is permission-controlled.** Snapshot/historical mounts are
  strictly read-only (`EROFS` for every mutation) *and* enforce the same POSIX
  permission rule as the live view; a snapshot of a root is not a bypass of the
  permissions that applied at that root. See §6.
* **The physical backing store may need stricter access controls than the logical
  mount.** Because the mount is a purely logical projection (§5) the backing
  directory is where the retained history actually lives; it should be protected
  with the controls appropriate to the most sensitive content OrFS has ever
  stored — not merely the controls appropriate to the current namespace.

This statement is the honest permanence guarantee; it is not a disclaimer added
after the fact but the direct expression of invariant I1.

---

## 3. Hardening per surface

### 3.1 Record framing (`src/record.rs`)

* Header and footer fields are read **field by field** from explicit
  little-endian byte offsets; **no Rust struct is ever cast over untrusted
  bytes**.
* `RecordHeader::decode` validates `magic`, `header_length`, `format_version`
  (reporting an incompatible version as `DecodeError::Compatibility`), and
  `payload_length` **against `MAX_PAYLOAD_LEN` (64 MiB) before any payload buffer
  exists**.
* `total_len` and every offset are computed with **checked arithmetic**
  (`checked_add`), surfacing `DecodeError::Overflow` rather than wrapping.
* `Record::decode` bounds-checks the whole framed length against the available
  bytes before copying the payload. The footer CRC32C and end-marker are
  validated before the record is accepted.

### 3.2 Payload decoders (every typed record)

All payload decoders are bounds-checked (`take_len_bytes`, `check_prefix`,
`check_trailing_crc`, cursor `Dec::take`) and, as of Phase 11, **validate their
semantics as well as their framing** — a *committed* record is authoritative
history, so an illegal value is corruption and is refused (§23.1, §35), never
silently indexed:

| Decoder | Enforced bound |
|---|---|
| `directory::DentryAddPayload` / `DentryRemovePayload` / `DentryRenamePayload` | `validate_name`: non-empty, ≤ `NAME_MAX` (255), no `/`, no NUL, not `.`/`..` |
| `inode::XattrSetPayload` / `XattrRemovePayload` | `validate_xattr_name` (≤ 255, no NUL) and value ≤ `XATTR_VALUE_MAX` (64 KiB) |
| `inode::SymlinkCreatePayload` | non-empty target ≤ `SYMLINK_TARGET_MAX` (`PATH_MAX`, 4096) |
| `namespace::SnapshotRootPayload` | `validate_name` on the snapshot name |
| `extent::DataExtentPayload` | data length checked against the framed payload length with `checked_add` (no debug-mode overflow) |
| `trigram::TrigramIndex`, `trigram::TrigramManifest`, `manifestation::GenerationManifest` | counts bounded by the **remaining input bytes** *before* any `Vec::with_capacity`; sketches bounded by `SKETCH_MAX_BITS` |
| `index::Index::decode_snapshot` | serialized snapshot must pass its own BLAKE3 self-digest; `serde_json`'s built-in recursion limit bounds nesting |

### 3.3 Bounded allocation — *no allocation driven by an untrusted length before validation*

The rule is enforced by construction: every length read from the input is
compared against the bytes actually present before it is used as a capacity. The
Phase 11 audit found and fixed the one place where this rule was violated
(`TrigramIndex::decode`), and tightened two more (the `HEAD` decoders).

### 3.4 Raw Unix filenames

Names are handled as **bytes** (`&[u8]`, `OsStr::as_bytes`,
`OsStr::from_bytes`) end to end: the namespace, index, record payloads, and FUSE
replies never assume UTF-8. Arbitrary non-UTF-8 names round-trip through
create / lookup / readdir / reopen (`hostile_files::raw_non_utf8_filenames_are_supported`).

### 3.5 Strict path traversal handling

Path components are validated where they enter the system
(`directory::validate_name`) **and** where they are re-read from committed
history (the decoders above). `.`/`..` are handled only as explicit lookup
shorthands in the FUSE layer; they are never stored as entries. Symlink *targets*
are stored verbatim (as POSIX requires) and returned by `readlink`; target
resolution is the kernel's job and OrFS performs no in-kernel path walk.

### 3.6 Valid inode / reference checking

Every index mutation resolves its subject with `index::subject` (which rejects a
missing inode and a payload/header inode-id disagreement) and
`Index::inode`/`inode_mut` (which reject unknown ids). Directory parents are
required to be *live* directories (`Namespace::require_live_dir`), so a removed
directory can never be the parent of a new mutation.

### 3.7 Permission enforcement

* `inode::has_permission_grouped` implements the class-based POSIX rule (owner /
  group / other, with the superuser bypass). The group class matches on the
  effective group **or any supplementary group** (Linux `in_group_p`); the FUSE
  transports supply the caller's supplementary groups from
  `/proc/<pid>/status`, and the typed query API carries them on its
  `Credential`. `inode::has_permission` is the group-less form, retained for
  callers with only effective ids.
* **Every** mutating FUSE handler checks permission before acting
  (`check_create`, `check_dir_write`, per-inode `0o2` for writes and xattrs).
  Both transports route these through the supplementary-group-aware rule
  (`src/fuse.rs` and `src/fuse_native.rs` share `crate::fuse::caller_groups`).
* **Reading an xattr now requires read permission** (`0o4`) on the inode,
  symmetric with reading contents; no attribute namespace bypasses the check.
* The sticky bit is honoured on `unlink`/`rmdir` (owner-of-entry / owner-of-dir /
  root).
* A read-only mount (`MountOptions::read_only`, used for every snapshot mount)
  rejects every mutation with `EROFS` regardless of caller identity.

### 3.8 Symlink safety

Symlink targets are opaque bytes with a bounded length. OrFS never follows a
symlink during a filesystem operation: `lookup` returns the symlink inode; the
kernel performs resolution. The only place OrFS itself walks a directory tree is
`manifestation::dir_bytes`, which **does not follow symlinks** and cannot be
redirected out of the backing store (§3.11).

### 3.9 Namespace ↔ backend separation

The mount is a **purely logical projection** of the authoritative log. The
backing directory (`or_log/`, `orfs.meta`, `quarantine/`, `.or_bloom/`, …) is
*never* reachable through the mount: `hostile_files::backing_directory_is_not_reachable_through_the_mount`
plants a secret file and a `.or_bloom/` directory in the backing store and
proves that neither `lookup` nor `readdir` at the root exposes them.
Concealed manifests and historical deleted content are therefore not visible
through ordinary user queries; the concealed planes are keyed by inode identity +
version + root and are only consulted by the read planner, never surfaced as
namespace entries.

### 3.10 Historical-view (snapshot) access

* A snapshot root must be `0` or a **committed transaction boundary**
  (`Snapshot::from_read_log`, `Log::pin_root`); an offset inside a record or
  beyond the committed root is refused.
* A `HistoricalRoot` reference is `(volume uuid, root)`. Opening a reference that
  names a *different volume* is refused (`Snapshot::open_historical`,
  `Snapshot::open_dir_historical`) so that a root offset can never be
  reinterpreted against another volume's log (§2 I2).
* A snapshot pins its root (`RootPin`) so a live writer cannot roll over or
  quarantine the segments it reads.
* Snapshot mounts are read-only both logically (the snapshot core returns
  `ReadOnly`) and at the kernel level.

### 3.11 No untrusted pointer casting; no uncontrolled recursion

* There is **no `transmute`, no `from_raw_parts` over an untrusted length, and no
  struct-over-bytes cast** anywhere in the crate. `from_raw_parts` appears only in
  `src/buffers.rs`, over allocations OrFS itself owns (audited in §4).
* Recursion in the query plane (`collect_dir`) and the concealer
  (`dir_bytes`) is now **iterative with a visited set**: a hostile committed
  directory cycle, a symlink loop, or an extremely deep tree cannot overflow the
  call stack or loop forever.

### 3.12 FUSE request decode

The classical transport is decoded by `fuser`; OrFS's own FUSE-over-`io_uring`
request framing (`FuseInHeader`, `FuseUringEntInOut`, `FuseUringReqHeader`,
`RingRequest`) is decoded with explicit length checks and `.ok()?`-style
`try_into`, returning `None` on short input — no panic, no allocation.
File-handle validation is uniform: every `read`/`write`/`readdir`/`releasedir`
looks the handle up in the handle table and returns `EBADF` for an unknown handle
or a kind mismatch (a directory handle used for I/O, or vice versa).

### 3.13 Native FUSE-over-`io_uring` (F2): buffer lifetimes, SQE layout, completion ownership

`src/fuse_native.rs` owns the `/dev/fuse` descriptor and drives an
`IORING_SETUP_SQE128` ring; `src/fuse_uring.rs` is the UAPI codec and command
layer. This is the crate's most `unsafe`-dense surface (37 of the 53 audited
sites: 27 in `fuse_native.rs`, 4 in `fuse_uring.rs`, 6 in `buffers.rs`), so its
invariants are **asserted by focused tests**, not merely stated in comments —
see `tests/native_fuse_fuzz.rs` and the unit tests named below.

**Request decode is total.** `FuseInHeader::from_bytes`,
`FuseUringEntInOut::from_bytes`, `FuseUringReqHeader::from_bytes`,
`RingRequest::decode`, and `FuseUringCmdReq::from_sqe_cmd` read fixed-size
little-endian fields with `.try_into().ok()?`; none uses an input length to size
an allocation and none can panic (`arbitrary_bytes_never_panic_any_decoder`;
fuzzed below in §4.1).

**The kernel-reported payload size is clamped.** The per-entry registered
payload buffer is exactly `PAYLOAD_BUF` (256 KiB). Both the single-loop and the
worker-pool dispatch paths derive the request payload length through one
function, `clamp_payload_sz(raw, cap) = min(raw, cap)`, so a hostile or
out-of-range `size` can never index past the buffer
(`fuse_native::tests::payload_size_is_clamped_to_the_registered_buffer`).

**The reply never over-claims the registered buffer.** The kernel copies exactly
`ring_ent_in_out.payload_sz` bytes out of the registered payload buffer, so
`write_reply` clamps the reply body to the buffer length before staging it.
This is a Phase 28 fix: an out-of-range `read`/`readdir` `size` used to produce a
reply body larger than `PAYLOAD_BUF`, which panicked the session thread (index
out of bounds) and — absent the panic — would have told the kernel to copy past
the registered buffer
(`reply_larger_than_the_registered_buffer_is_clamped_not_panicking`).

**Registered buffers are at stable, pinned addresses.** The kernel is handed the
`iov[0]`/`iov[1]` array once at `REGISTER` and dereferences it for the entry's
whole lifetime. `EntryState` owns its `AlignedBuffer`s and boxes its `iovec`
array, so its addresses do not change when it is moved (the
`unsafe impl Send for EntryState`); asserted by
`entry_state_buffers_are_stable_under_ownership_move` and, for the underlying
allocation, `buffers::tests::aligned_buffer_address_is_stable_when_ownership_moves_between_threads`.

**Completion ownership is explicit.** A dispatch worker receives a stable
`EntryPtr` to one entry **only while `inflight[idx]` is set**, and the session
thread neither touches that entry nor submits its `COMMIT_AND_FETCH` until the
matching `Done` returns; `WorkerPool::drop` closes the queues and joins every
worker **before** the ring and the entries are torn down, so no worker can still
hold an `EntryPtr` when the buffers are freed
(`worker_pool_drop_joins_workers_with_outstanding_jobs`,
`job_queue_close_wakes_waiters_and_drains_cleanly`). A registered buffer is
releasable only after every referencing completion is reaped **and** its pin is
dropped; a *cancel* is not a completion
(`buffers::tests::registered_buffers_are_released_only_after_every_completion_is_reaped`).
Shutdown with outstanding ring commands submits and drains without panic
(`tests/fuse_uring.rs::ring_control_cancel_and_shutdown_are_safe`).

**The raw 128-byte SQE layout is asserted.** `entry128_set_len` writes the ABI
`sqe->len` field (which must be `== 2` for `REGISTER`) through a raw pointer,
because the pinned `io-uring` crate exposes no setter. A focused test asserts
`size_of::<Entry128>() == 128` and that a write lands at exactly byte offset 24
and nowhere else, for several values
(`fuse_uring::tests::raw_sqe_len_field_is_written_at_the_documented_offset`); the
80-byte command area is asserted to encode/decode at the documented offsets over
arbitrary bytes (`cmd_area_decode_is_total_over_arbitrary_bytes`).

### 3.14 Derived-structure integrity (Phase 33)

A concealed structure is *derived*, so it is never trusted on its own word.
Every derived structure is either (a) verified against the authoritative bytes
before use, or (b) refused and rebuilt/fallen-back from. Two concrete cases:

* **FUSE-passthrough backing images.** An image is reused only when its identity
  matches, its length matches, its recomputed BLAKE3 matches the recorded digest,
  **and** that digest matches the digest the authoritative source produces now
  (`passthrough::authoritative_digest`). An attacker who tampers the image *and*
  rewrites the manifest to match is therefore still refused, because the derived
  pair is self-consistent but disagrees with authority. Regression:
  `passthrough::tests::tampered_image_and_manifest_are_refused`.
* **Manifested read structures.** The read planner re-checks the loaded body's
  identity against the request and only selects a *certified* candidate that has
  been measured for that exact object (§`docs/MANIFESTATION.md`); a
  missing/corrupt structure is a fallback to the authoritative read, never a
  different answer.

The general rule: **authority establishes truth; a concealed structure only
accelerates observation of it.**

---

## 4. `unsafe`-block audit

Every `unsafe` site in the crate, its purpose, its written invariant, and a
covering test where one exists. This inventory is regenerated from the source at
test time (`hostile_files::every_unsafe_block_has_a_written_safety_invariant`)
and written to `evidence/security/unsafe-audit.json` (schema `v2`), which asserts
that **all 53 sites carry a `SAFETY:` comment**. The count is **line-based**: one
entry per source line carrying the `unsafe` token (comment lines are excluded),
so an expression whose `unsafe` opener and body span two lines counts once (only
the opener carries the token). The Phase 28 audit reconciled this document with
the machine-generated count: it read **43** and is now **53**
(`fuse_native.rs` 27, `buffers.rs` 6, `uring.rs` 5, `fuse_uring.rs` 4, `fuse.rs`
4, `capabilities.rs` 2, `capacity.rs` 2, `stats.rs` 2, `bench.rs` 1) — the native
transport surface alone (Phase 15/21/26) is **37** of them. Each JSON entry also
carries `safety_invariant` (the `SAFETY:` comment text) and `covering_test` (a
named test where one exists). The table below is a representative selection
grouped by purpose; the committed JSON is the authoritative inventory. For the
native-path sites, see §3.13.

| File (site) | Purpose | Safety invariant |
|---|---|---|
| `bench.rs` | `posix_fadvise(..., POSIX_FADV_DONTNEED)` | The fd is an open regular file; `posix_fadvise` is an advisory hint that dereferences no memory. |
| `buffers.rs` | `unsafe impl Send for AlignedBuffer` / `BufferPool` | The buffer/pool owns its allocation outright; transferring ownership transfers no aliasing. |
| `buffers.rs` | `alloc_zeroed` / `dealloc` | `len > 0` so the layout is non-zero; the pointer is checked for null and freed exactly once with the same layout. |
| `buffers.rs` | `slice::from_raw_parts(_mut)` | `ptr` is valid for `len` bytes for the buffer's lifetime; `&mut self` proves exclusivity for the mutable form. |
| `capabilities.rs` | `zeroed()` + `uname` | `uname` is a pure query filling a caller-owned struct. |
| `stats.rs`, `capacity.rs`, `fuse.rs` | `zeroed()` + `statvfs` | `c` is a valid NUL-terminated path and `st` a valid aligned caller-owned struct. |
| `fuse.rs` | signal-handler body | Performs a single atomic store and returns (async-signal-safe). |
| `fuse.rs` | `umount2(..., MNT_DETACH)` | `c` is a valid NUL-terminated path; lazy detach cannot block on the caller. |
| `fuse.rs` | direct `mount(2)` / `recvmsg` fd passing | Only owned fds and owned, NUL-terminated buffers are passed; ownership is transferred exactly once. |
| `fuse_uring.rs` | `entry128_set_len` raw `sqe->len` write | `Entry128` is `repr(C)` and exactly 128 bytes; offset 24 holds `sqe->len`; written through a unique `&mut`. (Asserted: `raw_sqe_len_field_is_written_at_the_documented_offset`.) |
| `fuse_uring.rs` | `submission().push(&entry)` | The SQE references only the request's encoded bytes, copied into the submission queue. |
| `fuse_native.rs` | `unsafe impl Send for EntryState` / `EntryPtr` | Each owns its buffers/points into a stable, session-owned `Vec`; transfers exclusive access only. (Asserted: `entry_state_buffers_are_stable_under_ownership_move`.) |
| `fuse_native.rs` | `FUSE_DEV_IOC_BACKING_OPEN`/`CLOSE` ioctls | `self.fd` is a live `/dev/fuse` fd; the map is `repr(C)` POD; the request number is transcribed from the running kernel and unit-tested. |
| `fuse_native.rs` | `socketpair`/`recvmsg`/`dup`/`read`/`write`/`close`/`poll` | Each operates on owned fds and owned, correctly-sized buffers; no pointer is retained. |
| `fuse_native.rs` | `geteuid`/`getegid`, `sched_setaffinity` | Pure queries / a fully-owned, correctly-sized CPU mask that the kernel does not retain. |
| `uring.rs` | `register_buffers(&iov)`, `push(&entry)`, `buf.as_ptr().add(done)` | The iovecs point at page-aligned pool-owned buffers for the registration lifetime; the entry's buffers outlive the CQE; `done ≤ len`. |

See `evidence/security/unsafe-audit.json` for the machine-generated list with each
site's invariant text and covering test.

### 4.1 Native-FUSE fuzzing and sanitizers (Phase 28)

**Fuzzer.** `tests/native_fuse_fuzz.rs` is a deterministic, seeded, bounded
in-container mutation fuzzer for the native transport: it starts from valid
encodings and applies bit flips, byte overwrites, truncation, splicing, extreme
length words, and zero runs (plus fully random strings), asserting no panic, no
out-of-bounds/UB, no unbounded allocation, and field-preservation on every
accepted input. Targets and iteration counts (seed `0x0F35_28FF_7E5E_0001`):
`FuseInHeader` decode 40 000; `FuseUringReqHeader`/`RingRequest` decode 40 000;
80-byte SQE command area 20 000; reply encode 10 000 — **110 000 iterations, 0
panics** (`evidence/security/native-fuse-fuzz.json`). A hostile ring entry with
an out-of-range `nodeid`/`offset`/`payload_sz` or a bogus `commit_id`/`flags` is
decoded without panic; the payload-size clamp and reply clamp (§3.13) are the
consumers' half of that contract and are unit-tested.

`cargo fuzz`/libFuzzer is **not run**: it and Miri both require a nightly
toolchain, and this project is pinned to stable `1.99.0` and builds offline; Miri
additionally cannot execute the mount/`io_uring`/ioctl syscalls this code uses.

**Sanitizer.** `valgrind --tool=memcheck` (3.19.0, now installed in the build
image) runs over the native-path binaries — `buffers`/`fuse_uring`/`fuse_native`
unit tests and the fuzzer — with `--error-exitcode=1 --leak-check=full
--errors-for-leak-kinds=definite`: **0 errors, 0 definitely/indirectly lost** in
every target (`scripts/container-valgrind.sh`;
`evidence/security/valgrind.json`). AddressSanitizer and ThreadSanitizer are
**not** run for the same nightly reason, and Miri is inapplicable; this is stated
as a limitation, not a pass. Valgrind instruments the process's own accesses but
does not model the kernel copying out of the registered ring buffers — that side
is covered by the layout/clamp assertions above.

---

## 5. Sandbox and privilege notes

* All development, testing, fuzzing, and benchmarks run **inside the pinned
  container**, never on the host (`scripts/lib.sh`). Containers are unprivileged:
  `--cap-drop=ALL`, `--security-opt=no-new-privileges`, memory/pid capped.
* The FUSE mount tests are the only ones that add `--device /dev/fuse`,
  `--cap-add SYS_ADMIN`, and unconfined AppArmor/seccomp; they are confined to
  `scripts/container-fuse-test.sh` and `scripts/container-uring-test.sh`.
* `io_uring_setup` is blocked by the default Docker seccomp profile on this host;
  the uring tests prove the block at run time and only then relax seccomp
  (`scripts/uring-probe.c`).
* Containerized tooling is **not** kernel isolation: FUSE and `io_uring` run
  against the host kernel. See `docs/LIMITATIONS.md`.
* Because OrFS retains history, the **backing directory should be protected more
  strictly than the mount** (§2). The mount can be shared with ordinary users;
  the backing store should not.

---

## 6. Phase 11 vulnerability log

### Found and fixed

1. **Unvalidated names in committed directory records** — `DentryAddPayload`,
   `DentryRemovePayload`, and `DentryRenamePayload::decode` did not validate the
   name. A correctly-framed but hostile committed record could inject `..`, `/`,
   a NUL, an empty name, or a >255-byte name into the live namespace (path
   traversal / index corruption). **Fixed**: the decoders call `validate_name`;
   recovery refuses such a record (`committed_record_with_a_traversal_name_is_refused_on_recovery`).
2. **Unbounded snapshot names** — `SnapshotRootPayload::decode` and
   `publish_snapshot` accepted arbitrary names (NUL/long/empty). **Fixed** with
   `validate_name`.
3. **Unvalidated xattr names/values in committed records** — `XattrSetPayload` /
   `XattrRemovePayload::decode` did not enforce the encoder's bounds: a
   NUL-bearing name would corrupt the NUL-separated `listxattr` buffer, and an
   over-large value bypassed `XATTR_VALUE_MAX`. **Fixed**; `validate_xattr_name`
   now also rejects NUL.
4. **Unbounded symlink targets** — `SymlinkCreatePayload::decode` accepted a
   target up to the 64 MiB payload limit. **Fixed** with a `PATH_MAX` bound.
5. **Unbounded allocation from a tiny hostile trigram payload** —
   `TrigramIndex::decode` did `Vec::with_capacity(n)` with `n` an untrusted
   `u32` checked only against an attacker-controlled `logical_size`, allowing a
   multi-gigabyte allocation from a few input bytes. **Fixed**: `n` is bounded by
   the remaining input bytes before allocation.
6. **Untrusted-count `with_capacity` in the concealed `HEAD` decoders** —
   tightened to bound the count by the remaining input, not just an absolute cap.
7. **Uncontrolled recursion / symlink following in the concealer** —
   `manifestation::dir_bytes` recursed over the backing tree following symlinks
   (symlink-loop / deep-tree stack exhaustion, and a link out of the directory).
   **Fixed**: iterative, symlink-safe, visited-set bounded.
8. **Uncontrolled recursion over a hostile logical directory graph** —
   `query::collect_dir` recursed over the committed namespace; a committed cycle
   could exhaust the stack. **Fixed**: iterative with a visited set.
9. **Missing xattr read-permission check** — FUSE `getxattr`/`listxattr`
   returned attribute data without a permission check. **Fixed**: both require
   read permission (`0o4`).
10. **Debug-mode overflow in `DataExtentPayload::decode`** — folding the trailing
    CRC length into an untrusted data length could overflow (panic in a debug
    build). **Fixed** with `checked_add`.
11. **Cross-volume historical references** — a `(uuid, root)` reference was not
    checked against the backing volume's uuid. **Fixed**:
    `Snapshot::open_historical` / `open_dir_historical` refuse a foreign uuid.
12. **Committed-root coverage** — `Log::open` now refuses a committed root that
    extends beyond the canonical bytes that physically exist (a defensive
    invariant against a root dangling past present segments).
13. **Native F2 reply over-claimed the registered buffer (Phase 28).**
    `fuse_native::write_reply` copied the reply body into the entry's registered
    payload buffer with `payload[..data.len()]` and wrote `data.len()` as the
    kernel-visible `ring_ent_in_out.payload_sz`, without capping it at the buffer
    length (`PAYLOAD_BUF`, 256 KiB). A FUSE request whose `read`/`readdir` `size`
    field is out of range (a hostile or buggy client) makes the dispatcher return
    a body larger than the buffer, so the session thread **panicked** (index out
    of bounds — a denial of service on the native mount) and, absent the panic,
    would have told the kernel to copy past the registered buffer. **Fixed**: the
    body is clamped to the buffer length before staging, and the request-side
    `payload_sz` clamp is now a single tested function (`clamp_payload_sz`).
    Regression tests: `reply_larger_than_the_registered_buffer_is_clamped_not_panicking`,
    `payload_size_is_clamped_to_the_registered_buffer`. The classical F0/F1 path
    was unaffected (`fuser` bounds the reply itself).

### Left open, with reasons

* **Suffix-segment loss.** If the *trailing* committed segment files are
  physically removed (outside OrFS), recovery reconstructs the most recent
  **surviving** complete boundary — a strictly earlier, but still *valid*,
  committed root. OrFS never fabricates or reuses bytes, so no *invalid* state is
  produced, but the lost transactions are gone and the reduction is not
  accompanied by an error. Detecting it would require a durable
  physical-end/segment-count watermark updated on every commit; that is a
  deliberate design and performance decision, documented in `docs/RECOVERY.md`
  and `docs/LIMITATIONS.md`. Interior gaps and sequence breaks **are** refused.
* **Logical deletion is not secure erasure** — intrinsic to I1 (§2).
* **`RootPins` uses `std::sync::Mutex`**; a panic while the lock is held poisons
  it, and the code recovers via `into_inner`. This is safe because the guarded
  operations are trivial counter updates that panic only on allocation failure;
  it is noted for completeness.
* **Power-loss durability** is not modelled by the process-crash courts
  (`docs/TRANSACTIONS.md`); it remains an open proof obligation.

---

## 7. Evidence

| File | Contents |
|---|---|
| `evidence/security/unsafe-audit.json` | Every `unsafe` site (schema v2) + whether it has a `SAFETY:` invariant, that invariant's text, and a covering test where one exists |
| `evidence/security/hostile-input-results.json` | Real outcomes of a fixed hostile corpus against every decoder |
| `evidence/security/fuzz-decode.json` | Fuzzing method, seed, per-surface iteration counts, panics = 0 |
| `evidence/security/native-fuse-fuzz.json` | Native-FUSE fuzzer: seed, per-surface iteration counts (110 000), panics = 0 |
| `evidence/security/valgrind.json` (+ `valgrind-logs/`) | valgrind memcheck over the native-path unit/fuzz binaries: 0 errors, 0 definitely lost; ASan/Miri/TSan unavailability |
| `evidence/security/concurrency-stress.json` | Concurrency workloads and the invariants checked; the Loom decision |
| `evidence/recovery/segment-rollover.json` | A real mid-flight rollover |
| `evidence/recovery/commit-interruption.json`, `torn-write.json` | Process-crash fault-injection results |

Tests: `tests/hostile_files.rs` (hostile-input court + unsafe audit),
`tests/fuzz_decode.rs` (bounded mutation fuzzer), `tests/native_fuse_fuzz.rs`
(native-FUSE fuzzer), `tests/concurrency_stress.rs` (concurrency court),
`tests/recovery_adversarial.rs` (recovery/adversarial court). See
`docs/PROGRESS.md` for the exact passing counts.
