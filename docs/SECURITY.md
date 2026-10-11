# OrFS — Security Model, Hardening, and Unsafe Audit (Phase 11)

This document is normative for Phase 11 (research directive §28 *filesystem
security*, §29 *non-withdrawal privacy implications*, §34 *fault injection*).
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
| **Unprivileged local user** | Mounts the filesystem (possibly with `default_permissions`) and issues ordinary POSIX operations. | `src/fuse.rs` permission helpers, `src/inode.rs::has_permission` |
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

* `inode::has_permission` implements the class-based POSIX rule (owner / group /
  other, with the superuser bypass).
* **Every** mutating FUSE handler checks permission before acting
  (`check_create`, `check_dir_write`, per-inode `0o2` for writes and xattrs).
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

---

## 4. `unsafe`-block audit

Every `unsafe` site in the crate, its purpose, and its written invariant. This
table is regenerated from the source at test time
(`hostile_files::every_unsafe_block_has_a_written_safety_invariant`) and written
to `evidence/security/unsafe-audit.json`, which asserts that **all 21 sites carry
a `SAFETY:` comment**. Focused tests exercise the safe wrappers
(`tests/uring_integration.rs`, `tests/fuse_uring.rs`, `tests/log_model.rs`).

| File:line | Site | Safety invariant |
|---|---|---|
| `buffers.rs:77` | `unsafe impl Send for AlignedBuffer` | The buffer owns its allocation outright; transferring ownership to another thread transfers no aliasing. |
| `buffers.rs:87` | `alloc_zeroed(layout)` | `len > 0` so the layout is non-zero; the pointer is checked for null and is owned until `dealloc` with the same layout. |
| `buffers.rs:108`/`:114` | `slice::from_raw_parts(_mut)` | `ptr` is valid for `len` bytes for the buffer's lifetime; `&mut self` proves exclusivity for the mutable form. |
| `buffers.rs:127` | `dealloc(ptr, layout)` | `ptr`/`layout` came from `alloc_zeroed` with exactly this layout. |
| `buffers.rs:155` | `unsafe impl Send for BufferPool` | The pool owns every buffer outright; the `iovec` fields are raw pointers into those owned buffers. |
| `capabilities.rs:55`/`:56` | `zeroed()` + `uname` | `uname` is a pure query filling a caller-owned struct. |
| `stats.rs:134`/`:135`, `fuse.rs:1830`/`:1831` | `zeroed()` + `statvfs` | `c` is a valid NUL-terminated path and `st` a valid aligned caller-owned struct. |
| `fuse.rs:2049` | signal handler body | Performs a single atomic store and returns (async-signal-safe). |
| `fuse.rs:2174` | `umount2(..., MNT_DETACH)` | `c` is a valid NUL-terminated path; lazy detach cannot block on the caller. |
| `fuse_uring.rs:865`/`:1025` | `submission().push(&entry)` | The SQE references only the request's encoded bytes, copied into the submission queue. |
| `uring.rs:437` | `register_buffers(&iov)` | The iovecs point at page-aligned buffers owned by the pool for the registration lifetime. |
| `uring.rs:586`/`:633` | `buf.as_mut_ptr().add(job.done)` | The buffer is a caller-owned `&[mut] [u8]` that outlives the completion; `done ≤ len`. |
| `uring.rs:764`/`:912` | `sq.push(&entry)` | The caller guarantees every buffer referenced by the entry stays alive until the CQE. |

See `evidence/security/unsafe-audit.json` for the machine-generated list.

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
| `evidence/security/unsafe-audit.json` | Every `unsafe` site + whether it has a `SAFETY:` invariant |
| `evidence/security/hostile-input-results.json` | Real outcomes of a fixed hostile corpus against every decoder |
| `evidence/security/fuzz-decode.json` | Fuzzing method, seed, per-surface iteration counts, panics = 0 |
| `evidence/security/concurrency-stress.json` | Concurrency workloads and the invariants checked; the Loom decision |
| `evidence/recovery/segment-rollover.json` | A real mid-flight rollover |
| `evidence/recovery/commit-interruption.json`, `torn-write.json` | Process-crash fault-injection results |

Tests: `tests/hostile_files.rs` (hostile-input court + unsafe audit),
`tests/fuzz_decode.rs` (bounded mutation fuzzer), `tests/concurrency_stress.rs`
(concurrency court), `tests/recovery_adversarial.rs` (recovery/adversarial
court). See `docs/PROGRESS.md` for the exact passing counts.
