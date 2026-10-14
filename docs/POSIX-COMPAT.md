# OrFS POSIX / FUSE compatibility matrix (Phase 79)

This is the **explicit compatibility contract** for OrFS: for the whole
POSIX/FUSE surface it states, row by row, whether the operation is
**supported** as POSIX requires, a **deliberate deviation** (with the reason),
or **unsupported / refused** (with the exact typed error), plus the OrFS-specific
semantics that differ from POSIX **by design** — and, for each row, the **test or
receipt that proves the claim**.

It exists so a reviewer never has to infer compatibility from silence. Where the
standard POSIX court (`pjdfstest`) fails an assertion, that failure is
reconciled here so that **zero deviations are unclassified** (§6).

Everything numeric below comes from a machine-generated receipt under
`evidence/`; the commands that regenerate them are listed in §7 and indexed in
`docs/REPRODUCE.md`.

## 1. How to read this matrix

| Status | Meaning |
|---|---|
| **Supported** | OrFS behaves as POSIX/Linux requires for this operation under OrFS's documented model. |
| **Deviation** | A deliberate, documented difference from POSIX/Linux; the reason and the reference are given. |
| **Refused** | The operation (or a flag/argument form of it) is not representable and is rejected with a **typed error** — never a wrong success. |
| **By design** | OrFS-specific semantics that differ from POSIX because the filesystem *is* append-only / concealed-expansion, not because of a POSIX gap. |

The behavioural authority is `docs/FUSE-SEMANTICS.md` (§5, §6, §8, §9); the
residual honest limits are `docs/LIMITATIONS.md`; the namespace model is
`docs/NAMESPACE.md`.

## 2. Supported as POSIX requires

All of these are exercised **through a real FUSE mount** by
`tests/fuse_integration.rs` (receipt `evidence/correctness/posix-results.json`,
26/26 operations) and by the mounted model court; the standard suite
(`pjdfstest`) additionally drives them (receipt `evidence/correctness/pjdfstest.json`).

| Operation | Behaviour | Proof |
|---|---|---|
| `create` / `open` / `release` | Atomic create+open of a regular file; access-mode permission enforced and `O_TRUNC` honoured; a file handle is allocated and freed. | `fuse_integration` `create_write_read`; `posix-results.json` |
| `read` / `pread` / `readv` | Resolves logical extents, clamped to EOF; returns the committed bytes. | `fuse_integration` `create_write_read`, `pwrite` |
| `write` / `pwrite` / `pwritev` / append | Appends an immutable `DATA_EXTENT`; `O_APPEND` uses the authoritative EOF; advances `mtime`/`ctime` in the same transaction. | `fuse_integration` `append_and_seek`, `pwrite`, `append_pwrite` |
| `truncate` / `ftruncate` | Appends a `FILE_RESIZE` (grow zero-fills, shrink drops the tail); explicit size change needs write permission unless the request already carries a writable handle. | `fuse_integration` `truncate`; `pjdfstest` (Phase 25 closed `fd_truncate_permission`) |
| `fsync` / `fdatasync` / `fsyncdir` | The durability barrier: both call the engine's `sync()`. `fdatasync` is delivered as `fsync` and served by the same (stronger) `sync()`. | `tests/posix_extras.rs` `durability`; `fuse_integration` `fsync`, `fdatasync` |
| `mkdir` / `rmdir` | `rmdir` rejects a non-empty directory with `ENOTEMPTY` and enforces the sticky-bit rule. | `fuse_integration` `mkdir_readdir`, `rmdir_nonempty`; `pjdfstest` |
| `readdir` / `readdirplus` | Snapshot iteration; `readdirplus` looks up each child's current attributes with correct lookup accounting. | `fuse_integration` `mkdir_readdir` |
| `rename` (`RENAME_NOREPLACE`, `RENAME_EXCHANGE`) | One atomic transaction; flags map to `Ordinary`/`NoReplace`/`Exchange`; both containing directories' times advance. | `fuse_integration` `rename`; `pjdfstest` `rename_*` |
| `link` (hard link) | Adds a name, raises `nlink`; removal decrements while the inode and bytes are retained. | `posix_extras.rs` hard links; `fuse_integration` `hardlink` |
| `symlink` / `readlink` | Stores the target immutably; `readlink` returns the authoritative target bytes. | `fuse_integration` `symlink`; `posix_extras.rs` |
| `unlink` | Logical removal; sticky-bit rules enforced; an open handle keeps reading the inode's committed bytes. | `fuse_integration` `unlink_while_open`; `tests/concurrency_stress.rs` `open_file_during_unlink_keeps_reading_historical_bytes` |
| `stat` / `lstat` / `fstat` | Returns the version-consistent `InodeStat`, including the true `nlink` (0 for an unlinked-but-open file). | `fuse_integration` `create_write_read`, `perm_mode`, `chown`; `pjdfstest` |
| `chmod` / `chown` / `fchown` / `lchown` | Owner-or-root for mode/owner; `gid` change follows the Linux `chgrp(2)` rule (effective or supplementary group); the grouped rule is applied to every permission decision. | `fuse_integration` `chown`, `perm_mode`; `posix_extras.rs` supplementary groups |
| `utimens` / `utimensat` / `futimens` | Explicit values (including `UTIME_NOW`/`UTIME_OMIT`) applied verbatim; `UTIME_NOW` for a non-owner needs only write permission. | `fuse_integration` `utimens`, `utimens_now_omit`; `pjdfstest` `utimensat_*` |
| `access` | Full owner/group/other class check; root bypasses read/write. | `docs/FUSE-SEMANTICS.md` §5; `posix_extras.rs` |
| xattr (`setxattr`/`getxattr`/`listxattr`/`removexattr`) | See §3 for the two documented deviations; the core semantics (`size == 0` returns the length, a too-small buffer returns `ERANGE`, an absent attribute returns `ENODATA`, `XATTR_CREATE`/`XATTR_REPLACE`) are POSIX. | `fuse_integration` `xattr`; `posix_extras.rs` xattrs |
| `lseek` `SEEK_DATA`/`SEEK_HOLE` | Byte-granular against the logical extent map; beyond EOF → `ENXIO`; `SEEK_SET/CUR/END` are handled by the kernel. | `fuse_integration` `seek_data_hole` |
| `fallocate` (extend, `PUNCH_HOLE`, `ZERO_RANGE`) | Byte-granular zeroing; see §4 for the refused flag forms. | `fuse_integration` `fallocate` |
| `copy_file_range` | Copies through logical extents; see §3/§4 for the 1 MiB bound and flag refusal. | `fuse_integration` `copy_file_range` |
| `mmap` (read-only, and `MAP_SHARED`+`PROT_WRITE`) | Serviced by the kernel page cache in write-through mode; a dirtied page returns as an ordinary `FUSE_WRITE` and becomes an authoritative extent. Under `--direct-io` a shared-writable mapping is refused by the kernel with `ENODEV` (normal for direct-I/O FUSE). | `fuse_integration` `mmap_readonly`, `mmap_shared_write`; `docs/FUSE-SEMANTICS.md` §8.2 |
| `statfs` | `physical-safe` (default) reports the backing filesystem's real capacity; `plenum` reports the conceptual visible void. | `fuse_integration` `statfs`; `docs/FUSE-SEMANTICS.md` §5 |

## 3. Deliberate deviations

Each row is a documented, tested difference from POSIX/Linux. None of them ever
returns a **wrong success**.

| Surface | Deviation | Reason / reference | Proof |
|---|---|---|---|
| Implicit timestamps | A namespace mutation advances the containing directory's `mtime`/`ctime`, and a content mutation the file's, **as an appended `INODE_SETATTR` record in the same transaction** (never an in-place edit). | Linux/ext4 behaviour, realised append-only: `docs/FUSE-SEMANTICS.md` §5.1 | `pjdfstest` `*_timestamp` (closed in Phase 25) |
| `setuid`/`setgid` on non-owner write/truncate | The daemon clears `S_ISUID`/`S_ISGID` itself (the kernel's mode-clearing `SETATTR` is suppressed via `FUSE_HANDLE_KILLPRIV(_V2)`) in the **same** transaction. | Linux `killpriv`: `docs/FUSE-SEMANTICS.md` §5.2 | `pjdfstest` `chmod_12` (closed Phase 25) |
| xattr access rule | One **uniform** rule independent of namespace: read needs read permission, set/remove needs write permission. No special privilege for `security.*`/`trusted.*`/`system.*`, no `CAP_SYS_ADMIN`/`CAP_FOWNER` override. | A self-describing append-only store with no privileged-namespace concept: `docs/LIMITATIONS.md` §8 | `tests/posix_extras.rs` xattrs (uniform-rule checks) |
| `setxattr` position | `position != 0` → `EINVAL`. | Attributes are whole values, not positional ranges | `tests/posix_extras.rs` |
| `copy_file_range` | Bounded to **1 MiB per call** (a partial copy is allowed and reported); non-zero `flags` → `EINVAL`. | Bounded per-call work keeps the authoritative transaction size predictable | `fuse_integration` `copy_file_range` |
| `flush` | **Not** a durability barrier — returns `ok` because nothing is buffered. | Every mutating reply is already durable before ack (per `DurabilityMode`): `docs/FUSE-SEMANTICS.md` §8.1 | `tests/posix_extras.rs` `durability` |
| Supplementary groups | Read once per decision from `/proc/<pid>/status` `Groups:`; an unreadable entry classifies by effective ids alone. This can **over-deny** but never over-grant. | A FUSE request carries only fsuid/fsgid: `docs/LIMITATIONS.md` §13 | `posix_extras.rs`; `docs/FUSE-SEMANTICS.md` §6.1 |
| `default_permissions` | **Off** by default (enforced in the daemon) so semantics are identical across transports; exposed for compatibility testing. | `docs/FUSE-SEMANTICS.md` §6 | `docs/FUSE-SEMANTICS.md` §6; mount option tests |
| Writeback cache | **Not** negotiated; the mount is write-through with short TTLs. | The kernel's write coalescing would break the per-operation authoritative transaction model and the durability ack contract: `docs/FUSE-SEMANTICS.md` §8 | `docs/FUSE-SEMANTICS.md` §8; `posix-results.json` `cache_profile` |
| Timestamp granularity | 1 ns granularity fields. | Superset of POSIX `st_*tim`; no reduction | `docs/NAMESPACE.md` §2 |

## 4. Unsupported / refused (typed errors)

Every refusal is a **typed** error; the exact errno is fixed by the error model
(`src/error.rs`, `OrfsError::errno()`).

| Surface | Refused form | Typed error | Why | Proof |
|---|---|---|---|---|
| `mknod` / `mkfifo` / device/bind nodes | `S_IFIFO`, `S_IFCHR`, `S_IFBLK`, `S_IFSOCK` | **`EOPNOTSUPP`** | OrFS represents only regular files, directories and symlinks (`docs/FUSE-SEMANTICS.md` §5) | `pjdfstest` mechanical class; `posix-results.json` |
| `rename` | `RENAME_WHITEOUT` | **`EOPNOTSUPP`** | No whiteout concept; the source name is moved, never masked | `src/fuse.rs` `rename`; `docs/FUSE-SEMANTICS.md` §5 |
| `rename` | combined/unknown flag bits | **`EINVAL`** | Flags are mapped to exactly one of `Ordinary`/`NoReplace`/`Exchange` | `src/fuse.rs` `rename` |
| `fallocate` | `COLLAPSE_RANGE`, `INSERT_RANGE`, `UNSHARE_RANGE` | **`EOPNOTSUPP`** | Not representable without rewriting committed history | `src/fuse.rs` `fallocate`; `docs/FUSE-SEMANTICS.md` §5 |
| `fallocate` | `PUNCH_HOLE` without `KEEP_SIZE` | **`EINVAL`** | Linux requires the pair | `src/fuse.rs` `fallocate` |
| `getlk` / `setlk` (POSIX record locks) | any request | **`ENOSYS`** → kernel local lock manager | `FUSE_POSIX_LOCKS` is not negotiated; correct and complete for a single-node mount (`docs/FUSE-SEMANTICS.md` §9) | `docs/FUSE-SEMANTICS.md` §9; `posix-results.json` |
| `flock` (BSD locks) | any request | **`ENOSYS`** → kernel local lock manager | `FUSE_FLOCK_LOCKS` is not negotiated, same reason | `docs/FUSE-SEMANTICS.md` §9 |
| lookup | a component longer than `NAME_MAX` (255) | **`ENAMETOOLONG`** | POSIX name bound | `pjdfstest` (Phase 24 fix); `docs/FUSE-SEMANTICS.md` §5 |
| read-only mount (`--read-only`) | any mutation | **`EROFS`** | Explicit read-only mount | `src/fuse.rs` `ensure_writable` |

**Delegated to the kernel, not refused by OrFS.** POSIX record locks and `flock`
are intentional delegations (the daemon's `ENOSYS` tells the kernel to service
them with its own local lock manager). `mmap` and `SEEK_SET/CUR/END` are likewise
serviced by the kernel VFS. These are listed here so they are never mistaken for
silent gaps.

## 5. OrFS-specific semantics that differ from POSIX **by design**

| Semantics | Difference from POSIX | Reason / reference | Proof |
|---|---|---|---|
| **Non-withdrawal** | `unlink`, `rmdir`, truncate and rename-over change only the *visible* namespace; the committed bytes remain in the authoritative log. Logical deletion is **not** secure erasure. | The design law `L_{n+1} = L_n ⊕ Δ_n`; `docs/LIMITATIONS.md` §5, `docs/SECURITY.md` §2 | `tests/log_model.rs`; gate A (`docs/GATES.md`); `docs/LIMITATIONS.md` §5 |
| Open file survives `unlink` | An unlinked-but-open file reports `nlink 0` and keeps serving its committed bytes. | Open-handle semantics on an append-only inode (a POSIX requirement realised through the log) | `concurrency_stress.rs` `open_file_during_unlink_keeps_reading_historical_bytes`; `fuse_integration` `unlink_while_open` |
| Real historical snapshots | A pinned committed root reads the state *as of* that commit and never a later write. | Concealed expansion over an append-only log; not a POSIX surface | `tests/snapshot_model.rs`, `tests/snapshot_fuse.rs`; gate G |
| Manifested reads | Derived concealed structures accelerate reads but can never change the visible bytes. | EKBLOOM is exactness-preserving; `docs/EKBLOOM-INTEGRATION.md` | `tests/ekbloom_read.rs`; gate I |
| Capacity / ENOSPC | The backing is finite and fills monotonically; at the reserve, writes are refused (`ENOSPC`) and the volume latches read-only rather than withdrawing history. | Non-withdrawal cannot reclaim authoritative bytes; `docs/LIMITATIONS.md` §11, `docs/CAPACITY.md` | `tests/capacity_guard.rs`, `tests/fault_enospc.rs`; gate J |
| Bounded reclaim | `orfs reclaim` frees **derived** bytes only; permanent authority is never reclaimed. | `docs/LIMITATIONS.md` §17 | `tests/bounded_recovery.rs`; `evidence/performance/bounded-recovery.json` |
| Tier relocation | Sealed segments move to a cold tier without withdrawing authority. | `docs/TIERING.md`, `docs/LIMITATIONS.md` §16 | `tests/tier_relocation.rs` |

## 6. Reconciliation with the standard POSIX court (zero unclassified)

`scripts/posix/pjdfstest.sh` runs the pinned `pjdfstest` suite against a **mounted
OrFS volume** *and* a reference ext4 directory, then classifies every OrFS-failing
assertion. The classification (`evidence/correctness/pjdfstest.json`
`deviations`) is exhaustive:

* **Mechanical special-node rule.** Every assertion that fails because the test
  builds a FIFO/block/char/socket node — which OrFS rejects with `EOPNOTSUPP`
  (§4, row 1) — is classified as one of `unsupported_node_type` (682),
  `unsupported_errno` (32) or `unsupported_node_downstream` (3 062). Together
  these mechanically explain **3 776** assertions.
* **Deliberate deviations.** `deviations.documented_deviations` is **empty**: no
  assertion needs a hand-curated exception beyond the special-node rule.
* **Shared with the reference.** Exactly **1** assertion (`unlink_08.t` #2) is
  failed by the reference ext4 run too, so it is an environment/suite artefact,
  not an OrFS deviation. It is the sole entry in
  `scripts/posix/pjdfstest-expected.tsv`.
* **Unclassified: 0.** `deviations.unclassified` is empty and the gate fields
  `gate.unclassified_failures` and `gate.stale_allowlist_entries` are both `0`.

**Therefore every pjdfstest deviation is explained — either by the mechanical
special-node rule or by an explicitly listed exception — and there are 0
unclassified failures.** The suite result is `pass`.

The same classification is asserted mechanically by the runner (it fails on any
unclassified failure or any allowlisted assertion that stops failing), so the
"zero unclassified" claim cannot drift silently.

The overall court figures: **238** test files, **8 798** assertions; OrFS fails
**46** files / **3 777** assertions, the reference ext4 fails **2** files / **28**
assertions.

`xfstests` is **assessed, not runnable** here; `evidence/correctness/xfstests.json`
records `ran: false` with the exact attempted commands and blockers (it is not
counted as a passing gate). Native Rust equivalents of `fsx`, `fsstress` and
`fs_mark`, plus rename/link/unlink race storms and a mounted transport arm, are
in `tests/adversarial_concurrency.rs` and reported in
`evidence/correctness/adversarial-concurrency.json`; each is labelled an
*equivalent*, never a run of the real tool (`docs/LIMITATIONS.md` §18). In that
receipt the `fsx` arm reports **0** byte mismatches, the `fsstress` arm **0**
mismatches with **0** orphans and **0** duplicate inodes, and the mounted arm
**0** mismatches with **0** torn reads.

## 7. Verification

Every claim above is regenerated by a command; nothing runs on the host
(`scripts/lib.sh`, Docker-only).

| Claim | Command | Receipt |
|---|---|---|
| The whole POSIX surface + pjdfstest reconciliation | `sh scripts/container-posix-test.sh` | `evidence/correctness/pjdfstest.json`, `evidence/correctness/posix-results.json` |
| POSIX-extras primitives (xattrs, symlinks, hard links, groups, durability) | `sh -c '. scripts/lib.sh && docker_run cargo test -p orfs --test posix_extras'` | `evidence/correctness/posix-extras.json` |
| Mounted POSIX conformance (26 operations) | `sh scripts/container-fuse-test.sh` | `evidence/correctness/posix-results.json` |
| Sustained adversarial concurrency + the mounted transport arm | `sh scripts/container-adversarial-concurrency.sh` | `evidence/correctness/adversarial-concurrency.json` |
| xfstests assessment (`ran:false`) | `sh scripts/container-posix-test.sh` | `evidence/correctness/xfstests.json` |

The `docs`↔`receipt` numbers in this document are checked by
`sh scripts/check-docs-receipts.sh` (see `docs/RECEIPTS.md`).
