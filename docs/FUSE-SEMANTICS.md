# OrFS FUSE Semantics (Phase 4)

This document is the normative operation-by-operation description of the
traditional `/dev/fuse` transport (`src/fuse.rs`). It records what each FUSE
operation does, how open handles and lookup references are accounted, how
directory iteration behaves, which cache profile is in force, and exactly which
capabilities are honoured — and which are deliberately declined.

The transport is Plane D. Filesystem semantics live in the transport-neutral
`OrfsCore` (`src/namespace.rs`); a change to the transport must never change
filesystem semantics.

---

## 1. Mount model

`orfs mount <backing> <mnt> --transport fuse ...` opens the backing volume and
serves it through `fuser` 0.18's typed API. The daemon runs one request thread
(`n_threads = 1`), so all operations are serialized through the engine's single
commit sequencer. Read and write callbacks take `&self`; the engine is held
behind one `parking_lot::Mutex`, which is safe because the sequencer already
serializes mutations.

Mount options map explicitly:

| OrFS option | FUSE effect |
|---|---|
| transport `fuse` | traditional `/dev/fuse` (F0/F1) |
| transport `fuse-uring` | requests F2 (FUSE-over-`io_uring`); negotiates at runtime, falls back to F1/F0 (Phase 10, `docs/FUSE_URING.md`) |
| `--backing-io sync` | synchronous `pread`/`pwrite`/`fsync` |
| `--backing-io uring` | selects the `io_uring` backing engine; falls back to sync **only** if the kernel rejects io_uring (the outcome is reported, never silent) |
| `--durability sync\|ordered\|batched` | maps to `DurabilityMode` |
| `--direct-io` | sets `FOPEN_DIRECT_IO` on every open |
| `--readahead-kb N` | kernel `max_readahead` (0 keeps the kernel default) |
| `--max-write-kb N` | kernel `max_write` |
| `--attr-ttl-ms`, `--entry-ttl-ms` | attribute / entry cache TTLs |
| `--default-permissions` | adds `default_permissions` (see §6) |
| `--allow-other` | `allow_other` ACL |
| `--auto-unmount` | `auto_unmount` (implies a non-owner ACL) |
| `--read-only` | `ro` |
| `--statfs physical-safe\|plenum` | capacity accounting mode |

`orfs unmount <mnt>` prefers the setuid `fusermount3` helper, then `fusermount`,
then a direct `umount2(MNT_DETACH)` (needs `CAP_SYS_ADMIN`).

---

## 2. Identity: inodes vs. handles

Two distinct identities are maintained, as required by research §15/§26.1:

* **Inode identity** is the engine's stable id (`1` is the root; ids are never
  reused). It is what `getattr` reports and what survives unlink.
* **Open-handle identity** is a private 64-bit id allocated by the transport for
  one open file description. It is *not* an inode number and is never
  reported to userspace. Each `open`/`create` allocates one; `release` frees it.

Consequences:

* `unlink` removes a *name*. The inode and its historical records remain, so
  every already-open handle keeps reading and writing correctly. A fresh
  `open` by path fails with `ENOENT`.
* A handle records the flags it was opened with (used for `O_APPEND`).
* `release` frees only the handle; it does **not** decrement lookup references —
  that is `forget`'s job.

---

## 3. Lookup accounting

FUSE has a separate reference count for how many times the kernel learned about
an inode. OrFS increments its table whenever it returns an inode to the kernel:

* `lookup` (including the synthetic `.` and `..`),
* `create`, `mknod`, `mkdir`, `symlink`, `link`,
* every entry returned by `readdirplus`.
* `getattr` does **not** take a reference.

`forget(ino, n)` decrements by `n` and removes the entry at zero. Because OrFS
inode ids are stable, exhausted references never imply the inode may be freed
or its id recycled — the table is accounting, not a lifetime mechanism. The
table is exposed for tests via `OrfsFuse::outstanding_lookups` (unit-tested in
`src/fuse.rs`).

`readdirplus` is negotiated (`FUSE_DO_READDIRPLUS` | `FUSE_READDIRPLUS_AUTO`).

---

## 4. Directory iteration: cookies and mutation consistency

`opendir` captures an immutable snapshot of the directory — `.`, `..`, then the
visible children in name order — and stores it in the directory handle.
`readdir`/`readdirplus` return entries from that snapshot using the cookie
convention *"entry `i` is returned with cookie `i + 1`"*, which is the index of
the next entry. Iteration is therefore resumable and O(1) per resume.

**Mutation-consistency policy (normative):** a directory stream observes the
directory as of `opendir`. Mutations performed while the stream is open are not
reflected until the directory is reopened. This is the strongest guarantee
achievable without per-directory versioning and makes partial listings
resumable; it is the documented iteration model referenced by research §15.
`readdirplus` looks up each child's current attributes at reply time (inode ids
are stable, so an unlinked child still resolves).

---

## 5. Operation semantics

| Operation | OrFS semantics |
|---|---|
| `init` | Negotiates only honoured capabilities (see §7). Sets `max_write`, `max_readahead`, 1 ns time granularity. |
| `destroy` | Best-effort `sync()` of the authoritative log. |
| `lookup` | Resolves `.`/`..`/`name` in the live root; requires execute permission on the parent. A component longer than `NAME_MAX` (255) returns `ENAMETOOLONG`. |
| `forget` | Decrements lookup accounting. |
| `getattr` | Returns the version-consistent `InodeStat`. |
| `setattr` | Applies a masked change (`mode`/`uid`/`gid`/`atime`/`mtime`/`size`). `chmod`/`utimes` require owner or root (a `utimensat(UTIME_NOW)` needs only write permission for a non-owner, per Linux `ATTR_TOUCH` §6); changing the owner (`uid`) requires root and moving the file to a *different* `gid` requires root or an owner that belongs to the target group (§6); `size` requires write permission unless the request carries an already-open writable handle. An implicit `mtime`/`ctime` advancement and any `setuid`/`setgid` clearing are committed in the same authoritative transaction (§5.1, §5.2). Replies with fresh attributes. Requests an inode invalidation. |
| `readlink` | Returns the authoritative target bytes. |
| `mknod` | Regular files and directories are created; any other node type (`S_IFIFO`/`S_IFCHR`/`S_IFBLK`/`S_IFSOCK`) returns `EOPNOTSUPP`. `umask` is already applied by the kernel (OrFS does not set `FUSE_DONT_MASK`). |
| `mkdir` | Creates a directory; replies with the entry. |
| `unlink` | Logical removal; enforces sticky-bit rules; requests an entry invalidation. |
| `rmdir` | Rejects non-empty directories (`ENOTEMPTY`); enforces the same sticky-bit rule as `unlink` (only the entry owner, the sticky directory's owner, or root may remove it, else `EPERM`). |
| `symlink` | Stores the target immutably. |
| `rename` | One atomic transaction. Flags map to `Ordinary`, `RENAME_NOREPLACE`, or `RENAME_EXCHANGE`; `RENAME_WHITEOUT` → `EOPNOTSUPP`; combined flags → `EINVAL`. |
| `link` | Hard link; adjusts `nlink`. |
| `open` | Enforces access-mode permission; honours `O_TRUNC`; allocates a file handle. |
| `read` | Enforces read permission; resolves logical extents. Clamped to EOF. |
| `write` | Enforces write permission; appends an immutable `DATA_EXTENT` and advances the file's `mtime`/`ctime` in the same transaction (§5.1). For `O_APPEND` the *authoritative* end-of-file is used as the offset. Clears `S_ISUID`/`S_ISGID` when the kernel flags the write `FUSE_WRITE_KILL_SUIDGID` (§5.2). Requests an inode invalidation. |
| `flush` | **Not** a durability barrier — returns `ok` because nothing is buffered (§8). |
| `fsync` | Durably flushes the authoritative log (`sync()`), i.e. it *is* the durability barrier. `fdatasync(2)` arrives as `fsync` with the `datasync` hint and is served by the same full `sync()` (a strictly stronger guarantee). |
| `fsyncdir` | Same durability hook as `fsync`. |
| `release` | Frees the file handle. |
| `create` | Atomically creates and opens a regular file; replies with entry + handle. |
| `opendir` | Enforces read permission; snapshots the directory. |
| `readdir` | Snapshot iteration (§4). |
| `readdirplus` | Snapshot iteration with attributes and correct lookup accounting (§3). |
| `releasedir` | Frees the directory handle. |
| `statfs` | `physical-safe` reports the backing filesystem's real capacity (`statvfs`); `plenum` reports the conceptual `U64_MAX` "visible void". Default is `physical-safe`. |
| `setxattr` | Supports create (`XATTR_CREATE`) and replace (`XATTR_REPLACE`); `position != 0` → `EINVAL`. |
| `getxattr` / `listxattr` | `size == 0` returns the length; too-small buffer returns `ERANGE`. `listxattr` additionally exposes the derived `user.orfs.*` attributes. |
| `removexattr` | Appends an authoritative removal; absent attribute → `ENODATA`. |
| `access` | Full POSIX class check (owner/group/other; root bypasses read/write). |
| `fallocate` | `mode 0` extends; `KEEP_SIZE` alone is a no-op; `PUNCH_HOLE|KEEP_SIZE` and `ZERO_RANGE` zero the range; `COLLAPSE_RANGE`/`INSERT_RANGE`/`UNSHARE_RANGE` → `EOPNOTSUPP`. |
| `lseek` | `SEEK_DATA`/`SEEK_HOLE` resolve against the logical extent map (byte granular). Beyond EOF → `ENXIO`. `SEEK_SET/CUR/END` are handled in the kernel. |
| `copy_file_range` | Copies through logical extents, bounded to 1 MiB per call (partial copy allowed). Non-zero flags → `EINVAL`. |
| `getlk`/`setlk`/`flock` | **Declined**; see §9. |

Unsupported operations never return a wrong success: they return the documented
errno (`EOPNOTSUPP`, `ENOSYS`, `EINVAL`, …).

### 5.1 Timestamps

Every inode carries `atime`/`mtime`/`ctime` (1 ns granularity). They are set at
creation and updated by an explicit `setattr` (chmod/chown/utimes).

OrFS also advances timestamps **implicitly**, the way Linux/ext4 does. Each
implicit update is itself an authoritative, append-only `INODE_SETATTR` record
committed in the *same* transaction as the mutation that caused it — never an
in-place edit — so committed history is unchanged and a snapshot pinned to an
earlier root reads exactly the timestamps that root encoded:

* a namespace mutation (`create`, `mkdir`, `symlink`, `link`, `unlink`, `rmdir`,
  `rename`) advances the containing directory's `mtime` and `ctime` (`rename`
  advances both directories when it crosses them); and
* a content mutation (`write`, `truncate`, `ftruncate`, `O_TRUNC`) advances the
  file's `mtime` and `ctime`. The access time is left untouched.

An explicit `utimensat`/`utimes`/`futimens` still takes precedence: its values
(including `UTIME_NOW` and `UTIME_OMIT`) are applied verbatim. Verified against
the reference ext4 by the pjdfstest court (§11.1).

### 5.2 `setuid`/`setgid` on non-owner write

On Linux a write by a caller without `CAP_FSETID` to a file with
`S_ISUID`/`S_ISGID` set clears those bits. OrFS negotiates
`FUSE_HANDLE_KILLPRIV` and `FUSE_HANDLE_KILLPRIV_V2` (§7), so the kernel
suppresses its mode-clearing `SETATTR` and instead flags the write with
`FUSE_WRITE_KILL_SUIDGID`. The daemon clears `S_ISUID`/`S_ISGID` in the *same*
authoritative transaction as the write. A truncate by a caller without
`CAP_FSETID` clears them too (the kernel signals this as `FATTR_KILL_SUIDGID`;
the high-level API does not surface that bit, so the daemon approximates
`CAP_FSETID` as uid 0 and clears the bits with the resize in one transaction).
Verified by pjdfstest `chmod/12.t` (§11.1).

---

## 6. Permission enforcement

OrFS enforces permissions in the daemon, not via `default_permissions`. The
checks are applied consistently at `lookup` (execute on parent),
`open`/`read`/`write` (access mode on the inode), `opendir`/`readdir` (read on
the directory), and every namespace mutation (write+execute on the parent,
sticky-bit rules for `unlink`). Root bypasses read/write and needs at least one
execute bit to execute a regular file.

Every one of these decisions uses the kernel's `in_group_p` rule: a caller
matches the **group** class when its effective group **or any supplementary
group** equals the inode's group. A FUSE request carries only the caller's
fsuid/fsgid, never its supplementary groups, so the daemon reads them from
`/proc/<pid>/status` `Groups:` (§6.1) in both transports (`src/fuse.rs` and
`src/fuse_native.rs` share `crate::fuse::caller_groups`). A missing or
unreadable entry classifies the caller by its effective ids alone — it never
fabricates group membership. The typed query API (`src/query.rs`) shares the
same rule through `crate::inode::has_permission_grouped`, with groups supplied
explicitly on its [`Credential`](QUERY.md) (empty by default).

`--default-permissions` additionally asks the kernel to check, but it is **off**
by default: delegating to the kernel makes the daemon's behaviour depend on the
mount ACL and the kernel's `allow_other` policy, whereas OrFS wants identical
semantics across transports. It is exposed for compatibility testing.

### 6.1 Reading the caller's supplementary groups

Supplementary groups are read once from `/proc/<pid>/status` `Groups:` for each
permission decision (`crate::fuse::caller_groups`). The FUSE request's `pid` is
the caller's thread-group id and the requesting thread is blocked in the FUSE
call while the daemon services it, so the entry is stable for the duration of
the check. This is the same source Linux's own `chgrp_ok` and `in_group_p`
consult. Both transports use it identically, so a mounted read and a mount's
mutation permission decision cannot disagree.

**Ownership changes (`setattr` `uid`/`gid`)** (verified by the mounted court).
`chmod` and `utimes` require ownership or root, and only root may set a file's
`uid` to a different user. A non-root *owner* may move a file into a group it
belongs to — its effective group or a supplementary group — which is the Linux
`chgrp(2)` rule. A group the daemon cannot confirm membership in is refused with
`EPERM`, never accepted by guesswork. The owner may restate its current
`uid`/`gid`, which is a permitted no-op.

Note: the OrFS genesis root is owned by `uid 0`. A volume mounted by a
non-privileged user should have its root `chown`ed to that user (the integration
test does this), otherwise a correctly enforced `0755` root legitimately denies
writes to others.

---

## 7. Capabilities negotiated

Requested (only if the kernel advertises them):

* `FUSE_ASYNC_READ`, `FUSE_BIG_WRITES`, `FUSE_MAX_PAGES`, `FUSE_ASYNC_DIO`
* `FUSE_DO_READDIRPLUS`, `FUSE_READDIRPLUS_AUTO`
* `FUSE_HANDLE_KILLPRIV`, `FUSE_HANDLE_KILLPRIV_V2` — so the daemon clears
  `S_ISUID`/`S_ISGID` itself on write/truncate instead of the kernel's
  mode-clearing `SETATTR` (see §5.2).

**Not** requested, deliberately:

* `FUSE_WRITEBACK_CACHE` — see §8.
* `FUSE_POSIX_LOCKS`, `FUSE_FLOCK_LOCKS` — see §9.
* `FUSE_ATOMIC_O_TRUNC` — `O_TRUNC` is handled via `setattr`, which keeps the
  truncation visible as an authoritative transaction.
* `FUSE_PARALLEL_DIROPS` — the sequencer is single-threaded.
* `FUSE_EXPORT_SUPPORT`, `FUSE_PASSTHROUGH` — out of scope.

---

## 8. Cache modes

Default profile: **write-through with short TTLs**.

* entry TTL = 1 s, attribute TTL = 1 s (both configurable).
* `FOPEN_KEEP_CACHE` is **not** set, so the page cache does not persist across
  opens; `--direct-io` bypasses the page cache entirely.
* explicit invalidation: `create`/`mkdir`/`symlink`/`link`/`unlink`/`rmdir`/
  `rename` enqueue an entry invalidation; `write`/`setattr` enqueue an inode
  invalidation. Notifications are sent by a dedicated `orfs-notify` thread, never
  from a request handler: issuing a FUSE notify while answering a request can
  deadlock the kernel (`fuse_reverse_inval_entry` takes locks that a concurrent
  syscall holds while it waits for the very handler that is blocked sending the
  notification). Keeping notifications off the request thread preserves the
  invariant in research §27.

**Writeback cache is not enabled.** Under writeback the kernel buffers and
coalesces writes and forwards them to the daemon later, which would break OrFS's
per-operation authoritative transaction model, its visibility ordering, and its
durability acknowledgement contract. It may be revisited only together with its
own correctness and crash-recovery courts (research §16).

## 8.1 `flush` versus `fsync`

Every mutating reply is already durable *before* it is acknowledged, according
to the selected `DurabilityMode` (`sync` = fsync-before-ack; `ordered` =
ordered+published; `batched` = amortised sync). Nothing is buffered in the
daemon, so `flush` (called on each `close`) has no work to do and returns `ok`;
it is explicitly **not** a durability barrier. `fsync` (and `fsyncdir`) call the
engine's `sync()` and *are* the durability barrier. `fdatasync(2)` is delivered
by the kernel as `fsync` with the `datasync` hint; OrFS maps it to the same full
`sync()`, which is a strictly stronger obligation than `fdatasync` requires, so
it is never a wrong success.

## 8.2 `mmap`

With the writeback cache off, `mmap` is serviced by the kernel page cache in
*write-through* mode, and the daemon needs no separate mmap handler:

* A read-only mapping reads the visible bytes; there is no second copy.
* A `MAP_SHARED` + `PROT_WRITE` mapping is permitted. When a dirtied page is
  flushed (`msync`, `munmap`, or background writeback), the kernel sends it back
  as an ordinary FUSE `write` (flagged `FUSE_WRITE_CACHE`) at the page offset;
  the daemon commits it as an authoritative `DATA_EXTENT` exactly like any other
  write. The visible bytes and the authoritative log therefore cannot diverge,
  and the modification is durable under the selected `DurabilityMode` before the
  write is acknowledged.
* Only the valid bytes up to EOF are written back, so a mapping never spuriously
  extends a file (verified by the mounted court with a non-page-aligned file).
* Under `--direct-io` (`FOPEN_DIRECT_IO`) the kernel rejects
  `MAP_SHARED|VM_MAYWRITE` with `ENODEV`, as is normal for direct-I/O FUSE
  mounts; read-only mappings remain available.

---

## 9. Locking (declared limitation)

`getlk` and `setlk` return `ENOSYS`, and OrFS does not negotiate `FUSE_POSIX_LOCKS`
or `FUSE_FLOCK_LOCKS`. Per the FUSE contract this instructs the kernel to service
POSIX record locks and BSD `flock` with its own local lock manager, which is
correct and complete for a single-node mount — exactly OrFS's model. Distributed
locking is out of scope. This is a deliberate delegation, not a silent gap, and
is recorded here and in `evidence/correctness/posix-results.json`.

---

## 10. Scope boundaries and delegated behaviour

* Transport `fuse-uring` (FUSE-over-`io_uring`) — implemented in Phase 10 as a
  native transport adapter and, since Phase 15, **engages for real on this host**
  (kernel `fuse.enable_uring=Y`, FUSE ABI 7.45): `orfs mount --transport fuse-uring`
  runs a native session (`docs/FUSE_URING.md`,
  `evidence/correctness/fuse-uring-f2-engagement.json`). It falls back to F1/F0 only
  when the kernel cannot offer it. The classical `/dev/fuse` semantics above are
  unchanged and transport-neutral.
* Backing `io_uring` — implemented in Phase 5 and selected by `--backing-io uring`;
  it falls back to synchronous I/O **only** when the kernel rejects `io_uring`, and
  the real outcome is reported (mount message, `OrfsMount::backing_io_used`,
  `orfs doctor`).
* FUSE passthrough reads — implemented in Phase 21 for **immutable snapshot** reads
  only and served by the kernel on a native F2 mount (`docs/FUSE_PASSTHROUGH.md`); a
  live mutable core is never passthrough-eligible, so it can never bypass
  authoritative writes.
* Writeback cache — see §8.
* Cross-node locking — out of scope (§9 delegates POSIX record locks and `flock` to
  the kernel's local lock manager).

---

## 11. Standard POSIX courts (Phase 24)

The custom mounted model court (§33 of the design directive) is joined by two
standard suites, so POSIX behaviour is measured against an external oracle rather
than only against OrFS's own model. The **explicit, row-by-row compatibility
contract** — every operation supported / deviated / refused, with its typed error
and its proving test — is `docs/POSIX-COMPAT.md`; the courts below are what it
cites.

### 11.1 pjdfstest

`scripts/container-posix-test.sh` (image `Dockerfile.posix`) runs
[pjdfstest](https://github.com/pjd/pjdfstest) pinned at commit
`85a8aea9e685999ef0540392fd80535f873d7ff7` twice: once against a **mounted OrFS
volume** (`orfs mount --transport fuse --backing-io sync --allow-other
--entry-ttl-ms 0 --attr-ttl-ms 0`, as root, since the suite requires root), and
once against a **reference ext4 directory**. Per-file verdicts for both runs,
per-assertion failures, the pinned commit, the image digest, and the exact
environment are written to `evidence/correctness/pjdfstest.json`.

Why those mount options: `--allow-other` is required because the suite switches
to unprivileged uids (`nobody` = 65534) and a root-mounted FUSE filesystem denies
every other uid at the VFS layer otherwise; zeroed TTLs force every path walk back
through the daemon's permission checks (a positive entry TTL lets the kernel
satisfy a walk from a cached dentry and skip the search-permission re-check).

Result: **238 test files, 8,798 assertions.** OrFS fails 46 files / 3,777
assertions; the reference ext4 fails 2 files / 28 assertions. Every OrFS failing
assertion is accounted for:

* **3,776 assertions are mechanically unsupported**: pjdfstest's `create_file`
  builds FIFO/block/char/socket nodes, which OrFS rejects with `EOPNOTSUPP`
  (mknod §5). Recorded as classes `unsupported_node_type` (682),
  `unsupported_errno` (32) and `unsupported_node_downstream` (3,062).
* **1 assertion is shared with the reference**: `unlink/08.t` #2, which the
  reference ext4 fails too — an environment/suite artifact, not an OrFS
  deviation.
* **0 documented deviations** and **0 unclassified**. `scripts/posix/pjdfstest-expected.tsv`
  now carries only that one shared artifact; the gate fails on any unclassified
  failure or any allowlisted assertion that stops failing.

The court found and fixed three real bugs (Phase 24): an over-long name returned
`EINVAL` instead of `ENAMETOOLONG`; `rmdir` omitted the sticky-bit check that
`unlink` enforces; and the FUSE adapter clamped the reported `nlink` to `>= 1`,
so an unlinked-but-open file showed `nlink 1` instead of the POSIX `0`.

Phase 25 closed every POSIX deviation the Phase 24 run exposed, verified against
the reference: implicit `mtime`/`ctime` advancement on namespace and content
mutations (§5.1), `setuid`/`setgid` clearing on a non-owner write and truncate
(§5.2), `utimensat(UTIME_NOW)` permitted with only write permission (§6),
truncation through an already-open writable descriptor not re-checked (§6), and
non-root supplementary-group `chgrp` (§6). See `docs/LIMITATIONS.md` §12.

### 11.2 xfstests

xfstests (`fstests` generic tests, `xfstests-dev` pinned at commit
`3e1ee800e52a0f53d7d9a7809be1ffc80ec1788f`) **cannot be run against a mounted
OrFS volume in this environment.** xfstests does ship a supported FUSE substrate
(`README.fuse`: `FSTYP=fuse` + `FUSE_SUBTYP=<suffix>` + a
`/sbin/mount.fuse.<suffix>` mount helper), but it is defined for libfuse's
`passthrough_ll` example filesystem, and running *any* of the suite additionally
requires (a) building xfstests' own helper binaries, (b) `xfsprogs` (`xfs_io`),
and (c) an OrFS mount helper the project does not provide (OrFS mounts as a
foreground daemon). The exact attempted commands and observed errors are recorded
in `evidence/correctness/xfstests.json`; no results are fabricated.
