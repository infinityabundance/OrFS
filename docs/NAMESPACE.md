# OrFS Namespace Engine (Phase 3)

**Status:** implemented (Phase 3). This document is normative for the namespace
semantics of this build. It refines `research/OrFS.md` §6, §7 (incl. §7.1–§7.4),
§8, §13, §14, §23.2, §24, §25; where they differ, `research/OrFS.md` governs.

Source: `src/inode.rs` (inode model + inode-scoped payloads), `src/directory.rs`
(namespace payloads), `src/extent.rs` (logical extent map), `src/index.rs`
(derived, rebuildable index), `src/namespace.rs` (engine + `OrfsCore`).

---

## 1. Laws restated for Plane B

* **Law I — non-withdrawal.** No namespace operation edits a committed record.
  A write appends a `DATA_EXTENT`; an unlink appends a `DENTRY_REMOVE`
  tombstone; a truncate appends `FILE_RESIZE`; a rename appends
  `DENTRY_RENAME`. Historical extents and dentry records are never reclaimed.
* **The log is the source of truth.** The [`Index`] is a *derived* projection of
  committed records. It is always reconstructible from scratch, and if it ever
  disagrees with replay, **the log wins** (research §23.2).

Names are **not** part of inode identity. An inode is identified solely by its
stable id; a name is a `(parent_inode, name) → child_inode` relation
(research §6).

---

## 2. Inode model (`src/inode.rs`)

Every inode record and its fields:

| Field | Meaning |
|-------|---------|
| `id` | stable identity; `1` is the volume root (`FUSE_ROOT_ID`); names never affect it |
| `generation` | bumped only if an id were ever reused (never today) |
| `kind` | `file` / `directory` / `symlink` |
| `mode` | permission bits (low 12 bits of `st_mode`) |
| `uid`, `gid` | ownership |
| `nlink` | link count (see §4) |
| `size` | current logical length in bytes |
| `atime`, `mtime`, `ctime` | nanosecond timestamps |
| `xattrs` | stored extended attributes (`BTreeMap<name, value>`) |
| `extents` | current logical extent map (derived; see §3) |
| `versions` | **historical versions** — one metadata snapshot per authoritative record |
| `latest_record_offset` | offset of the latest authoritative record for the inode |

A **version** is appended by every authoritative record that touches the inode,
so `current_version = versions.len()` and the whole version history is
reconstructible from the log. `INODE_CREATE` creates version 1.

### 2.1 Inode-scoped payloads

All payloads are little-endian, begin with a 4-byte magic, and end with a
CRC32C over every preceding byte. Payloads are decoded only for *known* record
types; the framing layer still treats them as opaque bytes.

| Record | Magic | Fixed size | Fields |
|--------|-------|-----------:|--------|
| `INODE_CREATE` | `ICR1` | 88 B | `inode_id`, `generation`, `kind`, `mode`, `uid`, `gid`, `nlink`, `size`, `atime`, `mtime`, `ctime` |
| `SYMLINK_CREATE` | `SLK1` | var | `inode_id`, `generation`, `mode`, `uid`, `gid`, `mtime`, `target` |
| `INODE_METADATA` | `IMT1` | 20 B | `inode_id`, `nlink` |
| `PERMISSION_CHANGE` | `PCH1` | 32 B | `inode_id`, field mask over `{mode, uid, gid}` |
| `INODE_SETATTR` | `ISA1` | 44 B | `inode_id`, field mask over `{atime, mtime}` |
| `XATTR_SET` | `XAS1` | var | `inode_id`, `name`, `value` |
| `XATTR_REMOVE` | `XAR1` | var | `inode_id`, `name` |

`PERMISSION_CHANGE` carries `{mode, uid, gid}`; `INODE_SETATTR` carries
timestamps; `INODE_METADATA` publishes an explicit link count. They are kept
disjoint so each record type has exactly one meaning.

### 2.2 Deriving `user.orfs.*`

`getxattr`/`listxattr` additionally expose the derived, read-only attributes of
research §8 (`user.orfs.creation_root`, `user.orfs.current_root`,
`user.orfs.version`, `user.orfs.history_available`). These are computed from the
inode on demand and are **not** stored in the log or the index, so they never
affect rebuild equivalence.

---

## 3. Extents (`src/extent.rs`)

The logical content of a file is reconstructed from an ordered map of immutable
extents. The map always covers exactly `[0, size)` with disjoint extents; an
unwritten hole or a region exposed by a grow is an explicit zero extent, so a
read is an unambiguous walk.

| Record | Magic | Fields |
|--------|-------|--------|
| `DATA_EXTENT` | `DEX1` | `offset` (logical), `data` (immutable bytes, stored in the log) |
| `DATA_ZERO_RANGE` | `DZR1` | `offset`, `len` |
| `FILE_RESIZE` | `FRS1` | `new_size` |

A `DATA_EXTENT`'s bytes live permanently in the log at a fixed logical offset
(the record offset + header + this payload's fixed prefix). The in-memory extent
is only a reference `[start, len) → data_offset`; the bytes are fetched from the
log on read. **Overwriting logical bytes appends new immutable storage and never
rewrites historical bytes.**

### 3.1 POSIX semantics implemented

* **Arbitrary offset writes** — at zero, in the middle, at EOF, and **beyond
  EOF**. A write extends the logical size to cover its range; when the write
  starts beyond the current EOF, the gap `[size, offset)` is zero-filled — a
  sparse hole, not stored bytes (research §7.1).
* **Overlapping writes** — the newly written range replaces the previous
  mapping for exactly that range; unaffected bytes keep referencing their
  original immutable extents. Last writer wins for the overlap.
* **Sparse files** — unwritten holes read as zeros and consume no log bytes.
* **Partial writes** — supported at the record level; the engine's `write_at`
  reports the full length written.
* **Truncate shrink** — `FILE_RESIZE(new_size)` drops the visible map beyond
  `new_size` but **retains** every log byte (research §7.2).
* **Truncate extend** — the newly exposed region is zero-filled, so a later
  extension can **never resurrect** truncated bytes merely because they still
  exist physically (research §7.2). This is the key non-withdrawal obligation.

Worked example (shrink then grow must not resurrect):

```text
write(0, "AAAAAAAA")        # extent Data[0,8) -> log offset X
FILE_RESIZE(3)              # visible [0,3); bytes [3,8) retained in the log
FILE_RESIZE(8)              # [3,8) becomes zeros, NOT the old "AAAAA"
```

---

## 4. Directories, links, rename (`src/directory.rs`)

`(parent_inode, name) → child_inode` relations are stored separately from
inodes. The engine exposes `lookup`, `readdir`, `create`, `mkdir`, `unlink`,
`rmdir`, `link`, `symlink`, `readlink`, `rename`, and the xattr operations.

| Record | Magic | Fields |
|--------|-------|--------|
| `DENTRY_ADD` | `DAD1` | `parent`, `child`, `name` |
| `DENTRY_REMOVE` | `DRM1` | `parent`, `name` |
| `DENTRY_RENAME` | `DRN1` | `flags`, `old_parent`, `new_parent`, `old_name`, `new_name` |
| `HARDLINK_ADD` | `HLA1` | `parent`, `child`, `name` |
| `HARDLINK_REMOVE` | `HLR1` | `parent`, `name` |

### 4.1 Link counts

`nlink` is published explicitly in the log (`INODE_CREATE` for a new inode,
`INODE_METADATA` for every subsequent change) and is independently derivable:

* a **file/symlink** has one link per name;
* a **directory** has `2 + (number of immediate subdirectories)` links, and `0`
  once removed.

The derivation is authoritative: a directory whose last name was removed is no
longer *live* and cannot be the parent of a mutation (`create`/`mkdir`/
`symlink`/`unlink`/`rmdir`/`link`/`rename` all reject it with `NotFound`), so its
link count stays `0`. The inode is still retained and readable by id (a removed
directory lists as empty), matching every inode's immutable history.

The reference model in `tests/namespace_model.rs` derives link counts from the
tree and compares them against the engine, so the two are cross-checked rather
than restated.

### 4.2 Operations

* **create / mkdir / symlink** — `INODE_CREATE`/`SYMLINK_CREATE` + `DENTRY_ADD`
  (mkdir also bumps the parent's link count).
* **unlink** — a tombstone: `HARDLINK_REMOVE` when other names remain,
  `DENTRY_REMOVE` for the last name, plus an `INODE_METADATA` link-count update.
  The inode and all its data remain; `nlink` may reach 0 while the inode stays
  readable through its historical identity (research §7.3, §15).
* **rmdir** — rejects a non-empty directory (`ENOTEMPTY`) and the root; appends
  `DENTRY_REMOVE` plus link-count updates for the child (to 0) and parent.
* **link** — adds a name to a non-directory inode (`HARDLINK_ADD` +
  `INODE_METADATA`); directories cannot be hard-linked (`EPERM`).
* **rename** — one atomic `TX_BEGIN … TX_COMMIT` transaction:
  * `Ordinary` — replaces an existing destination. A destination directory must
    be empty; type mismatches (`EISDIR`/`ENOTDIR`) are rejected. The destination
    removal is appended *first*, then the source moves, all in one transaction.
  * `RENAME_NOREPLACE` — `EEXIST` if the destination exists.
  * `RENAME_EXCHANGE` — `DENTRY_RENAME` with the `exchange` flag atomically
    swaps two existing names.
  * Cross-directory moves adjust parent link counts.
  * A directory may not be moved into itself or a descendant
    (`DirectoryCycle`).
  * **Identity is preserved**: rename never changes the moved inode's id.

The `DENTRY_RENAME` record is a primitive *move* or *exchange*; the engine
expresses overwrite as a preceding removal, and the enclosing transaction makes
the whole rename atomic.

---

## 5. The derived index (`src/index.rs`)

The index maps:

```text
inode_id            -> current inode version (+ historical versions)
(parent_inode,name) -> child inode_id
inode_id            -> extent map
inode_id            -> xattr map
root                -> named committed snapshots / checkpoints
```

### 5.0 Persistent representation (Phase 27)

The index is published to readers as an immutable snapshot at every commit
boundary (`docs/CONCURRENCY.md` §2–§4). To make that publication cost
proportional to the *affected* objects rather than to total history, the spines
are persistent (path-copying) maps (`src/persistent.rs`):

* `inodes: PMap<u64, Arc<Inode>>`, `children: PMap<u64, PMap<Vec<u8>, u64>>`,
  `snapshots: PMap<Vec<u8>, u64>` — immutable treaps whose nodes are `Arc`-shared;
  cloning an `Index` is a handful of `Arc` bumps, and a mutation path-copies only
  `O(log n)` nodes. `checkpoints` is an `Arc<Vec>` appended copy-on-write.
* `Inode.versions` is a shared `VersionHistory` (an `Arc`-linked newest-first
  list): appending a version is `O(1)` and shares the prior history, so an inode
  clone never deep-copies the version vector.
* `Inode.extents` is an `ExtentMap` over `PMap<u64, Extent>` with an incremental
  overlay, so a write is `O(log E + k)` and a file with very many extents is not
  re-copied per write.

The observable index is unchanged — the same records, the same canonical digest,
and the same byte-for-byte snapshot document (`Index::encode_snapshot`)— so every
correctness court, historical reconstruction, and persisted accelerator remains
exact. Only the cost changed: see `docs/PERFORMANCE.md` §9.

### 5.1 Rebuildability and log-wins

* `Index::from_log(log, root)` builds the index purely by replaying committed
  records up to a committed boundary.
* A single function, `Index::apply_record`, mutates the index. The live index is
  extended after each commit by replaying exactly the records just committed
  (`apply_range`), so **the live index is provably equal to a rebuild over the
  same records**.
* Since Phase 20, `apply_range(start, end)` iterates the suffix directly with
  `Log::records_from`, decoding exactly `end - start` bytes rather than walking
  and skipping the whole preceding stream (see `docs/SNAPSHOTS.md` §6.1).
* A historical root's index is immutable: `Namespace::view(root)` resolves it once
  into a bounded in-memory LRU cache (keyed by `(uuid, root)`) and a persisted
  accelerator under `index/historical/`, then reuses it across every later
  lookup/read — no invalidation, because committed history is never withdrawn.
* `Namespace::index_matches_log()` rebuilds and compares; the evidence file
  `evidence/correctness/namespace-rebuild.json` records this.
* A persisted snapshot under `index/namespace.v1.json` is an **accelerator
  only**. It embeds a BLAKE3 digest of its canonical body and is validated on
  load; a torn, tampered, or foreign snapshot is rejected and the log is
  replayed instead. Correctness never depends on it.

### 5.2 Checkpoints and snapshots

`SNAPSHOT_ROOT` names a committed root (`name → root`); `INDEX_CHECKPOINT`
records a `{root, inode_count, dentry_count, digest}` checkpoint. Both are
acceleration/verification aids; `SNAPSHOT_ROOT` is emitted by
`Namespace::publish_snapshot` and a checkpoint by
`Namespace::write_index_checkpoint`. Snapshot *mounts* are Phase 6.

---

## 6. The transport-neutral core (`OrfsCore`)

`src/namespace.rs` exposes the `OrfsCore` trait — the surface the FUSE layer
(Phase 4) calls — with `lookup`, `read` via `read_at(inode, root, offset,
length)`, `write_at(inode, offset, data)`, `create`, `mkdir`, `unlink`, `rmdir`,
`rename`, `link`, `symlink`, `readlink`, `getattr`, `setattr`, `getxattr`,
`setxattr`, `listxattr`, `removexattr`, and `readdir`. Reads take a `root`
parameter: the live committed root, or a pinned historical root (materialized
once into the Phase 20 historical-index cache — research §7.4). Mutations always
append authoritative transactions.

Mapping to the FUSE operations of research §14 follows directly: `lookup` →
`lookup`; `getattr`/`setattr`; `read`/`write`; `opendir`/`readdir`; `create`;
`mkdir`; `unlink`; `rmdir`; `rename`; `link`; `symlink`/`readlink`;
`getxattr`/`setxattr`/`listxattr`/`removexattr`. Operations outside this set
(snapshots, io_uring, acceleration) are later phases.

### 6.1 Immutable read views (Phase 19)

Reads no longer serialise on the core. The engine publishes an immutable,
reference-counted read view (`Arc<dyn CoreRead>`; concretely `Arc<ReadState>`)
through a short-lived `RwLock<Arc<..>>` cell at each **commit boundary**. A reader
clones the `Arc`, drops the guard, and serves the whole request — including
physical segment I/O — with no lock held. A reader thus observes a whole
committed state, never a partial one. The index is stored so a published view
shares almost all of its memory with the live writer (inode nodes are `Arc`-shared;
the dentry map and per-directory child maps are `Arc`-swapped). The complete
model, the sharing strategy and its measured cost, and both transports are
documented in [`docs/CONCURRENCY.md`](CONCURRENCY.md).

---

## 7. Structural hardening (Phase-2 carry-over fixes)

* **(a) Typed bracket validation.** Recovery (`scan_log`) and
  `orfs verify --deep` now decode every committed `TX_BEGIN`/`TX_COMMIT`
  payload, cross-check the begin's declared expectations against the *actual*
  bracketed records, and verify the `TX_COMMIT` BLAKE3 bracket checksum.
  A fully-framed committed record whose bracket is inconsistent is a **hard
  error**, never silently treated as an uncommitted tail. `verify_bracket` parses
  the bracket into records and checks the actual count, length, and digest.
* **(b) Monotonic transaction ids.** Transaction ids are allocated strictly
  above the greatest id ever observed in the log (`Log::max_transaction_id`,
  which includes aborted and abandoned-tail ids). `CommitSequencer` seeds and
  advances its counter from that value, so an id consumed by a previously
  aborted transaction is never reused, across reopen.

---

## 8. Proof obligations

| Obligation | Discharged by |
|------------|---------------|
| Logical behaviour matches an independent reference model | `tests/namespace_model.rs::deterministic_scenarios_match_reference_model`, `::random_namespace_ops_match_reference_model` (proptest, 64 cases) |
| Writes at zero/middle/EOF/beyond-EOF, overwrite, sparse, partial, truncate up/down | same tests; `extent` unit tests |
| Overwriting never rewrites historical storage | extent references only immutable log bytes; `DATA_EXTENT` bytes are append-only |
| Truncate extend never resurrects truncated bytes | `extent::tests::resize_shrink_then_grow_does_not_resurrect_bytes` + model |
| unlink/hardlink/symlink/mkdir/rmdir/rename modes/cycles | deterministic scenarios + differential proptest |
| Rebuild from the log equals the live index | `index_rebuild_equivalence_and_log_wins`; `evidence/correctness/namespace-rebuild.json` |
| A tampered index snapshot is rejected; the log wins | same test |
| Committed bracket inconsistency is a hard error | `inconsistent_commit_bracket_is_a_hard_recovery_error` |
| Transaction ids are monotonic and never reuse aborted ids | `transaction_ids_are_monotonic_and_never_reuse_aborted_ids` |

---

## 9. Explicit non-claims (Phase 3)

* Permission/ownership **enforcement** is not applied; `uid`/`gid`/`mode` are
  recorded, not checked (Phase 11 / `docs/SECURITY.md`).
* No `mknod` (device/FIFO/socket) support; such requests must be rejected by the
  transport.
* `copy_file_range`, `fallocate` modes, `lseek` SEEK_DATA/HOLE, and locking are
  not yet implemented (Phase 4+).
* Snapshot **mounts** and index checkpoint *loading* for mount acceleration are
  Phase 6; Phase 3 provides the records, the derived index, and rebuild
  equivalence.
* No EKBLOOM acceleration is wired into the read path (Phase 8).
