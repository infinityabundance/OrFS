# OrFS Snapshots and Index Checkpoints

Normative notes for Phase 6: historical snapshots (read-only committed roots) and
index checkpoints. Implements research §2 (I2, I3), §7.4, §8, §14, §23, §24, §25,
§35.

## 1. Root identity (research §2, I2)

A **root** `R` is a *position*: the committed end offset of the authoritative
log. It is **not** a content hash.

```
R = committed_end_offset
```

An offset alone is not globally unique, so an externally meaningful reference is
the pair:

```
(volume UUID, R)
```

In the code this is `orfs::snapshot::HistoricalRoot { uuid: [u8; 16], root: u64 }`,
rendered as `uuid@root` (e.g.
`ecbf46cb-4153-4cd2-b25c-e7a067ecd7b1@100`) and parsed by `HistoricalRoot::parse`.

## 2. Prefix-snapshot invariant (research §2, I3; §7.4)

For **every committed root** `R`, the complete committed logical prefix `L[0:R]`
reconstructs exactly one valid historical filesystem state:

```
S_R = L[0:R]
```

**The endpoint must be a committed transaction boundary.** An offset inside a
record or an incomplete transaction is not a valid snapshot; `Snapshot::open`
rejects it (`Snapshot root R is not a committed transaction boundary`).
`Log::is_boundary(R)` is the authority.

A snapshot is reconstructed by **replaying/committed-prefix interpretation**, not
by reading live state: `Snapshot::from_read_log` builds the namespace index with
`Index::from_log(log, R)`, i.e. it applies the committed records in `[0, R)`.
Lookups, `getattr`, `readdir`, `readlink`, `read`, and extended-attribute queries
are all answered from that reconstructed state. Extent bytes are immutable and
read from the retained log at the offsets recorded in the reconstructed index.

Consequences:

* A snapshot taken at `R` **never observes a write committed after `R`**, because
  those records lie outside `L[0:R]`.
* Reconstruction is a pure function of the committed prefix, so the same
  `(uuid, R)` over the same retained log always yields the same view —
  **stable across remounts**.

## 3. A root is a reference, not contents (research §8)

The root identifies a historical volume state; the root number alone does **not**
contain the filesystem history. A `Snapshot` requires the corresponding
authoritative log body to be available. A self-contained *historical carrier* — an
export that embeds the authoritative log prefix so the state can be reproduced
without the volume — is a **separate, optional feature** and is not implemented
here. The implementation does not fake one.

## 4. Read-only enforcement (research §7.4, §14)

Snapshot mounts are read-only unless OrFS explicitly implements branching history
(it does not). Two independent layers enforce this:

1. **Kernel mount** — `fuse::run_snapshot` / `spawn_snapshot` forces
   `MountOptions.read_only = true` and mounts with `MountOption::RO`; the VFS
   returns `EROFS` for writes before the request reaches the daemon.
2. **Snapshot core** — `Snapshot` implements `OrfsCore` with every mutation
   (`write_at`, `setattr`, `create`, `mkdir`, `unlink`, `rmdir`, `rename`, `link`,
   `symlink`, `setxattr`, `removexattr`, `zero_range`) returning
   `OrfsError::ReadOnly`, which maps to `EROFS`.

`Snapshot::is_read_only()` is always `true`.

## 5. Root pinning (Phase 5 carry-over fix)

A snapshot holds a `RootPin` for its whole lifetime. The pin is registered in a
reference-counted, `Arc`-shared `RootPins` registry; a writer's segment rollover
consults it before quarantining/reusing a segment. If a segment is still required
by a pinned historical root, the rollover is refused with `OrfsError::Pinned`
(`EBUSY`) rather than silently withdrawing committed history.

This **extends the buffer-pool pin discipline to roots**. Two properties are
proved in tests:

* `Log` is `Send + Sync` because the io_uring Rings W and R are guarded by a
  `Mutex`, not a `RefCell` (`src/uring.rs`, `BackingRings`). A single `Arc<Log>`
  read handle is therefore shared by many reader threads and by any number of
  snapshots concurrently.
* While readers hold pins, a writer rolls the log over many times; the pinned
  root's bytes are unchanged and every pin is released exactly once.

Under normal operation committed segments (`id < R <= committed`) are never
rollover targets, so the guard is defence in depth; it fires only if an invariant
would otherwise be violated.

## 6. Index checkpoints (research §23, §24)

Full replay is `O(|L|)`. OrFS stores periodic index checkpoints **inside the
authoritative log** as `INDEX_CHECKPOINT` records (`0x0014`).

### Record payload

```
magic         u32    ICP1
root          u64    the committed root this index reflects
inode_count   u64    asserted live inode count at root
dentry_count  u64    asserted live dentry count at root
index_digest  [32]   BLAKE3 of the canonical index
index_len     u32
index_bytes   [index_len]  the serialized index snapshot document
crc32c        u32    over all preceding payload bytes
```

`Namespace::write_index_checkpoint` appends one such record as a committed
transaction. `SNAPSHOT_ROOT` (`0x0013`) publishes a *named* committed root
(`Namespace::publish_snapshot`, `snapshot list`).

### Mount procedure

`checkpoint::mount_index(log)` implements research §24 exactly:

1. **Discover** candidate checkpoints with a header-only scan
   (`Log::scan_record_offsets_of_types`) that reads 60 bytes per record and does
   not materialise intervening `DATA_EXTENT` payloads.
2. Iterate candidates **newest first**; for each, read exactly one record body
   (`Log::read_record_at`) and **load + validate** it:
   * the embedded snapshot parses and passes its own self-digest (a torn,
     truncated, or tampered index body is rejected here; the payload CRC32C also
     covers the body);
   * the index root equals the payload root and is a committed boundary `<= R`;
   * the index inode/dentry counts equal the payload's asserted counts.
3. **Replay only the committed records after the checkpoint root**
   (`Log::records_from` + `Index::apply_record`).
4. Reconstruct the latest committed state.

If a checkpoint fails validation, the next earlier checkpoint is tried. If none
validates, the index is rebuilt by **full replay** (`Index::from_log`). A corrupt
checkpoint is a discarded accelerator; committed history is never silently
skipped. The reconstructed index is bit-identical to a from-scratch rebuild over
the same records (proved by the test `checkpoint_load_and_replay_equals_full_replay`).

`Namespace::open` now uses this path and records the measured `MountReport`
(`Namespace::mount_report`).

### Mount cost — measured, not claimed

Mount is **not constant-time**. The two costs are:

* discovery: `O(#records)` header reads;
* replay: `O(bytes after the newest valid checkpoint)`.

Both are measured and reported by `MountReport` (`records_replayed`,
`bytes_replayed`, `checkpoints_found`, `checkpoints_rejected`, `wall_micros`,
`full_replay_fallback`). `evidence/performance/mount-replay-snapshot.json` records
measured full-replay vs checkpoint-mount times on identical logs. Checkpoints pay
off when the retained log dwarfs the index (namespace-light, write-heavy
workloads); a checkpoint on a trivially small log can cost more than it saves,
and the evidence says so.

## 7. Extended attributes (research §8)

Derived, read-only `user.orfs.*` attributes are surfaced (and reconstructed
historically by a snapshot):

| Attribute | Value | Meaning |
|---|---|---|
| `user.orfs.creation_root` | record offset of the inode's first version | a **reference** |
| `user.orfs.current_root` | record offset of the inode's latest version | a **reference** |
| `user.orfs.version` | monotonic inode version | |
| `user.orfs.history_available` | `1` | historical bytes are retained |
| `user.orfs.manifested_bytes` | physical bytes of the inode's manifested structure for its **current** version (`0` if none) | version-qualified accounting (Phase 7) |
| `user.orfs.ekbloom_profile` | the recorded profile, or `none` | Phase 7 |

The root values are **references**, not contents: a root number alone does not
contain the filesystem history. Since Phase 7, `user.orfs.manifested_bytes` and
`user.orfs.ekbloom_profile` report the concealed-plane accounting for the inode's
current version (`0`/`none` when nothing is manifested, or on any version
mismatch); a historical [`Snapshot`] reports `0`/`none` because it does not carry
the live volume's manifested structures. Values obey the ordinary
extended-attribute size and access rules (they are computed, not stored). See
`docs/MANIFESTATION.md` §9.

## 8. Invariants exercised by tests

* (a) `Replay(L[0:R])` reconstructs the exact namespace + contents at `R`, for
  many sampled roots (deterministic and randomized `proptest` sequences).
* (b) A snapshot at `R` does not observe later writes.
* (c) Snapshot mounts are read-only; writes return `EROFS`.
* (d) Checkpoint load + replay equals full replay; corrupt-checkpoint fallback to
  an earlier checkpoint, and to full replay.
* (e) Concurrent readers on one `Arc<Log>` + root pinning under concurrent writes.
* (f) Snapshot stability across remount.

Evidence: `evidence/correctness/snapshot-equivalence.json` (per-root
reconstruction verdicts) and `evidence/performance/mount-replay-snapshot.json` (measured
mount time vs retained history size, with and without checkpoints).

## 9. CLI

```sh
orfs snapshot list    <backing> [--json]   # named snapshots + checkpoints + boundaries
orfs snapshot inspect <backing> <root> [--json]
orfs snapshot mount   <backing> <root> <mnt>   # READ-ONLY FUSE mount
```
