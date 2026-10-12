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
by reading live state: `Snapshot::from_read_log` builds the namespace index from
the committed prefix `L[0:R]`. Since Phase 20 this is *materialized once* (see
§6.1): a validated persisted accelerator is reused when present, otherwise the
index is rebuilt from the log, preferring an in-log checkpoint so the replay is a
suffix. Lookups, `getattr`, `readdir`, `readlink`, `read`, and extended-attribute
queries are all answered from that reconstructed state. Extent bytes are immutable
and read from the retained log at the offsets recorded in the reconstructed index.

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

### Historical-root indexes: suffix replay, caching, and persistence (Phase 20)

Two costs made repeated historical reads waste work (external review §3D):

1. `Index::apply_range(start, end)` extended an index by iterating
   `Log::records_upto(end)` and *skipping* records before `start`. Because the
   live index is extended by exactly one commit per transaction, every commit
   decoded the **entire** preceding stream — `O(|L|)` per commit, `O(|L|²)` to
   build a history.
2. `Namespace::view(root)` reconstructed a historical index with `Index::from_log`
   on **every** non-current-root request.

Both are fixed:

* **Suffix replay.** `Index::apply_range` (via `apply_range_traced`) iterates the
   suffix directly with `Log::records_from(start, end)`, which seeks to `start`
   and decodes no byte before it. The decoded span is exactly `end - start`,
   independent of how much history precedes `start`. `start` must be a committed
   boundary (a non-boundary start is rejected rather than silently applying a
   garbled record). The same primitive backs `checkpoint::mount_index_at`.
* **Materialize once, reuse.** A root is immutable, so the index reconstructed
   from `L[0:R]` never changes and needs **no invalidation**. `Namespace` carries a
   bounded **in-memory LRU cache** keyed by `(volume uuid, root)`
   (`historical::HistoricalIndexCache`, default capacity 8, evicting the
   least-recently-used entry). The first access materializes the index —
   preferring the newest valid in-log checkpoint at or before `R` and replaying
   only `[checkpoint_root, R)` (`checkpoint::mount_index_at`) — and every later
   lookup/read is a pure cache hit with no replay, independent of history size.
* **Persisted accelerator.** On materialization the index is written (best-effort,
  temp-file + rename) to `index/historical/<root>.v2.bin` as a **derived**
  accelerator, so a **remount** can reuse it without any replay. A `Snapshot`
  opened over a volume also reuses a valid persisted accelerator
  (`materialize_index`). The format is described in §6.1.

**The log always wins.** Neither layer is authoritative. A historical index is
only ever *produced* by the same replay the log yields. A persisted accelerator
that is absent, torn, tampered, foreign (wrong UUID), or names a non-boundary is
dropped and the index is rebuilt from the log; a derived file never overrides
committed history. Because roots are immutable, a cache entry is never stale: any
later commit lands beyond `R` and cannot change `L[0:R]`.

### 6.1 Persistent historical accelerator: the binary format (Phase 43)

The Phase-20 accelerator wrapped the index's JSON snapshot inside a JSON
envelope, so a large history paid parsing, allocation, and materialization before
the index was usable. Phase 43 replaces the write side with an **immutable,
versioned binary container** and keeps a backward-compatible **read** of the
legacy JSON form.

```text
  v2 binary accelerator, `index/historical/<root>.v2.bin`:

  off  size field
  0    8    magic "ORFSHIX2"
  8    4    version = 2
  12   4    header_len = 88
  16   16   volume uuid            (volume identity)
  32   8    root                   (the committed boundary)
  40   8    blob_offset = 88       (explicit offset)
  48   8    blob_len               (explicit length)
  56   8    asserted inode count
  64   8    asserted dentry count
  72   4    flags (0)
  76   4    reserved
  80   8    reserved
  88   ..   packed index blob
  end  32   BLAKE3 digest over every preceding byte

  packed index blob (offset/length table of contents at its front):
  magic "ORIX", version, root, next_inode_id, five counts, then five
  directly addressable tables: inode, directory-entry, named-snapshot,
  checkpoint, and directory-key.
```

Validation is strictly ordered so that **no mapped byte becomes trusted before it
is checked**: (1) the container is at least header + digest long; (2) magic,
format version, and declared header length are exact; (3) the volume UUID and root
match the requested `(uuid, root)`; (4) the declared offsets and lengths tile the
file exactly, using checked arithmetic; (5) the whole-representation BLAKE3
digest matches. Only then is the packed blob decoded, its own table of contents
re-checked, and the asserted inode/dentry counts and root cross-checked against
the decoded index.

The blob is decoded from a **read-only `mmap`** of the file when the platform
supplies one (with an ordinary read as the fallback), so validating the small
header and the digest does not require materialising the file. The directory-key
table preserves the exact set of directory entries — including directories with no
visible children — so `decode_packed(encode_packed(i)) == i` exactly, which the
legacy JSON form does not guarantee.

**Backward compatibility / migration.** The legacy `index/historical/<root>.v1.json`
document is still read (`historical::load_persisted_historical` prefers the binary
form and falls back to the JSON form). No migration step is required and no
existing volume is invalidated: the next materialization of a root simply writes
the binary form, and both forms decode to the same index.

### 6.2 Committed-root directory (Phase 43)

Mount discovery and historical-root discovery both had to scan the whole log's
record headers to *find* an in-log checkpoint. Phase 43 adds a **derived,
append-only committed-root directory** under `index/roots/`, modelled on the
Phase-42 manifestation catalogue:

```text
  index/roots/CURRENT            pointer to the active segment ("ORCQ", CRC32C)
  index/roots/seg-<n:010>.cat    fixed-size CRC32C-framed records, append-only
  index/roots/sum-<n:010>.sum    folded "latest per key" summary, immutable
```

Each record carries a kind (checkpoint location, verified historical-index
location, or watermark), the committed root a completed scan covered (the
**watermark**), a checkpoint record offset where applicable, and — for a verified
accelerator — its whole-representation digest. A **watermark** record is appended
*last*, so a crash mid-publication can never claim a completeness the scan did not
establish; the directory is complete for checkpoint locations in `[0, W)` exactly
when a watermark `W` is present. A directory that claims a bound beyond the log's
committed root, has a missing interior segment, or fails to fold is **distrusted**
and the caller scans authoritatively.

`checkpoint::mount_index` and `checkpoint::mount_index_at` consult the directory
first and fall back to the header scan; every candidate offset it names is still
read from the log and fully validated, and the suffix is replayed. The directory
can therefore only ever cost a *fallback* or *extra replay* — never a wrong result
— and it never hides a checkpoint the log has.

**Publishing is writable-open only.** Only a writable head mount
(`Namespace::open` with `OpenMode::ReadWrite`) best-effort *publishes* the
`index/roots/` directory after a completed scan; the pure-scan audit
(`mount_index_scan`), historical views (`mount_index_at`), and read-only opens
(`mount_index_readonly`) **consult** it but never write it. This preserves
`docs/RECOVERY.md`'s read-only guarantee that a read-only open modifies *not a
single on-disk byte*.

### 6.3 Quick open vs. complete audit (Phase 43, integrity contract)

The system distinguishes two operations, and both carry it in their report:

* A **quick open** reuses a persisted accelerator validated for exactly
  `(uuid, root)` (identity, root, whole-representation digest, committed
  boundary). It does not replay the log. `checkpoint::open_index_quick` and a
  persisted hit in `HistoricalIndexCache` are quick opens;
  `MountReport::discovery_source` is
  `DiscoverySource::ValidatedAccelerator` and `MountReport::audited()` is
  `false`.
* A **complete audit** reads and validates authoritative records. The report's
  `DiscoverySource` is `Catalogue` (directory-assisted discovery, but the
  checkpoint record was read from the log), `LogScan` (header-scan discovery), or
  `FullReplay` (whole-log replay), and `audited()` is `true`.

`checkpoint::mount_index` (the mount path) is always an **audit**; it never trusts
the accelerator for the committed root. A caller that deliberately wants the fast
path uses `checkpoint::open_index_quick`, which falls back to `mount_index` when
the accelerator is absent or cannot be trusted. `checkpoint::mount_index_scan` is
the always-available authoritative audit that ignores every derived structure.

If the derived directory or an accelerator is corrupt, missing, or untrusted, the
audited reconstruction remains available and is used. **A fast path never asserts
history it has not verified.**

Evidence: `evidence/performance/historical-fast.json` (correctness, adversarial
fallback verdicts, and measured accelerator load, mount recovery, and
historical-root open costs, with an honest note).

### Mount cost — measured, not claimed

Mount is **not constant-time**. The two costs are:

* discovery: `O(#records)` header reads — or `O(1)` directory lookups when the
derived committed-root directory is complete for the prefix (§6.2);
* replay: `O(bytes after the newest valid checkpoint)`.

Both are measured and reported by `MountReport` (`records_replayed`,
`bytes_replayed`, `checkpoints_found`, `checkpoints_rejected`, `wall_micros`,
`full_replay_fallback`, and `discovery_source`).
`evidence/performance/mount-replay-snapshot.json` records measured full-replay vs
checkpoint-mount times (and the directory-assisted restart) on identical logs, and
`evidence/performance/historical-fast.json` records the same at an 8 000-op scale.
Checkpoints pay off when the retained log dwarfs the index (namespace-light,
write-heavy workloads); a checkpoint on a trivially small log can cost more than
it saves, and the evidence says so. The directory removes only the *discovery*
scan; the checkpoint's embedded index must still be decoded.

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
* (g) **Phase 20** — suffix replay is proportional to the suffix (decoded bytes
  equal `end - start`, independent of preceding history); a cached historical
  index equals full replay for many roots; the in-memory cache is a hard LRU
  bound; an absent, torn, or tampered persisted accelerator falls back to correct
  replay; and a remount reuses a persisted historical index without replaying.
* (h) **Phase 43** — a quick open returns byte-identical state to the audited
  reconstruction at the same root; the binary container is smaller and decodes
  faster than the legacy JSON form; a torn, truncated, corrupt-header, or
  corrupt-digest accelerator, a foreign volume uuid, a missing committed-root
  directory, and a corrupt (bogus-offset, torn, holed, or over-claiming) directory
  **all** fall back to the authoritative reconstruction and never return wrong
  bytes or a wrong root.

Evidence: `evidence/correctness/snapshot-equivalence.json` (per-root
reconstruction verdicts), `evidence/performance/mount-replay-snapshot.json`
(measured mount time vs retained history size, with and without checkpoints),
`evidence/performance/historical-index.json` (first-materialization vs
repeated-access cost, and exact decoded-byte proportionality of suffix replay),
and `evidence/performance/historical-fast.json` (Phase 43: accelerator load,
mount recovery, and historical-root open costs, plus the adversarial fallback
verdicts).

## 9. CLI

```sh
orfs snapshot list    <backing> [--json]   # named snapshots + checkpoints + boundaries
orfs snapshot inspect <backing> <root> [--json]
orfs snapshot mount   <backing> <root> <mnt>   # READ-ONLY FUSE mount
```
