# OrFS Concurrency Model (Phase 19)

**Status:** implemented (Phase 19; external review P0 — "remove the global core
lock from reads"). This document is normative for how OrFS serves concurrent
reads and how it publishes committed state to them. It refines
`docs/NAMESPACE.md` §5–§6, `docs/FUSE-SEMANTICS.md`, and `research/OrFS.md`
§26–§27.

Source: `src/namespace.rs` (`CoreRead`, `ReadState`, `ReadCell`, `OrfsCore`),
`src/log.rs` (`LogView`), `src/index.rs` (the shared index representation),
`src/fuse.rs` / `src/fuse_native.rs` (the two transports).

---

## 1. The problem this removes

Before Phase 19 the FUSE adaptor owned the core as `Mutex<C>` and **held that
mutex across `getattr()`, `read_at()` and every other request** — including the
physical segment I/O a read performs. A single read doing disk I/O therefore
serialised *every other* FUSE request behind it. No amount of ring depth or
transport work can overcome a globally serialised core (external review P0).

---

## 2. The read-view publication model

Writers and readers are split:

* **Writers** still serialise through the core (`Mutex<C>`). All mutations append
  authoritative transactions through the single commit sequencer, exactly as
  before. The committed index is mutated **in place** by the writer.
* **Readers** never touch the core lock. They read through an **immutable,
  reference-counted read view**:
  `Arc<dyn CoreRead>` (concretely an `Arc<ReadState>`).

The current view is published through one short-lived cell:

```text
ReadCell = Arc<parking_lot::RwLock<Arc<dyn CoreRead>>>
```

* A reader does `let view = cell.read().clone();` — taking the read-lock only
  long enough to clone the inner `Arc`, then **dropping the guard** — and serves
  the whole request (metadata + physical I/O) with **no lock held**. This is the
  same cell the FUSE layer holds, so it never has to take the core lock just to
  obtain the view.
* A writer installs a new view with a single store, `*cell.write() = new_view`,
  and holds the write-lock only for that pointer swap.

`ReadState` carries everything a read needs from one frozen point:

| Field | Purpose |
|-------|---------|
| `root: u64` | the committed root this view reflects |
| `index: Arc<Index>` | a complete, frozen index at `root` |
| `log: LogView` | a captured segment locator + the shared read-handle cache |
| `manifestation: Option<Arc<ManifestationState>>` | derived `user.orfs.*` summaries |
| `read_planner: Option<Arc<ReadPlanner>>` | the certified manifested read path |

`LogView` is a captured `SegmentLocator` plus an `Arc<Mutex<SegmentCache>>`. The
cache lock is taken only to look up (or lazily open) a segment handle — a
pointer-sized critical section — never across the `pread` itself. Segments are
immutable and a segment id is never reused, so a captured locator stays valid for
every offset that was committed when it was taken.

`CoreRead` is the read-only, `Send + Sync` surface (`root`, `parent_of`,
`lookup`, `getattr`, `read_at`, `readdir`, `readlink`, `getxattr`, `listxattr`,
`seek_data_hole`). Both the live engine (`Namespace`) and the immutable view
(`ReadState`) call the **same** free functions for byte assembly
(`read_extent_from`, `planned_read_from`, …), so they are byte-identical by
construction; `Snapshot::read_view_cell` builds a frozen view over the snapshot's
own log handle.

---

## 3. When a new view is published (the commit boundary)

A new complete `ReadState` is built **only** at the authoritative commit
boundary, in `Namespace::commit_plan`, immediately after the live index has been
extended by replaying exactly the just-committed records:

```text
commit append → index.apply_range(committed records) → publish_read_state()
```

`publish_read_state` builds the new view (a cheap index clone + a locator
capture) **before** taking the publication lock, then swaps it in. Consequently:

* A reader observes either the **whole old** committed state or the **whole new**
  one — never an intermediate, partially-applied index. (Index mutation is hidden
  behind the writer's `&mut self`; the published `Arc<Index>` is a private clone.)
* The publication lock is never held during reads and never held during commit
  I/O; the commit's log work happens under the core lock, before publication.
* The view is also refreshed when a concealed plane that affects derived reads is
  (re)enabled (`enable_manifestation*`, `enable_trigram`).

The derived-index equality invariant is unaffected: `apply_record` is still the
only index mutation, so the live index equals a from-scratch rebuild, and the
frozen views are just snapshots of that index.

---

## 4. Index sharing strategy and its measured cost

The review explicitly warns against deep-cloning the whole namespace index on
every commit ("that just moves cost to writes"). OrFS therefore stores the index
in persistent (path-copying) collections so a snapshot shares almost all of its
memory with the live writer (`src/index.rs`, `src/persistent.rs`):

* `inodes: PMap<u64, Arc<Inode>>` — a **persistent treap** (immutable, `Arc`-shared
  nodes). A commit copies only the `O(log n)` nodes on the root-to-key path; every
  untouched subtree is shared with the prior snapshot.
* `children: PMap<u64, PMap<Vec<u8>, u64>>` — each directory's listing is itself a
  persistent map, so an untouched directory is shared wholesale and only the
  affected directory's entry (and its listing) is path-copied.
* `snapshots: PMap<Vec<u8>, u64>` and `checkpoints: Arc<Vec<Checkpoint>>` — the
  named-snapshot and checkpoint spines are shared too (checkpoints are appended
  copy-on-write and are rare).
* `Inode.versions: VersionHistory` — an immutable, `Arc`-linked newest-first
  version list. Appending a version is `O(1)` and shares the entire prior history;
  cloning an inode never deep-copies the version vector.
* `Inode.extents: ExtentMap` over `PMap<u64, Extent>` — the extent map is
  persistent and its overlay is incremental (`O(log E + k)`), so a file grown to
  very many disjoint extents is not re-copied on every write.

Cloning an `Index` for publication is therefore a handful of `Arc` pointer copies
— never a copy of the inode/directory spines and never a deep copy of any inode
payload. The per-commit cost is `O(log n)` path copies for the maps a commit
touches plus `O(affected)` node clones, **independent of total retained history**.

**Measured.** `evidence/performance/publish-cost.json` (Phase 27,
`benches/endurance.rs`) records sustained create/rename/unlink churn at 10k / 100k
/ 1M iterations: the direct publication step — cloning the index, exactly what
`publish_read_state` does — is **flat at ≈60 ns** at every scale (the separate
read-view/locator capture is ≈40 ns), while the per-iteration commit latency stays
within a small constant factor (p50 ≈ 53 µs at 10k iterations vs ≈ 60 µs at 1M,
over the middle 1 024-iteration window). No step is `O(history)`. The tests
`tests/concurrency_stress.rs::concurrent_readers_and_writer_never_observe_partial_state`
exercises 150 commits against 3 spinning readers and confirms bounded
interference (readers always see whole committed versions; the writer makes
progress).

### 4.1 Path-copying is now implemented (Phase 27)

Phase 19 shared inode/directory **nodes** but still copied the `HashMap` **spines**
on the mutation path, and `Arc::make_mut` on a shared inode deep-copied its
(ever-growing) version vector — so sustained churn was `O(history²)`. Phase 27
replaces the spines with the persistent [`PMap`] and the version vector with a
shared [`VersionHistory`], and makes the extent map persistent; the `O(n)` spine
copy and the per-inode version deep copy are gone. The pre-fix behaviour and the
fix's measured flatness are recorded in `evidence/performance/publish-cost.json`
and `docs/PERFORMANCE.md` §8.

[`PMap`]: crate::persistent::PMap

---

## 5. Both transports read through the view

* **Classical `fuser` transport (`src/fuse.rs`)** — every read-side handler
  (`lookup`, `getattr`, `readlink`, `read`, `opendir`, `readdirplus`,
  `getxattr`, `listxattr`, `access`, `lseek`, and the non-truncating part of
  `open`) clones the view and does no core locking. Mutating handlers still take
  the core lock. `Config::n_threads` is set to the machine's available
  parallelism so the request-dispatch loop itself is concurrent.
* **Native FUSE-over-`io_uring` transport (`src/fuse_native.rs`)** — the
  `Dispatcher` borrows the same `OrfsFuse` adaptor, so its read handlers use the
  same view; semantics cannot drift between transports.

The transport-neutral core semantics are unchanged and byte-identical: the same
`read_extent_from`/`planned_read_from` code backs both the live engine and the
view.

---

## 6. Invariants and proof obligations

| Invariant | Discharged by |
|-----------|---------------|
| A reader never observes a torn/partial state; every read returns a whole committed version | `concurrent_readers_and_writer_never_observe_partial_state` (size/bytes/row-pattern consistency across 3 readers × 150 commits) |
| Concurrent readers scale (throughput vs 1/2/4/8/16 readers) | `readers_scale_and_are_not_blocked_by_other_readers_io`; `evidence/performance/reader-scaling.json` |
| A reader is not blocked by another reader's / a writer's physical I/O | same test: a view read completes (~tens of µs) while another thread holds the core lock for ~200 ms, whereas a read taking the lock waits the whole hold |
| Concurrent read bytes equal the single-threaded path | `read_extent_from` is the single implementation; all equivalence/model/snapshot courts stay byte-identical |
| The writer makes progress under reader load | `concurrent_readers_and_writer_never_observe_partial_state` asserts the final size and a committed boundary |

The classic Loom limitations from `tests/concurrency_stress.rs` still apply (the
real shared state is OS-threaded, includes `parking_lot` primitives and real
`pread`/`fsync` I/O, and is serialised in places by Rust borrow-checking), so the
real-code stress tests are used, as before.

---

## 7. What this does *not* claim

* Reads are not lock-free in the absolute sense: obtaining the current view takes
  a shared `RwLock` for one `Arc` clone, and a cold segment handle takes the
  shared cache lock briefly. Neither is held across physical I/O.
* `n_threads` for the classical transport is set from `available_parallelism`;
  the native F2 `SessionLoop` remains a single dispatch thread (its ring carries
  requests but completion handling is serial per session), so the concurrency
  benefit there is limited by that existing design, not by any core lock.
* Full path-copying of the index spines is **implemented** (Phase 27, §4.1): the
  spines are persistent `PMap`s and the version vectors are shared
  `VersionHistory`s, so publishing a view no longer copies retained history.

---

## 8. Conflict-aware parallel preparation (Phase 31)

Phase 19 removed the global lock from **reads**. Phase 31 attacks the remaining
serialisation on the **write** side without weakening the single authoritative
order: *prepare concurrently, publish serially* (external review §6 P1).

### 8.1 The two roles

```text
  parallel PREPARATION (many threads)          serial PUBLICATION (one sequencer)
  ─────────────────────────────────────         ─────────────────────────────────
  validate · build payloads · checksums          reserve · seal · write TX_BEGIN
  extent planning · bracket metadata             write data · TX_COMMIT
  … one wave of conflict-free ops                publish root · durability barrier
```

`src/group.rs` provides the preparation engine and `src/commit.rs`
(`CommitSequencer::commit_group`, §3.2 of `docs/TRANSACTIONS.md`) provides the
serial, ordered publication. The phase deliberately does **not** parallelise the
canonical log: publication stays a single serialised append so the commit order is
unambiguous.

### 8.2 The conflict rule

Every operation is keyed by a [`ConflictKey`] — the inode id it names (which is
also a directory id for dentry operations), i.e. the per-inode/per-directory rule
of the review. `conflict_waves` greedily partitions a batch into **waves**: two
operations with the same key are never placed in the same wave, so they can never
prepare concurrently, while distinct keys prepare in one wave. A batch whose keys
all coincide therefore degrades to fully serial preparation (there is nothing to
parallelise); `tests/group_commit.rs::parallel_preparation_cannot_publish_out_of_order`
exercises exactly this.

### 8.3 Ordering guarantees

Waves execute in index order, but the prepared transactions are *returned in the
caller's input order* regardless of which wave built them
(`prepare_in_waves`), and `commit_group` publishes strictly in that order.
Consequently the ordering of dependent operations is preserved: a duplicate key
is always on a later wave than the earlier one, and both are committed in input
order. Nothing is published out of order — proven by
`parallel_preparation_cannot_publish_out_of_order` (200 ops, 4 keys) and
`conflicting_operations_are_not_reordered`.

### 8.4 What it does and does not change

* **Correctness.** A grouped run is byte-for-byte identical to a serial run
  (`group_commit_is_byte_identical_to_serial_commit`): preparation may run on many
  threads, but every authoritative byte is produced by the same serial publication
  path as a single commit. Atomicity, no-partial-visibility, monotonic roots and
  ordered replay are therefore unchanged without qualification.
* **Transport wiring (Phase 32).** The FUSE adaptors still serialise *mutating*
  requests — the core lock was deliberately kept, because parallel *preparation*
  of untrusted per-request state is future work — but they no longer take it
  **directly**. Both transports' mutating handlers (`write`, `setattr`/truncate,
  `create`/`mkdir`/`mknod`/`symlink`, `unlink`/`rmdir`, `rename`/`link`,
  `setxattr`/`removexattr`, `fallocate`, `copy_file_range`) submit a job to a
  per-mount group-commit coordinator (`src/group_commit.rs`), which drains a
  bounded batch of concurrently-arrived jobs and runs them **sequentially, in
  submission order**, under one core lock. For a `sync` mount the whole batch is
  published with durability lowered to `ordered` and covered by **one** shared
  `fsync` before any caller is acknowledged (§3.2 of `docs/TRANSACTIONS.md`), so
  the I7 contract holds while the barrier is amortised; `ordered`/`batched`
  mounts add no barrier. Because the jobs run while the worker already holds the
  core lock, a job must never re-enter the coordinator (no such path exists).
  Admission is bounded (§8.6): a submission that finds the bounded queue full
  runs on the direct path instead. With the coordinator actually installed,
  grouping is a large, consistent end-to-end win at ≥8 concurrent writers
  (`docs/PERFORMANCE.md` §11.1).

### 8.5 Invariants and proof obligations

| Invariant | Discharged by |
|-----------|---------------|
| Conflicting operations never prepare concurrently | `conflict_waves` never puts two equal keys in one wave (`conflict_waves_never_place_equal_keys_together`, `parallel_preparation_cannot_publish_out_of_order`) |
| Dependent operations keep their order | `prepare_in_waves` returns input order; `commit_group` publishes in that order (`conflicting_operations_are_not_reordered`) |
| Parallel preparation cannot publish out of order | roots strictly advance and every root is a boundary (`parallel_preparation_cannot_publish_out_of_order`) |
| Grouping does not change the log | byte- and digest-identical to serial (`group_commit_is_byte_identical_to_serial_commit`) |
| Concurrent group committers stay consistent and recover exactly | `concurrent_group_committers_land_in_order_and_recover_exactly` |
| A refused (over-capacity) submission is never dropped or falsely acked | `group_commit.rs::a_refused_job_is_handed_back_intact_for_the_direct_path` (job returned unchanged; direct path holds the core lock and keeps I7) |
| Admission is bounded by the batch bound | `group_commit.rs::admission_is_refused_once_the_queue_is_full` |
| The adaptive wait never exceeds the latency objective | `group_commit.rs::coalesce_never_exceeds_the_budget`, `coalesce_window_is_capped_by_the_objective` |
| A strictly sequential writer is never delayed | `group_commit.rs::coalesce_does_not_delay_a_sequential_writer` |

### 8.6 Adaptive coalescing and bounded admission (this phase)

Two refinements turn the transport coordinator into an *adaptive latency*
mechanism rather than a fixed-cost one.

* **Deadline-aware coalescing.** The historical blind 300 µs linger is replaced
  by `coalesce_wait` (`GroupCommitLinger::Adaptive`, the default): wait
  `min(barrier_cost, objective)` — the opportunity bounded by the barrier it
  would amortise and by the latency objective — and only when contention is
  evident (the batch already has more than one member, a backlog exists, or the
  oldest member has waited past the objective) or an arrival is expected inside
  the window (`rate × window ≥ 1`). It never waits for a mount with no shared
  barrier and never delays a strictly sequential writer. The objective bounds the
  linger the coordinator *adds*, not the request's load-induced total wait —
  bounding the total would suppress coalescing exactly when it pays most. The
  predictor is a pure function of `CoalesceInputs` and is unit-tested; a
  conservative fallback to the historical fixed linger applies until it has both
  an arrival-rate estimate and a measured barrier.
* **Bounded admission.** The submission channel is a bounded `sync_channel`
  (capacity `batch × 2`). `try_admit` never blocks: a submission that finds the
  queue full is returned *unchanged* and run on the direct path by the caller,
  under the same core lock and with its normal durability (a per-request `fsync`
  under `sync`). The overload contract is therefore: bounded queueing delay, no
  dropped or falsely-acknowledged request, and a predictable latency-vs-
  throughput envelope instead of unbounded batching. It is the only second
  serialisation point, and it takes the *same* core lock, so authoritative order
  remains a single total order; a fallback interleaves with the worker's batches
  in lock-acquisition order rather than strictly in submission order (a caller
  that cares about order blocks on each reply). Reference work and evidence:
  `tests/group_commit_adaptive.rs`,
  `tests/group_commit_e2e.rs::group_commit_overload_falls_back_without_loss`,
  `evidence/performance/group-commit-adaptive.json`, `docs/PERFORMANCE.md` §11.1,
  `scripts/container-group-commit.sh`.
