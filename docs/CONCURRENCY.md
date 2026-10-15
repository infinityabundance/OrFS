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

---

## 9. F2 queue-affine concurrency (Phase 47)

### 9.1 The measured bottleneck

The native FUSE-over-`io_uring` session (F2) registers one entry per CPU queue
(`num_queues = num_possible_cpus()`; 16 on this host) on **one** `io_uring`
instance and, in the measured-default `single-loop` topology, services every queue
inline on the one thread that owns the ring. That thread is the entire concurrency
limit: the court times `Dispatcher::serve` alone (`NativeStats::dispatch_ns`) at
≈14–19 µs of CPU per 4 KiB read, so one thread saturates near `1/14µs` ≈ 70 k
ops/s and the profile barely scales (observed 27 k → 70 k ops/s from 1 to 32
readers). The classical transport runs `fuser`'s session with
`n_threads = available_parallelism()` (8 here) and scales accordingly.

### 9.2 The queue-affine topology

`ORFS_F2_RINGS=N` (default 0/absent = off) selects an opt-in topology: split the
CPU queues round-robin across `N` ring-owning servicer threads, each with its own
`io_uring` instance and the registered entries for exactly its queues. It is the
only topology that realises F2's parallel potential on this ABI, because the
kernel delivers a `URING_CMD` completion as task-work to the *submitting* task
(`io_uring_cmd_complete_in_task`): a single ring can only be reaped by one thread,
so parallelism has to come from *more rings*, not more waiters on one ring. Each
queue therefore has a stable owner that keeps the request's header/payload
buffers, the completion handling and the `COMMIT_AND_FETCH` reply commit local to
one CPU. There is **no** cross-thread buffer/request ownership transfer: the
`handoffs` counter is 0 for both inline topologies (the selectable worker `pool`
transfers ownership twice per request through its job queue and is measurably
worse on latency; see `docs/FUSE_URING.md` §6.2).

`ORFS_F2_ENTRIES_PER_QUEUE=K` (default 1) additionally registers `K` entries per
queue on the baseline interface, raising the kernel-side in-flight depth; `K = 1`
keeps the Phase-15..26 behaviour unchanged. Depth matters: at `K = 1` the affine
topology reached ≈54% of F0's 32-reader throughput, at `K = 4` it reached ≈73–93%
(depth was the binding constraint, not the number of rings).

### 9.3 Measured reader scaling (4 KiB direct-I/O reads)

Paired, order-balanced, 5 repetitions per level, one mount per profile alive for
the whole court (`tests/f2_concurrency.rs`, `ORFS_F2_RINGS=8`,
`ORFS_F2_ENTRIES_PER_QUEUE=4`); machine-generated in
`evidence/performance/f2-concurrency-affine.json`. ops/s (mean):

| readers | F0 | F1 | F2 single-loop | F2 queue-affine | affine / F0 |
|---:|---:|---:|---:|---:|---:|
| 1 | 27 079 | 27 169 | 27 343 | 27 901 | 103% |
| 2 | 53 955 | 54 682 | 51 606 | 56 822 | 105% |
| 4 | 100 813 | 103 063 | 71 486 | 103 448 | 103% |
| 8 | 160 346 | 162 043 | 71 546 | 141 866 | 88% |
| 16 | 182 909 | 208 228 | 72 498 | 170 821 | 93% |
| 32 | 192 696 | 173 512 | 70 365 | 179 663 | 93% |

Per-op latency (µs), pooled samples, p50 / p99:

| readers | F0 p50 | F0 p99 | F2-single p50 | F2-single p99 | F2-affine p50 | F2-affine p99 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 17.6 | 57.7 | 17.2 | 56.9 | 16.8 | 58.2 |
| 8 | 23.4 | 49.4 | 88.0 | 168.8 | 27.2 | 79.2 |
| 16 | 34.4 | 177.7 | 155.9 | 513.6 | 40.1 | 320.4 |
| 32 | 72.3 | 810.9 | 256.8 | 1549.7 | 68.0 | 811.0 |

### 9.4 Observations

* **Queue ownership is real.** The per-group record
  (`NativeStats::queue_groups`) shows all 8 ring-owning threads active and roughly
  even (2 455–5 129 requests each, summing to the 31 762 served), i.e. the kernel
  routes requests across the disjoint queue sets registered on different rings.
  The affine topology is not one hot ring with idle helpers.
* **No ownership handoff.** Every affine request is parsed, dispatched, committed
  and its buffers written by the same thread that holds the ring; `handoffs = 0`.
  The measured `wait_calls` per request is ≈0.76 (vs ≈0.25 single-loop): with the
  work spread over 8 threads, each blocking wait more often returns just one
  completion, which is expected and not a regression (the wait is idle time).
* **Shared adaptor locks become contended.** The transport-neutral `OrfsFuse`
  adaptor (handle table, lookup accounting, the metrics mutex, the read planner)
  is shared by all servicers. Per-op `Dispatcher::serve` time rose from ≈14 µs on
  one thread to ≈19–26 µs on eight — consistent with lock hand-off and cache-line
  migration on those shared structures as servicer count rises, and with the fact
  that it is affine *throughput*, not per-thread dispatch throughput, that
  improved. The same contention applies to F0's eight `fuser` threads; it is not
  F2-specific. (Attribution, not a profiler flame graph: no lock-contention
  sampling was run.)
* **Residual.** With 8 rings the kernel-side in-flight depth is still bounded by
  `num_queues × K`; asking for more rings than the 8-CPU container can usefully
  run hit an `io_uring_setup` `ENOMEM` at 16 rings here, so 8 × 2 queues is the
  practical ceiling on this host.

### 9.5 Verdict (honest)

Queue-affine servicing recovers most of the classical transport's reader scaling:
from 27–37% of F0 (single-loop) to 88–103% at 4–32 readers, at p50 parity or
better for 1/4/32 readers. It does **not** meet the strict bar of "F0-level
throughput with no p99 regression": at 8 and 16 readers the affine tail is still
worse than F0 (p99 79 vs 49 µs; 320 vs 178 µs), because each F2 request still costs
an extra kernel scheduling hop (the task-work completion of the daemon's
`COMMIT_AND_FETCH` plus the reply's own `COMMIT_AND_FETCH` submission) that F0's
direct `/dev/fuse` reply write does not pay. The win is real and large; the tail
gap is real and reported. The host is under external load, so absolute numbers
vary run to run (F0 32-reader throughput ranged 183 k–349 k across runs) while the
single-loop < affine ordering was stable.

Provenance: `tests/f2_concurrency.rs`,
`evidence/performance/f2-concurrency-affine.json`. Phase 66 extends this court to
**64 readers** and confirms it: queue-affine stays at 86–107% of F0 throughput, but
the p99 target is still unmet from 2 to 64 readers. Phase 74 adds p99.99 and the
ring's SQ/CQ counters and states the decision explicitly — **F2 queue-affine is a
throughput transport, not a latency one; use F0 for latency**
(`docs/PERFORMANCE.md` §31.1).

### 9.6 Where the dispatch cost is (Phase 84)

§9.1–§9.5 concern *reader concurrency* on the two transports. Phase 84 measures the
**serialized single-client metadata/read-write path** across transports with a
**same-device no-FUSE reference** and a **per-op decomposition**
(`tests/transport_ceiling.rs`, `docs/PERFORMANCE.md` §35,
`evidence/performance/transport-ceiling.json`). The relevant conclusion for the
transport choice: of F0's 31.4 µs/op overhead over the same-device baseline,
**~74 %** is the **irreducible kernel FUSE dispatch/VFS/scheduling residual** and
only ~25 % is daemon user-space work; F2 (single-loop and pool) makes that kernel
residual **larger** (33.8–48.8 µs/op), which is the same ordering §9.5 reports for
the tail. So dispatch, not the OrFS engine, is the transport-independent floor, and
it is why neither F1 nor F2 replaces F0 for latency. See `docs/LIMITATIONS.md` §21.

---

## 10. Bounded Loom models (Phase 70)

Phase 19 removed the global read lock and Phase 46 made group commit a ~5× win.
This section records a **bounded Loom model** that explores the interleavings of
the two synchronization protocols those phases rest on, and states precisely
what it covers and what it does not.

### 10.1 What is modelled — and what is not

The real types cannot be loom-instrumented without a large refactor: `ReadCell`
is a `parking_lot::RwLock`, the commit sequencer is serialised by Rust
borrow-checking (`&mut Volume`) rather than by a lock, and both paths perform
real `pread`/`fsync` I/O — Loom substitutes only `std::sync`-shaped primitives.
So, as the directive's explicit fallback allows, `src/sync_model.rs` re-expresses
the **minimal synchronization protocol** — the same lock order and the same
state machine — with configuration-selected primitives (`loom::sync` under
`--cfg loom`, `std::sync` otherwise). It is deliberately **not** the production
types; it **mirrors** them. This is the honest coverage boundary (§10.4), not a
claim that the models instrument the real code.

* `ReadViewCell` mirrors `ReadCell = Arc<parking_lot::RwLock<Arc<dyn CoreRead>>>`
  (`src/namespace.rs`): a writer publishes a complete `FrozenView` with one store
  under the write lock (`publish_read_state`); a reader clones the inner `Arc`
  under the read lock and drops the guard before any other work
  (`Namespace::read_view`, the FUSE read handlers), then — and only then — takes
  the shared segment-handle cache lock (mirroring `ReadState::log`'s
  `Arc<Mutex<SegmentCache>>`). The declared lock order is *publication lock →
  (release) → cache lock*, never nested.
* `GroupCommitModel` mirrors the admission/fence state machine of
  `src/group_commit.rs`: non-blocking bounded admission (`try_admit`), a worker
  that drains a batch in submission order, runs the jobs under the core lock,
  issues **one** shared durability barrier, and only then acknowledges every
  member. Its lock order is the real one — *core lock → channel/state lock*
  (`run_loop` holds `inner.core` across `execute_batch`, which sends its replies
  while the core lock is still held).

### 10.2 The invariants explored

| Model | Invariant |
|-------|-----------|
| read views | A reader never observes a torn/partial view: every loaded view is internally consistent (`FrozenView::is_consistent` — `sealed`, and every row equal to the view's `root`), so it can only be a whole committed version. |
| read views | No deadlock: every thread joins, and the publication lock is never held while the cache lock is taken. |
| group commit | A member is never acknowledged before a durability barrier covering its bytes completed (`ack_never_precedes_covering_barrier` scans the coordinator's happens-before ledger; this is I7). |
| group commit | Jobs are written in submission order (`writes_in_submission_order`), and every admitted or refused job is acknowledged exactly once (progress, no loss, no double-ack). |
| group commit | Refused submissions (a full bounded queue) are served on the direct path with their own barrier — never dropped. |

The real-code counterparts remain the OS-threaded courts: `tests/concurrency_stress.rs`
(3 spinning readers × 150 concurrent commits, and the reader-not-blocked-by-core-lock
test) and `tests/reader_scale_64.rs` (64 readers).

### 10.3 The flags and the runner

```sh
sh scripts/container-loom.sh
# == RUSTFLAGS="--cfg loom" cargo test --test loom_concurrency
```

`loom` is a `[target.'cfg(loom)'.(dev-)dependencies]` entry, so **no normal
build compiles it**, and the court `tests/loom_concurrency.rs` is `#![cfg(loom)]`,
so it is empty (and adds nothing) in a normal build — the default `cargo test`
count is unchanged. The models are deliberately tiny (2 reader threads + 1
writer; 2 submitters + 1 worker) and the search is bounded by a **preemption
bound of 2** (under which it is exhaustive, completing in ~7 s here) plus a
generous finite wall-clock cap (`LOOM_MAX_DURATION`-style, 60 s).
`ORFS_LOOM_FULL=1` lifts the preemption bound and the time cap for a longer,
unbounded-preemption search, and `ORFS_LOOM_{READERS,PUBLISHES,LOADS,SUBMITTERS,JOBS}`
override individual model sizes. The runner additionally bounds the whole run
with a finite timeout (`ORFS_LOOM_TIMEOUT`, default 1800 s).

### 10.4 The honest coverage boundary

* The model is **not** the production code. A regression in `src/namespace.rs`
  or `src/group_commit.rs` that is not reflected in `src/sync_model.rs` is not
  caught. What the court proves is that the protocol the real code implements is
  deadlock- and race-free, and it is the executable specification the real lock
  order must keep matching.
* It models no I/O, no linger/timing policy, no `parking_lot` fairness, and no
  transport topology (`n_threads`/F2). Those stay covered by the real-thread and
  mounted courts (§6, §9).
* Loom explores a **bounded** state space (≤2 preemptions by default); it is
  evidence, not a proof over unbounded histories.

## 11. Group-commit scaling for ordinary durable appends (Phase 88)

Phase 46 made the coordinator a ~5× win for *mutations*. Phase 87 then measured the
workload a WORM/append user actually issues — a 4 KiB `write(2)+fsync(2)` per
record through a real mount — and found OrFS-Rust **flat** across writers with the
coordinator off (244.8 ops/s at 1 writer, 255.4 at 64), because every `sync`
transaction took its own barrier. Phase 88 closes that: the coordinator now also
coalesces the explicit `fsync(2)` barrier, and a mounted court measures the scaling.

### 11.1 The `fsync` barrier joins the batch

`Inner::barrier` submits a **barrier member** into the current batch. The batch
executes it as a no-op (it does no work of its own) and its **one shared `sync`**,
issued after every member, acknowledges it. Because the channel is FIFO and batches
execute in submission order, that barrier covers every mutation submitted before
the call, so an `fsync(2)` is served by the same barrier as the writes it covers.
Groups off, `ordered`/`batched` mounts (no shared barrier to amortise) and
**refused admission** all fall back to the direct `core.sync()` under the core
lock — never a false success, never a silent drop. Both transports route through it
(`src/fuse.rs`, `src/fuse_native.rs`); `flush`/`fsyncdir` are not durability
barriers and keep their direct paths.

### 11.2 The measured curve (median of three runs, this host under heavy load)

4 KiB `write(2)+fsync(2)` per record, `--durability sync`, real `orfs mount`:

| writers | off ops/s | fixed ops/s | adaptive ops/s | fixed / off |
|---:|---:|---:|---:|---:|
| 4 | 155.5 | 572.3 | 342.4 | 3.68× |
| 8 | 161.6 | 1 056.5 | 671.7 | 6.54× |
| 16 | 159.4 | 1 112.1 | 660.5 | 6.98× |
| 64 | 161.1 | 867.8 | 672.5 | 5.39× |

`off` is flat; grouping **scales** (fixed ~7× at 16 writers) and reaches
~1 054 ops/s at 64 writers in the same-machine OSS comparison. The grouped arms
still issue **~1 barrier per 3.4 ops** at 8–64 writers — the batch is bounded by
how many writers can submit between two barriers, which is the **remaining loss**,
reported explicitly in the receipt's `barrier_frequency` block. Full analysis:
`docs/PERFORMANCE.md` §11.2; evidence:
`evidence/performance/group-commit-scaling.json`.

### 11.3 The contract under grouping — proved, not asserted

Coalescing changes only barrier *frequency*, never durability or order:

* **Acknowledged-after-barrier.** `tests/group_commit.rs::\
  group_commit_sync_acks_every_member_durable_in_order` and the mounted read-back
  (`tests/group_commit_scaling.rs`, every acknowledged append byte-exact after a
  daemon restart).
* **Order preserved.** The coordinator runs each batch's members sequentially in
  submission order; the committed sequence is a total order of strictly advancing
  valid boundaries (`grouped_durable_acks_survive_a_power_loss`,
  `ordering_result`).
* **Power loss.** `grouped_durable_acks_survive_a_power_loss` drives grouped `sync`
  commits on a **simulated power-loss device** and reopens: every acknowledged
  member survives, in order.
* **A failed barrier is refused.** `group_commit_barrier_failure_is_refused_not_acknowledged`
  (`--features failpoints`) fails the shared barrier and proves every affected
  append is refused with `EIO` (0 false successes) and the volume still reopens to
  a valid boundary. See `docs/DURABILITY.md` §8.

### 11.4 Bounded admission under overload

The channel is a bounded `sync_channel` of capacity `batch × 2`. A submission that
finds it full is refused **typed** and served on the direct path under the same
core lock with its normal durability. The mounted overload court (24 threads against
a capacity of 4) serves every mutation, never exceeds the bound, and reports
`direct_fallbacks > 0`; the counters are exposed in `GroupCommitStats`
(`capacity`, `admissions`, `direct_fallbacks`, `queue_depth`, `max_queue_depth`).
