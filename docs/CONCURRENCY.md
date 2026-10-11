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
so a snapshot shares almost all of its memory with the live writer
(`src/index.rs`):

* `inodes: HashMap<u64, Arc<Inode>>` — a commit that touches a few inodes
  re-copies only those inode **nodes**; their extent maps, version history and
  xattrs are never deep-copied, and every untouched inode is shared.
* `dentries: Arc<HashMap<(u64, Vec<u8>), u64>>` — data-only commits share the
  whole directory-entry map for free; it is rebuilt copy-on-write only when the
  namespace *structure* changes.
* `children: HashMap<u64, Arc<BTreeMap<Vec<u8>, u64>>>` — an untouched
  directory's listing is shared; only the affected directory is rebuilt.

Cloning an `Index` for publication is therefore a handful of `Arc` bumps plus a
copy of the inode and directory **spines** (pointer-sized entries) — never a deep
copy of the inode payloads. The per-commit cost is
`O(#inodes + #directories)` pointer copies and a `O(#changed)` node clone; a
data-only write shares `dentries`/`children` wholesale.

**Measured.** At publication in the reader-scaling workload the index clone is
negligible next to the commits themselves; the evidence
`evidence/performance/reader-scaling.json` records the read-side numbers and
`docs/PROGRESS.md` Phase 19 records the strategy. The tests
`tests/concurrency_stress.rs::concurrent_readers_and_writer_never_observe_partial_state`
exercises 150 commits against 3 spinning readers and confirms bounded
interference (readers always see whole committed versions; the writer makes
progress).

### 4.1 Deferred: full path-copying

The current representation shares inode/directory **nodes** but still copies the
`HashMap` **spines** on the mutation path. This is a bounded, measured
intermediate: the cost is pointer copies, not deep data copies, and it is
independent of inode payload size. The planned next step is to move the spines to
a persistent (path-copying) map — e.g. a HAMT or an `Arc`-per-bucket sharded map
— so a commit copies `O(log n)` nodes rather than `O(n)` spine entries. That is
deferred (not required to remove the global read lock, and it would be a larger,
separately-measured change); no correctness property depends on it.

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
* Full path-copying of the index spines is deferred (§4.1).
