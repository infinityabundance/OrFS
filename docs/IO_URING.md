# OrFS Asynchronous Backing I/O (`io_uring`) — Phase 5

**Status:** implemented (Phase 5). This document is normative for the backing-store
`io_uring` engine (research §17 **Domain A only**, §20 Rings W/R, §21, §22, §26).
The FUSE transport is **unchanged**: OrFS still speaks traditional `/dev/fuse`
(transport profile **F1**, not F2). Only *backing* I/O becomes asynchronous.

Sources: `src/uring.rs` (the sole `io_uring` interface), `src/buffers.rs`
(registered-buffer lifetime tracking), `src/log.rs` (I/O routing),
`src/commit.rs` (unchanged commit protocol, now driven through the engine).

---

## 1. Scope: Domain A only

Research §17 distinguishes two independent uses of `io_uring`:

| Domain | What it accelerates | This phase |
|--------|---------------------|-----------|
| **A — backing store** | authoritative writes, immutable reads, `fsync` | **implemented** |
| B — FUSE-over-`io_uring` transport | kernel↔userspace request transport | **Phase 10** (see `docs/FUSE_URING.md`) |

Using `io_uring` for backing I/O does **not** enable FUSE-over-`io_uring`, and
OrFS never claims it does. `--transport fuse-uring` now requests the Phase 10
F2 transport, which negotiates at runtime and falls back cleanly to F1/F0 when
the kernel does not enable it (see `docs/FUSE_URING.md`).

The logical bytes written and read are identical to the synchronous path; the
equivalence test (§8) proves it byte for byte.

---

## 2. Architecture

```text
 FUSE (/dev/fuse, unchanged)
        │
 Namespace (transport-neutral core, unchanged)
        │
 Log  ── io: BackingEngine ──┬── BackingEngine::Sync   (pread/pwrite + fsync)
                             │
                             └── BackingEngine::Uring { Ring W, Ring R }
                                        │             │
                                authoritative   concurrent immutable
                                writes + fsync   reads (batch)
```

* **Ring W (authoritative writer).** The single commit sequencer is the only
  logical writer. Every authoritative append and every durability `fsync` is
  submitted through Ring W; each completion is validated before the sequencer
  advances (research §21: `allocated ≠ submitted ≠ completed ≠ committed ≠ durable`).
* **Ring R (read engine).** Immutable-segment reads (`Log::read_range`,
  `TX_COMMIT` read-back) run through Ring R, a *separate* ring so reads never
  contend with authoritative submissions. `Log::read_range` issues the
  per-segment reads of a range as one concurrent batch.

Rings are created lazily and only when requested: `orfs mount --backing-io uring`
→ `MountOptions.backing_io` → `fuse::build_core` → `Namespace::enable_backing_io`
→ `Volume::enable_backing_io` → `Log::enable_uring` → `BackingEngine::engage`.
The default (`--backing-io sync`, and every existing test) leaves the engine on
the synchronous path, so no behaviour changes unless io_uring is asked for *and*
successfully engaged.

### 2.1 Measured, not assumed, ring sizes

`UringConfig` defaults to a **write depth of 32** and a **read depth of 64** with
**4 staging buffers of 256 KiB** (`src/uring.rs`). These are deliberately small
and reflect the workload, not a rule of thumb:

* The commit sequencer is single-threaded and submits synchronously, so Ring W
  never needs a deep queue; 32 is comfortably above any batch the sequencer
  issues (~4 records per transaction).
* Ring R must accommodate the concurrent reads of one range, which spans a small
  number of segments; 64 is a safe bound.
* Research §20 forbids "a fixed number of rings or workers without measurement";
  we therefore start with the documented small configuration and record the
  chosen values in evidence. A depth sweep is listed as follow-up (§10), not
  asserted here.

---

## 3. Ordering — the mechanism chosen and *why*

> **Rule.** Submitting a write SQE before an `fsync` SQE does **not** order them.
> `io_uring` may execute them concurrently, and the `fsync` may complete before
> the write is even issued. (This is stated verbatim in the `io-uring` crate's own
> `Fsync` documentation.)

OrFS therefore never relies on submission order. Two explicit mechanisms are used:

1. **Completion barrier (default commit path).** Every authoritative write is
   submitted with `submit_and_wait`, and its CQE is validated before the next
   step. The `TX_COMMIT` is written and read back only after the data writes have
   *completed*; the `fsync` is issued only after the commit record has completed.
   The ordering is established by *waiting for completions*, not by submission
   order. This is the mechanism the Phase 2 commit protocol already depends on,
   so no protocol change is required.

2. **`IOSQE_IO_DRAIN` barrier (explicit, measured).** When a durable point must be
   clamped after a group of writes that were submitted together,
   `UringEngine::write_then_fsync_ordered` and `UringEngine::fsync_order_barrier`
   flag the `fsync` SQE with `IOSQE_IO_DRAIN`: the kernel does not start it until
   every earlier SQE on the ring has completed. `write_then_fsync_ordered` submits
   the write and the `fsync` in the *same* batch and verifies from the completion
   order that the `fsync` did not complete first — this is machine-checked, not
   asserted (`OrderedReport::fsync_after_write_every_round`).

`Log::sync` (used by `DurabilityMode::Sync` and `batched`) uses the drain barrier,
so a durable point is clamped over every previously submitted write.

**Why not `IOSQE_IO_HARDLINK`?** A hard link continues to the next SQE *even when
the current one fails*, which would let a dependent operation proceed after its
dependency failed. OrFS requires failure-sensitive dependency handling: a failed
write must abort the dependent commit, not silently continue. Ordering is
therefore achieved by completion barriers / `IO_DRAIN`, never by `HARDLINK`.

---

## 4. Completion handling

Every SQE carries a stable, monotonic `user_data` (`EngineState::alloc_ud`), and
every CQE is matched back to its operation. `run_entries` drains the CQ until all
requested completions have been seen; a completion for an op not in the current
batch is stashed as an *orphan* and returned by a later wait (used by
cancellation). The following are handled explicitly:

| Case | Handling |
|------|----------|
| negative CQE result | decoded via `classify_completion` → `Retry`/`Cancelled`/`Failed(errno)` |
| short write (positive, `< requested`) | `advance_write` loops, re-submitting the remainder at `offset + done`; the original reservation is preserved (the prefix is never rewritten) |
| zero-progress write (`Done(0)`) | hard error (`WriteZero`) — never a silent success |
| short/partial read | `advance_read` loops; `Done(0)` (EOF) is a hard error |
| `-EINTR` | retried in place; submissions also retry on `ErrorKind::Interrupted` |
| `-ECANCELED` | surfaced as an error, never treated as success |
| queue saturation | batches are capped at the ring depth; a full SQ surfaces `WouldBlock` rather than dropping work |
| orphan/late completions | stashed and matched by `user_data`; counted in `orphan_completions` |
| resource exhaustion at setup | `ENOSYS`/`EPERM`/`EACCES`/`EMFILE`/`ENOMEM` → a human-readable reason → **fallback** (§6) |

`UringStats` records `submits`, `completions`, `short_writes`, `short_reads`,
`orphan_completions`, and `depth`; the equivalence and benchmark evidence capture
them (e.g. 120 003 submissions / 120 003 completions / 0 orphans in the bench run).

---

## 5. Buffer lifetimes and registered buffers

`src/buffers.rs` makes the async buffer rule explicit and machine-checked:

* `BufferPool` owns a fixed set of **page-aligned, zeroed** buffers at stable
  addresses; `AlignedBuffer` is `Send` (it owns its allocation outright).
* A `Pin` borrows the pool, so **the pool cannot be dropped while any pin
  exists** — the borrow checker enforces the strongest form of the rule.
* `Pin::begin_op`/`end_op` bracket each operation: a pinned buffer is "pinned
  while schedulable or in-flight", and `BufferPool::try_release` refuses release
  while anything is pinned or in flight.
* The engine's write path **stages** every write through a pinned buffer and
  releases the pin only *after* the completion has been collected. Cancellation
  is never treated as proof-of-safety: `wait_for`/`drain` collect the CQE first.
* With `io_uring_register_buffers` the staging buffers are **registered** and
  written with `WriteFixed`; if registration is unavailable the same buffers are
  written with plain `WRITE` (registration is a performance hint, never a
  correctness requirement). `Drop` unregisters before the pool frees.

Tested (in-crate, `src/buffers.rs`): exclusive/reusable pins, release refused
while pinned or in-flight, monotonic op ids, page alignment and zeroing.

---

## 6. Fallback (honest, runtime, reported)

`io_uring` availability is *probed at runtime* (`uring::probe_available`) — ring
creation plus a required-opcode probe. If it fails, `Log::enable_uring` keeps
`BackingEngine::Sync` and returns a `UringReport { engaged: false, reason: Some(..) }`.
Nothing is silently pretended:

* `orfs mount --backing-io uring` prints the real outcome from `fuse::run`.
* `orfs doctor` reports `backing io_uring available: yes/no (<reason>)`.
* `OrfsMount::backing_io_used` is the engine actually in use, never a guess.

### 6.1 Container seccomp: proven, not assumed

On this host the **default** Docker seccomp profile (`scripts/container-test.sh`)
blocks `io_uring_setup` with `EPERM`; `--security-opt seccomp=unconfined` permits
it. This was proven with `scripts/uring-probe.c`:

```text
default profile:        io_uring_setup: FAIL errno=1 (Operation not permitted)
seccomp=unconfined:     io_uring_setup: OK fd=3 features=0x3ffff
```

`scripts/container-uring-test.sh` re-runs that probe at the start and only adds
`--security-opt seccomp=unconfined` when the default profile is found to block
io_uring. It exports `ORFS_REQUIRE_URING=1`, which turns any fallback into a test
failure, so a green run proves io_uring really engaged.

---

## 7. Backpressure and fairness

* Queues are **bounded**: every batch is capped at the ring depth, and a full SQ
  is an explicit `WouldBlock`, never a drop.
* **Optional work cannot starve authoritative commits.** Ring W is a separate
  ring from Ring R, and Ring W submits only request-by-request from the sequencer.
  Reads (Ring R) run on their own ring. There is currently no background
  "optional" workload sharing Ring W.
* Work in flight is bounded by the pool size (writes) and the batch cap (reads),
  so a slow device applies backpressure through `submit_and_wait` rather than
  unbounded growth.

---

## 8. What is verified

`cargo test` (default container, io_uring blocked) and
`scripts/container-uring-test.sh` (io_uring live) run `tests/uring_integration.rs`:

| Test | Checks |
|------|--------|
| `equivalence_sync_vs_uring_is_byte_identical` | a 24-transaction workload through Ring W yields the **same root, the same BLAKE3 digest, and byte-identical committed bytes** as the synchronous path; also exercises Ring R (`read_range`) with agreement |
| `ordering_write_fsync_is_not_reordered` | `write_then_fsync_ordered` reports `fsync_after_write_every_round == true`; the bytes are visible after reopen |
| `short_write_retry_simulation_preserves_offset` | the production write loop retries shorts at `[0, 17, 57]` for a 100-byte write delivered as `17,40,43`; zero-progress, `EINTR`, `ECANCELED`, and over-report are all handled |
| `large_write_is_byte_identical_to_sync` | a 900 KiB write (larger than one staging buffer, so it chunks through the pool) equals the synchronous write byte for byte |
| `cancellation_and_teardown_are_safe` | a blocked read is canceled, its `-ECANCELED` completion is observed, and teardown drains |
| `fallback_is_honest_and_the_log_still_works` | when engagement fails it carries a reason; the log still commits and reads |
| `probe_matches_engagability` | `probe_available()` agrees with real ring construction |

In-crate unit tests cover `classify_completion`, short-write/read advancement,
the zero-progress error, and buffer-pool lifetimes.

Evidence (machine-generated):
* `evidence/correctness/uring-equivalence.json` — roots/digests/bytes equality,
  engine depth and registered-buffer count (written **only** from a real io_uring
  run, i.e. with `ORFS_REQUIRE_URING=1`).
* `evidence/performance/backing-uring.json` — sync vs uring, single-op vs batched.

---

## 9. Measured results (honest interpretation)

From `evidence/performance/backing-uring.json`
(kernel `7.2.9-2-cachyos`, container, page-cache-resident scratch files, 4 KiB
records, 20 000 appends, 40 000 random reads):

| Workload | sync | uring (1 op/submit) | uring (batched @ depth) |
|----------|-----:|--------------------:|------------------------:|
| sequential append | 8002 MB/s | 1239 MB/s | 4046 MB/s |
| random read | 15901 MB/s | 1430 MB/s | 4813 MB/s |

Interpretation, stated plainly:

* For **cache-hot, 4 KiB, one-op-at-a-time** I/O the synchronous `pread`/`pwrite`
  fast path is the fastest option; per-operation `io_uring` submit+wait costs more
  than one syscall's fast path. This is expected and honestly reported.
* **Batching recovers most of the gap** (3.3× append, 3.4× read over single-op
  uring) and is the case where io_uring is designed to win — deeper queues and
  higher-latency devices, which this sandbox cannot measure.
* These are **submission micro-benchmarks**, not device-durability benchmarks:
  no `fsync` is in the timed loop, and the durability profile is irrelevant to
  the number. The benchmark identifies its workload (record size, op counts,
  cache residency) so it can be reproduced.

The numbers are not a claim that `--backing-io uring` is faster on every
workload; they are the measured truth in this environment, including where the
synchronous path wins.

---

## 10. `unsafe` inventory

All `unsafe` is confined to the `io-uring` FFI contract, each block justified:

| Location | Invariant |
|----------|-----------|
| `squeue::SubmissionQueue::push` (`uring.rs`) | the buffer referenced by the SQE outlives the submission; the function collects every requested completion before returning |
| `job.buf.as_mut_ptr().add(..)` / `as_ptr().add(..)` (`read_batch`/`write_batch`) | indices are unique per round; the slices outlive the call |
| `Submitter::register_buffers` | iovecs point at pool buffers that outlive the ring's use; unregistered before the pool frees |
| `alloc_zeroed`/`dealloc` (`buffers.rs`) | one allocation, freed exactly once with the matching layout |
| `unsafe impl Send for AlignedBuffer` / `BufferPool` | the owner has exclusive ownership of its allocations; moving it transfers that ownership |
| `libc::pipe`/`close` (test) | returns valid fds; closed once |

---

## 11. Explicit non-claims (Phase 5)

* **Domain B** (FUSE-over-`io_uring`) is implemented in Phase 10 as a native
  transport adapter (discovery, negotiation, codec, and the `io_uring` command
  layer); it does not engage on the development host. See `docs/FUSE_URING.md`.
* **Ring B** (asynchronous bloom persistence) is not implemented; no acceleration
  structure is written in this phase.
* The commit sequencer still writes record-by-record to preserve the Phase 2
  fault-injection court; batched submission is provided and measured but is not
  yet the default commit path.
* Read concurrency is realized for multi-segment `read_range` and for the batch
  API; the current FUSE transport serializes core access, so cross-*file* read
  concurrency is not yet exercised end to end.
* A ring-depth / staging-size sweep is follow-up work; the chosen values are the
  documented small starting configuration.
