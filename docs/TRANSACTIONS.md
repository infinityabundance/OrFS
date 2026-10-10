# OrFS Transactions, Commit Sequencer, and Durability (Phase 2)

**Status:** implemented (Phase 2). This document is normative for the transaction
model, the commit protocol, durability acknowledgment semantics, and the
fault-injection court of this build. It refines `research/OrFS.md` §5.3, §7, §21,
§22, §23, §34, §35 and `research/OrFS prompt.md` §7, §26, §34; where they differ,
those research documents govern.

Source: `src/transaction.rs` (model), `src/commit.rs` (sequencer),
`src/failpoints.rs` (fault injection).

---

## 1. What a transaction is

A transaction is an **ordered list of immutable records** bracketed by
`TX_BEGIN … TX_COMMIT` (commit) or `TX_BEGIN … TX_ABORT` (abandonment):

```text
TX_BEGIN            (typed payload: tx id, expected count/length)
  INODE_CREATE      ┐
  DENTRY_ADD        │ immutable data records, in order
  ...               ┘
TX_COMMIT           (typed payload: count, bracket checksum, commit sequence)
```

Records are never edited once built. Every mutation of committed state is a new
transaction appended to the log, extending history: `L_{n+1} = L_n ⊕ Δ_n`
(Law I, non-withdrawal). A failed transaction's physical bytes may remain on
disk, but they are never reused and never become visible (§6).

### 1.1 States

The model has exactly these states (`TxState`, `src/transaction.rs`):

```text
PREPARED → RESERVED → SUBMITTED → DATA_COMPLETED
        → COMMIT_COMPLETED → PUBLISHED → DURABLE
                                    ↘
                                      FAILED   (any non-terminal state may fail)
```

| State             | Meaning |
|-------------------|---------|
| `PREPARED`        | Records built and validated; nothing reserved. |
| `RESERVED`        | Append positions assigned in the log. |
| `SUBMITTED`       | Data-record bytes handed to the backing store. |
| `DATA_COMPLETED`  | Every data-record write returned. |
| `COMMIT_COMPLETED`| The `TX_COMMIT` record is fully written and validated. |
| `PUBLISHED`       | The new committed root is published in memory. |
| `DURABLE`         | Required `fsync`/directory durability completed. |
| `FAILED`          | Terminal: never becomes visible. |

Transitions are explicit, forward-only, and enforced by
`TxState::can_transition_to`. The sequencer is the only component that advances
them. The design insists on the distinction

```text
allocated ≠ submitted ≠ completed ≠ committed ≠ durable
```

— a reservation is not a write, a completed write is not a commit, and a commit
is not durability.

### 1.2 Typed payload codecs

All multi-byte fields are little-endian; every payload is CRC32C-checked and
starts with a 4-byte magic so a malformed payload is rejected rather than
guessed.

| Record      | Fixed size | Fields |
|-------------|-----------:|--------|
| `TX_BEGIN`  | 28 B       | magic `TBN1`, `transaction_id`, `expected_byte_length`, `expected_record_count`, CRC32C |
| `TX_COMMIT` | 72 B       | magic `TCM1`, `transaction_id`, `record_count`, `bracketed_byte_length`, `commit_sequence_number`, BLAKE3 bracket checksum (32 B), CRC32C |
| `TX_ABORT`  | variable   | magic `TBA1`, `transaction_id`, `reason_code`, reserved, `message_length`, UTF-8 message, CRC32C |

The **bracketed range** is `TX_BEGIN … last data record`; its byte length, record
count, and BLAKE3 digest are what `TX_COMMIT` certifies. `TX_COMMIT` is not part
of its own bracket.

### 1.3 Builder

`TransactionBuilder` validates *before* anything is reserved:

* transaction id is non-zero;
* `VOLUME_GENESIS`, `TX_BEGIN`, `TX_COMMIT`, `TX_ABORT` are refused as data
  records (they are structural);
* payloads obey `MAX_PAYLOAD_LEN`;
* `expected_record_count` and `expected_byte_length` are computed from the exact
  framed sizes (sequence numbers are fixed-width, so the sizes are known before
  assignment).

---

## 2. Commit protocol

`CommitSequencer::commit` performs exactly this sequence (`src/commit.rs`):

```text
validate → build records → reserve append positions → write data records
  → wait for required write completions → write/validate TX_COMMIT
  → publish new in-memory committed root → reply per durability mode
```

1. **Validate.** The transaction is `PREPARED` and no transaction is open.
2. **Reserve + write `TX_BEGIN`** (sequence number and transaction id stamped;
   the header checksum is recomputed).
3. **Reserve + write each data record**, in order.
4. **Build `TX_COMMIT`** from the actual bracketed bytes: record count, byte
   length, and BLAKE3 checksum. The record's own sequence number is recorded in
   its payload.
5. **Write `TX_COMMIT`, then read it back from the backing store** and re-decode
   it, re-checking the type, framing, and payload equality. Only then does the
   record count as `COMMIT_COMPLETED`.
6. **Publish.** `Log::record_written` updates bookkeeping and
   `Log::publish_root_at` advances the committed root. Publication is strictly
   after step 5.
7. **Reply per durability mode** (§3).

`TX_ABORT` path: the same bracket is written but closed by `TX_ABORT` instead of
`TX_COMMIT`; the committed root does not advance.

### 2.1 Visibility

A reader observes exactly one thing: the committed root
`R = Log::committed_end_offset()`. `R` advances only in step 6, after the
`TX_COMMIT` bytes are written and validated, so `R` always sits on a transaction
boundary (`L[0:R]` is a complete committed state). A reader can therefore never
observe a partially applied transaction. A root is a *position*, never a hash.

---

## 3. Durability modes and acknowledgment semantics

The three profiles differ in **contract**, not merely performance. In every
profile the reply means "the transaction is committed and visible"; they differ
in what durability is promised.

| Mode | Mechanism | Ack state | What the reply guarantees |
|------|-----------|-----------|---------------------------|
| `sync` | write + `fsync` of the segment (and of any new segment's directory entry) before replying | `DURABLE` | The transaction's bytes are durable as far as the backing filesystem's `fsync` guarantees extend, so it survives a process crash and — subject to the device's documented cache behaviour — a power loss. |
| `ordered` | writes submitted in order; root published after they complete; **no** `fsync` by the commit | `PUBLISHED` | Ordering and visibility only. Durability is established later by an explicit flush/`fsync`. |
| `batched` | as `ordered`, with one `fsync` amortised over up to `batch_size` transactions | `PUBLISHED`, or `DURABLE` when the commit completes a batch | Ordering and visibility; a transaction becomes durable when its batch's sync point is reached (batch full, or an explicit flush). |

### 3.1 Honesty

A buffered-write acknowledgment is **not** a power-loss durability guarantee,
and OrFS never reports it as one:

* `DurabilityMode::claims_power_loss_durability()` returns `false` for every
  profile — even `sync` promises only what the backing device documents;
* `CommitOutcome.durable` is `true` only when an `fsync` actually completed
  during that commit;
* performance results must always name their durability profile
  (`research/OrFS.md` §22).

`O_SYNC`/`fsync` semantics are honoured by the `sync` profile and by
`CommitSequencer::flush`. `fsync` on a file does not make its directory entry
durable, so segment creation always follows a directory `fsync`.

---

## 4. Fault injection (the fault-injection court)

`src/failpoints.rs` provides named injection points, compiled out by default
behind the `failpoints` Cargo feature:

```sh
cargo test --features failpoints
```

Injection points (`Failpoint`):

| # | Name | Where |
|--:|------|-------|
| 1 | `before_reservation` | before the first reservation of a transaction |
| 2 | `after_reservation` | after a reservation, before any byte is written |
| 3 | `during_record_write` | mid-record (a torn record) |
| 4 | `after_partial_record_write` | after a data record, transaction incomplete |
| 5 | `before_commit` | before the `TX_COMMIT` record |
| 6 | `during_commit_record_write` | mid-`TX_COMMIT` (a torn commit) |
| 7 | `after_commit_completion` | commit written, before in-memory publication |
| 8 | `before_publication` | immediately before publication |
| 9 | `after_publication_before_sync` | published, before the required sync |
| 10 | `during_segment_rollover` | at the start of segment rollover |
| 11 | `during_directory_sync` | during a directory `fsync` |

Runtime control is **thread-local** (so parallel tests never interfere) and comes
from the environment (`ORFS_FAILPOINT`, `ORFS_FAILPOINT_ACTION` =
`error|abort`, `ORFS_FAILPOINT_SKIP`) or programmatically
(`failpoints::configure`, `configure_one`, `clear`). The `abort` action calls
`std::process::abort()`; the `error` action returns `OrfsError::Failpoint` and
requires the log to be discarded.

### 4.1 Process crash is not power loss

The crash court (`tests/crash_recovery.rs`) terminates a **child process** with
`SIGABRT` at each injection point and then reopens the volume in an independent
step. This is a genuine, strong test of OrFS's own logic — no destructor runs, no
user-space buffer is flushed, all in-memory state is gone — but the operating
system's page cache survives, so every byte that reached a `write` syscall is
still present. It does **not** model storage-device reordering, lost write-back
caches, or torn sectors. Power-loss durability is a separate proof obligation,
to be discharged with a controlled virtualized storage fault model executed
through the prescribed container workflow; it is not claimed here.

(`tests/transaction_model.rs` additionally exercises the `error` action
in-process: the write path is terminated, the log discarded, and the volume
reopened.)

---

## 5. Recovery

Reopening a crashed volume (`Volume::open(..., ReadWrite)`) scans the physical
segments, validates framing, transaction structure, and sequence continuity,
locates the last complete `TX_COMMIT` (or `VOLUME_GENESIS`), and establishes the
canonical committed root. Bytes beyond that root — torn records and well-framed
uncommitted records — are **retained** (moved to `or.log/quarantine/`, never
truncated) and new writes continue in a fresh segment whose id equals the
recovered root. Consequently the next transaction begins exactly at the
recovered root: failed bytes are never reused.

---

## 6. Invariants and proof obligations

After every recovery, all of the following must hold (`research/OrFS.md` §35).
Each is a machine-checked verdict produced by `tests/support::verify_recovered`
and recorded per failpoint in `evidence/recovery/*.json`.

| Invariant | Discharged by |
|-----------|---------------|
| The recovered root `R` is a complete transaction boundary. | `every_failpoint_leaves_a_valid_recoverable_root`, `process_crash_at_every_failpoint_recovers_to_a_valid_boundary`; `Log::is_boundary`. |
| All previously committed roots remain valid. | Same tests (`previously_committed_roots_still_valid`). |
| No uncommitted record is exposed as authoritative. | Same tests (`no_uncommitted_record_exposed`); the recovered prefix ends in `TX_COMMIT`/`VOLUME_GENESIS`. |
| No committed record was rewritten. | `no_committed_record_rewritten` (logical prefix) and `committed_physical_bytes_unchanged` (byte-exact segment prefixes). |
| The next transaction does not reuse failed bytes. | `next_transaction_does_not_reuse_failed_bytes` (begin offset == recovered root). |
| A reader never observes a partial transaction. | `root_does_not_move_until_commit_and_never_exposes_a_partial_transaction`; publication is the last step of the commit protocol. |
| The `TX_COMMIT` bracket checksum matches the bracketed bytes. | `commit_advances_the_root_to_a_transaction_boundary_and_records_typed_payloads`; `transaction::verify_bracket`. |

Randomized transaction/failpoint sequences (proptest) assert the same verdicts
across generated workloads and durability modes.

### 6.1 Explicit non-claims (Phase 2)

* No `io_uring` submission/completion ordering is implemented yet; the commit
  path uses synchronous `pwrite`/`fsync`. Ring W (`research/OrFS.md` §9) is a
  later phase.
* No power-loss (device-cache) evidence is produced; only process-crash evidence.
* `batched` amortises `fsync` but batching is per-sequencer, not yet the
  multi-writer coalescing of Ring W.
* Payload semantics for the *data* record types (inode, dentry, extent) belong to
  Plane B and are opaque here; only the three structural payloads are interpreted.
