# OrFS — Recovery States, Modes, and Invariants (Phase 11)

This document specifies how OrFS opens an existing volume after an interruption,
a corruption, or an adversarial modification, and what guarantees hold
afterwards. It refines the directive's §23 (*recovery*, *no silent repair*), §34
(*fault-injection court*), and §35 (*recovery and historical invariants*). The
authoritative-log invariants themselves are in `docs/LOG-INVARIANTS.md`; this
document covers the *classification and refusal* decisions layered on top.

---

## 1. Opening a volume

`Log::open(dir, segment_size, mode)` (and `Volume::open`, `Namespace::open`)
first **scans** the segments with `scan_log`, which validates framing, transaction
structure, sequence continuity, and typed brackets *without modifying anything*.
It then acts according to the open mode:

| Mode | Behaviour | Use |
|---|---|---|
| `OpenMode::ReadWrite` | A recoverable uncommitted tail is **retained** and a fresh writer is prepared at the committed root. Committed bytes are never touched. | Ordinary mounts. |
| `OpenMode::ReadOnly` | The scan validates and classifies but **not a single on-disk byte is modified**. This is the **degraded/read-only recovery mode**: a damaged-but-readable volume can be inspected without altering it. | `orfs inspect`, `orfs verify`, snapshot mounts, forensic reading. |

Both modes run the *same* validation; they differ only in whether a retained tail
is moved aside. A read-only open on a volume with an abandoned tail reports the
tail and leaves it in place, byte-for-byte.

### Recovery disposition

`Log::recovery()` returns the explicit classification of what was observed:

```rust
pub enum RecoveryDisposition {
    Clean,                                    // the log is exactly the committed prefix
    RetainedTail { kind, abandoned_bytes, quarantined },
}
```

`Clean` means there was nothing beyond the committed root. `RetainedTail`
distinguishes a `TornRecord` (a partially written record) from `Uncommitted`
(well-framed records that were never published by a `TX_COMMIT`), reports how many
physical bytes were retained, and whether a writable open moved them aside.

Callers no longer have to *infer* the state from `committed_end_offset` vs the
physical end; the classification is explicit and machine-readable.

---

## 2. The four cases

Recovery distinguishes exactly the cases the directive requires. Two are
**recovered**, two are **refused**; a refusal is always an `Err`, never a
successful open.

### 2.1 Harmless uncommitted tail — *recovered*

* A **torn record**: fewer bytes than a whole frame, or a header/footer checksum
  that does not validate, in the **final** segment.
* **Uncommitted records**: well-framed records after the last `TX_COMMIT`.

The committed root is the end of the last complete `TX_COMMIT`; the tail bytes
are beyond it and are never exposed as authoritative content. A writable open
retains the tail (moving only segments entirely at or above the root into
`or.log/quarantine/`, never truncating them) and continues in a fresh segment at
the committed root. Reported as `RetainedTail`.

Tests: `hostile_files::torn_tail_is_classified_as_a_harmless_uncommitted_tail`,
`recovery_adversarial::an_uncommitted_but_framed_record_is_a_retained_tail`.

### 2.2 Incomplete commit / inconsistent bracket — *refused*

A `TX_COMMIT` whose typed payload, bracket checksum, or record count disagrees
with the records actually bracketed is a **hard** error (`TxFault::Hard`), even in
the final segment. The log is never interpreted on a guess (§23.1).

Tests: `tests/transaction_model.rs`, `tests/log_model.rs`.

### 2.3 Malformed *committed* record — *refused*

A fully-framed, correctly-checksummed committed record whose typed payload is
invalid or out of domain (for example a directory entry named `..`, an
`INODE_CREATE` with an unknown kind, or an xattr with a NUL name) is corruption.
It is refused rather than indexed, so a hostile record can never inject an illegal
name or value into the live namespace.

Test: `recovery_adversarial::malformed_committed_record_is_refused_not_repaired`.

### 2.4 Corruption — *refused*

Refused at open time:

* a torn or malformed record in a **non-final** segment;
* a **physical gap** — an interior segment file removed, detected by the
  `SegmentLocator`'s contiguity rule (`extents[i+1].id == extents[i].end()`);
* a **duplicate** segment id;
* a committed root that extends **beyond** the canonical bytes that physically
  exist (a defensive invariant added in Phase 11);
* an **unsupported format version** or an unknown **mandatory** record type →
  `OrfsError::Compatibility`.

Tests: `recovery_adversarial::a_physical_gap_between_segments_is_refused`,
`unsupported_format_version_in_a_committed_record_is_refused`,
`hostile_files::torn_record_in_a_non_final_segment_is_corruption`.

---

## 3. §35 recovery and historical invariants

After **every** successful recovery:

| Invariant | Enforcement |
|---|---|
| `R_recovered` is a complete committed transaction boundary | `scan_log` only advances `committed_end_offset` on a complete `TX_COMMIT`/`VOLUME_GENESIS`; `is_boundary` holds |
| All committed roots up to that point remain valid | every `TX_COMMIT` end is a boundary; `replay_upto` succeeds for each |
| No uncommitted record is exposed as authoritative content | the committed prefix ends at a `TX_COMMIT`; later bytes are a `TailInfo`, never in the prefix |
| No previous committed record is rewritten | the writer only appends; quarantine moves files, never truncates; verified by copying the pre-open tree |
| No invalid bloom is selected for ordinary reads | manifested structures are version-qualified and certified; an absent/stale/corrupt one falls back to the authoritative extent read (`docs/EKBLOOM-INTEGRATION.md`) |
| The reconstructed namespace matches the namespace at the recovered root | `Index::from_log` replays exactly the committed prefix; recovery is byte-exact against a live handle |

These are hard correctness requirements and are asserted directly in
`tests/recovery_adversarial.rs` and `tests/crash_recovery.rs`.

---

## 4. Fault injection: process crash is not power loss

The fault-injection court (`tests/crash_recovery.rs`, `--features failpoints`)
arms a failpoint with the `abort` action inside a child process, kills it with
`SIGABRT` mid-write, then reopens the volume independently and checks the §35
invariants. This is a genuine, strong test of OrFS's own logic — no destructor
runs and in-memory state is gone — but the OS page cache survives a process
kill, so it does **not** model storage-device reordering, lost write-back cache
contents, or torn sectors. Power-loss durability is a separate, identified proof
obligation (`docs/TRANSACTIONS.md`). Evidence:
`evidence/recovery/commit-interruption.json`, `torn-write.json`.

`evidence/recovery/segment-rollover.json` records a real mid-flight rollover.

---

## 5. Known recovery limitation: trailing-segment loss

If the **trailing** committed segment files are physically removed *outside
OrFS*, the surviving segments still form a contiguous chain, so recovery cannot
distinguish this from a legitimately shorter log. OrFS then reconstructs the most
recent **surviving** complete boundary — a strictly earlier, but still *valid*,
committed root — and does **not** fabricate, reuse, or resurrect any byte. No
*invalid* committed state is produced, but the removed transactions are gone and
the reduction is not reported as an error.

Interior segment removal, sequence breaks, and committed roots dangling past
present bytes **are** refused (§2.4). Closing the trailing-segment gap would
require a durable physical-end/segment watermark updated on every commit; that is
a deliberate design and performance tradeoff, recorded here and in
`docs/LIMITATIONS.md`.

---

## 6. Evidence

| File | Contents |
|---|---|
| `evidence/recovery/commit-interruption.json` | Per-failpoint crash-and-recover verdicts |
| `evidence/recovery/torn-write.json` | Torn/tail-producing failpoints |
| `evidence/recovery/segment-rollover.json` | A real rollover (segments, valid lengths, committed root) |
| `evidence/recovery/manifested-generation.json` | Manifested-generation recovery |
