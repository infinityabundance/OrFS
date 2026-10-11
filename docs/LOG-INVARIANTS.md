# OrFS Authoritative Log Invariants (Phase 1)

**Status:** implemented (Phase 1). This document states the authoritative-log
invariants and how the Phase 1 code satisfies each. It refines
`research/OrFS.md` §2, §4, §5.4, §23; where they differ, `research/OrFS.md`
governs.

## Root-by-position

A **root** `R` is a position in the canonical logical byte stream:

```text
R = committed_end_offset
```

A root is **not** a content hash. Identity is scoped to a volume, so an external
reference is `(volume_uuid, R)`.

* `Log::committed_end_offset()` returns `R`.
* `Log::replay_upto(R)` reconstructs `L[0:R]`.
* Any `end` that is not a committed transaction boundary is rejected by
  `replay_upto`, so a root can never point into a record or an incomplete
  transaction.

## Invariants

### I1 — Authoritative non-withdrawal

Committed bytes are never overwritten, removed, reordered, or garbage
collected. The writer only ever appends at the segment frontier
(`Segment::write_at` is called at `id + valid`), and segment files are never
truncated. Logical deletion/truncation/rename are *future* record types (Plane
B), not in-place edits. Committed physical bytes are additionally proven stable
across appends and rollover by
`tests/log_model.rs::committed_bytes_never_rewritten_across_appends_and_rollover`.

### I2 — Root-by-position identity

See above. `Log::committed_digest_hex()` exists only as evidence; it is never
used as identity.

### I3 — Prefix snapshots

For every committed root `R`, `L[0:R]` reconstructs a valid committed state.
The endpoint is always a transaction boundary: `Log::boundaries()` contains the
end offset of each `TX_COMMIT` and of `VOLUME_GENESIS`, and
`Log::is_boundary(R)` is true for every published root. `replay_upto(R-1)` fails,
proving the endpoint is not a byte inside a record.

### I4 — Rebuildability

The log is the single source of truth. `scan_log` validates volume genesis,
segment framing, transaction structure, and sequence continuity purely from
`or.log/`. Index and `.or_bloom/` content is rebuildable and never load-bearing
for recovery.

### I5 — Concealed manifestation

`.or_bloom/{ekbloom,trigram,suffix,image,directory,manifests}/` and `index/` are
created by `orfs init` and accounted for physically by `orfs inspect`; they
carry no authoritative weight.

### I6 — Immutable committed generations

No acceleration structure is produced in Phase 1. Concealed generations were
implemented from Phase 7 onward (`docs/MANIFESTATION.md`) and never alter the
committed record stream.

### I7 — No false success

`orfs init` fsyncs the genesis record and the segment before returning. A record
is only part of the canonical stream once fully framed and written; the
committed root advances only after a complete `TX_COMMIT`.

### I8 — Physical capacity is finite

Reservations use checked arithmetic and surface `OrfsError::NoSpace`/overflow
paths. Phase 1 made no capacity-policy claim; Phase 23 added an explicit capacity
policy (`docs/CAPACITY.md`).

## Committed boundary rule

```text
R advances  ⇔  a complete, valid TX_COMMIT (or VOLUME_GENESIS) was appended.
```

`Log` enforces this in `finish_record`: `committed_end_offset` is updated only
for `VOLUME_GENESIS` and `TX_COMMIT`. `TX_ABORT` and ordinary records never move
it (see `aborted_transaction_does_not_publish_a_root`).

## Sequence numbers

Every canonical record has a contiguous `sequence_number` starting at `0`;
`scan_log` rejects any gap or regression (`TxMachine::accept`). On reopen the
next number to assign is the count of committed records.

## Physical / canonical distinction, and quarantine

Physical history and the canonical logical log are distinct.

* **Canonical log:** validated, committed records in logical order.
* **Physical history:** every byte on disk, including abandoned tails.

When a segment ends in a torn record, or in well-framed records that were never
published by a `TX_COMMIT`, the bytes beyond the committed root are **retained**
and the canonical stream continues in a fresh segment whose id equals the
committed root. Specifically, `Log::open(ReadWrite)`:

1. scans and validates, finding `R` and any tail;
2. if `physical_end > R`, moves every segment whose id `>= R` into
   `or.log/quarantine/` (never truncating them) and recreates a fresh, empty
   `<R>.seg`;
3. records the fresh segment as the writer at logical offset `R`.

Moving a segment changes only its *name and directory*, never its bytes; the
moved segments contain only bytes at offsets `>= R`, which are by definition
uncommitted. The tail segment that also holds committed bytes (id `< R`) is left
in place, untouched. This is verified by
`torn_tail_is_quarantined_not_truncated`.

## No silent repair (§23.1)

The scanner distinguishes and reports:

* an **incomplete final write** / malformed uncommitted tail → quarantined;
* a **corrupt committed record** (bad magic, header length, footer marker, or a
  framing fault in a non-final segment) → hard error, never skipped;
* a **missing genesis** → hard error;
* an **incompatible format version** or **unknown mandatory record type** →
  controlled compatibility error (`OrfsError::Compatibility`).

A fault in the final segment after the genesis is treated as an uncommitted
tail; the same fault in any earlier segment is corruption.

## Locator continuity

`SegmentLocator` requires extents to start at logical offset `0` and abut
exactly (`extents[i+1].id == extents[i].end()`); a gap or overlap is rejected at
construction. `locate(L)` returns `(segment id, L - id)`, or `None` for `L >= R`.
