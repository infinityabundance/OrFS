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
contents, or torn sectors. Evidence:
`evidence/recovery/commit-interruption.json`, `torn-write.json`.

**Phase 17 adds a stronger model.** `src/powerloss.rs` provides a controlled,
*simulated* storage device (a configurable volatile write-back cache, reordering,
partial/torn flushes, and a `power_fail()` that discards un-flushed writes) that a
whole OrFS volume can be run on; `tests/power_loss.rs` triggers un-clean power
failures at many points and recovers independently. It closes the gap the
process-crash court could not: under a device that honours `fsync`, every
acknowledged-durable `sync` mutation survives a power failure; under
`ordered`/`batched`, an unsynced ack may be lost but committed state is never
corrupted; under hostile (contract-violating) devices, recovery either reaches a
valid committed boundary or **refuses** — never a partial transaction, never a
withdrawn byte. The model is a **simulation**, not real hardware: it proves
recovery correct relative to its assumed device semantics, not real-hardware
durability. See `docs/POWERLOSS.md`; evidence `evidence/recovery/power-loss.json`.

`evidence/recovery/segment-rollover.json` records a real mid-flight rollover.

---

## 5. Trailing-segment loss is detected by the commit watermark (Phase 12)

If the **trailing** committed segment files are physically removed or truncated
*outside* OrFS, the surviving segments still form a contiguous chain, so a pure
segment scan cannot distinguish this from a legitimately shorter log. Phase 12
closes this gap with a **durable commit watermark** (`or.log/commit.watermark`):
the committed root `R` and the physical coordinate `(segment_id,
segment_valid_len)` of the byte just before `R`, checksummed with CRC32C, written
atomically at every durability point.

On open, `watermark::validate` compares the watermark's committed root with the
root the surviving bytes support. If the watermark is **ahead**, a committed
segment has been lost or truncated and the open is **refused** (both read-only and
read-write), never silently reduced. A missing watermark (a legacy volume) is
reported as unvalidated (`Ok(None)`), not as an error, so the fix is additive.

```text
recovered scan root >= watermark root   → open proceeds (history intact)
recovered scan root <  watermark root   → Err(Corrupt): trailing committed segment missing
```

Tests: `recovery_adversarial::a_removed_trailing_committed_segment_is_detected_not_silently_recovered`,
`removing_only_the_watermark_is_tolerated_and_unvalidated`,
`an_appended_uncommitted_tail_does_not_trip_the_watermark`,
`hostile_files::truncated_final_segment_does_not_expose_committed_content`, and
the `watermark` unit tests. The watermark is written *after* the segment is
fsynced, so it can never certify more durable history than the backing store
holds. `orfs verify` reports the watermark as a check.

Residual window: because the watermark is written at durability points, a crash
between committing bytes and persisting the watermark leaves it one point behind;
loss of exactly those not-yet-watermarked bytes is undetectable. Interior segment
removal, sequence breaks, and roots dangling past present bytes remain refused as
before (§2.4).

---

## 6. Evidence

| File | Contents |
|---|---|
| `evidence/recovery/commit-interruption.json` | Per-failpoint crash-and-recover verdicts |
| `evidence/recovery/torn-write.json` | Torn/tail-producing failpoints |
| `evidence/recovery/segment-rollover.json` | A real rollover (segments, valid lengths, committed root) |
| `evidence/recovery/manifested-generation.json` | Manifested-generation recovery |
| `evidence/recovery/capacity.json` | Capacity-policy invariant verdicts (ENOSPC/latch) |
| `evidence/recovery/enospc.json` | ENOSPC injection at record/rollover/watermark points |
| `evidence/recovery/device-error.json` | EIO / short write / failed fsync injection |

---

## 7. Capacity exhaustion, device errors, and degraded mode (Phase 23)

The power-loss court models *what survives*, but not what happens when the
backing store simply **cannot accept** a write. Phase 23 adds explicit failure
handling for ENOSPC and device errors, plus a real capacity policy
(`docs/CAPACITY.md`). The acknowledged-durability contract is never weakened and
a mutation is never reported successful unless it reached its documented
acknowledgment stage (I7).

### 7.1 Out of authoritative space (`ENOSPC`)

A transaction's **whole framed size** (`TX_BEGIN` + data + `TX_COMMIT`) is
admitted *before the first byte is written*. When it cannot fit:

* the mutation returns `OrfsError::NoSpace` (errno `ENOSPC`) and is **not
  acknowledged**;
* the committed root does **not** advance;
* earlier committed roots stay valid and no committed byte is rewritten;
* the next transaction never reuses the failed bytes;
* the volume latches **read-only**, so further mutations return `EROFS`.

Tests: `recovery_adversarial::early_enospc_refuses_before_writing_any_byte`,
`authoritative_capacity_exhaustion_transitions_to_read_only`,
`hard_quota_exhaustion_never_reclaims_authoritative_history`;
`power_loss::enospc_and_eio_at_every_record_write_never_violate_acknowledged_durability`
(sweeps every write point), `enospc_at_segment_rollover_never_violates_acknowledged_durability`,
`enospc_at_the_commit_watermark_never_violates_acknowledged_durability`.

### 7.2 Device errors (`EIO`, short writes, failed `fsync`)

The simulated device can reject a write, shorten it, or fail a `fsync`, at any
authoritative point (record write, segment rollover, directory sync, watermark).
The same invariants hold: the operation returns `EIO`, is not acknowledged, and
latches the volume read-only; an optional (manifestation) failure is recorded but
**never** fails an authoritative operation. Tests:
`power_loss::a_failed_fsync_is_never_acknowledged_durable`,
`a_short_write_is_a_failure_and_never_acknowledged`,
`recovery_adversarial::optional_manifestation_failure_never_fails_an_authoritative_commit`.

### 7.3 Reordered / partially-applied durable writes

Beyond cache discard, the model can **reorder** the application of durable
writes (`FlushMode::Reordered` — a honoured barrier that applies writes out of
order: nothing is lost, so acknowledged-durable mutations must survive) and
**partially/reordered-apply the durable image** (`DurableLoss::ReorderDurable` — a
contract-violating device drops durable sector blocks; recovery must reach a
complete committed boundary or refuse, never expose a partial transaction).
Tests: `a_reordered_durable_device_never_violates_acknowledged_durability`,
`reordered_partial_durable_images_recover_or_refuse_but_never_partially_commit`.

### 7.4 Degraded (read-only) mode

On an unrecoverable authoritative-store failure the volume transitions to an
explicit **read-only** mode: further mutations return `OrfsError::ReadOnly`
(errno `EROFS`) rather than being accepted, while reads continue. The latch is
in-memory and per handle; a reopened volume re-evaluates capacity. See
`docs/CAPACITY.md` §5.

---

## 8. Recovery acceleration: mount time vs retained history (Phase 27)

Measured by `benches/endurance.rs`
(`evidence/performance/recovery-acceleration.json`). **Mount/recovery time is
`Θ(total retained history)`, not constant-time.**

* **Without a checkpoint** (the authoritative fallback, §2, §5): `mount_index`
  discovers no checkpoint and replays the entire committed log. Measured 25 ms /
  17 MB replayed at 500 commits, 103 ms / 68 MB at 2 000, 331 ms / 271 MB at
  8 000 — linear in history.
* **With a valid in-log checkpoint**: `mount_index` loads the newest valid
  checkpoint and replays only the suffix, so `bytes_replayed` collapses (to
  1.2 MB / 4.3 MB / 16.8 MB in the same runs). But discovery still performs a
  **header-only scan of the whole log** to find candidate checkpoints and the
  checkpoint's **embedded serialized index** must be decoded and self-digest
  verified. At 8 000 commits (checkpoints every 500) the checkpoint's own payload
  also inflates the log (×1.5) and the decode outweighs the skipped replay, so the
  checkpointed mount is *slower* (390 ms vs 331 ms); the win shows at 2 000
  commits (66 ms vs 103 ms). This crossover is reported honestly — it is not
  claimed that a checkpoint is always faster.
* **Phase-20 historical accelerators** (`Snapshot::open_dir` /
  `HistoricalIndexCache`): a warm open skips the replay and loads the persisted
  index; for a small index this is comparable to a suffixed replay (cold vs warm
  p50 ≈ 0.75 ms), because both decode an `O(index)` document. The materialization
  work avoided (`bytes_replayed`) is reported by the historical cache counters.

Opening `R` *distinct* historical roots whose prefixes grow with `R` costs
`O(R·L)` total; the in-memory LRU and persisted accelerator remove the replay only
for repeated access to a *given* root. The relationship is linear and is reported
as measured, never as constant-time.

### 8.1 Derived discovery and the binary accelerator (Phase 43)

Mount recovery still performs the mandatory `scan_log` validation of every
committed record, but Phase 43 removes the **additional whole-log checkpoint
discovery scan** on a warm restart:

* a **derived, append-only committed-root directory** under `index/roots/` records
  checkpoint record offsets and verified historical-index locations together with
  the committed root its completed scans covered (the **watermark**). When the
directory is complete for the prefix, `mount_index` reads the newest recorded
checkpoint offset directly instead of scanning every record header. Every
candidate it names is still read from the log and fully validated, and the suffix
is still replayed (`DiscoverySource::Catalogue`); a directory that over-claims its
bound, has a hole, or cannot be folded is distrusted (`DiscoverySource::LogScan`).
  This is the same discipline as the Phase-42 manifestation catalogue
  (`src/manifestation.rs`): fixed-size CRC32C-framed records, a `CURRENT` pointer,
  sealed segments, and folded summaries. It is derived and reconstructible, so it
  never needs to be authoritative.
* the **binary historical accelerator** (§6.1 of `docs/SNAPSHOTS.md`) replaces the
  legacy JSON envelope, so a warm historical-root open parses a small validated
  header and packed inode/directory tables rather than a large JSON document.

**Quick open vs. complete audit.** Recovery reports distinguish them explicitly
(`MountReport::discovery_source`, `MountReport::audited()`):
`DiscoverySource::ValidatedAccelerator` is a **quick open** (the log was not
replayed) and is reachable only through the deliberate `mount_index_quick`-style
entry point `checkpoint::open_index_quick`; `Catalogue`, `LogScan`, and
`FullReplay` are **audits**. Ordinary `Namespace::open` calls `mount_index`, which
is always an audit and never trusts an accelerator for the committed root.
`checkpoint::mount_index` / `checkpoint::mount_index_at` fall back to
`checkpoint::mount_index_scan` semantics (a pure whole-log audit) whenever any
derived structure is absent or untrusted, so **authoritative reconstruction is
always available and is used** rather than a fast path asserting unverified
history.

Evidence: `evidence/performance/historical-fast.json` (measured at an 8 000-op
history: directory-assisted mount vs. the pre-Phase-43 scan, a validated quick
open vs. the audited mount, and binary vs. legacy accelerator load, with an honest
note about what is and is not improved).

---

## 9. Device-fault evidence: `verify --deep` + `recover` after injected faults (Phase 62)

Section 7 injects ENOSPC/EIO and asserts the §35 invariants *in-process*. Phase 62
closes the reviewer's residual item by injecting a fault and then driving the
**real `orfs` binary** — `orfs verify --deep` and `orfs recover` — on the damaged
volume. Court: `tests/verify_recover_faults.rs` (run by
`scripts/container-fault-verify.sh`); receipt
`evidence/recovery/fault-injection-verify-recover.json`, schema
`orfs.recovery.fault-injection-verify-recover.v1`. The always-on matrix has **9**
rows; `ORFS_FAULT_SWEEP=1` adds a **24**-row sweep.

The workload is a real `Namespace` (semantically-valid typed records, so the
deep `namespace_index_rebuild` check succeeds on the committed prefix). For each
fault the court asserts:

* `verify --deep` **surfaces** the damage (a failed check, or a `tail` check that
  names a non-empty tail) and — because it opens read-only — does **not** repair
  it (the whole tree is byte-identical afterwards);
* `orfs recover` reports a **valid committed boundary** and the committed prefix
  `[0, R)` is byte-identical on disk (checked directly, not via a reopen), so no
  committed byte is rewritten, withdrawn, or invented;
* a **refusal** (e.g. a torn durable tail whose commit watermark certifies more
  history than survives) leaves the tree untouched.

| Injected fault | `verify --deep` | `orfs recover` | reopen | data intact |
|---|---|---|---|---|
| torn trailing segment (rolled over) | detects `TornRecord` | quarantine, `R` unchanged | clean | yes |
| torn record **inside** the committed segment | detects `TornRecord` | quarantine, `R` unchanged | **refused** (see residual) | yes |
| partially-persisted commit/tail (stray record) | detects `Uncommitted` | quarantine, `R` unchanged | clean | yes |
| duplicated write (trailing segment) | detects `Uncommitted` | quarantine, `R` unchanged | clean | yes |
| write error at a record boundary (ENOSPC/EIO) | clean (atomic refusal) | recovers to the last ack | clean | yes |
| reordered write (honoured barrier) | clean (nothing lost) | recovers to the last ack | clean | yes |
| torn durable tail / reordered durable blocks | detects | **refuses** | refused | n/a |

### 9.1 Residual: an intra-segment tail is retained in place

OrFS recovery is defined for a tail that occupies a **whole trailing segment**
(a torn/uncommitted write that rolled over): the segment is moved to
`quarantine/` and the volume reopens cleanly. A tail that begins **inside** the
committed segment is deliberately **retained in place and not truncated**
(`tests/log_model.rs::torn_tail_is_quarantined_not_truncated` pins this). After
recovery continues in a fresh segment, the retained bytes are no longer in the
final segment, so a *later fresh open* refuses them with
`corrupt committed state: torn record in non-final segment …`. The CLI itself
still reports the correct committed boundary and **no committed byte is lost,
rewritten or withdrawn**; the court records this as an explicit `residual` field
rather than hiding it. This is the one honest limitation of the recovery path
exercised here.

### 9.2 Device-mapper probe (`dm-flaky` / `dm-error`): not usable here

The court attempts to build a real device-mapper fault target over a loop device
(`losetup` + `dmsetup`) and records the outcome. In this sandbox `ran: false`:
`dmsetup` is not installed in the pinned image (`dmsetup: not found`, exit 127),
the default container exposes neither `/dev/loop-control` nor
`/dev/mapper/control`, and even in the elevated container (`--cap-add SYS_ADMIN
--cap-add MKNOD --device /dev/loop-control --device /dev/mapper/control`, as root)
`losetup --find --show <file>` fails with `ENOENT` (the container has no
`/dev/loop0` node). No `dm-*` result is fabricated; the fault matrix above uses
the project's deterministic simulated device (`src/powerloss.rs`) and direct
segment-byte injection instead.
