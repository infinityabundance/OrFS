# OrFS — Volume Capacity Policy and Storage Exhaustion (Phase 23)

This document specifies OrFS's **capacity policy**: how authoritative growth is
admitted, how optional (manifestation) construction is throttled, and what
happens when the backing store is full or fails. It implements `research/OrFS.md`
**I8** (*physical capacity is finite*), **§30** (*capacity, statfs, and the
visible void*), **§31** (*storage exhaustion and non-withdrawal*), and the
directive's requirement that no-write-withdrawal must never be confused with
unlimited capacity.

Source: `src/capacity.rs`, `src/log.rs`, `src/error.rs`. Evidence:
`evidence/recovery/capacity.json`, `evidence/recovery/enospc.json`.

---

## 1. The two spaces

OrFS deliberately separates two physical spaces with **different failure
semantics**:

| Space | Contents | When it runs out |
|---|---|---|
| **Authoritative** | the committed record stream (`or.log/`) and its completeness witness (`commit.watermark`) | the mutation is refused with `ENOSPC`; the volume latches **read-only** (`EROFS`) |
| **Optional (manifestation)** | EKBLOOM payloads and generation manifests under `.or_bloom/` | optional construction is **throttled and skipped**; authoritative operations are unaffected |

This distinction is a hard contract: `OrfsError::NoSpace` (errno `ENOSPC`) is
returned only for authoritative exhaustion. An optional-plane failure is recorded
as `ManifestationStatus::Failed` (or throttled away) and **never** propagates to
an authoritative commit. A test with an always-failing manifestation builder
(`recovery_adversarial::optional_manifestation_failure_never_fails_an_authoritative_commit`)
proves the authoritative commit still succeeds and is visible.

---

## 2. The policy

```rust
pub struct CapacityPolicy {
    pub reserve_bytes: u64,                        // minimum free space to keep
    pub soft_quota_bytes: Option<u64>,             // throttle optional above this
    pub hard_quota_bytes: Option<u64>,             // refuse authoritative above this
    pub authoritative_capacity_bytes: Option<u64>, // explicit authoritative bound
}
```

* **`reserve_bytes`** — a floor of free backing bytes that must remain. An
  authoritative allocation is admitted only while `used + needed` stays at or
  below `capacity - reserve`. This keeps the device (and its metadata) from
  filling completely.
* **`soft_quota_bytes`** — an optional threshold above which *optional*
  (manifestation) construction is throttled. It never refuses an authoritative
  write.
* **`hard_quota_bytes`** — an optional ceiling on total usage; crossing it
  refuses authoritative growth and latches read-only. Reaching it is an orderly
  transition, never a reclamation.
* **`authoritative_capacity_bytes`** — an explicit bound on authoritative
  history. When `None`, the log derives the bound from the backing device at open
  as `available_now + authoritative_used_now`, so the reserve is honoured against
  the **real** device. Tests set an explicit small bound for determinism.

The default policy is unbounded with reserve `0`: an unconfigured volume behaves
exactly as before (the OS `ENOSPC` remains the ultimate backstop, and is mapped
to `OrfsError::NoSpace`). The FUSE mount flag `--reserve <bytes>` sets a
reserve; `orfs stat <path>` prints the full policy and growth diagnostics.

---

## 3. Early ENOSPC detection

A transaction costs more than its payload: it is a `TX_BEGIN` record, its data
records, and a `TX_COMMIT` record, each framed with a 60-byte header and a
16-byte footer. The commit sequencer computes the transaction's **whole framed
size** up front (`CommitSequencer::projected_transaction_bytes`) and calls
`Log::ensure_capacity` **before writing the first byte**. If the space is not
admissible, the mutation returns `ENOSPC` having written nothing
(`recovery_adversarial::early_enospc_refuses_before_writing_any_byte` asserts the
physical segment bytes are byte-identical before and after the refusal).

`Log::reserve` additionally re-checks per record as a backstop, so a device that
becomes full mid-transaction is still refused rather than allowed to write a
partial transaction.

---

## 4. Throttling order

When the backing grows scarce, **optional space is sacrificed first**. Before
enqueuing any manifestation (or trigram) job, `Namespace::commit_plan` asks the
governor `optional_allowed(authoritative_used, optional_used)`. Optional
construction stops as soon as total usage would reach the soft quota or the
authoritative reserve ceiling. Therefore:

1. Optional manifestation is throttled first (and may be set to `Skipped`).
2. Authoritative commits continue to be admitted for as long as the reserve
   survives.
3. Only when the reserve itself would be breached is an authoritative write
   refused.

The order is asserted by
`recovery_adversarial::optional_manifestation_is_throttled_before_authoritative_writes_are_endangered`.

---

## 5. Read-only transition (degraded mode)

On an **unrecoverable authoritative-store failure** — out-of-space (`ENOSPC`) or
a device error (`EIO`), including a short write or a failed `fsync` — OrFS latches
the volume into **degraded / read-only** mode:

* the failing operation returns the underlying error and is **not acknowledged**;
* the committed root is not advanced;
* every earlier committed root stays valid and is never rewritten (non-withdrawal);
* every subsequent mutation returns `OrfsError::ReadOnly` (errno `EROFS`) instead
  of being accepted onto an unreliable store;
* reads continue to work (a degraded volume is still inspectable).

The latch is in-memory and per handle: reopening the volume re-evaluates capacity
against the current device, so a transient exhaustion that is relieved (space
freed) restores writability on the next mount, while a genuinely full device goes
read-only again. The failing-option path

```text
acknowledged ≠ written ≠ allocated          (I7)
authoritative exhausted  → ENOSPC, latch EROFS
device error             → EIO,    latch EROFS
optional exhausted       → throttle/skip, authoritative unaffected
```

is asserted by `recovery_adversarial::authoritative_capacity_exhaustion_transitions_to_read_only`
and by the `tests/power_loss.rs` injection sweeps (`enospc.json`, `device-error.json`).

---

## 6. Physical-growth diagnostics

`orfs stat <path>` (and `stats::PhysicalAccounting`) reports both the physical
category breakdown (`M_log`, `M_ekbloom`, `M_indexes`, …) and the capacity
policy: authoritative capacity, reserve, soft/hard quotas, authoritative bytes in
use, admissible headroom, optional bytes manifested, whether optional is
throttled, and whether the volume is degraded (with the reason). No capacity is
ever reported as unlimited in physical-safe mode.

---

## 7. Non-withdrawal

The capacity policy only ever **refuses** growth. It never truncates, reclaims,
reuses, or rewrites committed history. Exhaustion is an orderly read-only
transition, never a silent reclamation
(`recovery_adversarial::hard_quota_exhaustion_never_reclaims_authoritative_history`).
`orfs` has no authoritative garbage collector (see `docs/LIMITATIONS.md` §5), so
the physical footprint grows monotonically over a volume's lifetime; the policy
makes that growth honest and bounded, not reversible.

---

## 8. Residual limits

* The reserve and quotas bound **this** volume's authoritative history; the
  backing device may still fill from **other** tenants. OrFS then degrades on the
  OS `ENOSPC`, never silently.
* The device-derived capacity is sampled at open; a device that shrinks (or a
  shared filesystem that fills) between open and write is caught by the OS error
  and latched, not predicted.
* A watermark that cannot be written **after** the segment bytes were durably
  written leaves the durable committed root one durability point behind the
  bytes: recovery may include a mutation that was never acknowledged. That is the
  safe direction (acknowledged ⇒ survives); the converse never happens. See
  `docs/RECOVERY.md`.
