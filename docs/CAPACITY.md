# OrFS — Volume Capacity Policy and Storage Exhaustion (Phase 23; operator runbook Phase 68)

This document specifies OrFS's **capacity policy**: how authoritative growth is
admitted, how optional (manifestation) construction is throttled, and what
happens when the backing store is full or fails. It implements `research/OrFS.md`
**I8** (*physical capacity is finite*), **§30** (*capacity, statfs, and the
visible void*), **§31** (*storage exhaustion and non-withdrawal*), and the
directive's requirement that no-write-withdrawal must never be confused with
unlimited capacity. Phase 68 adds the operator-facing report
(`orfs doctor --capacity`), the pre-flight `CapacityExhausted` refusal, and the
runbook in §9–§13.

Source: `src/capacity.rs`, `src/log.rs`, `src/error.rs`, `src/volume.rs`,
`src/main.rs` (`doctor --capacity`). Evidence: `evidence/recovery/capacity.json`,
`evidence/recovery/enospc.json`, `evidence/recovery/capacity-guard.json`.

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

### 3.1 The pre-flight backing guard (Phase 68)

`Log::ensure_capacity` now measures the **live** backing free space
(`statvfs`) — not the capacity snapshot taken at open — and refuses a transaction
whose framed size plus the configured reserve would not fit, **before the first
byte is written**. The refusal is the typed `OrfsError::CapacityExhausted
{ needed, admissible }` (errno `ENOSPC`). It is **non-latching** while positive
headroom remains (so a smaller transaction that still clears the reserve still
succeeds and the previous committed root is untouched); when the reserve floor
itself is breached (zero headroom) the volume latches **read-only** first. This
is the operational guardrail against a surprise `ENOSPC` mid-commit; see §11.

`Volume::init_with_reserve` (the `orfs init --reserve <bytes>` flag) performs the
same check before creating anything, refusing (`CapacityExhausted`) when the
framed genesis record plus the reserve cannot fit.

The **recovery edge** of a nearly-full backing is proven by
`tests/fault_enospc.rs` (Phase 72; `evidence/recovery/fault-enospc.json`): a
volume is filled to ~90/95/99/100% of its usable capacity, a `write + fsync` is
either committed cleanly or refused with a typed `ENOSPC` leaving the previous
committed root byte-identical and the volume read-only, and a crash at the edge
then `recover` selects the newest valid committed generation — see
`docs/RECOVERY.md` §7.1.

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
read-only again.

The Phase-68 live guard (`§3.1`) latches the same read-only state when the
reserve floor is breached (zero headroom). A reserve-crossing refusal that still
leaves positive headroom does **not** latch: it is a single predictable refusal
(the transaction is too large for the remaining headroom), and smaller
transactions continue to commit. The failing-option path

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
  backing device may still fill from **other** tenants. The Phase-68 live guard
  (`§3.1`) now **predicts** that (measuring free space before the write) instead
  of discovering it only as an OS `ENOSPC` mid-write; the OS error remains the
  ultimate backstop.
* The device-derived capacity is sampled at open for optional throttling and
  reporting; the pre-flight guard uses the **live** free space, so a device that
  shrinks (or a shared filesystem that fills) between open and write is refused
  predictably before the first byte.
* A watermark that cannot be written **after** the segment bytes were durably
  written leaves the durable committed root one durability point behind the
  bytes: recovery may include a mutation that was never acknowledged. That is the
  safe direction (acknowledged ⇒ survives); the converse never happens. See
  `docs/RECOVERY.md`.

---

## 9. What non-withdrawal implies for an operator

OrFS has **no authoritative garbage collector** (`docs/LIMITATIONS.md` §5):
committed history is never overwritten, truncated, reused, or reclaimed, so a
volume's physical footprint grows **monotonically** for the whole lifetime of the
volume. `L_{n+1} = L_n ⊕ Δ_n` holds forever. The direct operational consequence
is that **the backing store will eventually fill**, no matter how much space it
starts with, and the only capacity policy OrFS can apply is to *refuse* growth
(never to reclaim).

This is a deliberate law, not a bug. The capacity policy exists so that the
eventual exhaustion is:

* **visible** — `orfs doctor --capacity` reports the projected growth and the
  headroom that remains;
* **predictable** — a transaction that would cross the configured reserve is
  refused with a typed `ENOSPC` *before any byte is written*, not discovered as
  a partial or mid-record failure; and
* **orderly** — when the reserve floor is breached the volume transitions to an
  explicit read-only mode, with reads preserved.

The disks-fill-forever property means the operator's job is to **plan the growth
curve**, not to expect reclamation. `doctor --capacity` is the planning tool.

---

## 10. `orfs doctor --capacity` — the report

```sh
orfs doctor --capacity --backing /path/to/volume [--reserve <bytes>] [--json]
```

The plain `orfs doctor` capability probe is unchanged; `--capacity` selects the
capacity report (and requires `--backing`). The report is read-only — opening the
volume takes no write path. It contains:

| Field | Meaning |
|---|---|
| `physical_bytes` | Retained authoritative physical bytes: the committed segment files (`or.log/*.seg`) plus `commit.watermark`. |
| `segment_count` | The number of log segments. |
| `authoritative_bytes` | The committed frontier (the committed end offset `R`). |
| `free_bytes` | Bytes available to an unprivileged writer on the backing filesystem, via `statvfs` (`f_bavail * f_frsize`). |
| `mount_point`, `device`, `filesystem` | The backing mount identity, resolved from the inode's `st_dev` and `/proc/self/mountinfo`. |
| `reserve_bytes` | The reserve in force: the `--reserve` override, or the policy reserve. |
| `headroom_bytes` | `free_bytes − reserve_bytes` (saturating). |
| `transaction_count` | Committed transactions, excluding genesis. |
| `bytes_per_transaction` | Projected growth: the average framed bytes per committed transaction, **sampled** from up to the last 64 committed boundaries. `null` with no history. |
| `estimated_transactions_remaining` | `headroom_bytes / bytes_per_transaction` — how many more committed transactions of *today's average size* fit above the reserve. |
| `verdict` | `ok` / `warn` / `exhausted` (below). |
| `degraded`, `degraded_reason` | Whether the volume has latched read-only, and why. |
| `policy` | The capacity policy in force (reserve, quotas, explicit bound). |

### 10.1 The verdict

The verdict is computed against the (configurable) reserve:

| Verdict | Condition | Meaning |
|---|---|---|
| `ok` | headroom ≥ reserve and headroom ≥ one transaction | comfortable headroom |
| `warn` | `0 < headroom < reserve`, or headroom < one transaction | thin headroom — plan to grow or relocate |
| `exhausted` | `headroom == 0` (i.e. `free ≤ reserve`) | commits will be refused (read-only until space is freed) |

With the default reserve of `0`, `exhausted` means the device itself is full
(`free == 0`). A non-zero reserve (the FUSE mount flag `--reserve`, or the
`--reserve` argument here) makes the verdict flip earlier: set the reserve to
what you want kept free, and `warn`/`exhausted` track it.

### 10.2 `--json`

The JSON form is a stable envelope with the schema `orfs.capacity.report.v1`:

```json
{ "schema": "orfs.capacity.report.v1", "orfs_version": "0.2.0",
  "status": { "volume": "…", "verdict": "ok", "reserve_bytes": 0,
              "free_bytes": 104472592479, "headroom_bytes": 104472592479,
              "physical_bytes": 8287, "authoritative_bytes": 8287,
              "segment_count": 1, "transaction_count": 0,
              "bytes_per_transaction": null,
              "estimated_transactions_remaining": null,
              "mount_point": "/backing", "device": "/dev/nvme0n1p1",
              "filesystem": "ext4", "degraded": false,
              "degraded_reason": null, "policy": { … } } }
```

---

## 11. The pre-flight refusal (`CapacityExhausted`)

Before a commit appends anything, `Log::ensure_capacity` checks the transaction's
whole framed size (`TX_BEGIN` + data + `TX_COMMIT`) against the **live** backing
free space minus the reserve. If it would cross the reserve:

* the mutation returns `OrfsError::CapacityExhausted { needed, admissible }`
  (errno `ENOSPC`) and is **not acknowledged**;
* **no byte is written** — the previous committed root is untouched and the
  transaction is abandoned cleanly (`tests/capacity_guard.rs` asserts the root is
  intact and that a subsequent, smaller transaction still commits);
* the volume is **not** latched read-only while positive headroom remains, so
  smaller transactions keep working.

Only when the reserve floor itself is breached (zero headroom) does the volume
latch read-only; from then on further mutations return `EROFS` until space is
freed and the volume is reopened.

This is distinct from:

* `OrfsError::NoSpace` — an *explicit* capacity / hard-quota breach, or an OS
  `ENOSPC` surfaced by a write/`fsync`; this **does** latch read-only; and
* an optional-plane (manifestation) failure, which is throttled/skipped and never
  fails an authoritative commit.

---

## 12. Growing or relocating the backing store

Because exhaustion is not reclamation, the remedies are only: **free space** or **a
larger/other device**. In order:

1. **Confirm the verdict.** `orfs doctor --capacity --backing <dir> --reserve <R>`
   with the reserve you want to keep free. `ok` needs no action; `warn` means the
   growth curve is about to meet the reserve; `exhausted` means commits are being
   refused now.
2. **Free backing space that is *not* OrFS history.** Optional (manifested)
   structures are derived and rebuildable; removing `.or_bloom/` frees physical
   space without touching authoritative history. A volume's authoritative `or.log/`
   must **never** be trimmed by hand (non-withdrawal; see §7).
3. **Relocate the volume to a larger device.** OrFS is path-based: stop the mount,
   copy the whole backing directory (`volume.meta`, `or.log/`, `index/`,
   `.or_bloom/`) to the larger filesystem, and mount from the new path. The bytes
   are unchanged, so the copy is exact; `orfs verify --deep` on the new path
   confirms the authoritative structure and a deterministic namespace rebuild.
4. **Point the mount at a larger volume** (a fresh `orfs init` on the new device)
   when the goal is to start a new history rather than extend the old one.

`orfs grow` is unrelated to capacity: it expands the *concealed* (optional)
manifested body of an object to accelerate reads, and it consumes, never frees,
space.

---

## 13. The read-only transition, step by step

When the backing can no longer accept authoritative bytes (zero headroom above the
reserve, or a device error), the volume latches **read-only**:

1. The triggering mutation returns `ENOSPC` (capacity guard) or `EIO` (device
   error) and is not acknowledged.
2. The committed root does not advance; no committed byte is rewritten.
3. Every further mutation returns `OrfsError::ReadOnly` (errno `EROFS`).
4. **Reads keep working** — a read-only volume is still fully inspectable and
   mountable read-only.
5. The latch is in-memory and per handle: `orfs doctor --capacity` reports
   `degraded: true` with the reason. Reopening (re-mounting) re-evaluates capacity,
   so freeing space restores writability. The remedy is §12.

This is the *only* failure mode when the store is full: an orderly, typed refusal,
never a partial transaction, a silent truncation, or a reclamation of committed
history.
