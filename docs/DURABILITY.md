# OrFS — Durability Qualification Beyond the Model (Phase 80)

This document specifies the Phase-80 **failure-state model**: three *named,
distinguished* failure classes, the extended fault matrix that qualifies OrFS's
durability against them, and the commit-watermark **residual window** as an
explicit, tested property. It refines `docs/POWERLOSS.md` (the Phase 17 simulated
device), `docs/LIMITATIONS.md` §6/§9, and `docs/RECOVERY.md` §5.

> **This is a simulation, not hardware.** A green court shows that OrFS's recovery
> is correct **relative to this model's assumed device semantics**. It does
> **not** prove real-hardware durability. Real block-device fault targets
> (`dm-flaky`/`dm-error`) are not usable in this environment; the receipt records
> the concrete reason (§6).

Source: `src/powerloss.rs` (model + seam). Court:
`tests/durability_qualification.rs`. Runner:
`scripts/container-durability-qualification.sh`. Evidence:
`evidence/recovery/durability-qualification.json`
(schema `orfs.recovery.durability-qualification.v1`).

---

## 1. The three distinguished failure classes

A failure class names **which volatile layer is lost**, and therefore **how many
bytes are retained**. Every class must uphold the *same* acknowledged-durability
contract; only the **unacknowledged tail** may differ.

| Class | Userspace buffers | OS page cache | Device write-back cache | Modelled by |
|---|---|---|---|---|
| **Process** | lost | **survives** | not relevant | `SIGKILL`/abort (`tests/crash_recovery.rs`) |
| **Kernel** | lost | lost | **survives** (writes may reorder) | `FailureClass::Kernel` |
| **Storage** | lost | lost | **lost** (reorder/partial/torn per profile) | `FailureClass::Storage` (`src/powerloss.rs`) |

* **Process failure** (clean-ish kill / `SIGKILL` / abort) — the *strongest* class.
  Only the process's own buffers are lost; every byte that completed a `write`
  syscall survives because the **OS page cache survives**. This is the Phase 2/11
  crash model.
* **Kernel failure** (panic / reboot) — userspace buffers **and** the OS page
  cache are lost. Bytes the **device already accepted** survive (the device
  write-back cache is *not* lost); writes may be **reordered**.
* **Storage power loss** — additionally the device write-back cache is lost, so
  only flushed bytes survive, and per the configured [`FlushMode`]/[`DurableLoss`]
  writes may be reordered, partially applied, or torn. This is the Phase 17/23
  [`SimDevice`].

**Precedence.** The set of retained bytes is monotone:
`retained(Process) ⊇ retained(Kernel) ⊇ retained(Storage)`. The court makes the
difference in retained bytes **measurable**: under the *same* workload the
`Storage` class drops the un-flushed volatile tail (`retained_volatile_bytes = 0`,
`dropped_volatile_bytes > 0`) while `Kernel`/`Process` retain it
(`retained_volatile_bytes > 0`, nothing dropped), and the recovered root obeys the
same ordering.

**An honest finding.** For OrFS, `Process` and `Kernel` retain the *same* bytes:
the commit path has no acknowledged-but-unwritten userspace data, so the two
coincide for the acknowledged contract; the model differs only in that `Kernel`
may **reorder** the retained writes. The distinction that *matters* for OrFS is
between the cache-retaining classes (`Process`/`Kernel`) and `Storage`.

---

## 2. The extended fault matrix

Behind the `powerloss` feature (inert without an attached device),
`SimDevice` adds the modes the Phase-17/23 model lacked:

| Fault mode | Profile | What it models |
|---|---|---|
| **Delayed / in-flight completion** | `DeviceFaultKind::InFlight` (on `sync`) | An operation whose completion the caller **never received**. It surfaces as `OrfsError::InFlight` (`EAGAIN`): **transient, non-latching, never durable**. |
| **Torn watermark** | `SimConfig::torn_watermark` | A device/FS that violated the atomic `write-tmp → rename → fsync` for the watermark: a **present but corrupt** image. Recovery must **fail closed** (refuse), never treat it as absent. |
| **Torn directory entry** | `SimConfig::torn_directory_entry` | A session-created file loses its **directory entry** despite an observed directory `fsync`. For a committed segment this drops a segment ⇒ refuse or recover to a valid earlier boundary. |
| **Torn interior metadata** | `SimConfig::tear_interior` | One **interior** sector-aligned block of a committed file is torn (a hole in the log's framing/record metadata, *not* the trailing edge). |
| **Reordered writes** | `SimConfig::reordered` | An honoured barrier that applies durable writes **out of order**: nothing is lost, so every acknowledged-durable mutation must still survive. |
| **Lost flushes** | `SimConfig::partial`, `reordered_partial` | A flush that did not finish: only a subset of cached sectors is promoted. Safety-only (a contract-violating device). |
| **Repeated power loss** | `run_remount_cycles` | Power-fail → recover → continue → power-fail, **N** times, with correctness asserted after each cycle. |

The metadata-tearing modes target the **metadata the log depends on** — the
watermark, a directory entry, and an interior framing sector — rather than only a
file's trailing data sector. The generation manifest / catalogue lives **outside**
the log directory, so the log-directory device does not model it; it is covered by
the manifestation courts (Phases 42/78).

`DeviceFaultKind::InFlight` is added to the Phase-23 fault injector; it does **not**
touch `Failpoint::ALL`, so the §34 crash matrix is unaffected (the same discipline
Phase 76 used for its tier-relocation failpoints).

---

## 3. Every acknowledged-durability mode

The court runs the whole fault matrix for **each** `DurabilityMode` and asserts the
*acknowledged* contract:

| Mode | Acknowledged durability point | What may be lost before it | Acknowledged data survives all classes |
|---|---|---|---|
| `sync` | every commit (segment `fsync` + watermark write) | nothing acknowledged may be lost | **yes** |
| `ordered` | an explicit `flush` / `fsync` | ordered-but-unsynced mutations, under `Storage`; they survive under `Process`/`Kernel` | **yes** |
| `batched:N` | every `N` commits (amortised `fsync`) | mutations in the current batch, under `Storage` | **yes** |

For every mode the court asserts:

* after an **acknowledged durability point**, the acknowledged committed data
  **survives every fault class** (`acknowledged_data_survived = true`);
* before it, the contract states **exactly** what may be lost (the tail), and that
  loss is either **detected (refused)** or classified as the residual window (§4);
* recovery yields the **newest valid committed generation**
  (`newest_valid_generation_selected = true`), never a silently shortened history.

The same table is emitted machine-readable as `per_mode_contract` in the receipt.

---

## 4. The commit-watermark residual window — an explicit property

The watermark (`docs/RECOVERY.md` §5) is written **after** the bytes it describes
and never rewrites committed history. On open, `watermark::validate` compares the
watermark against the surviving committed root:

| Backing state | Watermark vs. surviving root | Detection | Outcome |
|---|---|---|---|
| A committed segment is lost/truncated below the watermark | watermark **ahead** | **detected** | open **refused** (never silently shortened) |
| Durable bytes were never watermarked | watermark **at or behind** | **undetectable** | recovery proceeds to the surviving root — the documented **residual window** |

The court classifies every row with a `residual_window` field:
`none` | `detected_refusal` | `undetectable_unwatermarked_tail`. The
`residual_window` profile (`SimConfig::residual_window`) demonstrates the
undetectable case: it loses durable bytes that were never watermarked while the
watermark stays behind, and the court asserts the loss is **classified**, never
presented as a normal recovery. `silent_shortening` — recovery returning a root
shorter than the watermark certifies **without refusing** — is asserted `false`
for every row.

**Can detection be strengthened?** No, not without changing the contract, and the
receipt records `can_be_strengthened: false` with the reason. Detecting the loss of
those not-yet-watermarked bytes would require either (a) an **additional
synchronous metadata write on the acknowledgment path** — a change to the
durability contract and cost, and one that the same power cut can equally defeat —
or (b) **rewriting committed bytes**, which non-withdrawal forbids. The gap is
inherent to any scheme that cannot rewrite committed history, so it is recorded as
an explicit property rather than claimed closed.

---

## 5. What the court asserts

| Assertion | Where |
|---|---|
| The three classes uphold the acknowledged contract while the retained (unacknowledged) tail differs | `failure_classes_uphold_the_acknowledged_contract_with_differing_tails` |
| Every durability mode survives the whole fault matrix (recover-or-refuse, never partial, never silent) | `every_durability_mode_survives_the_fault_matrix` |
| An in-flight completion is never treated as durable (`EAGAIN`, non-latching) | `an_in_flight_completion_is_never_treated_as_durable` |
| Torn metadata (watermark / directory entry / interior) is detected or recovers validly | `torn_metadata_is_detected_or_recovers_validly` |
| Repeated power loss with remount cycles is correct after every cycle, never withdrawing history | `repeated_power_loss_with_remounts_recovers_each_cycle` |
| The residual window is an explicit, tested property (detectable vs. undetectable) | `the_residual_window_is_an_explicit_property` |
| The full mode × class × profile sweep writes the receipt | `write_durability_qualification_evidence` (`ORFS_DQ_SWEEP=1`) |

Every recovered row is checked for the §35 invariants: the recovered root is a
complete committed boundary; the last record is a `TX_COMMIT`/`VOLUME_GENESIS`;
all earlier committed roots remain valid; no committed byte is rewritten; and the
next transaction begins exactly at the recovered root and succeeds.

---

## 6. Real block-device fault injection — probed, not assumed

The runner re-probes whether real `dm-flaky`/`dm-error` targets over a loop device
are buildable here, in an **elevated** container (root + `--cap-add SYS_ADMIN
--cap-add MKNOD` + `/dev/loop-control` / `/dev/mapper/control` when the host has
them). The probe result is embedded verbatim in the receipt's `dm_probe` field with
the exact failing commands. On this host the pinned image ships no `dmsetup` and
exposes no `/dev/mapper/control`, so the probe records
`ran: false` and the court uses the **simulated** device — no real device fault is
injected, and none is implied. (The same probe backs `docs/RECOVERY.md` §9.)

---

## 7. Evidence and runner

`scripts/container-durability-qualification.sh` runs, one container at a time:
(1) the elevated `dm` probe; (2) the bounded always-on smoke; (3) the opt-in sweep
(`ORFS_DQ_SWEEP=1`) that writes the receipt. The Phase-80 sweep runs a matrix of **315** rows and **5** power-fail/remount cycles; **145** rows are explicit detections (refusals) and **11** are the undetectable residual window.
The receipt carries honest environment and commit fields, the three classes with
their stated assumptions, the per-mode contract, the residual property, and the
`dm_probe` result.

---

## 8. What it does **and does not** prove

**Proves (relative to the assumed device semantics):** every class — `Process`,
`Kernel`, `Storage` — upholds the same acknowledged-durability contract; the
retained, unacknowledged tail differs and is measured; recovery never exposes a
partially applied transaction, never withdraws committed history, and always
recovers to a valid committed boundary or explicitly refuses; and the residual
window is an explicit, tested property rather than a hidden gap.

**Does not prove:** real-hardware durability. The model is software with assumed
device semantics — sector-granularity caching and `fsync` behaviour are
simplifications, and real devices, filesystems, and caches differ. No real
block-device fault was injected. `DurabilityMode::claims_power_loss_durability()`
remains `false` for every profile. See `docs/LIMITATIONS.md` §6/§19.

---

## 9. Group commit preserves every contract (Phase 88)

The opt-in group-commit coordinator amortises **one durability barrier across a
batch** of concurrently-arrived mutations (and, since Phase 88, the explicit
`fsync(2)` barrier too). It changes only barrier *frequency* — never the contract.
The Phase-88 courts prove the three obligations return the same verdict under
grouping as without it:

* **Acknowledged only after the covering barrier succeeds.** A grouped append is
  acknowledged only once the batch's shared `sync` (which covers its committed
  bytes) completes; a mutation whose bytes were published but whose covering
  barrier failed is refused with `EIO`, never acknowledged. The barrier itself is
  injectable: a new `DurabilityBarrier` failpoint sits on the log-level durability
  hook (`Log::sync`), so
  `tests/group_commit_scaling.rs::group_commit_barrier_failure_is_refused_not_acknowledged`
  (`--features failpoints`) can fail the shared barrier and prove **every affected
  append is refused** (0 false successes) while the volume still reopens to a valid
  boundary. The engine-level unit court
  (`src/group_commit.rs::tests::barrier_failure_yields_eio_for_every_successful_member`)
  proves the same rule at the coordinator.
* **Survives power loss.**
  `tests/group_commit.rs::grouped_durable_acks_survive_a_power_loss` drives grouped
  `sync` commits on the **simulated power-loss device** (`src/powerloss.rs`, honest
  `FlushMode::Barrier`) and, after the simulated failure, reopens the volume: every
  acknowledged-durable member's transaction survives and its root is a valid
  boundary. The mounted court additionally reads every acknowledged append back
  byte-exact after a **daemon restart**.
* **Order preserved.** The coordinator runs each batch's members sequentially, in
  submission order, against the single authoritative core, so the visible commit
  sequence is exactly the caller's order — a total order of strictly advancing valid
  boundaries. The FIFO channel plus submission-order batches are what make an
  `fsync(2)`'s shared barrier provably cover every mutation submitted before it.

**Bounded admission, not unbounded growth.** The submission channel is a bounded
`sync_channel`; an over-capacity submission is handed back and served on the direct
path under the same core lock with its normal durability — so an overloaded caller
still gets a per-request `fsync` under `sync` (I7), never a drop and never a false
success (`tests/group_commit_e2e.rs::group_commit_overload_falls_back_without_loss`).

The same status applies as §8: these are **simulated** storage devices, not real
hardware. They prove the contract relative to the model's assumed device semantics.
