# OrFS — Simulated Power-Loss Durability Model (Phase 17)

This document specifies the **controlled, deterministic, simulated storage
device** added in Phase 17 to test what survives an *un-clean power loss* —
distinct from the process-crash model of Phases 2/11. It refines
`research/OrFS.md` §22 (durability modes), §26 (committed-root visibility), and
§37 (crash/adversarial courts).

> **This is a simulation, not hardware.** A green power-loss court shows that
> OrFS's recovery is correct **relative to this model's assumed device
> semantics**. It does **not** prove real-hardware durability. Only an
> instrumented power-loss rig (real device, real write-back cache, real power
> cut) can test real hardware. See §5.

Source: `src/powerloss.rs` (model + seam). Court: `tests/power_loss.rs`.
Evidence: `evidence/recovery/power-loss.json`.

---

## 1. Why a separate model

The fault-injection court (`tests/crash_recovery.rs`) terminates the process with
`SIGABRT` mid-write and reopens the volume. That is a strong test of OrFS's own
logic — no destructor runs, all in-memory state is gone — but the operating
system's **page cache survives a process kill**, so every byte that reached a
`write` syscall is still present. A process kill therefore cannot model:

* a volatile device **write-back cache** (acknowledged writes that reach the OS
  but not the media);
* **reordering** of cached writes;
* **partial/torn** flushes and lost sectors;
* loss of bytes that were **fsync-ed but whose device did not honour it**.

Phase 17 adds a model with exactly these failure modes.

---

## 2. The model

`powerloss::SimDevice` wraps one log directory. All log file I/O in that
directory passes through a small seam (`Segment::write_at`, `Segment::sync`,
`Segment::create`, `fsync_dir`, `watermark::Watermark::write`,
`quarantine_segment`); when no device is attached every seam call is a no-op, so
a production build behaves exactly as before. The model is compiled behind the
`powerloss` Cargo feature (on by default; `--no-default-features` compiles a
no-op stub at every seam).

Per log file the device keeps:

* a **durable image** — the bytes a power failure would retain;
* a **volatile cache** — writes not yet flushed, in issue order;
* a coarse **directory-entry** durability flag.

Semantics:

| Operation | Effect |
|---|---|
| `record_create(name)` | Registers a newly created file (its name is not durable until a directory `fsync`). |
| `record_write(name, off, bytes)` | Appends to the volatile cache **and** writes through to the real file, so in-session reads observe the latest bytes. |
| `flush(name)` (an `fsync`) | Promotes cached writes to the durable image per [`FlushMode`]. |
| `sync_dir(dir)` | Makes every present file's name durable. |
| `write_watermark(wm)` | Models the atomic `write-tmp → rename → fsync` as one all-or-nothing durable write. |
| `power_fail()` | Discards **every un-flushed cached write**, applies the configured durable damage, **materialises** the surviving durable image to the real directory, and detaches. An independent recovery step then opens the volume as a fresh process would. |

### 2.1 Configuration

```rust
pub struct SimConfig { pub seed: u64, pub sector: u64,
                       pub flush: FlushMode, pub durable_loss: DurableLoss }

pub enum FlushMode { Barrier, Partial, ReorderedPartial, Reordered }
pub enum DurableLoss { None, TearTail, LostWatermark, ReorderDurable }
```

* `Barrier` — a completed `fsync` is an **honoured durability barrier**: every
  cached write becomes durable. This is the profile under which a `sync`
  acknowledgement is expected to survive.
* `Partial` — a completed `fsync` promotes only a seeded subset of cached
  **sectors**; the rest stay cached and are lost. Models a flush that did not
  finish.
* `ReorderedPartial` — as `Partial`, with the promoted subset chosen in a
  shuffled order (models reordering across the flush). For a monotonic append
  workload the *order alone* is unobservable; combined with partial promotion it
  yields holes, which recovery must handle.
* `Reordered` (Phase 23) — an **honoured barrier that applies durable writes out
  of order**: nothing is lost, so every acknowledged-durable mutation must still
  survive. Models a device that completes and persists writes in an order other
  than issue order.
* `TearTail` — at power failure, tear (truncate) the trailing sector of every
  flushed file.
* `LostWatermark` — at power failure, lose the commit watermark (a power cut in
  the window between the segment `fsync` and the watermark `fsync`).
* `ReorderDurable` (Phase 23) — at power failure, drop a seeded subset of the
  *durable* image's sector-aligned blocks (a reordered/partially-applied durable
  write by a contract-violating device). Recovery must reach a complete committed
  boundary or refuse; assertions are safety-only.

All randomness comes from a single seeded SplitMix64 generator, consumed in a
fixed (sorted-key) order, so a run reproduces **byte-for-byte**.

---

## 3. Assumptions (precise)

1. Writes are modelled at byte granularity inside file-sized images; `sector` is
   used only to decide which bytes a partial flush persists and how much a torn
   tail loses.
2. A completed `fsync` under `FlushMode::Barrier` is an honoured barrier. This
   models a device whose documented `fsync` contract holds.
3. Under `Partial`/`ReorderedPartial`/`TearTail` the device may lose already
   `fsync`-ed bytes. That models **hardware that violated its documented
   contract**, or a power cut *during* the flush whose completion the caller
   never received. Assertions for these profiles are restricted to **safety**.
4. Directory-entry durability is coarse: a file created during a session is
   durable once a directory `fsync` is observed. OrFS `fsync`s the segment
   directory immediately after creating a segment, so created segments are
   durable.
5. The commit watermark is modelled as **atomic** (all-or-nothing), matching its
   `write-tmp → rename → fsync` implementation: it is never torn, only present
   complete, stale, or absent.
6. The model never rewrites committed bytes: the durable image is built by
   applying only *promoted* writes in issue order. A power failure can make
   history **shorter**, never different (non-withdrawal, Law I).

---

## 4. What the court asserts

`tests/power_loss.rs` runs a whole OrFS volume on the device and, for each
durability mode and each fault point, records which mutations OrFS acknowledged
as **durable** (`CommitOutcome.durable`), triggers `power_fail()`, and recovers
in an independent step.

| Assertion | Where |
|---|---|
| Every mutation acknowledged `DURABLE` under `sync` survives (all fault points, seeds 1/7/99) | `sync_durable_acknowledgements_survive_power_loss` |
| A `sync` `power_fail` leaves **no** dropped volatile bytes | same |
| `ordered` acks may be lost; recovery returns to the pre-workload boundary, never exposing unflushed data | `ordered_acknowledgements_may_be_lost_but_committed_state_is_intact` |
| `batched` acks survive up to the last completed sync point | `batched_acknowledgements_survive_up_to_the_last_sync_point` |
| **Accepted contract**: an ordered ack *without* a sync may be absent after power loss, while the explicit-`fsync` prefix and all genesis bytes stay intact | `an_unsynced_ack_may_be_lost_but_never_corrupts_committed_state` |
| Partial/reordered/tearing devices either **recover to a valid boundary** or **refuse** (no silent repair); never corrupt | `partial_and_reordered_flushes_recover_or_refuse_but_never_corrupt`, `torn_flushed_bytes_recover_or_refuse_consistently` |
| A power cut between the segment and watermark `fsync` recovers forward; the watermark is never ahead of the surviving bytes | `power_loss_between_segment_and_watermark_fsync_recovers_forward_consistently` |
| A watermark ahead of surviving bytes is **detected** (refused) or recovers to a valid earlier boundary | `a_watermark_ahead_of_surviving_bytes_is_refused_or_recovered_validly` |
| Logical content (a `Namespace` workload) is byte-exact for every surviving file; no partial file is visible | `surviving_logical_content_is_consistent_after_power_loss` |

Every recovered case is checked for the §35 invariants: the recovered root is a
complete committed boundary; the last committed record is a `TX_COMMIT` /
`VOLUME_GENESIS`; all earlier committed roots remain valid; no committed byte is
rewritten (byte-exact prefix, and pre-existing segment prefixes unchanged); and
the next transaction begins exactly at the recovered root and succeeds.

---

## 5. What it does **and does not** prove

**Proves (relative to the assumed device semantics):** OrFS never exposes a
partially applied transaction, never withdraws committed history, always
recovers to a valid committed boundary or explicitly refuses, and — under a
device that honours `fsync` — makes exactly the acknowledged-durable mutations
survive.

**Does not prove:** real-hardware durability. Real devices, filesystems, and
their caches differ; `fsync` semantics vary; the model's sector granularity and
flush model are simplifications. `DurabilityMode::claims_power_loss_durability()`
is still `false` for every profile, including `sync`: even `sync` promises only
what the backing device documents. See `docs/LIMITATIONS.md`.

---

## 6. Watermark interaction

The watermark is written **after** the segment `fsync`. The model therefore
admits two complementary cases:

* **Watermark behind the durable bytes** (`LostWatermark`): the loss of the
  not-yet-watermarked bytes is undetectable by construction — the documented
  residual window (`docs/RECOVERY.md` §5). Recovery proceeds to the durable
  committed root; the surviving watermark is at or behind it.
* **Watermark ahead of the surviving bytes** (`TearTail`, or any device that
  drops flushed segment bytes): the watermark certifies more history than
  survives. Recovery **refuses** — it never silently reconstructs a shorter log.
  When the loss is confined to the final segment's tail, recovery instead
  returns a valid earlier committed boundary.

Both behaviours are asserted; they are the two documented outcomes of §5 of
`docs/RECOVERY.md`.

---

## 7. Device-failure injection (Phase 23)

The simulated device doubles as a **fault injector** for out-of-space (`ENOSPC`)
and device-error (`EIO`) handling. A `DeviceFaultRule` names an operation
(`Write`, `Sync`, `Create`, `DirSync`, `Watermark`, `Manifest`), a kind
(`NoSpace`, `IoError`, `ShortWrite`, `SyncError`), a `skip`/`fire` count, and an
optional file suffix. The log's I/O seams consult the plan
(`Segment::write_at`/`sync`/`create`, `fsync_dir`, `Watermark::write`, and the
manifestation publish path), so a fault can be placed at a chosen point.

```rust
pub enum DeviceOp { Write, Sync, Create, DirSync, Watermark, Manifest }
pub enum DeviceFaultKind { NoSpace, IoError, ShortWrite, SyncError }
pub struct DeviceFaultRule { op, kind, skip, fire, name_suffix }
```

The court (`tests/power_loss.rs`) sweeps every write / sync / create / watermark
point and asserts that a refused authoritative mutation is not acknowledged,
does not advance the committed root, leaves earlier roots intact, recovers to a
complete committed boundary, and latches the volume read-only (`EROFS`). Optional
manifestation faults are recorded as optional failures and never fail an
authoritative commit. A `proptest` randomises the kind and point. Evidence:
`evidence/recovery/enospc.json`, `evidence/recovery/device-error.json`.

This is still a simulation: the injected errors model a device that returns
`ENOSPC`/`EIO` (or a short write / failed `fsync`), not real hardware timing.

---

## 8. Distinguished failure classes and beyond-the-model qualification (Phase 80)

Since Phase 80 the same device can simulate one of three **distinguished failure
classes** (`powerloss::FailureClass`), which differ only in how much *volatile*
state they lose — and therefore how many bytes they retain:

* **`Process`** — a clean-ish process kill: only the process's buffers are lost;
  the **OS page cache survives** (the `tests/crash_recovery.rs` model).
* **`Kernel`** — a kernel panic/reboot: userspace buffers and the page cache are
  lost; bytes the device accepted survive (the write-back cache is not lost), and
  writes may be **reordered**.
* **`Storage`** — the Phase 17/23 profile: additionally the device write-back
  cache is lost, so only flushed bytes survive.

Every class upholds the *same* acknowledged-durability contract while the
**unacknowledged tail** differs; the court makes the difference in retained bytes
measurable. The model also gains **delayed/in-flight completions**
(`DeviceFaultKind::InFlight`, a transient non-latching `OrfsError::InFlight`),
**metadata-targeted tearing** (`DurableLoss::TornWatermark`,
`TornDirectoryEntry`, `TearInterior`), and the explicit **residual-window** profile
(`DurableLoss::ResidualWindow`). These are described, with the per-mode contract
table and the residual-window property, in **`docs/DURABILITY.md`**; the court is
`tests/durability_qualification.rs` and the evidence is
`evidence/recovery/durability-qualification.json`.
