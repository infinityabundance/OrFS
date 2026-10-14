# OrFS — Operator Runbook (Phase 71)

A task-oriented runbook for operating a **Docker-only** OrFS deployment: what to
watch, how to read it, and what to do. It is an operations guide, not a
performance page — every number it quotes is already measured and committed
elsewhere, and is referenced rather than re-argued.

Scope: a single OrFS volume, mounted with the `orfs` binary inside a pinned
container. The backing directory (`volume.meta`, `or.log/`, `index/`, `.or_bloom/`)
is the source of truth; `or.log` is authoritative, everything else is derived. All
compilation, tests, and mounts run in digest-pinned images (see `README.md`,
`docs/ORFS-SPEC.md` §6).

---

## 1. Daily health: `orfs doctor` and `orfs doctor --capacity`

```sh
orfs doctor                       # capability probe: kernel/container, FUSE, io_uring, perf
orfs doctor --capacity --backing /path/to/volume [--reserve <bytes>] [--json]
```

The plain `orfs doctor` probe reports what the **host kernel/container** offers
(FUSE, `FUSE_OVER_IO_URING`, `io_uring`, PMU counters). It mutates nothing.

`orfs doctor --capacity` is the **capacity report** and is the one to watch on a
live volume. It is read-only (opening it takes no write path) and reports retained
authoritative physical bytes, live backing free space, the mount/device/filesystem,
projected growth, and a **verdict**. The full field list and the JSON envelope
(`orfs.capacity.report.v1`) are in `docs/CAPACITY.md` §10.

### Reading the verdict

| Verdict | Condition | What to do |
|---|---|---|
| `ok` | headroom ≥ reserve **and** ≥ one transaction | none |
| `warn` | `0 < headroom < reserve`, **or** headroom < one transaction | plan to grow or relocate (§5) |
| `exhausted` | `headroom == 0` (`free ≤ reserve`) | commits are being **refused** now; §5 |

`headroom_bytes = free_bytes − reserve_bytes`. With the default reserve of `0`,
`exhausted` means the device itself is full. Set `--reserve` to the free space you
want kept, and `warn`/`exhausted` track that floor instead.

`bytes_per_transaction` is a **sampled** average (up to the last 64 committed
boundaries); `estimated_transactions_remaining = headroom / bytes_per_transaction`
answers "how many more transactions of today's average size fit above the reserve".

### Watching `or.log` growth

The authoritative `or.log/` only ever **grows** (Law I, non-withdrawal — see
`docs/LIMITATIONS.md` §5/§11 and `docs/CAPACITY.md` §7): committed history is never
truncated, reclaimed, or rewritten. So `physical_bytes` rises monotonically, and
capacity planning is a matter of the *rate* (`bytes_per_transaction`) and the
retained size, never of reclamation. Log growth is the primary capacity signal;
`.or_bloom/` (optional manifested structures) is derived and rebuildable and may be
deleted to free space (§5).

---

## 2. Recovery: when to run `orfs recover`, and what it will not do

```sh
orfs recover <backing>            # report the committed boundary; quarantine an abandoned tail
orfs verify --deep <backing>      # validate and classify; opens read-only, repairs nothing
orfs inspect [--json] <backing>   # identity, segments, root, accounting
```

**When to run `recover`:** after any **unclean** event — a crash or kill, a power
loss, a container OOM-kill mid-write, or an interrupted mount — and whenever
`orfs verify --deep` surfaces a non-empty tail. `recover` re-establishes the
committed boundary and, if a *harmless uncommitted tail* exists, moves it aside
into `or.log/quarantine/` (never truncating it) and prepares a fresh writer.

**What it repairs vs. refuses** (`docs/RECOVERY.md` §1, §2, §9):

* **Repaired (recovered):** a **torn or uncommitted tail** beyond the last
  `TX_COMMIT` — classified `RetainedTail`, quarantined, committed bytes untouched.
* **Refused (never silent):** an incomplete/inconsistent commit bracket; a malformed
  *committed* record; a torn record in a **non-final** segment; a physical gap or
  duplicate segment; a committed root extending past the bytes that exist; an
  unsupported format version. A refusal is always an `Err` — `recover` never
  "repairs" committed history by guessing, and never returns a partial transaction.
* **Read-only forensics:** `orfs verify`/`orfs inspect` open `OpenMode::ReadOnly` and
  modify **not a single byte**, so a damaged-but-readable volume can be examined
  safely. The guaranteed invariant is that the committed prefix `[0, R)` is
  byte-identical before and after recovery (Phase 62 court:
  `evidence/recovery/fault-injection-verify-recover.json`, `docs/RECOVERY.md` §9).

**One honest residual.** A tail that begins **inside** the committed segment is
deliberately **retained in place and not truncated**; after recovery continues in a
fresh segment, a *later fresh open* refuses it as a "torn record in non-final
segment". No committed byte is lost or rewritten, and the CLI still reports the
correct boundary — the limitation is recorded, not hidden (`docs/RECOVERY.md` §9.1).

Do **not** hand-edit or delete anything under `or.log/`; that violates non-withdrawal
and can only destroy history. `recover` is the supported tool.

---

## 3. Expected mount/open latency as history grows

Mount and historical-open cost grows with **retained history**; it is not
constant-time (`docs/RECOVERY.md` §8). Plan capacity accordingly. The measured
figures and their honest caveats live in `docs/PERFORMANCE.md` §9.5 (the Phase-43
historical fast path) and §13 (the history-scaling court).

* **Mount recovery is `Θ(retained history)`.** Without a usable checkpoint the whole
  committed log is replayed (measured 25 ms / 103 ms / 331 ms at 500 / 2 000 / 8 000
  commits). A valid checkpoint replays only the suffix, but discovery and decode are
  still `O(index)`; a warm restart with the derived committed-root directory removes
  the whole-log *discovery* scan (at an 8 000-op / 166 MB history: **47.7 ms**
  directory-assisted vs 60.4 ms scan-only; still not constant-time).
* **Historical-root opens.** A **cold** open replays (p50 ≈ 24.4 ms); a **warm** open
  loads the persisted binary accelerator (p50 ≈ 19.5 ms) — dominated by the mandatory
  validation scan, so the accelerator's own win is modest and reported honestly. A
  **validated quick open** (`checkpoint::open_index_quick`, log *not* replayed) is
  ≈ 14.5 ms vs ≈ 47.7 ms for an audited mount at the same root; it is an opt-in fast
  path and reports `audited() == false`.
* **The binary accelerator** replaced the legacy JSON envelope (at the same
  8 017-inode index: 2.89 MB loaded in ≈ 16.0 ms vs 18.4 MB in ≈ 51.8 ms — 6.4×
  smaller, ~3.2× faster to load). This is what a warm historical open pays instead
  of a JSON parse.
* **Answering reads as history grows** (`docs/PERFORMANCE.md` §13): the
  *authoritative* read degrades sharply (p50 ×33, 711 ns → 23.2 µs) because
  non-withdrawal fragments objects; the *manifested* arm is flat once selected
  (12.83 → 12.87 µs, ratio 1.003) and wins at depth, but is a net loss at shallow
  depth. Neither the accelerator nor a manifested structure is authoritative: a
  corrupt/foreign/missing one always falls back to reconstruction.

Operationally: **keep checkpoints and the derived directory intact**
(periodically take checkpoints), and treat a long retained history as a mount-latency
cost that grows linearly unless a valid checkpoint bounds the replay.

---

## 4. POSIX operational notes

* **Hard-linking a directory returns `EPERM`.** Attempting to `link()` a directory
  is rejected with `EPERM` (not `EACCES`), matching Linux (`docs/NAMESPACE.md` §4.2;
  Phase 56, `tests/posix_extras.rs`). This is correct behaviour, not a fault.
* **Supplementary groups are enforced from `/proc`.** Both transports classify every
  permission decision with the kernel's `in_group_p` rule, reading the caller's
  supplementary groups from `/proc/<pid>/status` `Groups:` (Phase 33). If `/proc` is
  not mounted, or the caller's pid is not visible to the daemon (e.g. a different pid
  namespace), membership cannot be established and the caller is classified by its
  effective ids alone — this can **over-deny but never over-grant**
  (`docs/LIMITATIONS.md` §13). Ensure `/proc` is mounted in the container that runs
  the FUSE daemon.
* **POSIX deviations that remain.** Phase 25 closed the deviations the Phase 24
  pjdfstest run found; the only remaining pjdfstest failure is an out-of-scope node
  type and one artefact the reference ext4 run fails too. See `docs/LIMITATIONS.md`
  §12 and `docs/FUSE-SEMANTICS.md` §11.1. The gate keeps the allowlist asserted so it
  cannot silently grow.
* **`fdatasync`** has no distinct primitive and is served by the same full `sync()`
  (a strictly stronger guarantee) — stated, not faked (`docs/PROGRESS.md` Phase 56).

---

## 5. Capacity exhaustion and the read-only transition

Behaviour is ordered, typed, and never silent (`docs/CAPACITY.md` §3, §11, §13):

1. **Pre-flight refusal.** A transaction's *whole framed size* is admitted before the
   first byte is written. If it would cross the reserve, the mutation returns
   `CapacityExhausted` (`ENOSPC`) and is **not acknowledged**; **no byte is written**
   and the previous committed root is untouched. While positive headroom remains the
   volume is **not** latched read-only, so smaller transactions keep working.
2. **Read-only transition.** Only when the reserve floor is breached (zero headroom),
   or on a device error (`EIO`), does the volume latch **read-only**: the triggering
   mutation returns `ENOSPC`/`EIO` and is not acknowledged; the committed root does
   not advance; every further mutation returns `ReadOnly` (`EROFS`); **reads keep
   working** and the volume stays mountable read-only. The latch is in-memory and per
   handle — reopening re-evaluates capacity, so freeing space restores writability.
3. **Remedies are only "free space" or "larger/other device"** (exhaustion is not
   reclamation). In order: confirm the verdict; free space that is **not** OrFS
   history (delete `.or_bloom/` — derived and rebuildable; **never** trim `or.log/`);
   or relocate the whole backing directory to a larger device and `orfs verify --deep`
   there. `orfs grow` is unrelated — it expands a *concealed* body to accelerate
   reads and consumes, never frees, space.

`orfs doctor --capacity --json` reports `degraded` and `degraded_reason` so a
monitor can alert on the latch.

### 5.1 Cold-tier relocation — shrink the *local* footprint without reclaiming history

When the **local** device must hold less retained history but the history itself
must be kept, move the cold (sealed) part of it to a cheaper tier:

```sh
orfs tier relocate --backing <dir> --tier-root <cold> [--segment <id> | --all]
orfs tier list     --backing <dir>     # per-segment state, digest, home, local bytes
orfs tier verify   --backing <dir>     # re-verify every relocated segment's digest
orfs tier recall   --backing <dir>     # restore a released segment to the local store
```

Relocation moves a **copy** (`docs/TIERING.md`): the tier copy is written, fsynced,
read back and digest-verified, and only then is the local copy removed — after a
durable `Released` transition (Kafka KIP-405). It **never reclaims** and never
withdraws authority: the committed root and watermark are unchanged.

* The **active head segment is never relocatable**; only sealed (immutable) segments.
* `orfs tier list` reports the **local authoritative footprint before/after** — it
  drops — while `total_authoritative_bytes` (local + tier) is **unchanged**.
* If the cold tier is offline, a read needing a released segment returns the typed
  `TierUnavailable` and the open is **refused** — never silently shortened.
  `orfs tier verify` names the offline segments explicitly.
* A crash or an interrupted relocation is **idempotent and convergent**: re-run the
  same command. A fault in the relocation catalogue **fails closed**.

### 5.2 The bounded reclaim — free space without withdrawing authority

When the verdict is `warn`/`exhausted`, `orfs doctor --capacity` reports the
**reclaimable** bytes and a recommended action; `orfs reclaim` performs it. It
**reports by default** (dry-run); nothing happens without `--apply`. It never
touches the active head or an authoritative byte, and it proves the committed root,
digest, committed bytes, and commit watermark **byte-identical** afterwards
(`docs/CAPACITY.md` §14):

```sh
orfs reclaim --backing <dir> [--reserve <B>] [--json]                     # report (dry-run)
orfs reclaim --backing <dir> --tier-root <cold> --relocate-sealed --apply   # frees the most
orfs reclaim --backing <dir> --drop-rebuildable --apply                     # derived, no tier needed
orfs reclaim --backing <dir> --drop-derived-metadata --apply                # index/ accelerators
```

Decision tree: **relocate sealed → drop rebuildable → drop derived metadata →
grow the backing**. `--drop-rebuildable` frees EKBLOOM bodies, the trigram index,
the search directory, atlases and passthrough images (they rebuild on demand, at a
read-latency cost); `--drop-derived-metadata` frees the `index/` accelerators
(rebuilt by a full log scan on the next open). Neither touches `or.log/`,
`volume.meta`, the generation manifests/catalogue, or the relocation catalogue. If
nothing derived remains, the only remedy is a larger/other device (§5.1, §5).

**Recovery under space pressure.** If `orfs recover` is refused at the reserve with
the typed `RecoverySpaceExhausted`, the committed history is intact and fully
readable — run `orfs verify --deep` (read-only) to confirm, free space with
`orfs reclaim`, and re-run `orfs recover` (`docs/RECOVERY.md` §11). A **read-only**
open (`orfs mount --read-only`, `orfs inspect`, `orfs verify`) needs no free space
and serves all committed history even at zero headroom.

---

## 6. Where the security model lives

The security model is `docs/THREAT-MODEL.md`: **the mount is the boundary** (mounting
needs `CAP_SYS_ADMIN` and `/dev/fuse`; no setuid helper), who can do what, and — as
important — **what is out of scope** (privileged/raw-device attackers,
confidentiality/encryption, host-level DoS). Two operator-facing points:

* The on-disk checks are **integrity, not authentication** — CRC32C/BLAKE3 detect
  corruption and casual tampering, but there is no MAC, signature, or encryption, so
  protect the **backing directory more strictly than the mount**.
* The per-surface hardening, the `unsafe` audit, the vulnerability log, and the
  native-FUSE fuzzing results are in `docs/SECURITY.md`; the acceptance-gate
  definitions (gate A is non-withdrawal; gate J is recovery) are in `docs/GATES.md`.

---

## 7. Quick reference

```sh
# Health
orfs doctor                                             # capability probe
orfs doctor --capacity --backing <dir> [--reserve <B>]  # capacity report + verdict
orfs doctor --capacity --backing <dir> --json           # machine-readable (orfs.capacity.report.v2)

# Bounded reclaim (frees derived space; never withdraws authority)
orfs reclaim --backing <dir> [--json]                                  # report (dry-run)
orfs reclaim --backing <dir> --tier-root <cold> --relocate-sealed --apply
orfs reclaim --backing <dir> --drop-rebuildable --apply

# Mount lifecycle
orfs mount <backing> <mnt> --transport <fuse|fuse-uring> --backing-io <sync|uring>
orfs unmount <mnt>

# Inspect / validate / recover
orfs inspect [--json] <dir>
orfs verify [--deep] <dir>      # read-only; surfaces damage, repairs nothing
orfs recover <dir>             # quarantine an abandoned tail; refuse corruption

# Cold-tier relocation (sealed segments only; never withdraws authority)
orfs tier relocate --backing <dir> --tier-root <cold> [--segment <id> | --all]
orfs tier list     --backing <dir>
orfs tier verify   --backing <dir>
orfs tier recall   --backing <dir> [--segment <id>]

# Query (typed API, separate from POSIX reads)
orfs query <path> --pattern <bytes> [--hex] [--limit N] [--build] [--no-recurse] [--json]
```

References: `docs/CAPACITY.md` (capacity runbook), `docs/TIERING.md` (cold-tier
relocation), `docs/RECOVERY.md` (recovery states and refusals), `docs/PERFORMANCE.md`
§9.5/§13 (mount and history-scaling latency), `docs/LIMITATIONS.md` §5/§11/§12/§13,
`docs/THREAT-MODEL.md` (security model), `docs/FUSE_URING.md` (F2 transport),
`docs/FUSE-SEMANTICS.md` (POSIX semantics).

---

## 8. Pre-PR continuous verification: `scripts/container-verify.sh`

Before opening a change, run the one-command gate:

```sh
sh scripts/container-verify.sh          # full pre-PR court
sh scripts/container-verify.sh --fast   # cheap/always-available subset
```

It runs every court this project checks, **one container at a time** (the shared
`scripts/lib.sh` helpers guarantee that), prints a per-stage
`PASS`/`FAIL`/`SKIPPED` line, and exits non-zero if any stage fails:

| # | Stage | Needs |
|---|---|---|
| 1 | `check-all` (fast): fmt/clippy + docs-receipts + chart drift | Docker |
| 2 | default test suite | Docker |
| 3 | default test suite `--features failpoints` | Docker |
| 4 | POSIX court (pjdfstest + POSIX ops) | Docker + `/dev/fuse` |
| 5 | native fsx/fsstress-equivalent fault-injection court | Docker |
| 6 | `io_uring` court (integration + backing benchmark) | Docker |
| 7 | bounded Loom concurrency model | Docker |
| 8 | docs-receipts re-check (final) | host only |

`--fast` runs stages 1, 2 and 8 only — fmt/lint, docs-receipts, chart drift and
the default suite, none of which need a mount — and skips the failpoint suite and
every court that needs `/dev/fuse` or is heavy. A stage that cannot run in this
environment (the POSIX court without `/dev/fuse`, or any container stage without a
usable Docker daemon) is reported `SKIPPED (reason)` and is **not** counted as a
pass, so a green summary never hides a court that did not actually run.

This is the pre-PR entry point; `scripts/check-all.sh` remains the same cheap gate
for CI. See `docs/REPRODUCE.md` for the per-court receipt commands.

The suites regenerate evidence receipts as a side effect (which is why
`check-all` runs the docs-receipts check *before* the suite). Before the final
docs-receipts stage, `container-verify.sh` restores the tracked evidence files
that the run itself rewrote — keeping any file already modified when the run
began — so the final check validates the evidence state under review, not
throwaway timing churn, and the tree is left clean. A receipt you want to refresh
is regenerated by its dedicated court and committed, as usual.
