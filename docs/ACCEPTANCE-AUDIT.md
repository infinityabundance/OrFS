# OrFS — Independent Acceptance Audit (gates A–N)

**Auditor role:** adversarial, independent.
**Method:** verify by running, from a pristine checkout, in-container only.
**Audited revision:** `79cc421` (`phase12: consistent bench workload names and evidence/doc refresh`).
**Date:** 2026-10-11.

Every gate below cites the concrete artifact (test / evidence file / command output) that
proves it. A doc claim with no backing test or run is called out as a finding. Nothing here
is transcribed from the project's own reports.

---

## 1. Clean-checkout reproducibility (headline)

A fresh clone was made to `/mnt/1tb_kingston/.orfs-audit` (parent contains the sibling
`EKBLOOM`, matching the absolute `file:///mnt/1tb_kingston/EKBLOOM` pin), and the repo's own
scripts were run from it inside the pinned container.

| Attempt | Command | Result |
|---|---|---|
| Pristine | `scripts/container-reproduce.sh` (empty `CARGO_HOME`) | **FAIL** — `failed to get ekbloom: revspec '255452e1a803080de99f7a18aaef840c8c835209' not found` |
| Cache-seeded | `. scripts/lib.sh && docker_run sh -c 'CARGO_NET_OFFLINE=true cargo build --release && cargo test --release'` | **PASS** — 220 tests, 0 failed; fmt + clippy clean |

Cause: `Cargo.toml:41` pins `ekbloom` to git rev `255452e1…`, which **no longer exists** in
`/mnt/1tb_kingston/EKBLOOM` (HEAD is now `708c349…`). The original tree only builds because
`.cargo-home/git/db/EKBLOOM-6b6990a7e0157fc0` still caches the deleted object. The 220-test
figure is reproduced (and `--features failpoints` gives 225, including the crash court), but
**not from a genuinely pristine environment**.

Two secondary reproducibility defects were also found:

* `scripts/lib.sh:24` resolves `ORFS_PROJECT_DIR` with `dirname "$0 2>/dev/null || echo ."`.
  The `/` inside `2>/dev/null` corrupts the argument, so `dirname` returns garbage and the
  script silently falls back to `$PWD`. The scripts only work when invoked with cwd = project
  root (the documented usage); invoked any other way they silently operate on the wrong tree.
* Cloning outside the mount parent breaks the absolute EKBLOOM pin (expected but undocumented
  in a reproducible way).

### Container courts (all pass, **one container at a time**)

| Court | Result |
|---|---|
| `tests/fuse_integration.rs` (kmount) | 2/2 passed — real `/dev/fuse` mount |
| `tests/fuse_uring.rs` (kmount) | 3/3 passed |
| `tests/snapshot_fuse.rs` (kmount) | 1/1 passed |
| `tests/performance_court.rs` (kmount) | 1/1 passed, 214.73 s |
| `tests/uring_integration.rs` | 7/7 passed; `scripts/uring-probe.c` → `io_uring_setup: OK fd=3` |
| `benches/{backing_io,mechanisms}` | completed; regenerated `backing-uring/mechanisms/ekbloom-frontier.json` |

> **Contention hazard.** Four pre-existing OrFS containers were found hung in
> `performance_court`/`fuse_integration` and are **unkillable** (`docker stop`/`rm -f` →
> “did not receive an exit event”, i.e. uninterruptible kernel sleep). Running multiple
> kmount containers concurrently appears to be the trigger; a single kmount container
> completes cleanly (verified). The auditor did not create these and cannot remove them.

---

## 2. Per-gate verdicts

| Gate | Verdict | Proving artifact |
|---|---|---|
| **A** Genuine non-withdrawal | **PASS** | `tests/log_model.rs::committed_bytes_never_rewritten_across_appends_and_rollover`, `torn_tail_is_quarantined_not_truncated`; `evidence/recovery/torn-write.json` (`no_committed_record_rewritten=true`, `committed_physical_bytes_unchanged=true` at all 3 failpoints) |
| **B** Valid historical roots | **PASS** | `tests/log_model.rs::every_published_root_is_a_complete_transaction_boundary`; `evidence/correctness/committed-roots.json` (24 roots, each a `TX_COMMIT` boundary; all invariants true) |
| **C** Log-only reconstruction | **PASS** | `tests/log_model.rs::replay_from_committed_prefixes_is_deterministic`; `evidence/correctness/log-replay.json` (`distinct_replays_agree=true`), `namespace-rebuild.json` |
| **D** Transaction atomicity | **PASS** | `tests/transaction_model.rs::root_does_not_move_until_commit_and_never_exposes_a_partial_transaction`; `tests/concurrency_stress.rs` |
| **E** Real FUSE functionality | **PASS** | `tests/fuse_integration.rs` 2/2 under `docker_run_kmount` in the clean checkout; `evidence/correctness/posix-results.json` 18/18. Gap: `pwrite`(indirect)/`chown`/`utimens`/`fdatasync`/`mmap` |
| **F** Correct io_uring execution | **PASS** | `tests/uring_integration.rs` 7/7 (ordering, CQE/error handling, short-write retry, cancel/teardown, sync/uring byte-equivalence, honest fallback); `evidence/correctness/uring-equivalence.json`; `evidence/performance/backing-uring.json` |
| **G** Real historical snapshots | **PASS** | `tests/snapshot_model.rs` (10) + `tests/snapshot_fuse.rs::snapshot_mount_is_read_only_and_historical` (passed under kmount); `evidence/correctness/snapshot-equivalence.json` |
| **H** Concealed manifestation | **PASS** | `tests/manifestation.rs` (version-qualified generations, recovery selects newest valid & ignores torn, drop-all rebuild identical); `evidence/recovery/manifested-generation.json` (published 2/recovered 2/rejected 0, blake3 payloads) |
| **I** EKBLOOM correctness | **PASS** | `tests/ekbloom_read.rs` incl. `proptest_planned_equals_authoritative`, `compatible_certified_path_serves_an_exact_read`; `evidence/correctness/ekbloom-read-equivalence.json`. **Caveat:** no workload accelerates — `ekbloom-frontier.json` shows the planner served 2000/2000 4 KiB reads via `logical-extent` (fallback) for every profile |
| **J** Recovery | **PASS** | `tests/crash_recovery.rs` 2/2 with `--features failpoints` (SIGABRT at every failpoint) + `tests/recovery_adversarial.rs`; `evidence/recovery/{torn-write,commit-interruption,segment-rollover}.json`. Caveat: process-crash court only; power-loss is an explicit open obligation |
| **K** Physical accounting | **PASS** | `evidence/performance/manifestation-accounting.json` (`m_total == on_disk_total_bytes == 13646`, `totals_match=true`) |
| **L** FUSE-over-io_uring | **PARTIAL** | `src/fuse_uring.rs`; `tests/fuse_uring.rs` 3/3; `evidence/performance/fuse-uring.json`, `fuse-uring-ring.json`. **Not active** — `/sys/module/fuse/parameters/enable_uring = N`; plus `io-uring 0.7.15` cannot set `sqe->len`, and `fuser 0.18` hides the `/dev/fuse` fd. Only negotiation + fallback can be demonstrated on any host here |
| **M** Reproducibility | **FAIL** | See §1. Pristine clone cannot resolve the dangling EKBLOOM pin; passes only with a pre-seeded cache. `scripts/lib.sh` project-root resolution is also broken |
| **N** Measured advantage | **PASS** | Committed `evidence/performance/{sequential-read,random-read,append-write,fuse-baseline,mount-replay}.json` exactly back `docs/PERFORMANCE.md` (e.g. sequential-read conventional 27256 / F0 2916 / F1 2475 / E1 1.9 MB/s), and reproduce from the clean checkout (F0 2576 MB/s). No superiority is claimed; E1 is slower and the frontier never beats authoritative — so the evidence is genuine but the *objective* (speed up reads by manifesting) is not met |

---

## 3. Documentation completeness

All **12 required documents exist**: `ORFS-SPEC`, `ON_DISK`, `LOG-INVARIANTS`,
`TRANSACTIONS`, `FUSE-SEMANTICS`, `IO_URING`, `FUSE_URING`, `EKBLOOM-INTEGRATION`,
`RECOVERY`, `SECURITY`, `PERFORMANCE`, `LIMITATIONS` (plus `MANIFESTATION`, `NAMESPACE`,
`PROGRESS`, `QUERY`, `SNAPSHOTS`). **No required document is missing.**

Findings:

* **`docs/ORFS-SPEC.md` is stale and self-contradictory.** Its phase table marks phases
  4–12 **planned**, and its document-set table marks `FUSE-SEMANTICS`, `IO_URING`,
  `FUSE_URING`, `EKBLOOM-INTEGRATION`, `RECOVERY`, `SECURITY`, `PERFORMANCE`, `LIMITATIONS`
  as **planned / not written** — all of which exist and are implemented. This is the
  declared master index, so the drift is material.
* `README.md` marks phases **11 and 12 as “—”** while `PROGRESS.md` marks them Complete.
* `PROGRESS.md` counts are stale: Phase 11 says 215 (default) / 220 (failpoints) and
  “21 unsafe sites”; the tree actually yields 220 / 225 and **22** unsafe sites.
* `FUSE_URING.md` §7 is titled “two blockers” whereas `LIMITATIONS.md` §4 lists three.
* Normative claims otherwise carry test/proof obligations; e.g. `ORFS-SPEC.md` §6 promises
  “no performance or correctness claim not backed by evidence”, which holds for the
  mechanisms/perf docs.

## 4. Evidence completeness vs directive §39

* **All required evidence files are present, non-empty and machine-generated**, except
  **`evidence/receipts/source-commit.json`, which is missing.**
* Machine-generation was verified independently: a fresh in-container test run regenerates
  the files, and `evidence/correctness/committed-roots.json` reproduces **byte-for-byte**;
  others differ only by embedded timestamps/paths/timings.
* **Latent collision:** `evidence/performance/mount-replay.json` is written by **two** tests —
  `tests/performance_court.rs` (`orfs.performance.mount-replay.v1`) and
  `tests/snapshot_model.rs` (`orfs.evidence.mount-replay.v1`). Under a plain `cargo test`,
  `snapshot_model` runs last and silently **clobbers** the performance mount data. The
  committed copy is the performance version only because of run ordering.
* `evidence/receipts/{container,toolchain,environment}.json` are present; `doctor.json` and
  `ekbloom.json` are extra receipts.

## 5. Overclaims

* **None for F2** (FUSE-over-`io_uring`) — README, `LIMITATIONS.md` §4, `FUSE_URING.md` §7
  and `fuse-uring.json` all state it does not engage here.
* **None for the image pixel-surface pyramid** — `PROGRESS.md` (“Explicitly not implemented”),
  `QUERY.md` §9.1 and `src/image.rs` state only geometry is implemented, not materialised
  surfaces.
* The only overclaim-shaped issues are **documentation drift** (`ORFS-SPEC.md`, `README.md`,
  `PROGRESS.md` counts), not feature overclaims.

## 6. Prioritized remaining work

1. **Fix reproducibility (M).** Re-pin `ekbloom` to a rev that exists in EKBLOOM, update
   `Cargo.lock` and `evidence/receipts/ekbloom.json`, and prove a pristine clone builds.
2. **Fix `scripts/lib.sh` project-root resolution** so the scripts locate their own tree, not `$PWD`.
3. **Add `evidence/receipts/source-commit.json`** (required source-provenance receipt).
4. **Refresh the documentation**: `ORFS-SPEC.md` phase/document tables, `README.md` phase
   table, `PROGRESS.md` counts and unsafe-site count, `FUSE_URING.md` blocker count.
5. **Remove the `mount-replay.json` writer collision** (distinct paths or a single writer).
6. **Face the governing objective**: demonstrate (or explicitly concede) a workload where
   manifestation beats the authoritative read; today E1 is slower and the frontier always falls back.
7. **Close POSIX court gaps** (dedicated `pwrite`, `chown`, `utimens`, `fdatasync`, `mmap`).
8. **Document/limit the watermark residual window** and the concurrent-kmount hang hazard.

---

### Corrections during audit (for transparency)

An early path-resolution mistake caused one container run to execute against the original
tree and **overwrite 10 committed evidence files** with non-FUSE data. Those files were
restored with `git checkout -- evidence/` before assessment, and the verdicts above are
based on the committed content. No source or test semantics were modified; the only
intentional additions are this report and `evidence/receipts/acceptance-audit.json`.
