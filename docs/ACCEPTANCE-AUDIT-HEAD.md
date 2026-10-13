# OrFS — acceptance-audit re-run at HEAD (current-HEAD gate table + two-run diff)

This document is the **second run** of the acceptance court. `docs/ACCEPTANCE-AUDIT.md`
is the historical, point-in-time audit at revision `2187a3e` (phase 40) and is
**byte-identical / never rewritten**. This file re-runs the gates at the current
HEAD and publishes the **diff** between the two runs, so a reviewer can see what
moved since the phase-41 audit rather than reading a single frozen snapshot.

The machine-readable record is `evidence/receipts/acceptance-audit-v4.json`
(schema `orfs.evidence.acceptance-audit.v4`). Gate definitions live in
`docs/GATES.md`. All execution is Docker-only (`scripts/lib.sh`); nothing ran on
the host.

**Audited revision:** `60218086971a784ff77071190bf28bd50a838005` (`6021808`,
`phase59: native fsx/fsstress-equivalent fault-injection court`), `master`, clean
tree. **Supersedes (does not replace):** the phase-40 audit at `2187a3e`
(`evidence/receipts/acceptance-audit.json@v3`), **21 commits behind**.
**Date:** 2026-10-13.

---

## 1. Current-HEAD gate table

| Gate | Verdict at HEAD | Re-run this session? | Proving artifact (verified this run) |
|---|---|---|---|
| **A** Genuine non-withdrawal | **PASS** | yes (failpoints suite) | `evidence/recovery/torn-write.json` `all_verdicts_ok=true`, 3 failpoints, `recovered_root==baseline_root==1429`; `tests/log_model.rs` |
| **B** Valid historical roots | **PASS** | yes (default suite) | `evidence/correctness/committed-roots.json`: **24** roots, all `is_transaction_boundary=true`, all 4 invariants true |
| **C** Log-only reconstruction | **PASS** | yes (default suite) | `log-replay.json` `distinct_replays_agree=true`; `namespace-rebuild.json` `rebuild_equals_live=true` |
| **D** Transaction atomicity | **PASS** | yes (default suite) | `tests/transaction_model.rs` + proptests; `tests/concurrency_stress.rs` |
| **E** Real FUSE functionality | **PASS** | yes (kmount + POSIX) | `fuse_integration.rs` **2/2**; `posix-results.json` **26/26**; re-run pjdfstest identical (**238/46/3777** vs ext4 **238/2/28**, `unclassified=0`) |
| **F** Correct `io_uring` execution | **PASS** | yes (uring) | `uring_integration.rs` **7/7** `ORFS_REQUIRE_URING=1`; `uring-equivalence.json` digests/roots equal; `backing-uring.json` `io_uring_available=true`, `orphan_completions=0` |
| **G** Real historical snapshots | **PASS** | yes (kmount) | `snapshot_fuse.rs` **1/1**; `snapshot-equivalence.json` **9/9** roots, `all_verified=true` |
| **H** Concealed manifestation | **PASS** | yes (default suite) | `tests/manifestation.rs`; `manifested-generation.json` `all_ok=true`, published 2/recovered 2/rejected 0 |
| **I** EKBLOOM exact-equivalence | **PASS-with-caveat** | yes (default + kmount) | `ekbloom-read-equivalence.json` **492/492**, 0 mismatches, 182 accelerated. *Caveat:* `ekbloom-frontier.json`: all **18** profiles serve **2000/2000** via `logical-extent` fallback — the 4 KiB accelerated path is inert |
| **J** Recovery (ENOSPC/EIO/power-loss) | **PASS-with-caveat** | yes (failpoints) | `--features failpoints` **461/0**; `torn-write/commit-interruption/segment-rollover.json`; `power-loss/enospc/device-error.json` `all_invariants_ok=true`; `capacity.json` `subsequent_errno=30=EROFS`. *Caveat:* a **nondeterministic hang** was observed on the first failpoints attempt (§3) |
| **K** Physical accounting | **PASS** | yes (default suite) | `manifestation-accounting.json` `m_total == on_disk_total_bytes == 15805`, `totals_match=true` |
| **L** FUSE-over-`io_uring` (F2) | **PASS** | yes (kmount, real mount) | mount logged `orfs: FUSE-over-io_uring engaged`; `fuse_uring.rs` **5/5**; `fuse-uring-f2-engagement.json` `engaged=true`, `server_accepted=true`, `register_sqes=16`, `requests_served=59` |
| **M** Reproducibility (clean checkout) | **ran:false** | **no** — not in the required re-run set | v3 result stands (pristine clone at `2187a3e` built/tested **361/0** from the crates.io `ekbloom = "=0.3.0"` pin, checksum `b02f89ad…`). See §3 |
| **N** Measured advantage | **PASS-with-caveat** | yes (read-only receipts) | `ekbloom-e2e-release.json`: certified `path`/`full`/`max-speed` **~1.3–1.4×** on random 1-byte direct reads (e.g. full 2955 vs none 4118 ns p50); `ekbloom-search-e2e-release.json` trigram search **8.6207×** over the same API's scan. *Caveat:* narrow — 4 KiB reads do not win; F2/E1/E2 gain nothing |

**Test totals this session:** default **451 passed / 0 failed / 0 ignored**
(45 binaries); `--features failpoints` **461 passed / 0 failed / 0 ignored**
(45 binaries). `scripts/container-check.sh` (fmt + clippy `-D warnings`): **PASS**.

---

## 2. Two-run diff (`2187a3e` → `6021808`)

**21 commits** separate the two audited revisions (phases 41–59, plus the
phase-41 provenance refresh and a docs/pub bump).

| Gate | v3 verdict (`2187a3e`) | HEAD verdict (`6021808`) | Change |
|---|---|---|---|
| A | PASS | PASS | unchanged |
| B | PASS | PASS | unchanged |
| C | PASS | PASS | unchanged |
| D | PASS | PASS | unchanged |
| E | PASS | PASS | unchanged (kmount 2/2 + pjdfstest reproduced exactly) |
| F | PASS | PASS | unchanged |
| G | PASS | PASS | unchanged |
| H | PASS | PASS | unchanged |
| I | PASS | PASS-with-caveat | verdict unchanged; the pre-existing 4 KiB-frontier caveat is now labelled in the verdict |
| J | PASS | PASS-with-caveat | verdict unchanged; **new reproducibility caveat** (nondeterministic hang, §3) |
| K | PASS | PASS | unchanged |
| L | PASS | PASS | unchanged (fresh real F2 engagement reproduced) |
| M | PASS | ran:false | **not re-run this session** (not in the required set; see §3) |
| N | PASS | PASS-with-caveat | verdict unchanged; same scope caveat |

### Summary of what moved

* **Test counts grew, stayed green:** default **361 → 451**, failpoints
  **371 → 461** (+90/+90); test binaries **30 → 45**.
* **The kernel-mount court grew:** the phase-47 `f2_concurrency` court (**2/0**)
  now runs under `container-fuse-test.sh`, which also reports `group_commit_e2e`
  **5/0**.
* **Group commit is now an honest *win*:** after the phase-46 wiring-defect
  correction the mount court measures create+unlink churn **89 vs 477 ops/s**
  (~5.4×) and the write workload **6.25×** — where the v3 court reported *no*
  end-to-end win. The old "no win" text is retained in `docs/PROGRESS.md` as an
  explicit correction.
* **A nondeterministic hang was observed** (§3) — recorded, not concealed.
* **All fourteen gate verdicts remain PASS.** No gate regressed; gates I and N
  carry their pre-existing scope caveats and J carries a new reproducibility
  caveat.
* **Provenance receipts unchanged:** `source-commit.json` (`da9b74b`),
  `crates-io.json` (published v0.2.0 at `bcb8e0c`), and `ekbloom.json`
  (registry `ekbloom = "=0.3.0"`, checksum `b02f89ad…`). All remain allowlisted
  as historical point-in-time records.

---

## 3. What could not be re-run here, and why (honest)

* **Gate M — clean-checkout reproducibility: `ran:false`.** A pristine clone +
  `scripts/container-reproduce.sh` (a full release build and test from an empty
  `CARGO_HOME`) is expensive and was **outside this phase's required re-run set**;
  the dependency pin is unchanged (`ekbloom = "=0.3.0"`, checksum `b02f89ad…`, no
  git dependency). The v3 clean-checkout result (**361/0**) therefore stands
  unrefuted, but was **not independently re-verified this session**. This is a
  deferral, not a failure.
* **Gate J — a nondeterministic hang in the failpoints suite (reproducibility
  caveat, not a correctness failure).** On the **first** attempt,
  `sh scripts/container-test.sh --features failpoints` deadlocked in the library
  unit test `fuse_native::tests::worker_pool_drop_joins_workers_with_outstanding_jobs`:
  all threads were parked in `futex_wait` and the container sat at **0 % CPU**.
  The container was this audit's own, so it was removed (`docker rm -f`) and the
  suite re-run cleanly — **461/0**, that test completing in **1.28 s**. The only
  job-queue wakeup, `JobQueue::close` → `notify_all`, does **not** take the queue
  mutex, while `JobQueue::pop` re-checks `closed` immediately before
  `Condvar::wait`, so a lost-wakeup window is plausible. The hang was **not
  diagnosed to a fix** in this audit (out of scope); it is recorded as a latent
  defect and a follow-up (§4).
* **`xfstests` / external `fsstress`/`fsx`: not runnable here.** Unchanged:
  `evidence/correctness/xfstests.json` remains an honest `ran:false`
  (assessed-not-runnable) record; phase 59 added a native equivalent
  (`evidence/security/fault-injection.json`).

### Environment caveat (why a mount court is not hysterically reproducible)

The host carries **11 pre-existing wedged `orfs-kmount:1.99.0` containers**
(`Up` 28 h–2 days, uninterruptible) plus unrelated foreign containers. They were
**not** created by this run, were **not** killed, and Docker was **not** restarted.
A **single** kernel-mount container mounted successfully this session — the wedge
is a concurrency artefact — so the kmount court ran for real and returned a green
verdict.

---

## 4. Follow-ups surfaced by this run

1. **Diagnose and fix the failpoints-suite deadlock** (`src/fuse_native.rs`
   `JobQueue::close`/`pop` lost-wakeup window); add a regression test.
2. **Gate N breadth** (unchanged, honest, open research): the advantage holds only
   for 1-byte reads and content search; 4 KiB reads and F2/E1/E2 gain nothing.
3. **Re-run Gate M** at a future HEAD, or promote the clean-checkout reproduce
   into the standard re-run set.
4. **Host hygiene:** the pre-existing wedged kmount containers remain; a single
   container is not a sufficient trigger, concurrency is.
