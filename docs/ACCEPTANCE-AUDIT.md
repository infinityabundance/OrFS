# OrFS — Independent Acceptance Audit (gates A–N)

**Auditor role:** adversarial, independent.
**Method:** verify by running, from a pristine checkout, in-container only; cite the concrete artifact for every verdict.
**Audited revision:** `253173d` (`phase28: native FUSE adversarial hardening and fuzzing`), `master` = `origin/master`.
**Supersedes:** the snapshot at rev `79cc421` (`docs/ACCEPTANCE-AUDIT.md` @ `f02b017`).
**Date:** 2026-10-12.

Every gate cites the test / evidence file / command output that proves it. A doc claim
with no backing test or run is called out. Nothing is transcribed from the project's own
reports. Where a claim could not be reproduced, that is stated.

---

## 1. Clean-checkout reproducibility (Gate M) — now PASS

A fresh clone of local HEAD was made under the required parent (so the sibling
`EKBLOOM` tree is present) and the repo's **own scripts** were run from it, inside the
pinned container, one container at a time.

```
git clone /mnt/1tb_kingston/OrFS /mnt/1tb_kingston/OrFS-audit-clean   # empty .cargo-home, no cache seeding
sh /mnt/1tb_kingston/OrFS-audit-clean/scripts/container-reproduce.sh
```

| Run (from the pristine clone) | Result |
|---|---|
| `container-reproduce.sh` (release build + `cargo test --release`) | **PASS — 327 passed, 0 failed** |
| `container-check.sh` (`fmt -p orfs --check` + `clippy --all-targets -D warnings`) | **PASS** — clean |
| `cargo test --features failpoints` | **PASS — 332 passed, 0 failed** |
| `container-fuse-test.sh` (kmount) | **PASS** — see §2 |
| `container-uring-test.sh` | **PASS** — see §2 |
| `container-posix-test.sh` (pjdfstest) | **PASS** — see §2 |
| `container-endurance.sh` | **PASS** (bench) — see §2 and the finding in §5 |

The clone had **no** `.cargo-home`; the run fetched every crate and the EKBLOOM
dependency (`rev=708c349128668bf26b50684ce473d8de4058dc31`, `version=0.3.0`) from the
public GitHub URL and checked that exact rev out under
`.cargo-home/git/checkouts/ekbloom-5e921c23dad56ebb`. **No sibling working tree and no
pre-seeded cache were needed.** This closes the previous audit's Gate-M failure (the
dangling `file://` pin at rev `255452e1`).

The previous `scripts/lib.sh` **project-root resolution defect is fixed**: the script
now derives `ORFS_PROJECT_DIR` from `$0`'s own directory, validates each candidate by the
presence of `Cargo.toml`, and fails loudly otherwise. Verified behaviourally — every
court above was launched by absolute script path from a *different* cwd
(`/mnt/1tb_kingston/OrFS`) and correctly operated on the clone (the logs compile
`/mnt/1tb_kingston/OrFS-audit-clean`).

---

## 2. Per-gate verdicts

| Gate | Verdict | Proving artifact (verified this audit) |
|---|---|---|
| **A** Genuine non-withdrawal | **PASS** | `tests/log_model.rs::committed_bytes_never_rewritten_across_appends_and_rollover`, `torn_tail_is_quarantined_not_truncated`; `evidence/recovery/torn-write.json` (`all_verdicts_ok=true`, 3 crash failpoints, `recovered_root == baseline_root`, `scan_tail_kind=TornRecord`, physical bytes retained) |
| **B** Valid historical roots | **PASS** | `tests/log_model.rs::every_published_root_is_a_complete_transaction_boundary`; `evidence/correctness/committed-roots.json` (24 roots, each `is_transaction_boundary=true`, `last_record_type=TX_COMMIT`; all 4 invariants true) |
| **C** Log-only reconstruction | **PASS** | `tests/log_model.rs::replay_from_committed_prefixes_is_deterministic`; `evidence/correctness/log-replay.json` (`distinct_replays_agree=true`), `evidence/correctness/namespace-rebuild.json` (`rebuild_equals_live=true`, `log_wins_after_tamper=true`) |
| **D** Transaction atomicity | **PASS** | `tests/transaction_model.rs::root_does_not_move_until_commit_and_never_exposes_a_partial_transaction` + proptest `random_transaction_sequences_recover_consistently`, `random_failpoints_recover_consistently`; `tests/concurrency_stress.rs` |
| **E** Real FUSE functionality | **PASS** | kmount: `tests/fuse_integration.rs` **2/2**; POSIX court `evidence/correctness/posix-results.json` **26/26** ops (now incl. `pwrite`, `chown`, `utimens`, `fdatasync`, `mmap`); `evidence/correctness/pjdfstest.json` (see §7) |
| **F** Correct io_uring execution | **PASS** | `tests/uring_integration.rs` **7/7** with `ORFS_REQUIRE_URING=1` (probe re-proves the seccomp necessity); `evidence/correctness/uring-equivalence.json` (`digests_equal=true`, `roots_equal=true`); `evidence/performance/backing-uring.json` (`io_uring_available=true`, `orphan_completions=0`) |
| **G** Real historical snapshots | **PASS** | `tests/snapshot_model.rs` (incl. `snapshot_does_not_observe_later_writes`, `cached_historical_index_equals_full_replay_for_many_roots`) + `tests/snapshot_fuse.rs` **1/1** under kmount; `evidence/correctness/snapshot-equivalence.json` (9/9 roots, `all_verified=true`) |
| **H** Concealed manifestation | **PASS** | `tests/manifestation.rs` (`generations_are_version_qualified`, `recovery_selects_newest_valid_and_ignores_torn`, `drop_all_and_rebuild_yields_identical_logical_bytes`, incremental overlay); `evidence/recovery/manifested-generation.json` (published 2 / recovered 2 / rejected 0; overlay + version-qualified manifests) |
| **I** EKBLOOM exact-equivalence | **PASS** | `tests/ekbloom_read.rs` (`proptest_planned_equals_authoritative`, `compatible_certified_path_serves_an_exact_read`); `evidence/correctness/ekbloom-read-equivalence.json` (`equivalent=true` per case). Caveat (not a failure): in the in-crate 4 KiB frontier every profile still serves via `logical-extent` fallback (`evidence/performance/ekbloom-frontier.json`), so exactness holds while the *4 KiB* accelerated path is inert |
| **J** Recovery (incl. ENOSPC/EIO/power-loss) | **PASS** | `cargo test --features failpoints` **332/0** (`tests/crash_recovery.rs::process_crash_at_every_failpoint_recovers_to_a_valid_boundary`); `evidence/recovery/{torn-write,commit-interruption,segment-rollover}.json`; `tests/power_loss.rs` + `evidence/recovery/power-loss.json` (`all_invariants_ok=true`), `enospc.json` (errno 28, `all_invariants_ok=true`), `device-error.json` (errno 5); `tests/recovery_adversarial.rs` (watermark, gap, capacity → `ESROFS`) |
| **K** Physical accounting | **PASS** | `evidence/performance/manifestation-accounting.json` (`m_total == on_disk_total_bytes == 15805`, `totals_match=true`, `ekbloom_bytes_match=true`); `tests/manifestation.rs::accounting_matches_on_disk_bytes`; endurance reproduction (199 999 extents, 0 errors) |
| **L** FUSE-over-`io_uring` | **PASS** | **Real F2 engagement verified by running.** Under `container-fuse-test.sh` the kmount court logged `orfs: FUSE-over-io_uring engaged` and `tests/fuse_uring.rs` **5/5**, incl. `f2_real_mount_engages_and_carries_requests`, `f2_court_f0_f1_f2`; `evidence/correctness/fuse-uring-f2-engagement.json` (`init_flags.engaged=true`, `server_accepted=true`, `register_sqes=16`, `requests_served=59`), `fuse-uring-equivalence.json`, `fuse-uring-ring.json`, `evidence/performance/{fuse-uring,f2-concurrency}.json` |
| **M** Reproducibility | **PASS** | §1 — pristine `git clone` builds/tests from the public EKBLOOM pin with an empty cache; `lib.sh` root resolution fixed |
| **N** Measured advantage | **PASS** | `evidence/performance/ekbloom-e2e-release.json`: certified `path`/`full`/`max-speed` are **~1.3–1.4×** faster than `none` for random **1-byte** direct reads (e.g. 2955 vs 4118 ns P50), and the concealed trigram index is **8.6×** over the same API's scan (`ekbloom-search-e2e-release.json`); reproduced from the clean clone. **Scope caveat:** the advantage is *narrow* — 4 KiB reads do not win (planner falls back), and F2/E1 gain nothing over F0/F1 |

---

## 3. Documentation completeness and drift

All **required documents exist** — `ORFS-SPEC`, `ON_DISK`, `LOG-INVARIANTS`,
`TRANSACTIONS`, `FUSE-SEMANTICS`, `IO_URING`, `FUSE_URING`, `EKBLOOM-INTEGRATION`,
`RECOVERY`, `SECURITY`, `PERFORMANCE`, `LIMITATIONS` — plus the newer `CAPACITY`,
`CONCURRENCY`, `POWERLOSS`, `MANIFESTATION`, `SNAPSHOTS`, `NAMESPACE`, `QUERY`,
`FUSE_PASSTHROUGH`, `PROGRESS`. No required document is missing.

Drift found (normative docs contradicted by the shipped state / evidence):

1. **`docs/FUSE_URING.md` §8 and §10 still say "FUSE passthrough … is not implemented".**
   Phase 21 implemented it (`docs/FUSE_PASSTHROUGH.md`, `src/passthrough.rs`) and the
   passthrough court passes **4/4** in this audit. Contradiction.
2. **`docs/FUSE-SEMANTICS.md` §10** lists transport `fuse-uring` as *"it does not engage
   on this host, so mounts fall back to F1/F0"* and FUSE passthrough as *"a later
   optimization"*. Both are false at HEAD — F2 engages for real and passthrough is
   implemented and measured.
3. **`docs/IO_URING.md` §11** repeats *"Domain B … does not engage on the development
   host"* — false; F2 engages.
4. **`docs/ORFS-SPEC.md` §4** is stale in framing: *"The thirteen build phases (0–12)"* and
   *"its **253** tests (default) pass"*. The tree has 327 default / 332 failpoints tests and
   the project is at Phase 28. (The prior audit's "phase/document tables mark things
   planned" defect **is fixed** — every row now reads `complete`/`exists`.)
5. **`README.md` phase table stops at Phase 14**, omitting 15–28 (Phase 10's row is
   correctly updated to *active on this host*).
6. **`docs/PROGRESS.md` has no Phase 18 or Phase 26 section** — the headers jump
   `17→19` and `25→27`, though commits `3c927b9` (phase18) and `87da684` (phase26) exist and
   `FUSE_URING.md`/`PERFORMANCE.md` both cite "Phase 26".
7. **`docs/CONCURRENCY.md` §7 self-contradicts §4.1**: §7 says *"Full path-copying of the
   index spines is deferred (§4.1)"* while §4.1 says it is now implemented (Phase 27).
8. **`docs/CONCURRENCY.md` §4** quotes the index-clone as *"≈40 ns"* while the committed
   `evidence/performance/publish-cost.json` records `index_clone_ns=60` (`40` is
   `read_view_clone_ns`); `PROGRESS.md` says 60 ns.
9. **`docs/FUSE_URING.md` §6.3–§6.4 tables do not match the committed evidence.** At 16
   readers the doc table says F0 383 490 / F1 382 577 / F2 108 094 ops/s, but both
   `fuse-uring.json` and `f2-concurrency.json` record **F0 485 614 / F1 475 708 / F2
   113 636**. The qualitative conclusion (F2 does not scale) is unchanged; the figures are
   stale.

---

## 4. Evidence completeness (directive §39 and the newer courts)

* **Present, non-empty and machine-generated**: all required plus newer evidence —
  `correctness/{log-replay,committed-roots,inode-semantics,snapshot-equivalence,posix-results,ekbloom-read-equivalence,pjdfstest,namespace-rebuild,query-parity,xfstests,fuse-uring-*,fuse-passthrough}.json`,
  `recovery/{torn-write,commit-interruption,segment-rollover,manifested-generation,power-loss,enospc,device-error,capacity}.json`,
  `performance/*` (incl. `fuse-uring,f2-concurrency,passthrough,incremental-manifestation,endurance,publish-cost,recovery-acceleration,reader-scaling`),
  `security/{concurrency-stress,fuzz-decode,hostile-input-results,unsafe-audit,native-fuse-fuzz,valgrind}.json` + `valgrind-logs/`.
  No empty/placeholder files (`find … -size -40c` → none). Machine-generation is confirmed
  independently: a pristine run regenerates them, and `committed-roots.json` reproduces
  **byte-for-byte**.
* **Fixed since the last audit:** the `evidence/performance/mount-replay.json` two-writer
  collision is gone — the snapshot court now writes `mount-replay-snapshot.json`.
* **`evidence/receipts/source-commit.json` is present but stale**: it records
  `orfs_git_commit = fa38029`, not HEAD `253173d` (it is a regenerable host receipt;
  `scripts/receipts-host.sh`).
* **`evidence/correctness/xfstests.json`** is an honest `ran:false —
  assessed-not-runnable-in-this-environment` record, not a fabricated pass.

---

## 5. Overclaims and cross-checks of the headline claims

**No feature overclaim found.** F2 is now *correctly* claimed active and that claim is
backed by a real mount; passthrough is claimed and backed; the image pixel-surface pyramid
is correctly not claimed. The only overclaim-shaped issues are the **documentation drift**
in §3 and the script defect below.

Cross-checks:

* **Concurrency scaling** — supported. `evidence/performance/reader-scaling.json`:
  concurrent-view throughput 636→2750 MB/s over 1→16 readers, while the old global-lock
  path stays ~380–640 MB/s; a view read completes in 10.5 µs while another thread holds the
  core lock 200 ms.
* **Passthrough engagement** — supported. The court passes 4/4 with
  `daemon_reads=0` on a read and `passthrough_registered/reused≥1`
  (`evidence/correctness/fuse-passthrough.json`); `~27×` vs daemon-served is the measured
  warm-cache figure.
* **Incremental manifestation economics** — supported.
  `evidence/performance/incremental-manifestation.json`: for a 32 KiB object a 64-byte
  change costs 3016 ns / 324 B incremental vs 704 458 ns / 163 844 B full; verdicts all
  `verified`.
* **E1-regression fix** — supported qualitatively and by evidence. `E1`/`E2` now match
  `F0`/`F1` on the committed sequential-read evidence (previously ~1.9 MB/s); the planner
  falls back because the profile is non-accelerating.
* **POSIX suite** — independently reproduced (§7).
* **Endurance** — reproduced from the clean clone: 1M-iteration churn `index_clone_ns=60`
  (flat) with 0 errors; a file grown to **199 999** disjoint extents; **2000/2000**
  historical roots with 0 errors; 4 remounts × 4 readers = 297 844 reads, 0 errors,
  monotone roots.
* **F2 statistical results** — the *conclusions* hold (see §3 item 9): F2 is latency-neutral
  single-threaded and does not scale with reader concurrency at ABI 7.45; only the tabulated
  figures are stale relative to the committed evidence.

**Script defect (machine-checkable):** `scripts/container-endurance.sh` advertises a
*"correctness courts re-run after endurance (no-corruption gate)"*, but `docker_run` is
defined with **`exec`** (`scripts/lib.sh:89`), so the first invocation replaces the shell
and **the second `docker_run cargo test …` never executes**. Verified: the run log ends
immediately after the bench (`wrote … to evidence/performance`) with **no** test output. The
endurance bench itself reports 0 errors, and the separate pristine `cargo test` is green, so
the omission is not currently masking corruption — but the advertised gate is dead code.

---

## 6. Prioritized remaining work

1. **Fix `scripts/container-endurance.sh`** so the post-endurance no-corruption court
   actually runs (use `docker run` without `exec`, or call the test command before the
   bench's `exec`, or split into one `sh -c '… && …'`). `scripts/lib.sh:89`.
2. **Refresh the drifted normative docs** (§3): remove the "passthrough not implemented" and
   "F2 does not engage" statements in `FUSE_URING.md` §8/§10, `FUSE-SEMANTICS.md` §10,
   `IO_URING.md` §11; fix `CONCURRENCY.md` §7 self-contradiction and the 40-vs-60 ns figure;
   re-sync `FUSE_URING.md` §6.3–§6.4 tables to the committed evidence.
3. **Add the missing `PROGRESS.md` Phase 18 and Phase 26 sections**, and correct
   `ORFS-SPEC.md` ("thirteen phases", test count) and the `README.md` phase table
   (extend to 28).
4. **Regenerate `evidence/receipts/source-commit.json`** at HEAD (`scripts/receipts-host.sh`).
5. **Extend the advantage** (Gate N): the objective is now met only for 1-byte reads and
   content search; 4 KiB reads and the F2/E1/E2 configurations still gain nothing. This is
   reported honestly, not a defect, but it is the open research direction.
6. **Reconcile the pjdfstest accounting presentation** (§7): state plainly that the
   "0 deviations" rests on the mechanical unsupported-node-type classification (3062 of the
   3777 failing assertions are cascades from such a test), rather than on few failing
   assertions.
7. **Host hygiene:** the kmount hang hazard persists — **12 pre-existing `orfs-kmount`
   containers are unremovable** (`docker rm -f` → *"did not receive an exit event"*), created
   before this audit (see §8).

---

## 7. The §33 POSIX court, reconciled

`container-posix-test.sh` was run from the pristine clone and **passed**:

* OrFS mount: 238 files, **46 failing**, 3777 failing assertions.
* Reference ext4 (same suite, same image): 238 files, **2 failing**, 28 failing assertions.
* `unclassified=0`, `stale_allowlist=0`, `result=pass` — identical to the committed
  `evidence/correctness/pjdfstest.json`.

`deviations.documented_deviations` is **empty**; the sole allowlist entry
(`scripts/posix/pjdfstest-expected.tsv`) is `unlink_08/2 — shared_with_reference` (the
reference ext4 fails it too). So **every Phase-24 OrFS deviation is closed** and the
allowlist cannot silently grow. The 46 "failing" files and 3777 assertions are classified as
**unsupported node types** — OrFS rejects `mknod` for FIFO/block/char/socket with
`EOPNOTSUPP` (`docs/FUSE-SEMANTICS.md §5`) — with 3062 of them classed
`unsupported_node_downstream` (a file that fails at node creation then cascades). The claim
"27 deviations → 0" is supported by the gate; the honest caveat is that the gate's teeth are
the *classification rule*, not a small failing-assertion count. The intentionally-unsupported
node types are documented and mechanically excluded.

---

## 8. Containers / housekeeping

* Containers created by this audit (clone build/test, kmount, uring, posix, endurance,
  failpoints) all exited and were removed by `--rm`; none were left behind.
* **12 pre-existing `orfs-kmount:1.99.0` containers** (plus one unrelated
  `ekbloom-rust-fuse` container) remain in `Up` state and are **unremovable** —
  `docker rm -f` returns *"could not kill container: tried to kill container, but did not
  receive an exit event"* (uninterruptible sleep, each holding a defunct
  `fuse_uring-…`/mount). They predate this audit, were not created by it, and cannot be
  removed by it. A single kmount container completes cleanly (verified); concurrency is the
  apparent trigger.
* The pristine clone and its logs were removed after the audit; no evidence in the primary
  tree was modified by any run (verified `git status` clean throughout).
