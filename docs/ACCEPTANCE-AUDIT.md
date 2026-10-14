# OrFS — Independent Acceptance Audit (gates A–N)

**Auditor role:** adversarial, independent.
**Method:** verify by running, from a pristine checkout, in-container only; cite the concrete artifact for every verdict.
**Audited revision:** `2187a3e949bd116445988a281db110c13228742b` (`phase40: whole-system history-scaling court`), `master`.
**Supersedes:** the audit snapshot at rev `253173d` (`phase28: native FUSE adversarial hardening and fuzzing`), receipt `evidence/receipts/acceptance-audit.json@v2`.
**Date:** 2026-10-12.

Every gate cites the test / evidence file / command output that proves it. A doc claim
with no backing test or run is called out. Nothing is transcribed from the project's own
reports. Where a claim could not be reproduced, that is stated.

The audited commit is 13 phases past the previous audit (`253173d` → `2187a3e`): phases
29–40. The headline changes since then are the crates.io publication of `orfs` 0.1.0 and
of its `ekbloom` dependency (a git rev is no longer used), the group-commit coordinator
(phases 31/32/39), the object-localized read selection (phase 37), the docs-from-receipts
checker (phase 38), and the whole-system history-scaling court (phase 40). **All fourteen
gate verdicts remain PASS**; the numbers below are refreshed from this session's runs.

---

## 1. Clean-checkout reproducibility (Gate M) — PASS

A fresh clone of local HEAD was made under the required parent and the repo's **own
scripts** were run from it, inside the pinned container, one container at a time. The
clone path requested by the previous audit was writable, so the previous procedure was
followed exactly.

```
git clone /mnt/1tb_kingston/OrFS /mnt/1tb_kingston/OrFS-audit-clean
# clone HEAD == 2187a3e949bd116445988a281db110c13228742b; worktree clean;
# no .cargo-home and no target/ (empty cache) — confirmed with ls
sh /mnt/1tb_kingston/OrFS-audit-clean/scripts/container-reproduce.sh   # launched from a DIFFERENT cwd
```

| Run (from the pristine clone) | Result |
|---|---|
| `container-reproduce.sh` (release build + `cargo test --release`) | **PASS — 361 passed, 0 failed** |
| `container-check.sh` (`fmt -p orfs --check` + `clippy --all-targets -D warnings`) | **PASS** — clean, exit 0 |
| `container-fuse-test.sh` (kmount) | **PASS** — see §2 |
| `container-uring-test.sh` | **PASS** — see §2 |
| `container-posix-test.sh` (pjdfstest) | **PASS** — see §2 |

The clone had **no** `.cargo-home`; the run downloaded **113 crates** from the public
registry — including `ekbloom v0.3.0` (`Downloaded ekbloom v0.3.0`, then
`Compiling ekbloom v0.3.0`) — and compiled `orfs v0.1.0 (/mnt/1tb_kingston/OrFS-audit-clean)`,
which proves every command operated on the clone and not on the primary tree. **No sibling
`EKBLOOM` working tree and no pre-seeded cache were needed.** This remains a genuine
clean-checkout reproducer.

**EKBLOOM is now consumed as the published crates.io release, not a git rev.** `Cargo.toml`
pins `ekbloom = "=0.3.0"` and `Cargo.lock` records
`source = "registry+https://github.com/rust-lang/crates.io-index"` with
`checksum = "b02f89add93be1429809445c7570c1271a68957702728c95437887243bdcf2cf"` (registry
checksum `b02f89ad…`). There is no `git`/`file://` dependency anywhere in the graph, so a
clean checkout cannot dangle on an unreachable git remote. `evidence/receipts/ekbloom.json`
(`pin_kind = registry-exact`) and `evidence/receipts/source-commit.json` record the same
pin, and `evidence/receipts/crates-io.json` records the published `orfs` 0.1.0. This closes
the previous Gate-M failure (the dangling `file://` pin at rev `255452e1`) more strongly
than the git-pinned fix did.

The `scripts/lib.sh` project-root resolution (derives `ORFS_PROJECT_DIR` from `$0`'s own
directory; validates by the presence of `Cargo.toml`) was exercised behaviourally: every
court above was launched by absolute script path from a different cwd and correctly
operated on the clone.

---

## 2. Per-gate verdicts

| Gate | Verdict | Proving artifact (verified this audit) |
|---|---|---|
| **A** Genuine non-withdrawal | **PASS** | `tests/log_model.rs::committed_bytes_never_rewritten_across_appends_and_rollover`, `torn_tail_is_quarantined_not_truncated`; `evidence/recovery/torn-write.json` (`all_verdicts_ok=true`; **3** crash failpoints; `recovered_root == baseline_root == 1429`; tail kinds `TornRecord`/`Uncommitted`/`TornRecord`; physical bytes retained) |
| **B** Valid historical roots | **PASS** | `tests/log_model.rs::every_published_root_is_a_complete_transaction_boundary`; `evidence/correctness/committed-roots.json` (**24** roots, each `is_transaction_boundary=true`, `last_record_type=TX_COMMIT`; all **4** invariants true) |
| **C** Log-only reconstruction | **PASS** | `tests/log_model.rs::replay_from_committed_prefixes_is_deterministic`; `evidence/correctness/log-replay.json` (`distinct_replays_agree=true`), `evidence/correctness/namespace-rebuild.json` (`rebuild_equals_live=true`, `log_wins_after_tamper=true`) |
| **D** Transaction atomicity | **PASS** | `tests/transaction_model.rs::root_does_not_move_until_commit_and_never_exposes_a_partial_transaction` + proptests `random_transaction_sequences_recover_consistently` / `random_failpoints_recover_consistently`; `tests/concurrency_stress.rs` |
| **E** Real FUSE functionality | **PASS** | kmount: `tests/fuse_integration.rs` **2/2**; POSIX court `evidence/correctness/posix-results.json` **29/29** ops (incl. `pwrite`, `chown`, `utimens`, `fdatasync`, `mmap`, and the Phase-82 `write_through_created_fd`); `evidence/correctness/pjdfstest.json` (see §7) |
| **F** Correct io_uring execution | **PASS** | `tests/uring_integration.rs` **7/7** with `ORFS_REQUIRE_URING=1` (probe re-proves the seccomp necessity); `evidence/correctness/uring-equivalence.json` (`digests_equal=true`, `roots_equal=true`); `evidence/performance/backing-uring.json` (`io_uring_available=true`, `orphan_completions=0`) |
| **G** Real historical snapshots | **PASS** | `tests/snapshot_model.rs` (incl. `snapshot_does_not_observe_later_writes`, `cached_historical_index_equals_full_replay_for_many_roots`) + `tests/snapshot_fuse.rs` **1/1** under kmount; `evidence/correctness/snapshot-equivalence.json` (9/9 roots, `all_verified=true`) |
| **H** Concealed manifestation | **PASS** | `tests/manifestation.rs` (`generations_are_version_qualified`, `recovery_selects_newest_valid_and_ignores_torn`, `drop_all_and_rebuild_yields_identical_logical_bytes`, incremental overlay); `evidence/recovery/manifested-generation.json` (`all_ok=true`, **2** manifests, published 2 / recovered 2 / rejected 0) |
| **I** EKBLOOM exact-equivalence | **PASS** | `tests/ekbloom_read.rs` (`proptest_planned_equals_authoritative`, `compatible_certified_path_serves_an_exact_read`); `evidence/correctness/ekbloom-read-equivalence.json` (**492/492 equivalent, 0 mismatches**; 182 accelerated cases). Caveat (not a failure): in the in-crate 4 KiB frontier every profile still serves via `logical-extent` fallback (`served_paths: {"logical-extent": 2000}` for all 18 profiles in `evidence/performance/ekbloom-frontier.json`), so exactness holds while the *4 KiB* accelerated path is inert |
| **J** Recovery (incl. ENOSPC/EIO/power-loss) | **PASS** | `cargo test --features failpoints` **371/0** (`tests/crash_recovery.rs::process_crash_at_every_failpoint_recovers_to_a_valid_boundary`); `evidence/recovery/{torn-write,commit-interruption,segment-rollover}.json`; `tests/power_loss.rs` + `evidence/recovery/power-loss.json` (`all_invariants_ok=true`), `enospc.json` (`all_invariants_ok=true`), `device-error.json` (`all_invariants_ok=true`); `tests/recovery_adversarial.rs` (watermark, gap, capacity → `evidence/recovery/capacity.json` `subsequent_errno=30` = `EROFS`) |
| **K** Physical accounting | **PASS** | `evidence/performance/manifestation-accounting.json` (`m_total == on_disk_total_bytes == 15805`, `totals_match=true`, `ekbloom_bytes_match=true`); `tests/manifestation.rs::accounting_matches_on_disk_bytes` |
| **L** FUSE-over-`io_uring` | **PASS** | **Real F2 engagement verified by running.** Under `container-fuse-test.sh` the kmount court logged `orfs: FUSE-over-io_uring engaged` and `tests/fuse_uring.rs` **5/5**, incl. `f2_real_mount_engages_and_carries_requests`, `f2_court_f0_f1_f2`; `evidence/correctness/fuse-uring-f2-engagement.json` (`init_flags.engaged=true`, `server_accepted=true`, `register_sqes=16`, `requests_served=59`), `fuse-uring-equivalence.json`, `fuse-uring-ring.json`, `evidence/performance/{fuse-uring,f2-concurrency}.json` |
| **M** Reproducibility | **PASS** | §1 — pristine `git clone` builds/tests from the **crates.io** `ekbloom = "=0.3.0"` registry pin with an empty cache; `lib.sh` root resolution holds |
| **N** Measured advantage | **PASS** | `evidence/performance/ekbloom-e2e-release.json`: certified `path`/`full`/`max-speed` are **~1.3–1.4×** faster than `none` for random **1-byte** direct reads (e.g. 2955 vs 4118 ns P50), and the concealed trigram index is **8.6×** over the same API's scan (`ekbloom-search-e2e-release.json`, `indexed_speedup_over_scan = 8.6207`). **Scope caveat:** the advantage is *narrow* — 4 KiB reads do not win (planner falls back), and F2/E1/E2 gain nothing over F0/F1 |

A new court at this HEAD — **phase 40, whole-system history-scaling** — is not one of gates
A–N but is the headline of the audited commit. `tests/history_scaling.rs`
(`history_scaling_sweep`, release, **1 passed / 0 failed / 1 filtered**, 22.85 s) builds the
identical deterministic committed history in two arms (manifestation on vs off) and asserts
the pinned roots and per-checkpoint read digests are byte-identical. It writes
`evidence/performance/history-scaling.json`; committed values show the authoritative arm
degrading with history (p50 711 → 3115 → 7303 → 23153 ns across epochs 0/4/12/36) while the
manifested arm is flat once the accelerated path covers the reads (1422 → 3968 → 12834 →
12874 ns; `manifested_served_reads` 0 → 32 → 1536 → 2048 of 2048), and all four recorded
assessments are `true` (`authoritative_degrades_as_history_grows`,
`manifested_faster_than_authoritative_at_deepest`, `manifested_flat_once_selected`,
`persistent_bytes_grow`).

---

## 3. Documentation completeness and drift

All **required documents exist** — `ORFS-SPEC`, `ON_DISK`, `LOG-INVARIANTS`,
`TRANSACTIONS`, `FUSE-SEMANTICS`, `IO_URING`, `FUSE_URING`, `EKBLOOM-INTEGRATION`,
`RECOVERY`, `SECURITY`, `PERFORMANCE`, `LIMITATIONS` — plus the newer `CAPACITY`,
`CONCURRENCY`, `POWERLOSS`, `MANIFESTATION`, `SNAPSHOTS`, `NAMESPACE`, `QUERY`,
`FUSE_PASSTHROUGH`, `PROGRESS`, `PUBLISHING`, `RECEIPTS`. No required document is missing.

**Phase 38 ("documentation reconciled to evidence") fixed most of the drift the previous
audit flagged, and added a host-side checker.** `scripts/check-docs-receipts.sh` (with
`scripts/docs-receipts.json`) now mechanically compares a curated set of doc citations to
the machine-generated evidence; run against the committed HEAD tree it reports
**PASS — provenance 3 records (0 failing); citations 37 checked (37 ok, 0 failing)**. All
nine drift items are now resolved (items 4 and 9 were closed in phase 41):

1. ~~`FUSE_URING.md` §8/§10 "FUSE passthrough … is not implemented"~~ — **fixed**; §8/§10 now
   read "**implemented and engaged**" and cite `evidence/correctness/fuse-passthrough.json`.
2. ~~`FUSE-SEMANTICS.md` §10 "fuse-uring … does not engage on this host"~~ — **fixed**; §10
   now says it engages for real (cites `fuse-uring-f2-engagement.json`).
3. ~~`IO_URING.md` §11 "Domain B … does not engage"~~ — **fixed**; §11 now says Domain B is
   implemented in Phase 10.
4. ~~`ORFS-SPEC.md` §4 heading and test counts~~ — **fixed** (phase 41). §4 now reads "The
   ordered build phases **(0–40)**", and the status block records **361** default / **371**
   failpoints tests (this session's measured counts; the `container-test.sh` comment and the
   `(0–31)` heading were updated with it).
5. ~~`README.md` phase table stops at Phase 14~~ — **fixed**; it now runs to Phase 40.
6. ~~`PROGRESS.md` missing Phase 18 / Phase 26~~ — **fixed**; both sections exist.
7. ~~`CONCURRENCY.md` §7 self-contradicts §4.1~~ — **fixed**; §7 now says path-copying is
   implemented (Phase 27, §4.1).
8. ~~`CONCURRENCY.md` §4 "≈40 ns index clone"~~ — **fixed**; §4 now correctly distinguishes
   the **≈60 ns** index clone from the **≈40 ns** read-view/locator capture, matching
   `evidence/performance/publish-cost.json`.
9. ~~`FUSE_URING.md` §6.3–§6.4 table figures~~ — **fixed** (phase 41). The §6.4 concurrency
   table and its prose were re-synced to the committed evidence (`f2-concurrency.json`), all
   rows: 1/2/4/8/16 readers F0 **78 477**/**160 409**/**305 010**/**427 959**/**506 903**, F1
   **80 431**/**162 045**/**303 062**/**421 147**/**500 147**, F2
   **76 845**/**107 837**/**108 242**/**113 581**/**113 322** ops/s, with significance stated
   by 95% CI disjointness and the mixed-workload line re-synced (F0 83 064 / F1 57 157 / F2
   48 406). The qualitative conclusion (F2 is latency-neutral single-threaded and does not
   scale with reader concurrency at ABI 7.45) is unchanged.

---

## 4. Evidence completeness (directive §39 and the newer courts)

* **Present, non-empty and machine-generated**: all required plus newer evidence —
  `correctness/{log-replay,committed-roots,inode-semantics,snapshot-equivalence,posix-results,ekbloom-read-equivalence,pjdfstest,namespace-rebuild,query-parity,xfstests,fuse-uring-*,fuse-passthrough}.json`,
  `recovery/{torn-write,commit-interruption,segment-rollover,manifested-generation,power-loss,enospc,device-error,capacity}.json`,
  `performance/*` (incl. `fuse-uring,f2-concurrency,passthrough,incremental-manifestation,endurance,endurance-postcourt,publish-cost,recovery-acceleration,reader-scaling,group-commit,group-commit-e2e,group-commit-e2e-writes,history-scaling,ekbloom-read-paths`),
  `security/{concurrency-stress,fuzz-decode,hostile-input-results,unsafe-audit,native-fuse-fuzz,valgrind}.json` + `valgrind-logs/`,
  and `receipts/{acceptance-audit,source-commit,ekbloom,crates-io,doctor,toolchain,environment,container}.json`.
  No empty/placeholder files. Machine-generation is confirmed independently: a pristine run
  regenerates them, and `committed-roots.json` reproduces **byte-for-byte**. Re-running the
  courts and benches in this session regenerated 31 evidence files under `evidence/`; that
  churn was reverted to HEAD so this audit edits only the two authorized artifacts (the
  committed artifact at HEAD is what is cited).
* **New at this HEAD:** `evidence/performance/history-scaling.json` (phase 40),
  `group-commit*.json` (phases 31/32/39), `endurance-postcourt.json` (phase 30),
  `ekbloom-read-paths.json`, and the `receipts/{ekbloom,crates-io,doctor}.json` provenance
  records.
* **`evidence/receipts/source-commit.json`** records `orfs_git_commit = 1024b5f` (6 behind
  HEAD); it is a regenerable host receipt, and the new checker classifies it as
  `allowed-historical` (a provenance receipt names the commit its evidence was produced at,
  not a claim of current-tree coverage).
* **`evidence/correctness/xfstests.json`** remains an honest `ran:false —
  assessed-not-runnable-in-this-environment` record, not a fabricated pass.

---

## 5. Overclaims and cross-checks of the headline claims

**No feature overclaim found.** F2 is correctly claimed active and backed by a real mount;
passthrough is claimed and backed; the image pixel-surface pyramid is correctly not claimed.
The two documentation-drift items in §3 (the `ORFS-SPEC` phase-range/test-count and the
`FUSE_URING` §6.3–§6.4 figures) were closed in phase 41; no overclaim remains.

Cross-checks (all from this session's runs or the committed evidence):

* **Test counts are higher and still green.** Default `cargo test` = **361 passed / 0 failed**
  (30 suites); `--features failpoints` = **371 passed / 0 failed**. The previous audit
  recorded 327 / 332, so the counts grew by 34 / 39 while staying fully green.
* **Concurrency scaling** — supported. `evidence/performance/reader-scaling.json`:
  concurrent-view throughput scales with readers while the old global-lock path stays flat;
  a view read completes while another thread holds the core lock.
* **Passthrough engagement** — supported. The court passes 4/4 with `daemon_reads=0` on a
  read and `passthrough_registered/reused ≥ 1` (`evidence/correctness/fuse-passthrough.json`).
* **Incremental manifestation economics** — supported.
  `evidence/performance/incremental-manifestation.json`: a small change costs far less than a
  full rebuild; verdicts all `verified`.
* **Group commit — honest, and NOT a win on the measured end-to-end workload.** The new
  `group_commit_e2e` court passes 4/4, but its own output is candid: for synchronized
  create+unlink churn `group_commit=false` ran **91 ops/s vs true 38 ops/s** (the coordinator
  is *slower* here), and the concurrent write workload measured a **1.00×** on/off ratio.
  `evidence/performance/group-commit-e2e.json` states plainly that "NO statistically
  defensible end-to-end win is claimed on this workload — the per-mutation cost is not
  dominated by one barrier." This matches the phase-32/39 framing and is a correct
  non-overclaim, not a defect.
* **POSIX suite** — independently reproduced (§7).
* **History scaling (new, phase 40)** — reproduced from the primary tree (1/0, 22.85 s); see
  §2. The manifested arm only wins at depth, which is reported honestly.
* **F2 statistical results** — the conclusions and the tabulated figures now agree
  (`FUSE_URING.md` §6.3–§6.4 were re-synced to the committed evidence in phase 41).
* **Endurance — not re-run in this session.** `scripts/container-endurance.sh` is expensive
  and was outside the required re-run set. The previous audit's defect (the post-endurance
  no-corruption court never ran because `lib.sh` used `exec`) **is fixed**: `docker_run` now
  deliberately does not `exec`, and the committed
  `evidence/performance/endurance-postcourt.json` records `ran=true, result=pass` for the
  `{lib, namespace_model, snapshot_model, concurrency_stress, transaction_model,
  recovery_adversarial}` re-run. Not independently re-verified here.

---

## 6. Prioritized remaining work

1. ~~**`FUSE_URING.md` §6.3–§6.4 figures are stale**~~ — **closed in phase 41**; the table
   and prose were re-synced to `f2-concurrency.json`.
2. ~~**`ORFS-SPEC.md` residual drift**~~ — **closed in phase 41**; §4 reads "(0–40)" and the
   test counts are the measured 361 / 371.
3. ~~**Regenerate `evidence/receipts/source-commit.json` at HEAD**~~ — **closed in phase 41**
   (`scripts/receipts-host.sh` was re-run at the phase-41 tree).
4. **Gate N breadth** (unchanged, honest, open research): the advantage holds only for
   1-byte reads and content search; 4 KiB reads and F2/E1/E2 gain nothing.
5. **Group commit is not yet a win on a mount-scale workload** (§5): the engine-level win
   needs a larger prepared backlog than a mount workload produces. Reported honestly.
6. **Keep the docs-from-receipts checker honest**: it passes at HEAD, but its citation set
   does not yet cover the `ORFS-SPEC`/`FUSE_URING` figures above, so those can drift again
   unnoticed (extending the mapping is future work).
7. **Host hygiene:** the pre-existing `orfs-kmount` containers remain wedged (see §8).

---

## 7. The §33 POSIX court, reconciled

`container-posix-test.sh` was run and **passed** (identical to the committed
`evidence/correctness/pjdfstest.json`):

* OrFS mount: 238 files, **46 failing**, 3777 failing assertions.
* Reference ext4 (same suite, same image): 238 files, **2 failing**, 28 failing assertions.
* `unclassified=0`, `stale_allowlist=0`, `result=pass`.

The sole allowlist entry (`scripts/posix/pjdfstest-expected.tsv`) is `unlink_08/2 —
shared_with_reference` (the reference ext4 fails it too), so **every Phase-24 OrFS deviation
is closed** and the allowlist cannot silently grow. The honest caveat stands: the "0
deviations" rests on the *classification rule* — OrFS rejects `mknod` for
FIFO/block/char/socket with `EOPNOTSUPP` (`docs/FUSE-SEMANTICS.md §5`), and the bulk of the
3777 failing assertions are `unsupported_node_downstream` cascades from such a file — not on
a small failing-assertion count. The intentionally-unsupported node types are documented and
mechanically excluded.

---

## 8. Containers / housekeeping

* This audit ran, one container at a time: `container-reproduce.sh` (clone build + release
  tests), `container-check.sh` (clone fmt/clippy), `container-test.sh` (default and
  `--features failpoints`), `container-fuse-test.sh` (kmount), `container-uring-test.sh`,
  `container-posix-test.sh`, and `container-history-scaling.sh`. All were `--rm` and exited;
  none was left behind, and none of the pre-existing wedged containers was touched.
* Several **pre-existing `orfs-kmount:1.99.0` containers** remain in `Up` state and are
  **unremovable** (uninterruptible `D` sleep, each holding a defunct `fuse_uring-…`/mount).
  They predate this audit, were not created by it, and cannot be removed by it. A single
  kmount container completes cleanly (verified this session); concurrency is the apparent
  trigger. See the final `docker ps` recorded with this audit's receipt.
* No stray `orfs-build:1.99.0` container was present at the start of this audit.
* The pristine Gate-M clone was made at `/mnt/1tb_kingston/OrFS-audit-clean` and removed
  after the audit; this session's run logs are under `target/` (gitignored). No primary-tree
  source file was modified by any run; the 31 evidence files regenerated by the runs were
  reverted to HEAD.
