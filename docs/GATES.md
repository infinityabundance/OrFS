# OrFS acceptance gates A–N — definitions and how to run them

`docs/ACCEPTANCE-AUDIT.md` records the **verdicts** of an independent acceptance
audit (a point-in-time document at the audited commit). This file publishes the
**gate definitions** themselves, so anyone can run each gate and judge it
independently rather than reading a verdict.

Each gate has: what it *means*, the **command** that exercises it, and the
**acceptance criterion** that makes it PASS. All commands run inside the pinned
container (`scripts/lib.sh`, Docker-only).

| Gate | Meaning | Command(s) | Acceptance criterion |
|---|---|---|---|
| **A** Genuine non-withdrawal | Committed authoritative history is never overwritten, truncated, reused, or GC'd; every committed transition extends the previous history (`L_{n+1} = L_n ⊕ Δ_n`) | `scripts/container-test.sh` (`tests/log_model.rs`) | `committed_bytes_never_rewritten_across_appends_and_rollover` and `torn_tail_is_quarantined_not_truncated` pass; `evidence/recovery/torn-write.json` shows `all_verdicts_ok=true` with physical bytes retained and a torn tail quarantined (never truncated) |
| **B** Valid historical roots | Every published root is a complete transaction boundary | `tests/log_model.rs` | `every_published_root_is_a_complete_transaction_boundary` passes; `evidence/correctness/committed-roots.json` reports each root `is_transaction_boundary=true`, `last_record_type=TX_COMMIT`, all invariants true |
| **C** Log-only reconstruction | The namespace is reconstructible from the log alone, deterministically | `tests/log_model.rs` | `replay_from_committed_prefixes_is_deterministic` passes; `log-replay.json` `distinct_replays_agree=true`; `namespace-rebuild.json` `rebuild_equals_live=true` and `log_wins_after_tamper=true` |
| **D** Transaction atomicity | A root does not move until commit; no partial transaction is ever exposed | `tests/transaction_model.rs`, `tests/concurrency_stress.rs` | the atomicity test and both proptests (`random_transaction_sequences_recover_consistently`, `random_failpoints_recover_consistently`) pass |
| **E** Real FUSE functionality | The filesystem mounts and serves genuine POSIX operations | `scripts/container-fuse-test.sh`, `scripts/container-posix-test.sh` | `tests/fuse_integration.rs` 2/2; `posix-results.json` 26/26 ops; `pjdfstest.json` under the allowlist gate (see `docs/ACCEPTANCE-AUDIT.md` §7) |
| **F** Correct `io_uring` execution | The backing `io_uring` path is equivalent to the sync path and correctness-clean | `scripts/container-uring-test.sh` | `tests/uring_integration.rs` 7/7 with `ORFS_REQUIRE_URING=1`; `uring-equivalence.json` `digests_equal=true`, `roots_equal=true`; `backing-uring.json` `io_uring_available=true`, `orphan_completions=0` |
| **G** Real historical snapshots | A pinned historical root reads the state as of that commit and never later writes | `scripts/container-fuse-test.sh` (`tests/snapshot_model.rs`, `tests/snapshot_fuse.rs`) | `snapshot_does_not_observe_later_writes` and `cached_historical_index_equals_full_replay_for_many_roots` pass; `snapshot-equivalence.json` all roots verified |
| **H** Concealed manifestation | Manifested structures are version-qualified, recoverable, and rebuildable to identical bytes | `scripts/container-test.sh` (`tests/manifestation.rs`) | version-qualification, torn-recovery, and drop-all-and-rebuild-to-identical-bytes tests pass; `manifested-generation.json` `all_ok=true` |
| **I** EKBLOOM exact equivalence | Every manifested read is byte-identical to the authoritative read | `scripts/container-test.sh` / `scripts/container-fuse-test.sh` (`tests/ekbloom_read.rs`) | `proptest_planned_equals_authoritative` passes; `ekbloom-read-equivalence.json` all cases `equivalent=true`, 0 mismatches |
| **J** Recovery (ENOSPC / EIO / power loss / torn writes / durability classes) | A crash or device fault at any point recovers to a valid committed boundary, or refuses cleanly, for every distinguished failure class | `scripts/container-test.sh --features failpoints`; `scripts/container-durability-qualification.sh`; `tests/power_loss.rs`, `tests/recovery_adversarial.rs`, `tests/durability_qualification.rs` | `process_crash_at_every_failpoint_recovers_to_a_valid_boundary` passes; `power-loss.json`, `enospc.json`, `device-error.json` all `all_invariants_ok=true`; `durability-qualification.json` `newest_valid_generation_selected=true`, `silent_shortening=false`, `unclassified_durable_losses=0`, with the residual window classified per row; capacity court returns the correct errno |
| **K** Physical accounting | Claimed physical / manifested / concealed bytes equal the bytes actually on disk | `scripts/container-test.sh` (`tests/manifestation.rs`) | `accounting_matches_on_disk_bytes` passes; `manifestation-accounting.json` `totals_match=true`, `ekbloom_bytes_match=true` |
| **L** FUSE-over-`io_uring` (F2) | F2 engages for real and carries requests, equivalently to F1 | `scripts/container-fuse-test.sh` | the mount logs F2 engagement; `tests/fuse_uring.rs` 5/5 incl. `f2_real_mount_engages_and_carries_requests`; `fuse-uring-f2-engagement.json` `engaged=true`, `server_accepted=true` |
| **M** Reproducibility | A pristine checkout builds and tests from the crates.io dependency pins | `scripts/container-reproduce.sh` | a clean clone with an empty cargo cache builds and runs the default suite green, fetching `ekbloom = "=0.3.0"` from crates.io |
| **N** Measured advantage | A manifested path is measurably faster than the authoritative path under its measured conditions | `scripts/container-fuse-test.sh` (`tests/ekbloom_read.rs`, `tests/ekbloom_frontier_e2e.rs`) | `ekbloom-e2e-release.json` certified profiles beat `none` for 1-byte random reads; `ekbloom-search-e2e-release.json` indexed search beats the scan. **Scope caveat:** the advantage is narrow — 4 KiB reads do not win, and F2/E1/E2 do not beat F0/F1 |
| **O** Sustained adversarial concurrency + explicit compatibility exceptions | Native Rust equivalents of `fsx`/`fsstress`/`fs_mark`, custom rename/link/unlink storms, and a **real-mount** arm — all deadlock-bounded (a watchdog fails rather than hangs) — plus the explicit POSIX compatibility matrix | `scripts/container-adversarial-concurrency.sh` | `evidence/correctness/adversarial-concurrency.json` `all_ok=true` with **0** mismatches, **0** orphans, **0** duplicate inodes and **0** torn reads, and every mounted read byte-exact; `docs/POSIX-COMPAT.md` reconciles `pjdfstest` with **0** unclassified deviations |

## How to read a verdict honestly

* A gate is PASS only when its **acceptance criterion** holds on the audited tree; the
  audit records the artifact and the exact numbers it verified
  (`docs/ACCEPTANCE-AUDIT.md` §2).
* Some gates carry a **scope caveat** (gate N's narrow advantage; gate I's inert
  4 KiB accelerated path). Those are stated with the verdict, not hidden.
* `xfstests` is **assessed, not runnable** in this environment (`evidence/correctness/xfstests.json`
  records `ran:false` with the reason); it is not counted as a passing gate.

## Adding a gate

1. Define the criterion as a command plus an artifact under `evidence/`.
2. Add it to the table above and to the audit's per-gate verdict table.
3. Do not record a PASS without a committed artifact that the criterion reads.
