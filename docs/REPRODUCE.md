# OrFS reproducibility index — every number maps to a receipt and a command

Every performance or correctness figure quoted in these docs comes from a
machine-generated JSON receipt under `evidence/`, and every receipt is regenerated
by one command. This file is the index: **doc claim → receipt → command**. It exists
so a reviewer can re-run any single number instead of trusting the prose.

## How to reproduce a receipt at its recorded revision

1. Find the revision the receipt was produced at: the receipt itself, or
   `evidence/receipts/source-commit.json` (and the per-receipt `source_commit`
   field where present).
2. Check out that revision and run the court's script:
   `git checkout <rev> && sh scripts/<court>.sh`. (The check-docs-receipts gate in
   `scripts/check-docs-receipts.sh` uses the same recorded revisions and reports any
   receipt that names a commit which is not an ancestor of `HEAD`.)
3. A full clean-build/clean-test reproduction is `sh scripts/container-reproduce.sh`
   (release build + release test inside the pinned container).
4. Provenance receipts (host environment, container image id, toolchain, dependency
   fingerprint, source commit) are captured by `sh scripts/receipts-host.sh` and
   `sh -c '. scripts/lib.sh && docker_run sh scripts/receipts-container.sh'`.

All execution is Docker-only (`scripts/lib.sh`); nothing runs on the host.

## One-command verification (pre-PR)

`sh scripts/container-verify.sh` is the pre-PR entry point: it runs the cheap
`check-all` gate (fmt/clippy + docs-receipts + chart drift), then the default suite
and the default suite `--features failpoints`, then the POSIX, native
fsx/fsstress fault-injection, `io_uring` and bounded Loom courts, then the
docs-receipts check again — one container at a time — and prints a per-stage
`PASS`/`FAIL`/`SKIPPED` summary, exiting non-zero on any failure.

```sh
sh scripts/container-verify.sh          # full pre-PR court
sh scripts/container-verify.sh --fast   # fmt/clippy + docs-receipts + charts + default suite
```

`--fast` runs only the cheap, always-available parts and skips anything that needs
a mount (`/dev/fuse`) or is heavy. A stage that cannot run in the environment is
reported `SKIPPED (reason)` and is **not** counted as a pass. See
`docs/OPERATIONS.md` §8.

## Dedicated courts (one script, one workload, one receipt)

| Receipt | Written by | Command |
|---|---|---|
| `evidence/performance/baselines.json` | `tests/baselines.rs` | `sh scripts/container-baseline.sh` |
| `evidence/performance/search-directory.json` | `tests/search_directory.rs` | `sh scripts/container-search-directory.sh` |
| `evidence/performance/direct-page-atlas.json` | `tests/direct_page_atlas.rs` | `sh scripts/container-direct-page-atlas.sh` |
| `evidence/performance/expansion-controller.json` | `tests/expansion_controller.rs` | `sh scripts/container-expansion-controller.sh` |
| `evidence/performance/microarch.json` | `tests/microarch.rs` | `sh scripts/container-microarch.sh` |
| `evidence/performance/planner-cache.json` | `tests/planner_cache.rs` | `sh scripts/container-planner-cache.sh` |
| `evidence/performance/read-planner.json` | `benches/read_path.rs` | `sh scripts/container-read-planner.sh` |
| `evidence/performance/index-layout.json` | `tests/index_layout.rs` | `sh scripts/container-index-layout.sh` |
| `evidence/performance/manifestation-catalogue.json` | `tests/manifestation_catalogue.rs` | `sh scripts/container-manifestation-catalogue.sh` |
| `evidence/performance/history-scaling.json` | `tests/history_scaling.rs` | `sh scripts/container-history-scaling.sh` |
| `evidence/performance/endurance-amplification.json` | `tests/endurance_amplification.rs` | `sh scripts/container-endurance-amplification.sh` |
| `evidence/performance/storage-economics.json` | `tests/storage_economics.rs` | `sh scripts/container-storage-economics.sh` |
| `evidence/performance/tier-relocation.json` | `tests/tier_relocation.rs` | `sh scripts/container-tier-relocation.sh` |
| `evidence/performance/bounded-recovery.json` | `tests/bounded_recovery.rs` | `sh scripts/container-bounded-recovery.sh` |
| `evidence/performance/historical-fast.json` | `tests/historical_fast.rs` | `sh scripts/container-historical-fast.sh` |
| `evidence/performance/historical-index-integrated.json` | `tests/historical_index_integration.rs` | `sh scripts/container-historical-integrate.sh` |
| `evidence/performance/group-commit-adaptive.json` | `tests/group_commit_adaptive.rs` | `sh scripts/container-group-commit.sh` |
| `evidence/performance/f2-concurrency-affine.json` | `tests/f2_concurrency.rs` | `sh scripts/container-fuse-test.sh` |
| `evidence/performance/external-comparison.json` | `tests/external_comparison.rs` | `sh scripts/container-fuse-test.sh` |
| `evidence/performance/baseline-passthrough.json` | `tests/baseline_passthrough.rs` | `sh scripts/container-baseline-passthrough.sh` |
| `evidence/performance/planner-mounted-paired.json` | `tests/planner_mounted.rs` | `sh scripts/container-planner-mounted.sh` |
| `evidence/performance/backing-uring.json`, `mechanisms.json` | `tests/uring_integration.rs`, `benches/mechanisms.rs` | `sh scripts/container-uring-test.sh` |
| `evidence/performance/uring-depth.json` | `tests/uring_depth.rs` | `sh scripts/container-uring-depth.sh` |
| `evidence/performance/endurance-postcourt.json`, `endurance.json` | `tests/performance_court.rs` | `sh scripts/container-endurance.sh` |
| `evidence/correctness/pjdfstest.json`, `posix-results.json` | the POSIX court | `sh scripts/container-posix-test.sh` |
| `evidence/security/valgrind.json` | Valgrind Memcheck targets | `sh scripts/container-valgrind.sh` |
| `evidence/performance/reader-scaling-64.json` | `tests/reader_scale_64.rs` | `sh scripts/container-reader-scale64.sh` |
| `evidence/correctness/posix-extras.json` | `tests/posix_extras.rs` | `sh -c '. scripts/lib.sh && docker_run cargo test -p orfs --test posix_extras'` |
| `evidence/correctness/adversarial-concurrency.json` | `tests/adversarial_concurrency.rs` | `sh scripts/container-adversarial-concurrency.sh` |
| `evidence/performance/application-workloads.json` | `tests/application_workloads.rs` | `sh scripts/container-application-workloads.sh` |
| `evidence/security/fault-injection.json` | `tests/fs_fault_injection.rs` | `sh scripts/container-fault-injection.sh` |
| `evidence/recovery/fault-injection-verify-recover.json` | `tests/verify_recover_faults.rs` | `sh scripts/container-fault-verify.sh` |
| `evidence/recovery/capacity-guard.json` | `tests/capacity_guard.rs` | `sh -c '. scripts/lib.sh && docker_run cargo test -p orfs --test capacity_guard'` |
| `evidence/recovery/fault-enospc.json` | `tests/fault_enospc.rs` | `sh scripts/container-fault-enospc.sh` |
| `evidence/recovery/durability-qualification.json` | `tests/durability_qualification.rs` | `sh scripts/container-durability-qualification.sh` |
| `evidence/performance/pmu.json`, `flamegraph-microarch.{folded,svg,json}` | `tests/microarch_pmu.rs` | `sh scripts/container-pmu.sh` |
| `evidence/receipts/acceptance-audit-v4.json` | the acceptance-audit re-run (a manual aggregation, not one test) | the gate set: `sh scripts/container-test.sh` and `sh scripts/container-test.sh --features failpoints`, `sh scripts/container-check.sh`, `sh scripts/container-posix-test.sh`, `sh scripts/container-uring-test.sh`, `sh scripts/container-fuse-test.sh` (see `docs/ACCEPTANCE-AUDIT-HEAD.md` §1) |
| `tests/fixtures/{legacy_v0,current_v1}/` (frozen bytes; **not** a receipt) | `tests/format_compat.rs` (`generate_fixtures`) | `sh -c '. scripts/lib.sh && docker_run cargo test -p orfs --test format_compat -- --ignored generate_fixtures'` |

The frozen `or.log` compatibility fixtures (`tests/fixtures/`, Phase 67) are
committed bytes, not a receipt; the court `tests/format_compat.rs` runs in the
default suite (`sh scripts/container-test.sh`) and asserts each fixture is
byte-identical to a freshly written equivalent and that an unknown higher
`format_version` is refused. See `tests/fixtures/README.md` and `docs/MIGRATION.md`.

## Bounded Loom models (no receipt)

The bounded Loom concurrency models (Phase 70: `src/sync_model.rs`,
`tests/loom_concurrency.rs`) are run by `sh scripts/container-loom.sh`
(`RUSTFLAGS="--cfg loom" cargo test --test loom_concurrency`) and write **no**
receipt — they are a bounded state-space exploration, not a measurement. `loom`
is a `[target.'cfg(loom)'.dependencies]` / `[target.'cfg(loom)'.dev-dependencies]`
entry, so a normal build never compiles it and the default test count is
unaffected. See `docs/CONCURRENCY.md` §10.

## Evidence (re)generated by the general suites

These receipts are written by the ordinary test suites, so the command is the suite
that contains the writing test:

| Suite | Command | Receipts |
|---|---|---|
| default suite | `sh scripts/container-test.sh` | `performance/{ekbloom-e2e,ekbloom-frontier,ekbloom-read-paths,historical-index,incremental-manifestation,latency-anatomy,manifestation-accounting,mechanisms,mount-replay,passthrough,reader-scaling,search-latency}.json`; `correctness/{ekbloom-read-equivalence,inode-semantics,namespace-rebuild,query-parity,snapshot-equivalence,uring-equivalence}.json`; `security/{fuzz-decode,hostile-input-results,unsafe-audit,concurrency-stress}.json` |
| failpoints | `sh scripts/container-test.sh --features failpoints` | `recovery/{torn-write,commit-interruption,segment-rollover,power-loss,enospc,device-error,capacity,manifested-generation}.json` |
| FUSE mount | `sh scripts/container-fuse-test.sh` | `performance/{fuse-baseline,fuse-uring,f2-concurrency,f2-concurrency-affine,group-commit-e2e,group-commit-e2e-writes,mount-replay-snapshot,baseline-passthrough,planner-mounted-paired,external-comparison}.json`; `correctness/{fuse-passthrough,fuse-uring-equivalence,fuse-uring-f2-engagement,fuse-uring-ring}.json`; `security/native-fuse-fuzz.json` |
| `io_uring` | `sh scripts/container-uring-test.sh` | `performance/{backing-uring,mechanisms,f2-concurrency}.json` |

## Images and charts

Every committed figure under `docs/charts/` is generated from a committed
`evidence/*.json` receipt by `scripts/render_charts.py` (Python 3 standard
library only; deterministic — no external fonts, no JavaScript, no timestamps).
Regenerate every chart with:

```sh
python3 scripts/render_charts.py          # rewrite docs/charts/*.svg
python3 scripts/render_charts.py --check  # drift check: exit 1 if any differs
```

Each figure is referenced from a `docs/PERFORMANCE.md` section. The full
image → receipt → command mapping:

| Image (`docs/charts/`) | Referenced in | Source receipt | Receipt command |
|---|---|---|---|
| `history-scaling.svg` | `PERFORMANCE.md` §13 | `evidence/performance/history-scaling.json` | `sh scripts/container-history-scaling.sh` |
| `history-scaling-bytes.svg` | `PERFORMANCE.md` §13 | `evidence/performance/history-scaling.json` | `sh scripts/container-history-scaling.sh` |
| `endurance-amplification.svg` | `PERFORMANCE.md` §30 | `evidence/performance/endurance-amplification.json` | `sh scripts/container-endurance-amplification.sh` |
| `endurance-amplification-ratio.svg` | `PERFORMANCE.md` §30 | `evidence/performance/endurance-amplification.json` | `sh scripts/container-endurance-amplification.sh` |
| `storage-economics-predicted-vs-actual.svg` | `STORAGE-ECONOMICS.md` §3.4 | `evidence/performance/storage-economics.json` | `sh scripts/container-storage-economics.sh` |
| `storage-economics-accounting.svg` | `STORAGE-ECONOMICS.md` §2.1 | `evidence/performance/storage-economics.json` | `sh scripts/container-storage-economics.sh` |
| `bounded-recovery.svg` | `CAPACITY.md` §14.4 | `evidence/performance/bounded-recovery.json` | `sh scripts/container-bounded-recovery.sh` |
| `manifestation-catalogue.svg` | `PERFORMANCE.md` §14 | `evidence/performance/manifestation-catalogue.json` | `sh scripts/container-manifestation-catalogue.sh` |
| `planner-cache.svg` | `PERFORMANCE.md` §17 | `evidence/performance/planner-cache.json` | `sh scripts/container-planner-cache.sh` |
| `microarch.svg` | `PERFORMANCE.md` §18 | `evidence/performance/microarch.json` | `sh scripts/container-microarch.sh` |
| `search-directory.svg` | `PERFORMANCE.md` §19 | `evidence/performance/search-directory.json` | `sh scripts/container-search-directory.sh` |
| `baselines.svg` | `PERFORMANCE.md` §20 | `evidence/performance/baselines.json` | `sh scripts/container-baseline.sh` |
| `baselines-latency.svg` | `PERFORMANCE.md` §20 | `evidence/performance/baselines.json` | `sh scripts/container-baseline.sh` |
| `uring-depth.svg` | `PERFORMANCE.md` §21 | `evidence/performance/uring-depth.json` | `sh scripts/container-uring-depth.sh` |
| `uring-depth-sq.svg` | `PERFORMANCE.md` §21 | `evidence/performance/uring-depth.json` | `sh scripts/container-uring-depth.sh` |
| `reader-scaling-64.svg` | `PERFORMANCE.md` §22 | `evidence/performance/reader-scaling-64.json` | `sh scripts/container-reader-scale64.sh` |
| `reader-scaling-64-tail.svg` | `PERFORMANCE.md` §22 | `evidence/performance/reader-scaling-64.json` | `sh scripts/container-reader-scale64.sh` |
| `pmu.svg` | `PERFORMANCE.md` §23 | `evidence/performance/pmu.json` | `sh scripts/container-pmu.sh` |
| `direct-page-atlas.svg` | `PERFORMANCE.md` §27 | `evidence/performance/direct-page-atlas.json` | `sh scripts/container-direct-page-atlas.sh` |
| `expansion-controller.svg` | `PERFORMANCE.md` §28 | `evidence/performance/expansion-controller.json` | `sh scripts/container-expansion-controller.sh` |
| `f2-concurrency-64-tail.svg` | `PERFORMANCE.md` §29 | `evidence/performance/f2-concurrency-affine.json` | `sh scripts/container-fuse-test.sh` |
| `f2-decision-tail.svg` | `PERFORMANCE.md` §31 | `evidence/performance/f2-concurrency-affine.json` | `sh scripts/container-fuse-test.sh` |
| `f2-decision-throughput.svg` | `PERFORMANCE.md` §31 | `evidence/performance/f2-concurrency-affine.json` | `sh scripts/container-fuse-test.sh` |
| `external-comparison.svg` | `PERFORMANCE.md` §31 | `evidence/performance/external-comparison.json` | `sh scripts/container-fuse-test.sh` |
| `external-comparison-throughput.svg` | `PERFORMANCE.md` §31 | `evidence/performance/external-comparison.json` | `sh scripts/container-fuse-test.sh` |
| `baseline-passthrough.svg` | `PERFORMANCE.md` §29 | `evidence/performance/baseline-passthrough.json` | `sh scripts/container-baseline-passthrough.sh` |
| `planner-mounted-paired.svg` | `PERFORMANCE.md` §29 | `evidence/performance/planner-mounted-paired.json` | `sh scripts/container-planner-mounted.sh` |
| `adversarial-concurrency.svg` | `PERFORMANCE.md` §32 | `evidence/correctness/adversarial-concurrency.json` | `sh scripts/container-adversarial-concurrency.sh` |
| `application-workloads.svg` | `PERFORMANCE.md` §33 | `evidence/performance/application-workloads.json` | `sh scripts/container-application-workloads.sh` |

The **chart command** is the same for every row: `python3 scripts/render_charts.py`
(generate) or `python3 scripts/render_charts.py --check` (drift check). The
receipt commands above reproduce the *data*; they need Docker and are not run by
this document. `python3 scripts/render_charts.py --list` prints the same mapping.

## What this index deliberately does not do

* **Every committed image is indexed above.** The figures under `docs/charts/`
  are committed SVGs generated by `scripts/render_charts.py` from the receipts;
  the "Images and charts" section maps each one to its receipt and its exact
  command. The only `.png` mention in the doc set is about OrFS's
  *image-recognition* feature (`docs/QUERY.md` §9), which is not a figure.
* **Not every prose sentence is a receipt.** The curated, machine-checked subset is
  `scripts/docs-receipts.json` (run `sh scripts/check-docs-receipts.sh`); the
  remaining known gaps are listed in `docs/RECEIPTS.md` §"Deliberately NOT covered".
* **Cold-cache numbers are not reproducible here.** Dropping the page cache needs
  `CAP_SYS_ADMIN`; courts that would depend on it record the limitation instead
  (`tests/baselines.rs`).
