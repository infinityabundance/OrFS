# Docs-from-receipts check

This document describes the scheme by which OrFS **generates documentation from,
and checks documentation against, the generated evidence receipts**, and how to
run the check that rejects docs whose numbers no longer match the evidence.

The regulator of record is the machine-generated evidence under `evidence/`
(performance measurements and correctness results) plus the provenance receipts
under `evidence/receipts/`. Prose in `docs/` *cites* those numbers. Over time the
prose drifts while the evidence is regenerated (or vice versa). This check makes
that drift a build failure instead of a silent inaccuracy.

## 1. Scheme

Two independent verifications, both driven by the machine-readable mapping
[`scripts/docs-receipts.json`](../scripts/docs-receipts.json):

1. **Provenance / currency** (`provenance` block). Every receipt in
   `evidence/receipts/*.json` that records a source commit — under any of the
   configured field names `orfs_git_commit`, `source_commit`,
   `audited_head_commit` — is compared with the repository HEAD:

   | classification | meaning |
   |---|---|
   | `current` | the recorded commit *is* HEAD |
   | `stale` | the recorded commit is an **ancestor** of HEAD (older coverage) — a distinct, clearly-labelled finding |
   | `unknown` | the recorded commit is not a commit in this repository |
   | `diverged` | the recorded commit is neither HEAD nor an ancestor of HEAD |

   A `stale`, `unknown`, or `diverged` receipt **fails** the check unless it is
   explicitly listed in the **allowlist** with a reason. Allowlisted receipts are
   still printed (as `allowed-historical`), so nothing passes silently.

   > The check never rewrites a receipt. A receipt that records an older commit
   > is reported, not "refreshed". Refreshing a receipt to claim newer coverage
   > would fabricate evidence.

2. **Curated doc → evidence citations** (`citations` block). Each citation names
   a doc file, a regex over that doc's text, one or more capture groups, and for
   each group the evidence JSON file and the path to the value it must equal.
   The doc's stated number is compared with the evidence value within a
   per-citation tolerance.

The check only reads files. It writes nothing to `docs/` or `evidence/`.

## 2. Running it

It is a **host** check: it does **not** use Docker or cargo, and needs only
`python3` (standard library) and `git`.

```sh
sh scripts/check-docs-receipts.sh          # human-readable, itemised report
sh scripts/check-docs-receipts.sh --json   # machine-readable report
```

Exit codes:

| code | meaning |
|---|---|
| `0` | every provenance receipt and every citation matches |
| `1` | at least one stale/unknown/diverged receipt or at least one citation mismatch/error (the report itemises each) |
| `2` | `python3` is not on `PATH` |

### The reproducible gate entry point

`scripts/check-all.sh` is the single host entry point that runs the cheap,
deterministic gates in order:

```sh
sh scripts/check-all.sh          # fmt/lint (container) + this check + chart drift + full test suite (container)
sh scripts/check-all.sh --fast   # fmt/lint (container) + this check + chart drift only
```

It calls `scripts/container-check.sh` (fmt + clippy in the pinned container),
then `check-docs-receipts.sh` (host), then `python3 scripts/render_charts.py
--check` (host; Phase 64 — a committed `docs/charts/*.svg` that no longer matches
its receipt fails the gate exactly like a citation), then
`scripts/container-test.sh`. The
mounted FUSE / `io_uring` / POSIX courts are deliberately excluded because they
need `/dev/fuse`, `CAP_SYS_ADMIN` and an unconfined seccomp profile, which a
hosted CI runner generally cannot grant; run them explicitly. A CI job can call
`check-all.sh` directly.

### Why it is not folded into `container-check.sh`

`scripts/container-check.sh` is the *in-container* `cargo fmt -p orfs --check` +
`clippy` gate, and the project contract is that compilation/test tooling runs only
inside the pinned container (see `docs/LIMITATIONS.md`, `README.md`). This check
is host-side and Docker-free (it needs only `sh`, `git`, `python3`), so it stays a
separate step that `check-all.sh` sequences after the container gate.

## 3. What is covered — and what is not

**Do not read this section as "all doc numbers are checked."** Coverage is a
curated subset. The check is honest about the boundary; uncovered claims are
listed explicitly.

### Provenance

Covered: every `evidence/receipts/*.json` that records a commit under the three
configured field names. Currently that is `source-commit.json`
(`orfs_git_commit`), `crates-io.json` (`source_commit`) and
`acceptance-audit.json` (`audited_head_commit`).

Allowlisted as intentionally historical:

| receipt | field | why |
|---|---|---|
| `crates-io.json` | `source_commit` | a crates.io publish record names the commit that was *published* (a historical ancestor of any later HEAD) |
| `acceptance-audit.json` | `audited_head_commit` | an independent audit is a point-in-time record at the commit audited; it must not be rewritten to a newer commit |
| `source-commit.json` | `orfs_git_commit` | a provenance receipt captured at the moment evidence was generated, regenerated on demand; the commit it names is the ancestor the evidence was produced at, not a claim of current-tree coverage |

`source-commit.json` is allowlisted as a **point-in-time provenance receipt**,
not a currency claim: it is regenerated on demand and records the commit at which
the committed evidence was produced (necessarily an ancestor of any later HEAD),
so it is not expected to name HEAD.

### Citations covered

| citation id | doc · section | value checked (`doc value` → evidence path) |
|---|---|---|
| `perf-s5-frontier-history` | `docs/PERFORMANCE.md` §5.2 | frontier table, profile `full`, `` `history` `` mean/min → `ekbloom-frontier.json` `profiles[summary.label=full].measured_paths_4k[path=history].{mean,min}_ns` |
| `perf-s5-frontier-logical` | `docs/PERFORMANCE.md` §5.2 | frontier table, profile `full`, `` `logical-extent` `` mean/min → `…[path=logical-extent].{mean,min}_ns` |
| `perf-s5-frontier-maxspeed` | `docs/PERFORMANCE.md` §5.2 | inline: `` `checkpoint` `` / `` `path-bloom` `` mean under `max-speed` → `…[summary.label=max-speed]…` |
| `perf-s5-baseline` | `docs/PERFORMANCE.md` §5.2 | authoritative baseline P50 4 KiB / 1 byte, and sequential GB/s → `authoritative_baseline.read_4k.p50_ns`, `.read_1b.p50_ns`, `.sequential_mb_per_s` |
| `perf-s6-commit-path` | `docs/PERFORMANCE.md` §6 | ordered commit rate, P50, P99 → `mechanisms.json` `commit_path.commits_per_s`, `commit_path.latency.{p50,p99}_ns` |
| `perf-s6-trigram-orfs` | `docs/PERFORMANCE.md` §6 | trigram `plan("orfs")` vs naive scan → `trigram_query.patterns[pattern=orfs].{index_plan,naive_scan}.p50_ns` |
| `perf-s6-trigram-absent` | `docs/PERFORMANCE.md` §6 | absent-trigram plan vs scan → `trigram_query.patterns[pattern=zzzz-no-such-trigram].{index_plan,naive_scan}.p50_ns` |
| `io-uring-s9-append` | `docs/IO_URING.md` §9 | sequential-append MB/s ×3 (sync / uring / batched) → `backing-uring.json` `results.sequential_append.{sync,uring,uring_batched}.mb_per_s` |
| `io-uring-s9-read` | `docs/IO_URING.md` §9 | random-read MB/s ×3 → `results.random_read.{sync,uring,uring_batched}.mb_per_s` |
| `audit-gateN-advantage` | `docs/ACCEPTANCE-AUDIT.md` §2 gate N | the "2955 vs 4118 ns P50" 1-byte direct pair → `ekbloom-e2e-release.json` `workloads[profile=full|none].read_1b.direct.p50_ns` |
| `audit-gateN-search-speedup` | `docs/ACCEPTANCE-AUDIT.md` §2 gate N | concealed-trigram speedup → `ekbloom-search-e2e-release.json` `search.indexed_speedup_over_scan` |
| `concurrency-s6-corelock` | `docs/CONCURRENCY.md` §6 | "core lock held ~200 ms" → `reader-scaling.json` `not_blocked_by_core_lock.locked_read_us_while_core_lock_held` |
| `concurrency-s6-readers` | `docs/CONCURRENCY.md` §6 | the reader sweep covers `1/2/4/8/16` → set of `reader-scaling.json` `results[].readers` |
| `manifest-s14-5-size-table` | `docs/MANIFESTATION.md` §14.5 | full-build vs 64-byte-change by object size (32/128/512 KiB) → `incremental-manifestation.json` `cost[object_size=…].{full,incremental}_build_ns` |
| `manifest-s14-5-changed-bytes` | `docs/MANIFESTATION.md` §14.5 | fixed-256 KiB incremental build vs changed bytes (64 B/1 KiB/8 KiB/32 KiB) → `cost_vs_changed_bytes[changed_bytes=…].incremental_build_ns` |
| `perf-s17-planner-cache-scan` | `docs/PERFORMANCE.md` §17 | volatile-cache court: body-plan rebuilds during a cold scan, admission policy vs the FIFO model → `planner-cache.json` `{measured,fifo_model}.scan_plan_builds` |
| `perf-s18-microarch-manifest-handle` | `docs/PERFORMANCE.md` §18 | microarchitecture court: `latest_for_shared` allocations per call → `microarch.json` `manifest_handle_allocations.latest_for_shared_allocs` |
| `perf-s19-search-directory-rare` | `docs/PERFORMANCE.md` §19 | global search directory: a rare pattern's files examined and content bytes read → `search-directory.json` `directory_path[pattern_hex=7a7a71].{files_considered,content_bytes_read}` |
| `perf-s21-uring-sq-pressure` | `docs/PERFORMANCE.md` §21 | io_uring depth sweep: SQ-full events at the smallest ring depth → `uring-depth.json` `rows[requested_depth=1].read.stats.sq_full_events` |
| `perf-s22-reader-scale64-noreplan` | `docs/PERFORMANCE.md` §22 | 64-thread reader scaling: the shared planner rebuilt no plan during the steady-state phase → `reader-scaling-64.json` `steady_state_counters.plan_builds_delta` |
| `recovery-s9-fault-verify-recover-rows` | `docs/RECOVERY.md` §9 | fault-injection verify/recover court: the always-on matrix and the opt-in sweep row counts → `fault-injection-verify-recover.json` `runs.default.row_count` / `runs.sweep.row_count` |
| `tier-reloc-*` (8 citations) | `docs/TIERING.md` §10 | the tier-relocation court's headline counts: segments relocated/total, bytes relocated, digest matches/mismatches, default boundaries checked, crash-matrix rows, offline segments reported, and the local/total authoritative byte footprint → `tier-relocation.json` `assessment.{relocation,identity,crash_matrix,tier_unavailable}.*` |
| `bounded-evac-free-space`, `bounded-evac-relocated`, `bounded-evac-boundaries`, `bounded-drop-rebuildable` (4 citations) | `docs/CAPACITY.md` §14.4 | the bounded-reclaim court's headline numbers: the free space freed by relocating sealed segments, the bytes relocated, the committed boundaries checked, and the bytes freed by dropping rebuildable manifestations → `bounded-recovery.json` `evacuation.{freed_bytes,relocated_bytes,boundaries_checked}` and `drop_rebuildable.dropped_bytes` |
| `expansion-governor-refusal`, `expansion-reclaim-not-undone`, `expansion-cancel-bound` (5 citations) | `docs/CAPACITY.md` §15 | the Phase-78 subordination court's **deterministic** counts (not the host-sensitive times): the governor-refusal constructed/planned/refused, the reclaim-not-undone dropped bytes and refusals, and the cancelation bound + resumed constructions → `expansion-controller.json` `subordination.*` |
| `posix-compat-pjdfstest-unclassified`, `posix-compat-pjdfstest-unsupported`, `posix-compat-pjdfstest-totals`, `posix-compat-adversarial-zero` (10 value checks) | `docs/POSIX-COMPAT.md` §6 | the compatibility matrix's reconciliation: `pjdfstest` zero unclassified failures, the mechanically-unsupported assertion count, the court totals (OrFS vs reference ext4), and the adversarial-concurrency receipt's zero mismatches / orphans / duplicate inodes / torn reads → `correctness/pjdfstest.json` `gate.*` / `deviations.*` / `{orfs,reference}.summary.*` and `correctness/adversarial-concurrency.json` |

### `docs/ACCEPTANCE-AUDIT.md` is exempt from live comparison

`docs/ACCEPTANCE-AUDIT.md` is a **point-in-time record** of an independent
acceptance audit taken at a specific commit. Its prose is deliberately *not*
re-checked against the current evidence, with one exception: the two stable
release-evidence citations `audit-gateN-advantage` and
`audit-gateN-search-speedup` **stay** in the table above because they track the
published `-release` evidence, which is stable across regenerations.

The former `audit-s5-concurrency` citation is **removed**: it compared a
historical audit figure with a since-regenerated `reader-scaling.json` (a debug
run whose absolute throughput and latency vary run-to-run), so no honest live
comparison is possible. Rather than "correct" the audit's point-in-time numbers
to a later run — which would fabricate the audit — the citation is dropped and
the audit document is left untouched.

### Deliberately NOT covered

These are known-gap examples, not an exhaustive list. They are either derived
(a ratio/range the check does not re-derive), qualitative, or in documents whose
numbers were not curated in this first pass:

* `docs/PERFORMANCE.md` §5.2 — the "best 4 KiB profile … 301 ns / 511 ns"
  sentence, and the trailing "$P(M)$ roughly flat (~300–520 ns)" range.
* `docs/PERFORMANCE.md` §5.4–§5.6 — the Phase-16 end-to-end tables and the
  library-level isolation figures (e.g. the `26 ns` / `1021 ns` / `501 ns` /
  `1112 ns` / `5450 ns` claims and the `2.2×` / `10.9×` / `8.6×` ratios), and the
  `grep -r` / `M / logical` derived figures.
* `docs/PERFORMANCE.md` §6 — the io_uring "e.g. 3 179 vs 1 346 MB/s" fragment
  (ambiguous anchor) and the derived `≈217×` trigram ratio.
* `docs/IO_URING.md` §9 — the derived "batching narrows the gap (2.4× append,
  1.2× read over single-op uring)" sentence.
* `docs/ACCEPTANCE-AUDIT.md` §2 gate N — the "~1.3–1.4×" range (a range, not a
  single number); and `docs/ACCEPTANCE-AUDIT.md` §5 in full — the "636→2750 MB/s
  over 1→16 readers" and "10.5 µs" view figures, plus the "~380–640 MB/s"
  global-lock range — all fall under the point-in-time exemption above.
* `docs/MANIFESTATION.md` §14.5 — the "read latency against generation depth
  (~3 µs, flat)" sentence.
* `docs/CONCURRENCY.md` §4 — the `≈60 ns` / `≈40 ns` publish-cost figures and
  the `p50 ≈ 53 µs / ≈ 60 µs` commit-latency figures (`publish-cost.json`).
* `docs/SNAPSHOTS.md`, `docs/QUERY.md`, `docs/FUSE_PASSTHROUGH.md` — no numbers
  from these were curated in this first pass.
* `docs/PERFORMANCE.md` §18–§20 — the microarchitecture, global-search-directory
  and external-baseline figures. §18's deterministic `latest_for_shared` count and
  §19's rare-pattern file/byte counts are curated; the host-sensitive latency
  figures (ns/read, reader scaling, the ext4/tmpfs/overlay latencies) are
  deliberately left uncovered because they move between runs.
* `docs/PERFORMANCE.md` §22–§23 — the 64-thread reader-scaling and PMU courts. §22's
  steady-state no-replan invariant (`plan_builds_delta`) **is** curated; the
  host-sensitive aggregate throughput and p50/p95/p99/p99.9 figures, every
  `pmu.json` counter (cycles, IPC, cache/branch miss rates — which move between runs
  and hosts), and the flamegraph are deliberately uncovered.
  `evidence/correctness/posix-extras.json` is likewise not curated: it is
  qualitative (`all_ok: true` plus per-check PASS/errno strings), not numeric.
* `docs/PERFORMANCE.md` §27 (Phase 64) — the direct-page-atlas court. Its honest
  content is a **selection** (which path the planner measured cheapest per size)
  plus host-sensitive latency; the deterministic facts in the receipt are the
  per-object extent counts, the atlas payload bytes, and `parity.all_byte_exact`.
  The latency/ratio figures are deliberately left uncurated because they move
  between runs. The committed figure `direct-page-atlas.svg` is nonetheless gated:
  `scripts/check-all.sh` now runs `python3 scripts/render_charts.py --check`, so a
  chart cannot silently diverge from this receipt.
* `docs/PERFORMANCE.md` §28 (Phase 65) — the autonomous concealed-expansion
  controller court. Its honest content is a **curve** (aggregate read time versus
  the manifested-space budget `B`) plus the chosen structures and the per-class
  selected path; the deterministic facts in the receipt are the chosen inode sets,
  the predicted/actual manifested bytes, the monotonicity flags, and the fact that
  every planner read is asserted byte-identical. The aggregate-time figures are
  host/load-sensitive single-run values and are deliberately left uncurated. The
  committed figure `expansion-controller.svg` is nonetheless gated by
  `python3 scripts/render_charts.py --check`. The Phase-78 **`subordination`**
  counts (deterministic) *are* curated, but against `docs/CAPACITY.md` §15, not
  §28.
* `evidence/recovery/fault-injection-verify-recover.json` (Phase 62) is mostly
  **qualitative** (a per-row matrix of `verify --deep` verdicts, `recover`
  outcomes, `data_intact` booleans and the `dm_probe` `ran:false` result); only
  its two row counts are curated (citation
  `recovery-s9-fault-verify-recover-rows`). Its `dm_probe` block records
  `ran: false` with the exact failing `losetup`/`dmsetup` commands — no `dm-*`
  result is fabricated.
* `tests/fixtures/` (Phase 67) — the frozen `or.log` compatibility fixtures and
  the `tests/format_compat.rs` court. These are **frozen bytes** plus boolean
  assertions (byte-identity against a fresh write, the reported `format_version`,
  and the typed refusal of a higher version), not numeric receipts under
  `evidence/`, so there is nothing to curate. They are indexed in
  `docs/REPRODUCE.md` and documented in `tests/fixtures/README.md` and
  `docs/MIGRATION.md`.
* `docs/PROGRESS.md`, `README.md` — out of scope by construction (this check
  governs docs against receipts, not the reverse index of phases).

Adding coverage is a one-line mapping edit — see §5.

## 4. Tolerances

Measurement receipts are single runs, so the check uses a tolerance rather than
exact equality. The default is `rel = 0.05` (5%) with `abs = 0`; a citation may
override `rel` and/or `abs`. A citation passes when
`|doc·doc_multiplier − evidence·evidence_multiplier| ≤ abs + rel·|evidence·evidence_multiplier|`.
Rotation (rounding to the precision quoted in the doc) is expected to fall well
inside 5%; a genuine drift (docs quoting an older run) does not.

## 5. Adding a new citation

1. Open `scripts/docs-receipts.json` and append an object to `citations`:

   ```json
   {
     "id": "short-unique-id",
     "doc": "docs/SOMEDOC.md",
     "section": "§N",
     "claim": "what the doc asserts",
     "regex": "a regex with (capture) (groups)",
     "fields": [
       {"group": 1, "label": "what group 1 is",
        "evidence": "evidence/performance/some.json",
        "path": "a.b[3].c",
        "doc_multiplier": 1, "evidence_multiplier": 1,
        "rel": 0.05, "abs": 0}
     ]
   }
   ```

   * `regex` is a Python regular expression searched over the whole doc. Make the
     anchor **unique** (include surrounding words/table pipes) so it cannot match
     the wrong row; `\s` matches newlines, so prefer `[ \t]` if a capture must not
     span lines.
   * `path` grammar: dotted keys (`a.b.c`), array index (`a[3]`), and array
     element selection by a field (`profiles[summary.label=full]`, dotted
     selector keys allowed). Use `[key=value]` rather than a raw index so the
     citation survives reordering.
   * `doc_multiplier` / `evidence_multiplier` convert units to a common scale
     (e.g. a doc in ms against evidence in ns uses `doc_multiplier: 1000000`).
   * Set `kind: "set"` (with a `collect: {"array": "...", "field": "..."}` field)
     for set membership instead of a numeric comparison.

2. Run `sh scripts/check-docs-receipts.sh` and confirm the new citation is the
   `[OK]`/`[MISMATCH]` outcome you expect.
3. If your citation reveals a genuine docs↔evidence discrepancy, **do not edit
   the doc or the evidence to make it pass** as part of adding the check —
   report it and let the owner decide whether the doc or the receipt is
   authoritative. (Editing the quoted number to match the receipt is the
   remediation once the drift is acknowledged; that is a separate change.)

## 6. Allowlisting an intentionally historical receipt

Add an entry to `provenance.allowlist` in `scripts/docs-receipts.json`:

```json
{"receipt": "NAME.json", "field": "source_commit", "reason": "why this is historical by design"}
```

The `reason` is mandatory in spirit: the entry is printed on every run so the
exception is visible, never silent.
