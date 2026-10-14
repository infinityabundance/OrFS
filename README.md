# OrFS

**Non-withdrawal, concealed-expansion FUSE filesystem** — a real, mountable,
native-Rust Linux filesystem with permanent authoritative history, `io_uring`
backing I/O, and EKBLOOM-accelerated read paths.

> Governing objective: **spend manifested space to maximise speed.**

OrFS is two laws made executable:

- **Law I — Non-withdrawal.** Committed authoritative history is never
  overwritten, truncated, reused, or garbage-collected. Every committed
  transition extends the previous history: `L_{n+1} = L_n ⊕ Δ_n`.
- **Law II — Concealed expansion.** Additional operational structures are
  physically manifested behind the ordinary logical namespace, deliberately
  spending storage, memory, and construction work to accelerate reads.

`or.log` is the source of truth. EKBLOOM is the acceleration engine (consumed
as an independent, exact-version crates.io dependency; see `docs/LIMITATIONS.md`).
FUSE is the Linux interface.

## Status

This repository is being built in ordered phases (see `docs/ORFS-SPEC.md` and
`docs/PROGRESS.md`). The CLI is honest: a command that is part of the design
but not yet wired rejects the request with its owning phase rather than
pretending to work.

Working today: `orfs doctor` (and `orfs doctor --capacity --backing <dir>`, a
capacity report that also names a bounded action to free derived space, and
`orfs doctor --economics --backing <dir>`, the four-category storage accounting
plus a validated retained-growth forecast), `orfs init`,
`orfs inspect [--json]`,
`orfs verify [--deep]`, `orfs recover`, `orfs tier relocate|list|verify|recall`
(immutable relocation of sealed segments to a cold tier), `orfs reclaim`
(bounded-space recovery: relocate sealed segments and/or drop derived structures
without withdrawing authority), and
`orfs mount <backing> <mnt> --transport <fuse|fuse-uring> --backing-io <sync|uring> ...`
(plus `orfs unmount`). `--transport fuse-uring` requests FUSE-over-`io_uring`
(F2), which negotiates at runtime and falls back cleanly when the kernel does not
enable it (see `docs/FUSE_URING.md`).

| Phase | Area | State |
|---|---|---|
| 0 | Environment, pinned container workflow, evidence foundation | complete |
| 1 | Authoritative append-only log | complete |
| 2 | Transactions and durability | complete |
| 3 | Namespace and extents | complete |
| 4 | Traditional FUSE | complete |
| 5 | Backing `io_uring` | complete |
| 6 | Historical snapshots and index checkpoints | complete |
| 7 | Concealed manifestation | complete |
| 8 | EKBLOOM integration | complete |
| 9 | Concealed query structures | complete |
| 10 | FUSE-over-`io_uring` | implemented; **active on this host** (real F2 mount — see `docs/FUSE_URING.md`) |
| 11 | Security and crash-hardening | complete |
| 12 | Performance court | complete |
| 13 | Reproducibility repair (independent-audit findings) | complete |
| 14 | POSIX court closure (§33) | complete |
| 15 | Real FUSE-over-`io_uring` (F2) transport | complete; **active on this host** |
| 16 | Measured manifestation frontier end-to-end | complete |
| 17 | Simulated power-loss durability model | complete |
| 18 | Lean authoritative read path, planner isolation, extent index | complete |
| 19 | Concurrent immutable read views (remove the global read lock) | complete |
| 20 | Persistent historical-root indexes and suffix replay | complete |
| 21 | Kernel-served FUSE passthrough for immutable snapshots | complete |
| 22 | Incremental, adaptive generational manifestation | complete |
| 23 | ENOSPC/device-error recovery hardening and a capacity policy | complete |
| 24 | Broad POSIX court (pjdfstest; xfstests assessment) | complete |
| 25 | Close the pjdfstest POSIX deviations | complete |
| 26 | F2 transport servicing and rigorous concurrent measurement | complete |
| 27 | Fix publish `O(N²)` churn; large-scale endurance and recovery acceleration | complete |
| 28 | Native FUSE adversarial hardening and fuzzing | complete |
| 29 | Independent acceptance audit (gates A–N) | complete |
| 30 | Consistency repair (docs, scripts, receipts) | complete |
| 31 | Faster commits: ordered group commit + conflict-aware parallel preparation | complete |
| 32 | End-to-end group-commit coordinator (opt-in); correctness court; honest measurement | complete |
| 33 | Review-finding consolidation: read-path timing, native `nlink`, supplementary groups, calibration guarantee, passthrough integrity | complete |
| 34 | crates.io publishing readiness (blocked on the `ekbloom` dependency) | complete |
| 35 | Consume the published `ekbloom` release; publish readiness | complete |
| 36 | Publish `orfs` v0.1.0 to crates.io | complete |
| 37 | Object-localized read selection + allocation-light authoritative fallback | complete |
| 38 | Docs-from-receipts check; documentation reconciled to evidence | complete |
| 39 | Group commit extended to ordinary write workloads (both transports) | complete |
| 40 | Whole-system history-scaling court | complete |
| 41 | Acceptance audit re-run at HEAD; residual doc-drift closed | complete |
| 42 | Immutable append-only manifestation catalogue (growth-independent publication) | complete |
| 43 | Compiled object read plans; bounded planner lifecycle | complete |
| 44 | Single reproducible automated gate for the docs-receipts check | complete |
| 45 | Fast historical-root access (binary accelerator + committed-root directory) | complete |
| 46 | Adaptive, bounded group commit; wiring-defect correction (grouping is a ~5× win) | complete |
| 47 | F2 queue-affine concurrency (recovers F2 to ~88–103% of F0; p99 target unmet) | complete |
| 48 | Persistent index layout competition (nothing integrated; treap wins on mutation) | complete |
| 49 | Scan-resistant volatile planner caches (S3-FIFO admission); §10 volatile-cache court | complete |
| 50 | CPU microarchitecture court; per-read manifest clone removed (8→2 allocs/read); lock-free served counters | complete |
| 51 | Documentation refresh (cache/eviction descriptions); publish `orfs` v0.2.0 to crates.io | complete |
| 52 | Global search directory (§9): version-qualified trigram→object directory with density-adaptive posting sets | complete |
| 53 | External baseline comparators (ext4 / tmpfs / overlay / raw memory) — the floor every speedup is measured against | complete |
| 54 | Serious-filesystem docs: threat model, acceptance-gate definitions (A–N), reproducibility index | complete |
| 55 | io_uring depth sweep with SQ/CQ-pressure counters; on-disk wire-format specification | complete |
| 56 | 64-thread read scaling (p50/p95/p99/p99.9); POSIX-extras court (xattrs, links, groups, durability); directory hard-link returns `EPERM` | complete |
| 57 | Real PMU hardware counters + flamegraph; the "no counters" claim corrected (`perf_event_paranoid` was a myth — the container seccomp profile was the gate) | complete |
| 58 | Integrate a sealed dense-ordinal inode-id spine for the immutable historical role (7× smaller, flat `O(1)` lookup); the live writer spine stays the treap | complete |
| 59 | Native fsx/fsstress-equivalent fault-injection court (external xfstests not runnable) | complete |
| 60 | Acceptance-audit re-run at HEAD with a two-run diff vs the phase-41 audit | complete |
| 61 | Fix the native-FUSE `JobQueue` lost-wakeup race the HEAD audit recorded (mutex-guarded predicate + notify); regression tests | complete |
| 62 | Device-fault evidence: `verify --deep` + `recover` after injected mid-log faults (the `dm-flaky`/`dm-error` probe is `ran:false`) | complete |
| 63 | Evidence charts: inline-styled SVG figures for the performance courts + an image→receipt→command reproducibility index | complete |
| 64 | Direct-page manifestations (research §5): a manifested, page-aligned contiguous atlas of a selected object's bytes, wired in as a measured `direct-image` planner candidate | complete |
| 65 | Autonomous concealed-expansion controller (research §12): a pure predictor chooses no-manifestation vs the direct-page atlas under a manifested-space budget `B`; best-effort construction + byte-identity verification; measured monotone answer-time improvement with authority retained | complete |
| 66 | Mounted courts for three reviewer items: F2 concurrency extended to 64 readers (throughput 86–107% of F0; the strict p99 target is **not** met at every count, stated plainly); a `baseline_passthrough` three-way comparison (ext4 vs FUSE passthrough vs ordinary OrFS mount); and a paired mounted planner benchmark (manifested vs authoritative-only over one history) | complete |
| 67 | Explicit `format_version` in the authoritative log's genesis identity (`0` = legacy, `1` = current; accept any known version `≤` current, refuse a higher one with a typed error); frozen `legacy_v0`/`current_v1` compatibility fixtures + a byte-identity court (`tests/format_compat.rs`); `docs/MIGRATION.md` | complete |
| 68 | Capacity guard: `orfs doctor --capacity` operator report (retained bytes, live backing free space, projected growth, `ok`/`warn`/`exhausted` verdict); a typed `CapacityExhausted` pre-flight refusal **before any byte is written**; `init` reservation refusal; `docs/CAPACITY.md` runbook | complete |
| 69 | Endurance space-amplification curve (reviewer item 8): a bounded court drives a growing retained history over many epochs and samples `logical` vs `authoritative_physical` vs `manifested` vs `total physical` bytes, the amplification ratio, and the growth counters, in an authoritative and a manifested arm over the same history; rendered as charts. Amplification grows monotonically (auth 1.50→10.08; manifested 6.56→88.48) over the bounded run; the multi-day run is the follow-up | complete |
| 70 | Bounded Loom model for the concurrent immutable read views + the group-commit coordinator (reviewer item 11): proves no deadlock/race after the Phase-19 lock removal — a reader never sees a partial view, and a batch never acks a transaction before the durability barrier covering its bytes | complete |
| 71 | Documentation decisions (docs-only): the final index-spine decision (`docs/INDEX.md` — the live writer spine stays the path-copying treap; the sealed historical role uses the dense-ordinal `InodeStore::Sealed`), the Docker-only operator runbook (`docs/OPERATIONS.md`), and the rejected image pixel-surface pyramid (`docs/REJECTED.md`) | complete |
| 72 | ENOSPC fault injection at the edge (reviewer item #13): fill a volume to ~90/95/99/100% of its usable capacity with the deterministic Phase-23 capacity latch, prove `write + fsync` either commits cleanly or is refused with a typed ENOSPC leaving the previous root byte-identical and the volume read-only, and prove a crash at the edge then `recover` selects the newest valid committed generation and silently repairs nothing | complete |
| 73 | One-command continuous verification (`scripts/container-verify.sh`): the pre-PR gate runs `check-all`, the default + `--features failpoints` suites, and the POSIX / native fault-injection / `io_uring` / Loom courts, then the docs-receipts check again — one container at a time, with a per-stage `PASS`/`FAIL`/`SKIPPED` summary; `--fast` runs the cheap, always-available subset. Publishes the volatile-cache scan-resistance **hit-rate** comparison (admission 95.2 % vs FIFO 88.0 % vs LRU 95.2 %) and the steady-state `allocs/read` (8 → 2) in `docs/PERFORMANCE.md` §17/§18 | complete |
| 74 | F2 honest p99 **decision** + external comparison (reviewer items #3, #9): the F2 court records **p99.99**, the ring's **SQ/CQ counters**, and a **PMU** pass on the F2 daemon threads; `docs/PERFORMANCE.md` §31 states the call — F2 queue-affine matches F0's p50 and 93–110 % of its throughput (winning at 64 readers) but **loses p99 from 4 readers up**, so **use F0 for latency, `ORFS_F2_RINGS=8` for throughput**. Publishes the mounted **OrFS (F0/F2) vs ext4 vs tmpfs** head-to-head with the honest losses (rand 4 KiB p99 ~70–118× worse; seq read ~17–40× lower) and adds **p99.99** to the 64-thread scaling | complete |
| 75 | Storage economics (separated accounting + a validated retained-growth forecast): `orfs doctor --economics` accounts every byte beneath a volume in **four non-overlapping categories** (permanent authoritative history / rebuildable manifestations / metadata / temporary construction space), proves they sum to the observed on-disk total, and predicts retained growth and time-to-full from a **written**-bytes rate and an overwrite ratio. The court `tests/storage_economics.rs` **falsifies** the naive live-bytes model (an overwrite still appends; prediction φ·W matches measurement within tolerance); `docs/STORAGE-ECONOMICS.md` forward-refs the tier-relocation phase | complete |
| 76 | Immutable tier relocation: `orfs tier relocate\|list\|verify\|recall` moves **sealed** authoritative segments to a cheaper cold tier **without withdrawing authority** — the local copy is removed only after the tier copy is written, fsynced, read back and digest-verified, and only after a durable `Released` transition (Kafka KIP-405). The tier is **content-addressed** `(uuid, segment id, digest)` so copy/delete are idempotent and a crash converges; an append-only catalogue in the **Metadata** category is the strongly-consistent, separate state. The active head is never relocatable; an offline tier returns a typed `TierUnavailable` and refuses the open (never silently shortened). `tests/tier_relocation.rs` proves identity, verify-before-forget, a six-row crash matrix, catalogue fail-closed, and mixed local+remote recovery; `docs/TIERING.md` | complete |
| 77 | Bounded-space recovery: `orfs doctor --capacity` (schema `orfs.capacity.report.v2`) reports the **relocatable sealed bytes**, the **droppable rebuildable bytes**, and a recommended bounded action; `orfs reclaim` (dry-run by default, `--apply` to act) relocates sealed segments and/or drops **derived** structures, then asserts the committed root, digest, committed bytes, and commit watermark **byte-identical** — it never touches the active head or an authoritative byte. Recovery under space pressure fails **closed** with the typed `RecoverySpaceExhausted` (`ENOSPC`) and an intact, fully-readable history; a read-only open serves all committed history at zero free. `tests/bounded_recovery.rs` proves an edge crash → newest generation, evacuation at the reserve (measured free-space increase, commits resume, committed roots byte-identical), an unavailable tier, a safe drop-rebuildable, and read-only-at-0-free; `docs/CAPACITY.md` §14, `docs/RECOVERY.md` §11 | complete |

Honest non-claims: the **image pixel-surface pyramid is rejected, not merely
unimplemented** — only descriptive geometry is implemented, and the decision and
rationale are in `docs/REJECTED.md`. No performance superiority of F2 or of the
manifested read paths is claimed. See `docs/LIMITATIONS.md` and `docs/PERFORMANCE.md`.

## Development is Docker-only

All compilation, tests, fuzzers, benchmarks, and mount experiments run inside
minimal, digest-pinned Docker images with memory/swap caps (OOM protection).
Nothing is built directly on the host.

```sh
scripts/container-build.sh        # cargo build
scripts/container-test.sh         # cargo test
scripts/container-check.sh        # fmt + clippy
scripts/container-reproduce.sh    # clean release build + test
```

Container FUSE and `io_uring` still depend on the host kernel; this workflow
does **not** provide kernel isolation.

## Layout

```text
src/        one library crate + the `orfs` binary (internal modules, not crates)
tests/      integration tests (log/transaction/namespace/snapshot/crash/...)
benches/    benchmarks
docs/       normative specifications (see docs/ORFS-SPEC.md)
evidence/   machine-readable, reproducible evidence
scripts/    pinned-container execution
research/   originating design documents (local-only; gitignored, not published)
```

## License

MIT OR Apache-2.0.
