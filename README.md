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

Working today: `orfs doctor`, `orfs init`, `orfs inspect [--json]`,
`orfs verify [--deep]`, `orfs recover`, and
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

Honest non-claims: the image pixel-surface pyramid is **not materialised** (only
its geometry is implemented), and no performance superiority of F2 or of the
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
