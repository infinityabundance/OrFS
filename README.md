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
as an independent, version-pinned dependency). FUSE is the Linux interface.

## Status

This repository is being built in ordered phases (see `docs/ORFS-SPEC.md`).
The CLI is honest: a command that is part of the design but not yet wired
rejects the request with its owning phase rather than pretending to work.
`orfs doctor` is fully real today.

| Phase | Area | State |
|---|---|---|
| 0 | Environment, pinned container workflow, evidence foundation | in progress |
| 1 | Authoritative append-only log | — |
| 2 | Transactions and durability | — |
| 3 | Namespace and extents | — |
| 4 | Traditional FUSE | — |
| 5 | Backing `io_uring` | — |
| 6 | Historical snapshots and index checkpoints | — |
| 7 | Concealed manifestation | — |
| 8 | EKBLOOM integration | — |
| 9 | Concealed query structures | — |
| 10 | FUSE-over-`io_uring` | — |
| 11 | Security and crash-hardening | — |
| 12 | Performance court | — |

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
research/   the originating OrFS specification design documents
```

## License

MIT OR Apache-2.0.
