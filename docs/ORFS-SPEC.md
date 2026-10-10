# OrFS — Master Specification Index

**Product:** OrFS — a non-withdrawal, concealed-expansion Linux filesystem
(FUSE), built in native Rust with `io_uring` backing I/O and EKBLOOM-accelerated
read paths.

This document is the **master index** for the OrFS implementation. It states the
governing laws and objective, maps the build to four correctness planes and
thirteen ordered phases, and tracks the normative document set. It deliberately
makes **no performance or correctness claim that is not backed by evidence in
`evidence/`**.

---

## 1. Authority

The originating, authoritative design specification is:

> **`research/OrFS.md`** — *OrFS — Non-Withdrawal, Concealed-Expansion Filesystem* (v0.2, proposed engineering specification).

That document is the source of truth for intent, invariants, on-disk concepts,
transport profiles, courts, and acceptance criteria. It is **local-only**: the
`research/` directory is gitignored and is not published with this repository.
The documents under `docs/` (including this index) are **implementation-facing
subordinate specifications**: they may refine or operationalise
`research/OrFS.md`, but where they conflict, `research/OrFS.md` governs.
`research/` is read-only reference material and is never modified by the
implementation.

---

## 2. The two laws and the governing objective

**Law I — Non-withdrawal.** Committed authoritative history is never overwritten,
truncated, reused, or garbage-collected. Every committed transition extends the
previous history:

```
L_{n+1} = L_n ⊕ Δ_n        (L_0 ⪯ L_1 ⪯ L_2 ⪯ …)
```

Logical deletion, truncation, and rename are new committed events, not
in-place mutation of prior records. A root is a *position* (committed end
offset) in a volume's authoritative record sequence, not a content hash.

**Law II — Concealed expansion.** Additional operational structures are
deliberately manifested *behind* the ordinary logical namespace, spending
storage, memory, and construction work to accelerate reads. The manifested body
may be larger than the logical contents and is not exempt from physical
accounting.

**Governing objective:**

> **Spend manifested space to maximise speed.**

`or.log` (the authoritative append-only log) is the source of truth. EKBLOOM is
the outward acceleration engine, consumed as an independent, version-pinned
dependency. FUSE is the Linux interface.

A fault in the manifested plane must never corrupt the authoritative plane; a
change to the transport plane must never change filesystem semantics.

---

## 3. The four planes

The implementation is organised into four planes, each with a separate
correctness contract (see `src/lib.rs`):

| Plane | Name | Responsibility |
|---|---|---|
| **A** | Authoritative history | Permanent records, transaction ordering, committed roots, replay/recovery |
| **B** | Namespace interpretation | Reconstructs ordinary FS semantics from the log: inodes, directories, extents, snapshots |
| **C** | Manifested acceleration | Additional read/query/navigation structures that never alter authoritative history |
| **D** | Transport & storage | FUSE transport, `io_uring` backing operations, optional accelerated kernel interfaces |

---

## 4. The thirteen build phases (0–12)

Each phase is independently testable and has an exit gate. `research/OrFS.md`
(milestones M0–M8 and the acceptance requirements) governs the substance of each
phase.

| Phase | Area | State |
|---|---|---|
| 0 | Environment, pinned container workflow, capability probe, EKBLOOM wiring, evidence foundation | **complete** |
| 1 | Authoritative append-only log (Plane A) | **complete** |
| 2 | Transactions and durability (Plane A) | **complete** |
| 3 | Namespace and extents (Plane B) | **complete** |
| 4 | Traditional FUSE transport (Plane D) | planned |
| 5 | Backing `io_uring` (Plane D) | planned |
| 6 | Historical snapshots and index checkpoints (Planes A/B) | planned |
| 7 | Concealed manifestation (Plane C) | planned |
| 8 | EKBLOOM integration (Plane C) | planned |
| 9 | Concealed query structures (Plane C) | planned |
| 10 | FUSE-over-`io_uring` (Plane D) | planned |
| 11 | Security and crash-hardening (all planes) | planned |
| 12 | Performance court (all planes) | planned |

### Phase 0 status (accurate)

What actually exists and is verified today:

- The `orfs` crate builds, its tests pass, and `cargo fmt`/`clippy -D warnings`
  are clean **inside the pinned container** (`scripts/container-*.sh`).
- `src/capabilities.rs` + `orfs doctor` perform a **real** kernel/container
  capability probe (no mutation of host state).
- The error model (`src/error.rs`) is fully populated and maps to POSIX errnos.
- EKBLOOM `v0.3.0` is consumed as an immutable, rev-pinned git dependency
  (`ekbloom = { git = "file:///mnt/1tb_kingston/EKBLOOM", rev = "255452e1…", version = "=0.3.0" }`)
  and exercised by a round-trip test; its state mathematics is not reimplemented
  here. See `docs/LIMITATIONS.md` §1.
* Every other CLI subcommand (`mount`, `unmount`, `stat`, `snapshot`,
  `manifest`, `grow`, `query`, `bench`) is present in the target surface but
  **explicitly unimplemented**: it rejects with `ENOSYS` naming its owning phase.
  No placeholder behaviour is advertised as working. `init`, `inspect`,
  `verify`, and `recover` are genuinely implemented.

Phases 4–12 are **not implemented**. The CLI is intentionally honest about this.
Phases 0–3 are complete; see `docs/PROGRESS.md`.

---

## 5. The document set

Normative implementation documents to be produced. Status is marked honestly.

| Document | Subject | Status |
|---|---|---|
| `docs/ORFS-SPEC.md` | This master index (laws, objective, planes, phases, doc map) | **exists** |
| `docs/ON_DISK.md` | Physical layout, segments, record envelope, format versioning | **exists** (Phase 1) |
| `docs/LOG-INVARIANTS.md` | Authoritative log invariants, replay, root-by-position identity | **exists** (Phase 1) |
| `docs/PROGRESS.md` | Honest per-phase status and delivered artifacts | **exists** |
| `docs/TRANSACTIONS.md` | Transaction framing, ordering, atomicity, durability modes | **exists** (Phase 2) |
| `docs/NAMESPACE.md` | Inode/dentry/extent/index semantics, proof obligations | **exists** (Phase 3) |
| `docs/FUSE-SEMANTICS.md` | POSIX/FUSE operation semantics, handles, cache modes, permissions | planned (Phase 4) |
| `docs/IO_URING.md` | Backing `io_uring` rings (writer/read/bloom), backpressure, fallback | planned (Phase 5) |
| `docs/FUSE_URING.md` | FUSE-over-`io_uring` transport, capability negotiation, safe fallback | planned (Phase 10) |
| `docs/EKBLOOM-INTEGRATION.md` | Manifestation profiles, certified selection, exact fallback | planned (Phase 8) |
| `docs/RECOVERY.md` | Crash/torn-write recovery, rebuildable indexes, no silent repair | planned (Phase 2+) |
| `docs/SECURITY.md` | Permission model, hostile-backing-data handling, threat model | planned (Phase 11) |
| `docs/PERFORMANCE.md` | Benchmark methodology, metrics, reproducibility rules | planned (Phase 12) |
| `docs/LIMITATIONS.md` | Known limits, kernel-dependence, unsupported capabilities | planned |

Until a document above is written, this index is the only normative OrFS
document in `docs/`; treat unimplemented phases as unspecified by code.

---

## 6. Evidence and reproducibility

All project execution is **Docker-only**: build, tests, lint, fuzzers,
benchmarks, and mount experiments run inside digest-pinned images with
memory/swap caps, never on the host (see `scripts/`). Container FUSE and
`io_uring` still depend on the host kernel; this is documented under
`docs/LIMITATIONS.md` (pending).

Machine-readable evidence lives under `evidence/`:

- `evidence/receipts/` — host environment, container image IDs, toolchain,
  EKBLOOM dependency fingerprint, and the `doctor` capability report.
- `evidence/{correctness,recovery,performance,security}/` — populated by later
  phases.

Reproduce the Phase 0 gates:

```sh
scripts/container-build.sh     # cargo build
scripts/container-test.sh      # cargo test  (tests/smoke.rs)
scripts/container-check.sh     # cargo fmt -p orfs --check + clippy -D warnings
scripts/receipts-host.sh       # host-side receipts
sh -c '. scripts/lib.sh && docker_run sh scripts/receipts-container.sh'
```
