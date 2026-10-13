# OrFS — Master Specification Index

**Product:** OrFS — a non-withdrawal, concealed-expansion Linux filesystem
(FUSE), built in native Rust with `io_uring` backing I/O and EKBLOOM-accelerated
read paths.

This document is the **master index** for the OrFS implementation. It states the
governing laws and objective, maps the build to four correctness planes and the
ordered build phases, and tracks the normative document set. It deliberately
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

## 4. The ordered build phases (0–70)

Each phase is independently testable and has an exit gate. `research/OrFS.md`
(milestones M0–M8 and the acceptance requirements) governs the substance of each
phase. The early phases are summarised here; `docs/PROGRESS.md` is the detailed
per-phase record.

| Phase | Area | State |
|---|---|---|
| 0 | Environment, pinned container workflow, capability probe, EKBLOOM wiring, evidence foundation | **complete** |
| 1 | Authoritative append-only log (Plane A) | **complete** |
| 2 | Transactions and durability (Plane A) | **complete** |
| 3 | Namespace and extents (Plane B) | **complete** |
| 4 | Traditional FUSE transport (Plane D) | **complete** |
| 5 | Backing `io_uring` (Plane D) | **complete** |
| 6 | Historical snapshots and index checkpoints (Planes A/B) | **complete** |
| 7 | Concealed manifestation (Plane C) | **complete** |
| 8 | EKBLOOM integration (Plane C) | **complete** |
| 9 | Concealed query structures (Plane C) | **complete** |
| 10 | FUSE-over-`io_uring` (Plane D) | **complete; active** — the real F2 session mounts (see `docs/FUSE_URING.md`) |
| 11 | Security and crash-hardening (all planes) | **complete** |
| 12 | Performance court (all planes) | **complete** |
| 13 | Reproducibility repair (independent-audit findings) | **complete** |
| 14 | POSIX court closure (§33) | **complete** |
| 15 | Real FUSE-over-`io_uring` (F2) transport | **complete; active** — F2 engages for real on this host |
| 16 | Measured manifestation frontier end-to-end | **complete** |
| 17 | Simulated power-loss durability model | **complete** |
| 18 | Lean authoritative read path, planner isolation, extent index | **complete** |
| 19 | Concurrent immutable read views (remove the global read lock) | **complete** |
| 20 | Persistent historical-root indexes and suffix replay | **complete** |
| 21 | Kernel-served FUSE passthrough for immutable snapshots | **complete** |
| 22 | Incremental, adaptive generational manifestation | **complete** |
| 23 | ENOSPC/device-error recovery hardening and a capacity policy | **complete** |
| 24 | Broad POSIX court (pjdfstest; xfstests assessment) | **complete** |
| 25 | Close the pjdfstest POSIX deviations | **complete** |
| 26 | F2 transport servicing and rigorous concurrent measurement | **complete** |
| 27 | Fix publish `O(N²)` churn; large-scale endurance and recovery acceleration | **complete** |
| 28 | Native FUSE adversarial hardening and fuzzing | **complete** |
| 29 | Independent acceptance audit (gates A–N) | **complete** |
| 30 | Consistency repair (docs, scripts, receipts) | **complete** |
| 31 | Faster commits: ordered group commit + conflict-aware parallel preparation | **complete** |
| 32 | End-to-end group-commit coordinator (opt-in); correctness court; honest measurement | **complete** |
| 33 | Review-finding consolidation: read-path timing, native `nlink`, supplementary groups, calibration guarantee, passthrough integrity | **complete** |
| 34 | crates.io publishing readiness (blocked on the `ekbloom` dependency) | **complete** |
| 35 | Consume the published `ekbloom` release; publish readiness | **complete** |
| 36 | Publish `orfs` v0.1.0 to crates.io | **complete** |
| 37 | Object-localized read selection + allocation-light authoritative fallback | **complete** |
| 38 | Docs-from-receipts check; documentation reconciled to evidence | **complete** |
| 39 | Group commit extended to ordinary write workloads (both transports) | **complete** |
| 40 | Whole-system history-scaling court | **complete** |
| 41 | Acceptance audit re-run at HEAD; residual doc-drift closed | **complete** |
| 42 | Immutable append-only manifestation catalogue (growth-independent publication) | **complete** |
| 43 | Compiled object read plans; bounded planner lifecycle | **complete** |
| 44 | Single reproducible automated gate for the docs-receipts check | **complete** |
| 45 | Fast historical-root access (binary accelerator + committed-root directory) | **complete** |
| 46 | Adaptive, bounded group commit; wiring-defect correction (grouping is a ~5× win) | **complete** |
| 47 | F2 queue-affine concurrency (recovers F2 to ~88–103% of F0; p99 target unmet) | **complete** |
| 48 | Persistent index layout competition (nothing integrated; treap wins on mutation) | **complete** |
| 49 | Scan-resistant volatile planner caches (S3-FIFO-style admission); §10 volatile-cache court | **complete** |
| 50 | CPU microarchitecture court (§11); per-read manifest clone removed; lock-free served counters | **complete** |
| 51 | Documentation refresh (cache/eviction descriptions); publish `orfs` v0.2.0 to crates.io | **complete** |
| 52 | Global search directory (§9): version-qualified trigram→object directory with density-adaptive posting sets | **complete** |
| 53 | External baseline comparators (ext4 / tmpfs / overlay / raw memory) | **complete** |
| 54 | Serious-filesystem docs: threat model, acceptance-gate definitions (A–N), reproducibility index | **complete** |
| 55 | io_uring depth sweep with SQ/CQ-pressure counters; on-disk wire-format specification | **complete** |
| 56 | 64-thread read scaling (p50/p95/p99/p99.9); POSIX-extras court; directory hard-link returns `EPERM` | **complete** |
| 57 | Real PMU hardware counters + flamegraph; the "no counters" claim corrected (the container seccomp profile was the gate, not `perf_event_paranoid`) | **complete** |
| 58 | Integrate a sealed dense-ordinal inode-id spine for the immutable historical role (7× smaller, flat `O(1)` lookup); the live writer spine stays the treap | **complete** |
| 59 | Native fsx/fsstress-equivalent fault-injection court (external xfstests not runnable) | **complete** |
| 60 | Acceptance-audit re-run at HEAD with a two-run diff vs the phase-41 audit | **complete** |
| 61 | Fix the native-FUSE `JobQueue` lost-wakeup race the HEAD audit recorded (mutex-guarded predicate + notify); regression tests | **complete** |
| 62 | Device-fault evidence: `verify --deep` + `recover` after injected mid-log faults (the `dm-flaky`/`dm-error` probe is `ran:false`) | **complete** |
| 63 | Evidence charts: inline-styled SVG figures for the performance courts + an image→receipt→command reproducibility index | **complete** |
| 64 | Direct-page manifestations (research §5): a manifested, page-aligned contiguous atlas of a selected object's bytes, wired in as a measured `direct-image` planner candidate | **complete** |
| 65 | Autonomous concealed-expansion controller (research §12): a pure predictor chooses no-manifestation vs the direct-page atlas under a manifested-space budget `B`; best-effort construction + byte-identity verification; measured monotone answer-time improvement with authority retained | **complete** |
| 66 | Mounted courts for three reviewer items: F2 concurrency to 64 readers (p99 target unmet, stated plainly), a `baseline_passthrough` three-way comparison, and a paired mounted planner benchmark (manifested vs authoritative-only, same history) | **complete** |
| 67 | Explicit `format_version` in the authoritative log's genesis identity (`0` = legacy, `1` = current); frozen `v0`/`v1` compatibility fixtures + a byte-identity court; the accept-`≤`-current / refuse-higher rule with a typed error; `docs/MIGRATION.md` | **complete** |
| 68 | Capacity guard: `orfs doctor --capacity` operator report (retained bytes, live backing free space and mount/device, projected growth, `ok`/`warn`/`exhausted` verdict); a typed `CapacityExhausted` pre-flight refusal before any byte is written; `init` reservation refusal; the read-only transition; `docs/CAPACITY.md` operator runbook | **complete** |
| 69 | Endurance space-amplification curve (reviewer item 8): a bounded court grows a committed history over many epochs (content-neutral rewrites) and samples `logical` vs `authoritative_physical` vs `manifested` vs `total physical` bytes, the amplification ratio, and the growth counters, in an authoritative and a manifested arm over the same history; rendered as charts. Amplification grows monotonically (authoritative 1.50→10.08; manifested 6.56→88.48) over the bounded run; the multi-day run is the follow-up | **complete** |
| 70 | Bounded Loom model for the concurrent immutable read views and the group-commit coordinator (reviewer item 11): `src/sync_model.rs` mirrors the read-view publication and the coordinator's admission/fence, compiled against `loom::sync` under `--cfg loom`; `tests/loom_concurrency.rs` proves no deadlock/race after the Phase-19 lock removal (a reader never sees a partial view; a batch never acks before the barrier covering its bytes); `scripts/container-loom.sh` | **complete** |

### Implementation status (accurate)

Phases 0–70 are implemented; `docs/PROGRESS.md` is the per-phase record.

The crate `orfs` v0.2.0 is published on crates.io (see `docs/PUBLISHING.md`);
v0.1.0 was the first release.

- The `orfs` crate builds, its **485** tests (default) pass, and
  `cargo test --features failpoints` adds the crash-injection court (495 tests in
  total); `cargo fmt -p orfs --check` / `clippy --all-targets -- -D warnings` are
  clean **inside the pinned container** (`scripts/container-*.sh`).
- `src/capabilities.rs` + `orfs doctor` perform a **real** kernel/container
  capability probe (no mutation of host state).
- The CLI is fully wired: `doctor`, `init`, `inspect`, `verify`, `recover`,
  `mount`/`unmount`, `stat`, `snapshot`, `manifest`, `grow`, `query`, and `bench`
  are implemented and exercised by tests.
- EKBLOOM `v0.3.0` is consumed **unchanged** as an exact-version crates.io
  dependency (`ekbloom = "=0.3.0"`) and exercised by round-trip/equivalence
  tests; its state mathematics is not reimplemented here. A clean checkout builds
  with **no** sibling EKBLOOM tree. (Before Phase 35 it was a rev-pinned git
  dependency; that form is not publishable, because crates.io rejects git
  dependencies.) See `docs/LIMITATIONS.md` §1 and
  `evidence/receipts/{ekbloom,source-commit}.json`.

Honest non-claims (see the linked documents):

- **F2** (FUSE-over-`io_uring`) is implemented and **active on this host**: the
  kernel offers `FUSE_OVER_IO_URING` (`fuse.enable_uring=Y`) and the native session
  mounts for real (Phase 15; `docs/FUSE_URING.md`, `evidence/performance/fuse-uring.json`).
  Requesting it where the kernel cannot offer it still falls back to F1/F0 with
  byte-identical contents.
- **E1/E2** use **asynchronous** manifestation: a small write never waits for a
  whole-object rebuild, and a manifested profile EKBLOOM documents as
  non-accelerating is not even loaded on the read path (Phase 18). No performance
  superiority is claimed: the manifested frontier falls back to the authoritative
  read (`docs/PERFORMANCE.md`).
- The **image pixel-surface pyramid** is **not materialised**; only geometry is
  implemented (`docs/QUERY.md` §9.1, `src/image.rs`).

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
| `docs/FUSE-SEMANTICS.md` | POSIX/FUSE operation semantics, handles, cache modes, permissions | **exists** (Phase 4) |
| `docs/IO_URING.md` | Backing `io_uring` rings (writer/read/bloom), backpressure, fallback | **exists** (Phase 5) |
| `docs/SNAPSHOTS.md` | Historical snapshots, index checkpoints, mount cost | **exists** (Phase 6) |
| `docs/MANIFESTATION.md` | Concealed manifestation engine and physical accounting | **exists** (Phase 7) |
| `docs/EKBLOOM-INTEGRATION.md` | Manifestation profiles, certified selection, exact fallback | **exists** (Phase 8) |
| `docs/QUERY.md` | Concealed query structures and the typed query API | **exists** (Phase 9) |
| `docs/FUSE_URING.md` | FUSE-over-`io_uring` transport, capability negotiation, safe fallback | **exists** (Phase 10) |
| `docs/RECOVERY.md` | Crash/torn-write recovery, rebuildable indexes, no silent repair | **exists** (Phase 11) |
| `docs/MIGRATION.md` | On-disk migration: the `or.log` format-version registry, the v0→v1 compat matrix, the field locations for a third-party reader, and how to freeze a new compatibility fixture | **exists** (Phase 67) |
| `docs/SECURITY.md` | Permission model, hostile-backing-data handling, threat model | **exists** (Phase 11) |
| `docs/THREAT-MODEL.md` | Who can mount, what the security model prevents and does not | **exists** (Phase 54) |
| `docs/GATES.md` | Acceptance gates A–N: definitions, commands, acceptance criteria | **exists** (Phase 54) |
| `docs/ACCEPTANCE-AUDIT-HEAD.md` | Acceptance-audit re-run at HEAD: current-HEAD gate table and the two-run diff vs the phase-41 audit | **exists** (Phase 60) |
| `docs/REPRODUCE.md` | Reproducibility index: doc claim → receipt → command | **exists** (Phase 54) |
| `docs/charts/*.svg` | Generated evidence figures (inline-styled SVG), each mapped to a committed receipt in `docs/REPRODUCE.md` | **exists** (Phase 63) |
| `docs/PERFORMANCE.md` | Benchmark methodology, metrics, reproducibility rules | **exists** (Phase 12) |
| `docs/PMU.md` | Real hardware performance counters and the flamegraph; the container-flag requirement | **exists** (Phase 57) |
| `docs/LIMITATIONS.md` | Known limits, kernel-dependence, unsupported capabilities | **exists** |
| `docs/CAPACITY.md` | The volume capacity policy, `orfs doctor --capacity`, the pre-flight `CapacityExhausted` refusal, and the operator runbook for disk filling and the read-only transition | **exists** (Phase 23; runbook Phase 68) |

Every normative document above exists; there are no planned-only documents.

---

## 6. Evidence and reproducibility

All project execution is **Docker-only**: build, tests, lint, fuzzers,
benchmarks, and mount experiments run inside digest-pinned images with
memory/swap caps, never on the host (see `scripts/`). Container FUSE and
`io_uring` still depend on the host kernel; this is documented under
`docs/LIMITATIONS.md`.

Machine-readable evidence lives under `evidence/`:

- `evidence/receipts/` — host environment, container image IDs, toolchain,
  EKBLOOM dependency fingerprint, source commit, and the `doctor` capability
  report.
- `evidence/{correctness,recovery,performance,security}/` — test- and
  benchmark-generated evidence (POSIX court, recovery, performance court,
  unsafe audit, hostile-input results).

Reproduce the gates (from a clean checkout; the EKBLOOM pin is public, so no
sibling working tree is required):

```sh
scripts/container-build.sh        # cargo build
scripts/container-test.sh        # cargo test  (485 tests)
scripts/container-fuse-test.sh    # real-mount FUSE + performance court
scripts/container-uring-test.sh   # io_uring integration + backing benchmark
scripts/container-check.sh        # cargo fmt -p orfs --check + clippy -D warnings
scripts/receipts-host.sh          # host-side receipts (incl. source-commit.json)
sh -c '. scripts/lib.sh && docker_run sh scripts/receipts-container.sh'
```
