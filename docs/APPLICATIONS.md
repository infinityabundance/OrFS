# OrFS — End-to-End Application Workloads (Phase 81; the `git` blocker resolved in Phase 82)

This document records the **application layer**: five real programs driven end to
end against a **real OrFS FUSE mount** and against external baselines on the same
machine, in the same container.

> **Every number here comes from a real run inside the pinned container and is
> machine-generated into `evidence/performance/application-workloads.json`**
> by `tests/application_workloads.rs` under
> `scripts/container-application-workloads.sh`. The receipt is the authoritative
> record. Where a workload did not complete, that is stated as a loss — no number
> is invented.

The documented position this quantifies: OrFS is **not yet a faster
general-purpose replacement** for ext4/tmpfs on ordinary workloads
(`docs/PERFORMANCE.md` §31.2, Phase 74). This phase measures that at the
**application** layer rather than the filesystem-operation layer.

---

## 1. What is measured, and how

* **Court.** `tests/application_workloads.rs`, run by
  `scripts/container-application-workloads.sh` inside the `Dockerfile.appworkload`
  image (pinned Rust base + `git`, `sqlite3`, `tar`, `gcc`, `make`, `fuse3`).
  A bounded **always-on smoke** runs the same five workloads at a tiny scale; the
  **full sweep** is opt-in (`ORFS_APP_SWEEP=1`) and writes the receipt.
* **The mount.** A real OrFS volume is mounted with `fuse::spawn` — the same code
  path as `orfs mount` — using `MountOptions::default()`: the classical FUSE
  transport (**F0**), synchronous backing I/O, **page cache on**, durability
  `Ordered`. Writes are enabled.
* **Order-balanced trials.** Each workload runs **3 trials**; the arm order
  rotates between trials, and every trial time is recorded alongside the median.
* **Bounded.** Fixed file/op counts (recorded in the receipt and in §2) so every
  workload completes reliably and cannot OOM.

## 2. The workloads (bounded configuration)

The sweep configuration:

* **git repository** — `git init` → `add` → `commit` → modify → `add` → `commit`
  → `git clone --no-local` → `checkout -b` → `gc`, over **1200 files across 60
  directories**.
* **SQLite database** — `PRAGMA journal_mode=WAL`, `synchronous=FULL`, a bulk
  transaction of **20000 rows**, **200** individual fsync'd inserts, an index,
  50 indexed queries, and `VACUUM`, via the `sqlite3` CLI.
* **image-extraction analogue** — extract a **synthetic** OCI-layer-like tarball
  (**2000 small files** of 1 KiB and **4 large files** of 4 MiB, ≈18 MiB) with
  `tar`. It is a synthetic analogue of image extraction, **not** a real
  `docker pull`.
* **source build** — a generated C project with **120 translation units**, built
  with `make -j<8>`.
* **metadata-heavy tree** — **50000 files** (250 directories × 200 files)
  exercised in process with `create`, `stat`, `readdir`, `rename`, `unlink`; each
  of `create`/`stat`/`rename`/`unlink` contributes **50000 samples** and
  `readdir` contributes **250**.

## 3. The baseline contract (why this comparator is fair)

The **primary baseline (`host_fs`)** is a directory on the **same bind-mounted
host filesystem as the OrFS backing volume**. Both arms therefore share the same
storage *device* and differ only in the **filesystem stack** (OrFS-over-FUSE
versus the host's native filesystem, which `stat -f` reports as `ext2/ext3`, i.e.
ext4). That isolates the thing under test instead of conflating it with device
speed — which is the only fair comparison for a filesystem.

A second, clearly-labelled **`tmpfs`** arm (an in-container RAM `tmpfs`) is run as
a **reference floor** only. It is *not* the headline comparator, because RAM
speed is not a filesystem property.

The court also runs a small **semantics probe** on every arm: create a file with
mode `0444` and write through the descriptor the create returned (the `git`
loose-object pattern). POSIX checks the permission at `open`, not per write, so
this succeeds on every arm — including OrFS since Phase 82 (§6). The probe keeps
the semantics machine-checked rather than inferred.

## 4. Results (one run; release; one host under external load)

`ratio = baseline wall-clock ÷ OrFS wall-clock`; **`< 1` means OrFS is slower**.

| workload | OrFS (s) | host_fs (s) | tmpfs (s) | host_fs/OrFS | tmpfs/OrFS | verdict |
|---|---:|---:|---:|---:|---:|---|
| git repository | 1.083 | 0.1215 | 0.0928 | **0.112×** | 0.086× | **loss — 8.9× slower** |
| sqlite database | 0.841 | 0.2884 | 0.0401 | **0.343×** | 0.048× | **loss — 2.9× slower** |
| image-extraction analogue | 0.432 | 0.0146 | 0.0092 | **0.034×** | 0.021× | **loss — 29.6× slower** |
| source build | 0.152 | 0.1114 | 0.1110 | **0.733×** | 0.731× | **loss — 1.4× slower** |
| metadata tree (50 000 files) | 31.73 | 0.6090 | 0.2304 | **0.019×** | 0.0073× | **loss — 52.1× slower** |

**Every workload is a loss.** `verdict.orfs_faster_than_baseline = false` for all
five, top-level and machine-readable in the receipt
(`verdict.per_workload`), so the doc cannot drift into an unfounded claim.

![End-to-end applications: baseline time / OrFS time](charts/application-workloads.svg)

*Figure 81.1 — baseline wall-clock divided by OrFS wall-clock per workload
(1.0 = equal, below 1.0 = OrFS slower). All five workloads, including `git`,
now complete on OrFS; the source is
`evidence/performance/application-workloads.json`; regenerate with
`python3 scripts/render_charts.py --check`.*

### 4.1 Metadata latency (per operation; p50/p99, µs)

Only the metadata-tree workload is an in-process workload, so it is the only one
that yields per-operation client latency. (readdir is per directory, 200 entries
each.)

| op | OrFS p50 | OrFS p99 | host_fs p50 | host_fs p99 | tmpfs p50 | tmpfs p99 |
|---|---:|---:|---:|---:|---:|---:|
| create | 178.8 | 253.4 | 3.94 | 8.08 | 1.27 | 5.60 |
| stat | 13.11 | 26.92 | 0.43 | 0.57 | 0.30 | 0.42 |
| readdir (per dir) | 336.5 | 390.9 | 21.2 | 51.1 | 12.7 | 16.0 |
| rename | 256.3 | 342.0 | 4.75 | 8.65 | 1.01 | 4.73 |
| unlink | 147.8 | 211.9 | 1.87 | 3.54 | 0.76 | 1.47 |

The **mutating** metadata operations (create/rename/unlink) cost **~50–90×** the
native filesystem; `stat` costs **~30×**; a directory read of 200 entries costs
**~16×** host and **~27×** tmpfs.

## 5. Why (honest reading)

This is the **FUSE round-trip plus metadata cost**, the same mechanism
`docs/PERFORMANCE.md` §20 / §31.2 and `docs/FUSE-SEMANTICS.md` already record:

1. **Every metadata operation is a round trip.** A create is not one syscall but a
   kernel→daemon `CREATE` that the daemon answers with an authoritative,
   append-only commit; a `stat` still costs the request/reply hop unless it hits
   the attribute cache (the mount uses the default 1 s TTLs, so a fresh tree
   misses). ext4 does all of this in the kernel, with the directory and inode
   structures directly reachable.
2. **The whole point of OrFS is durability of history, not metadata speed.**
   Each mutation extends the authoritative log (`L_{n+1} = L_n ⊕ Δ_n`); an
   ordinary filesystem overwrites in place. That is a deliberate, structural
   trade-off, and it is exactly what makes ordinary metadata-heavy applications
   slower.
3. **Bulk `tar` is the worst case** for the same reason: 2004 create+write+close
   sequences, each a full daemon round trip, versus a kernel-resident copy loop.

OrFS's measured advantages remain **internal and structural** (manifested vs
authoritative reads; kernel passthrough vs the daemon; indexed search vs a scan).
None of them is restated here as a win, because the application layer does not
exhibit them.

## 6. Headline finding — the `git` blocker was resolved in Phase 82

Phase 81 discovered, and recorded honestly, that the git workload **failed on the
OrFS arm** with:

```
fatal: unable to write loose object file: Permission denied
```

**Mechanism (proven, not guessed).** `git` writes a loose object by creating a
file with mode **`0444`** and writing through the descriptor the create returned.
POSIX decides permission at `open`, so the write succeeds on ext4/tmpfs. OrFS
**re-checked the inode's write bit on every `write`**, so a freshly created `0444`
file refused the write and `git` aborted. This was a **POSIX-conformance defect,
not a security feature** — the permission had already been enforced at
`open`/`create`, so re-checking at `write` granted *less* access than POSIX (the
same principle `setattr` already applied to `ftruncate` through a writable
descriptor).

**Phase 82 fixes it at the root.** `write` (and `read`) now honour the **open file
description's** access mode — the decision made at `open`/`create` — instead of
re-reading the inode's mode; the two transports share the predicates
(`src/fuse.rs` `handle_is_writable`/`handle_is_readable`). Access is still decided
at `open`/`create`, so the **threat model is unchanged** (`docs/SECURITY.md`,
`docs/THREAT-MODEL.md`).

The court's `0444`-create probe and the real `git` workload now both succeed on
OrFS:

| arm | create(0444) then write through the fd | git workload |
|---|---|---|
| `host_fs` | ok (POSIX) | complete (0.122 s) |
| `tmpfs` | ok (POSIX) | complete (0.093 s) |
| **OrFS** | **ok (POSIX-compliant since Phase 82)** | **complete (1.083 s)** |

The conformance is proven through **real mounts on both transports**: the
traditional transport by `tests/fuse_integration.rs` (`write_through_created_fd`,
`access_decided_at_open`, and the semantic `git_loose_object_write_via_created_fd`),
and the native F2 transport by `tests/fuse_uring.rs` (the same `create(0444)`-then-
write step is part of the F0/F1/F2 equivalence transcript). See
`docs/POSIX-COMPAT.md` §2.

## 7. Honesty and limitations

* **Single host, single run.** Wall-clock is host/load-sensitive; the container is
  CFS-capped and the host is under external load, so absolute seconds vary run to
  run. The **same-device** baseline and the order-balanced, repeated trials are
  what make the *direction* meaningful. The direction here (OrFS slower
  everywhere) is large enough to be robust.
* **No speedup is claimed.** No workload shows OrFS faster than a measured
  external baseline in this same container; that is the honest result
  (`docs/LIMITATIONS.md` §7: "no portability claim").
* **The image-extraction workload is synthetic.** It is a bounded
  OCI-layer-like tarball extracted with `tar`, **not** a real `docker pull`
  (`docs/LIMITATIONS.md` §20).
* **The tmpfs arm is a RAM floor**, reported for context, never as the headline
  comparator.

## 8. Provenance

* Receipt: `evidence/performance/application-workloads.json`
  (schema `orfs.performance.application-workloads.v1`).
* Court: `tests/application_workloads.rs`; runner:
  `scripts/container-application-workloads.sh`; image: `Dockerfile.appworkload`
  (`orfs-app:1.99.0`).
* Chart: `docs/charts/application-workloads.svg`
  (`python3 scripts/render_charts.py --check`).
* Cross-references: `docs/PERFORMANCE.md` §20/§31.2 (external comparators),
  `docs/FUSE-SEMANTICS.md` §5/§6 (operation and permission semantics),
  `docs/POSIX-COMPAT.md` §2 (access decided at `open`), `docs/SECURITY.md`,
  `docs/THREAT-MODEL.md`, `docs/LIMITATIONS.md` §7/§20, `docs/REPRODUCE.md`.

## 9. Where the loss comes from — the transport ceiling (Phase 84)

These application losses are the application-layer face of the same cost Phase 84
isolates on the metadata path (`docs/PERFORMANCE.md` §35,
`evidence/performance/transport-ceiling.json`):

* The **same-device no-FUSE baseline** runs the identical bounded
  `create`/`stat`/`rename`/`unlink`/read/write workload in **1.4 µs/op**; a real
  **F0** mount costs **32.8 µs/op**. Of that **31.4 µs/op** FUSE overhead,
  **~74 %** (23.2 µs/op) is the **irreducible** kernel FUSE round-trip/VFS/scheduling
  residual on this host, and only **~25 %** (8.0 µs/op) is the daemon's own
  user-space work.
* So the metadata-tree and `tar`/`git` losses (§4) are **mostly the fixed FUSE
  dispatch tax**, not a defect that a hot-path tweak removes — which is why
  `docs/LIMITATIONS.md` §21 states the ceiling plainly. The **measured** reductions
  OrFS *can* make are real but bounded: the Phase-84 commit/append changes cut the
  engine's allocations per op by **~16 %** and the mounted F0 `allocs/op` from
  **101.7 to 87.9**, without touching the irreducible share.
* Cross-reference: `docs/PERFORMANCE.md` §33 (these workloads) → §34 (Phase-83
  attribution) → **§35 (this ceiling and decomposition)**.
