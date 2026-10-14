# Hardware performance counters (PMU) and the flamegraph

This document records how OrFS obtains **real** hardware performance counters and
a sampling flamegraph, and corrects a claim that was previously made in the
project's comments and evidence.

## The claim that was wrong

The project stated that hardware performance counters were unavailable because
`perf_event_paranoid=2`, "so there are no flamegraphs". That is **wrong**, and it
was never verified with the syscall.

On Linux, `perf_event_paranoid=2` denies only *kernel* profiling to an
unprivileged caller. A **user-space, per-thread** counter — `pid=0` (the calling
thread), `cpu=-1`, `exclude_kernel=1`, `exclude_hv=1` — is still permitted at
level 2. The real gate on this host is the **container profile**: with
`--cap-drop=ALL` and Docker's default seccomp profile, `perf_event_open` is
denied with `EPERM` — exactly as the same default profile denies
`io_uring_setup`, which this project already bypasses with
`--security-opt seccomp=unconfined`.

`src/bench.rs` no longer infers availability from the paranoid level. It performs
the `perf_event_open` syscall and records the outcome (`perf_counters_available`
plus `perf_event_open_error`, the errno name).

## Probe: which container flags are actually required

`scripts/container-pmu.sh` proves this at run time with `scripts/pmu-probe.c`
(the `perf_event_open` analogue of `scripts/uring-probe.c`). On this host
(`perf_event_paranoid=2`, kernel `7.2.9-2-cachyos`), the results are:

| Profile | Result | errno |
|---|---|---|
| default (`--cap-drop=ALL`, default seccomp) | **DENIED** | `EPERM` (errno 1) |
| `--security-opt seccomp=unconfined` | PERMITTED | — |
| default seccomp + `--cap-add PERFMON` | PERMITTED | — |
| default seccomp + `--cap-add SYS_ADMIN` | PERMITTED | — |

So the required flags are either `--security-opt seccomp=unconfined` **or**
`--cap-add PERFMON` (Docker's default seccomp profile gates `perf_event_open` on
`CAP_PERFMON`, so the narrower capability grant also suffices). The script
selects the least-privilege working option and runs the courts under it. The
errno of the blocked path is `EPERM (os error 1)`.

## Method

* `tests/support/pmu.rs` — a minimal PMU access module. `libc` exposes
  `SYS_perf_event_open` but neither `struct perf_event_attr` nor the `PERF_*`
  constants, so the 64-byte ABI-v0 attribute struct and the constants used are
  declared from `include/uapi/linux/perf_event.h`.
  * `PmuGroup` opens a group of user-space hardware events (`cycles`,
    `instructions`, `cache-references`, `cache-misses`, `branch-instructions`,
    `branch-misses`, and the data-/instruction-TLB read misses) for the calling
    thread (or, via `open_pid`, another thread of the process), with
    `reset`/`enable`/`disable` and `read_all`. The cycle counter is the group
    leader; a member the micro-architecture does not provide is skipped and its
    exact errno recorded (`missing_reasons`), but the leader's failure is returned
    with the errno name (`EPERM`/`EACCES`/`ENOSYS`/`EINVAL`). The TLB events use
    the `PERF_TYPE_HW_CACHE` encoding (`cache_id | op<<8 | result<<16`), the only
    way to ask for a TLB event; on this host the kernel refuses both, so they are
    recorded as missing rather than estimated.
  * `Sampler` is a `PERF_SAMPLE_IP` sampling ring (software CPU clock) used for
    the flamegraph.
* `tests/microarch_pmu.rs` — the court. Per component it resets and enables the
  group around a measured loop, disables it, then reads every counter once; it
  records the wall-clock time in all cases.

## Counters (release build, single host, one thread)

`evidence/performance/pmu.json` (schema `orfs.performance.pmu.v1`) holds the raw
numbers and the environment. The four components and their per-op figures:

| Component | ops | wall ns/op | cycles/op | insn/op | cache-miss/op | branch-miss/op | IPC | cache-miss rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `PMap` point lookup | 500 000 | 122.6 | 635.0 | 198.9 | 6.60 | 8.13 | 0.31 | 0.285 |
| EKBLOOM manifested read (via planner) | 20 000 | 281.0 | 1452.9 | 5127.0 | 0.011 | 1.01 | 3.53 | 0.038 |
| `ReadPlanner` steady-state selection | 500 000 | 91.1 | 469.9 | 1300.0 | 0.006 | 0.001 | 2.77 | 0.070 |
| backing log segment read | 100 000 | 185.9 | 451.9 | 1161.0 | 0.016 | 1.00 | 2.57 | 0.027 |

Reading the table: the `PMap` point lookup is cache-dominated (IPC 0.31, ~6.6
cache misses per lookup — the treap walks pointer-linked nodes), whereas the
steady-state planner selection is instruction-bound with a much lower miss rate
(IPC ~2.8–3.5), the point of the manifested acceleration. Absolute nanoseconds are
host- and load-sensitive, and the exact instruction count of the selection varies
between runs because the planner's calibration is timing-based (it may select a
manifested path in one run and the authoritative path in another); the counters
and the IPC / miss-rate ratios are the point, and each row also carries its
wall-clock time.

`bench::Environment::capture` in the same evidence records
`perf_counters_available: true`, `perf_event_paranoid: "2"` and a null
`perf_event_open_error` — i.e. **real counters at paranoid level 2**.

## Flamegraph

Produced by `pmu_flamegraph` (opt-in `ORFS_PMU=1`), run in a **debug** build for
unambiguous symbols, writing `evidence/performance/flamegraph-microarch.folded`
and `evidence/performance/flamegraph-microarch.svg` (plus a sidecar the release
sweep embeds). The method is a `PERF_SAMPLE_IP` sampling ring over a mixed
workload (`PMap` lookups + manifested reads); each sampled instruction pointer is
resolved with `addr2line` (DWARF, falling back to `nm`) against the test binary
and labelled by module from `/proc/self/maps` for frames outside it. A run
produces ~6 100 samples and ~200 collapsed leaf frames; the SVG renders in any
browser.

**Caveat (recorded honestly).** This is a *leaf-IP* profile, not a call-chain
flamegraph: frame-pointer call chains were tried (`PERF_SAMPLE_CALLCHAIN`) but the
kernel emitted context markers and unreliable stacks, so a full stack is not
claimed. On this host a fraction of sampled leaves fall outside the workload's
actual call path (verified: the hottest leaf changes between runs and some belong
to symbolisation code that runs after sampling), so the flamegraph is
**indicative** of where the read path spends time — the counter table above is
the decisive, deterministic evidence. The dominant leaves observed are the
per-read `Result<Arc<LoadedBody>, _>` handling and the candidate ordering in the
planner (`rank_measured`).

## Phase 83 — the counters put to work (no excuses left)

Phase 57 proved the mechanism; Phase 83 finishes the correction and uses the
counters. The stale "counters are unavailable because `perf_event_paranoid=2`"
claim is removed from the current tree (`scripts/container-microarch.sh` now
*proves* at run time which flags are required, least-privilege first) and the
historical phase logs that carried it are marked historical/corrected, pointing
here.

* **The microarchitecture court reads real counters** (`tests/microarch.rs`,
  `scripts/container-microarch.sh` under the probed `--cap-add PERFMON` profile).
  `evidence/performance/microarch.json` now carries a `counters` section: per-op
  cycles/instructions/cache-references/cache-misses/branch-misses for the `PMap`
  lookup, the EKBLOOM manifested read, the `ReadPlanner` steady-state read, the
  backing log-segment read, the ordered commit, and a historical-index open, with
  the 6 generic events granted and the two TLB events refused
  (`dtlb_read_misses` → `ENOENT`, `itlb_read_misses` → `EINVAL`). See
  `docs/PERFORMANCE.md` §18.
* **The mounted hot path is attributed with real counters**
  (`tests/hotpath_counters.rs`, `scripts/container-hotpath-counters.sh` under
  `docker_run_kmount_pmu`). A real OrFS volume is mounted (`fuse::spawn`, F0) and a
  bounded `create`/`stat`/`rename`/`unlink` + small `read`/`write` workload is
  driven through it with per-thread counters on the calling thread and on every
  live `fuser*` daemon thread, a counting allocator, per-op latency percentiles,
  and a daemon flamegraph. `evidence/performance/hotpath-counters.json`
  (schema `orfs.performance.hotpath-counters.v1`); flamegraph
  `evidence/performance/flamegraph-hotpath.{folded,svg,json}`. See
  `docs/PERFORMANCE.md` §34.

The flamegraph symboliser/folder/SVG renderer is now a shared module
(`tests/support/flamegraph.rs`) used by both courts, and `Sampler::open_pid`
attaches a sampling ring to another thread of the process (a FUSE servicer), so
the leaves sampled are the daemon's, not the caller's.

## Reproduce

```sh
# Prove the container flags and run the whole court (one container at a time):
sh scripts/container-pmu.sh

# Just the counters (smoke is always-on; the sweep is opt-in):
sh -c '. scripts/lib.sh && docker_run cargo test -p orfs --test microarch_pmu -- --nocapture'
sh -c '. scripts/lib.sh && docker_run_uring sh -c "ORFS_PMU=1 cargo test --release -p orfs --test microarch_pmu pmu_sweep -- --nocapture"'
```

Under the default (seccomp-confined) container the PMU is unavailable: the smoke
still runs and reports software timings, and the sweep records
`available:false` with the exact errno — no number is fabricated.
