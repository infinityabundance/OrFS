#!/bin/sh
# Phase 84 — the metadata/transport ceiling, measured.
#
# One container at a time. It runs, in order:
#   1. a run-time PROOF that `perf_event_open` is permitted under the exact
#      mount+PERFMON container profile the court runs in (`scripts/pmu-probe.c`);
#   2. the bounded always-on smoke (`ORFS_FUSE_TEST=1`): mounts a real OrFS
#      volume on each available transport and drives the bounded metadata/read/write
#      workload through it with the counters attached;
#   3. the opt-in receipt (release, `ORFS_TRANSPORT_CEILING=1`) that writes
#      evidence/performance/transport-ceiling.json: per-transport latency
#      percentiles, real counters/op, the allocs/op, which transport actually
#      served, and the measured decomposition against the same-device baseline.
#
# The profile is `docker_run_kmount_pmu`: `/dev/fuse` + SYS_ADMIN + an unconfined
# AppArmor/seccomp profile (needed to mount, and to permit both `perf_event_open`
# and `io_uring_setup` for F2) plus `--cap-add PERFMON`. `seccomp=unconfined` is
# what makes the F2 request ring possible at all on this host; a fallback to F0 is
# recorded concretely, never assumed away.
#
# See docs/PERFORMANCE.md §35 and docs/PERFORMANCE.md §34 for the Phase-83 court
# this extends.
#
# Usage:
#   sh scripts/container-transport-ceiling.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== transport-ceiling: prove perf_event_open under the mount+PERFMON profile ==="
docker_run_kmount_pmu sh -c 'cc scripts/pmu-probe.c -o /tmp/orfs-pmu-probe && /tmp/orfs-pmu-probe'

echo "=== transport-ceiling: smoke (bounded; real mounts + real counters) ==="
docker_run_kmount_pmu sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export CARGO_TARGET_DIR="$(pwd)/target/transport-ceiling"
    timeout -k 10 1800 cargo test -p orfs --test transport_ceiling \
        transport_ceiling_smoke -- --nocapture --test-threads=1
'

echo "=== transport-ceiling: receipt (release; writes evidence/performance/transport-ceiling.json) ==="
docker_run_kmount_pmu sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export ORFS_TRANSPORT_CEILING=1
    export CARGO_TARGET_DIR="$(pwd)/target/transport-ceiling"
    timeout -k 10 3600 cargo test --release -p orfs --test transport_ceiling \
        transport_ceiling_receipt -- --nocapture --test-threads=1
'

echo "evidence: evidence/performance/transport-ceiling.json"
