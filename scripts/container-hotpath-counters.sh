#!/bin/sh
# Phase 83 — counter-guided forensics of the MOUNTED metadata/read hot path.
#
# One container at a time. It runs, in order:
#   1. a run-time PROOF that `perf_event_open` is permitted under the exact
#      mount+PERFMON container profile the court runs in (`scripts/pmu-probe.c`);
#   2. the bounded always-on smoke (`ORFS_FUSE_TEST=1`): mounts a real OrFS
#      volume and drives a small workload through it with the counters attached;
#   3. the opt-in sweep (release, `ORFS_HOTPATH=1`) that writes
#      evidence/performance/hotpath-counters.json and the daemon flamegraph.
#
# The profile is `docker_run_kmount_pmu`: `/dev/fuse` + SYS_ADMIN + an unconfined
# AppArmor/seccomp profile (needed to mount) plus `--cap-add PERFMON` (the
# least-privilege grant that makes the counters work at `perf_event_paranoid=2`;
# see docs/PMU.md and scripts/container-pmu.sh). The kmount profile already carries
# `seccomp=unconfined`, which permits `perf_event_open`; the scoped capability
# makes the intent explicit and is proven, not assumed, by step 1.
#
# See docs/PERFORMANCE.md §34 and docs/PMU.md.
#
# Usage:
#   sh scripts/container-hotpath-counters.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== hotpath-counters: prove perf_event_open under the mount+PERFMON profile ==="
docker_run_kmount_pmu sh -c 'cc scripts/pmu-probe.c -o /tmp/orfs-pmu-probe && /tmp/orfs-pmu-probe'

echo "=== hotpath-counters: smoke (bounded; real mount + real counters) ==="
docker_run_kmount_pmu sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export CARGO_TARGET_DIR="$(pwd)/target/hotpath-counters"
    timeout -k 10 1200 cargo test -p orfs --test hotpath_counters \
        hotpath_counters_smoke -- --nocapture --test-threads=1
'

echo "=== hotpath-counters: sweep (release; writes the receipt + flamegraph) ==="
docker_run_kmount_pmu sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export ORFS_HOTPATH=1
    export CARGO_TARGET_DIR="$(pwd)/target/hotpath-counters"
    timeout -k 10 2400 cargo test --release -p orfs --test hotpath_counters \
        hotpath_counters_sweep -- --nocapture --test-threads=1
'

echo "evidence: evidence/performance/hotpath-counters.json"
echo "evidence: evidence/performance/flamegraph-hotpath.folded"
echo "evidence: evidence/performance/flamegraph-hotpath.svg"
