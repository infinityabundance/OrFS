#!/bin/sh
# Phase 53 — external baseline comparator runner.
#
# Runs `tests/baselines.rs` inside the pinned container, one container at a time:
#   1. the always-on smoke (bounded, default gate);
#   2. the full sweep (ORFS_BASELINES=1) in the **release** build, which writes
#      evidence/performance/baselines.json.
#
# The same src/bench.rs workloads are run on tmpfs (/dev/shm), the container
# scratch (/tmp), and the host filesystem (a scratch dir on the bind-mounted
# project), plus a raw Vec<u8> scan — the external comparators that make OrFS's
# speedups meaningful. See docs/PERFORMANCE.md §20.
#
# Usage:
#   sh scripts/container-baseline.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== baselines: smoke (always-on, default gate) ==="
docker_run cargo test -p orfs --test baselines baselines_smoke

echo "=== baselines: full sweep (release, representative build) ==="
docker_run sh -c 'ORFS_BASELINES=1 cargo test --release -p orfs --test baselines baselines_sweep -- --nocapture'

echo "evidence: evidence/performance/baselines.json"
