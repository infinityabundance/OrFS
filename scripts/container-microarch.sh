#!/bin/sh
# Phase 50 — CPU microarchitecture court runner (reviewer §11).
#
# Runs `tests/microarch.rs` inside the pinned container, one container at a time:
#   1. the always-on smoke (bounded, default gate);
#   2. the full sweep (ORFS_MICROARCH=1) in the **release** build, the
#      representative build for performance evidence, which writes
#      evidence/performance/microarch.json.
#
# Hardware performance counters are unavailable on this host
# (`perf_event_paranoid=2`); the court records that and uses PMU-free proxies
# (a counting allocator, concurrent-reader throughput, a working-set latency
# curve) — see docs/PERFORMANCE.md §18.
#
# Usage:
#   sh scripts/container-microarch.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== microarch: smoke (always-on, default gate) ==="
docker_run cargo test -p orfs --test microarch microarch_smoke

echo "=== microarch: full sweep (release, representative build) ==="
docker_run sh -c 'ORFS_MICROARCH=1 cargo test --release -p orfs --test microarch microarch_sweep -- --nocapture'

echo "evidence: evidence/performance/microarch.json"
