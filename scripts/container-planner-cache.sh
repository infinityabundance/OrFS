#!/bin/sh
# Phase 49 — volatile-cache court runner (reviewer §10).
#
# Runs `tests/planner_cache.rs` inside the pinned container, one container at a
# time:
#   1. the always-on smoke (bounded, default gate);
#   2. the full sweep (ORFS_CACHE_COURT=1) in the **release** build, the
#      representative build for performance evidence, which writes
#      evidence/performance/planner-cache.json.
#
# Usage:
#   sh scripts/container-planner-cache.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== planner-cache: smoke (always-on, default gate) ==="
docker_run cargo test -p orfs --test planner_cache planner_cache_smoke

echo "=== planner-cache: full sweep (release, representative build) ==="
docker_run sh -c 'ORFS_CACHE_COURT=1 cargo test --release -p orfs --test planner_cache planner_cache_sweep -- --nocapture'

echo "evidence: evidence/performance/planner-cache.json"
