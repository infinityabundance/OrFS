#!/bin/sh
# Phase 65 — autonomous concealed-expansion controller court runner (research §12).
#
# Runs `tests/expansion_controller.rs` inside the pinned container, one container
# at a time:
#   1. the always-on smoke + the bad-decision recovery court (bounded, default
#      gate);
#   2. the full budget sweep (ORFS_EXPANSION=1) in the **release** build, the
#      representative build for performance evidence, which writes
#      evidence/performance/expansion-controller.json.
#
# Usage:
#   sh scripts/container-expansion-controller.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== expansion-controller: smoke + bad-decision recovery (always-on, default gate) ==="
docker_run cargo test -p orfs --test expansion_controller

echo "=== expansion-controller: budget sweep (release, representative build) ==="
docker_run sh -c 'ORFS_EXPANSION=1 cargo test --release -p orfs --test expansion_controller expansion_controller_sweep -- --nocapture'

echo "evidence: evidence/performance/expansion-controller.json"
