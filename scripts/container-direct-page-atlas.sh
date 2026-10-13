#!/bin/sh
# Phase 64 — manifested direct-page atlas court runner (reviewer research §5).
#
# Runs `tests/direct_page_atlas.rs` inside the pinned container, one container at
# a time:
#   1. the always-on smoke (bounded, default gate);
#   2. the full sweep (ORFS_ATLAS=1) in the **release** build, the representative
#      build for performance evidence, which writes
#      evidence/performance/direct-page-atlas.json.
#
# Usage:
#   sh scripts/container-direct-page-atlas.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== direct-page-atlas: smoke (always-on, default gate) ==="
docker_run cargo test -p orfs --test direct_page_atlas direct_page_atlas_smoke

echo "=== direct-page-atlas: full sweep (release, representative build) ==="
docker_run sh -c 'ORFS_ATLAS=1 cargo test --release -p orfs --test direct_page_atlas direct_page_atlas_sweep -- --nocapture'

echo "evidence: evidence/performance/direct-page-atlas.json"
