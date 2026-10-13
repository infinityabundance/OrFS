#!/bin/sh
# Phase 52 — global search directory court runner (reviewer §9).
#
# Runs `tests/search_directory.rs` inside the pinned container, one container at a
# time:
#   1. the always-on smoke (bounded, default gate);
#   2. the full sweep (ORFS_SEARCHDIR=1) in the **release** build, the
#      representative build for performance evidence, which writes
#      evidence/performance/search-directory.json.
#
# Usage:
#   sh scripts/container-search-directory.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== search-directory: smoke (always-on, default gate) ==="
docker_run cargo test -p orfs --test search_directory search_directory_smoke

echo "=== search-directory: full sweep (release, representative build) ==="
docker_run sh -c 'ORFS_SEARCHDIR=1 cargo test --release -p orfs --test search_directory search_directory_sweep -- --nocapture'

echo "evidence: evidence/performance/search-directory.json"
