#!/bin/sh
# Phase 43 read-planner court + paired benchmark, inside the pinned container.
#
# Runs, one container at a time:
#   1. the full aging court (ORFS_READ_PLANNER_AGING=1000000) — ~1e6 distinct
#      ManifestIdentity values through the planner's bounded identity tables;
#   2. the read-planner benchmark (label "after") that writes
#      evidence/performance/read-planner.json.
#
# The paired "before" run is produced by running the same bench once on the
# pre-Phase-43 tree:
#   git stash push -- src/readpath.rs   # or: git checkout -- src/readpath.rs
#   sh -c '. scripts/lib.sh && docker_run sh -c \
#       "ORFS_READ_PLANNER_LABEL=before cargo bench -p orfs --bench read_path -- --planner-only"'
#   git stash pop
# (The bench uses only the planner's public API, so it compiles on both trees.)
set -eu
. "$(dirname "$0")/lib.sh"
docker_run sh -c 'ORFS_READ_PLANNER_AGING=1000000 cargo test -p orfs --test read_path_planner -- --nocapture && ORFS_READ_PLANNER_LABEL=after cargo bench -p orfs --bench read_path -- --planner-only'
