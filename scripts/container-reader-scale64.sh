#!/bin/sh
# Reviewer item — 64-thread read-path scaling court runner.
#
# Runs `tests/reader_scale_64.rs` inside the pinned container, one container at a
# time:
#   1. the always-on smoke (bounded, default gate);
#   2. the full 64-thread sweep (ORFS_READER_SCALE64=1) in the **release** build,
#      the representative build for performance evidence, which writes
#      evidence/performance/reader-scaling-64.json.
#
# The court serves one manifested object through one shared ReadPlanner at
# 1/2/4/8/16/32/64 concurrent readers, asserting every read is byte-exact and that
# the planner neither re-plans nor grows during the steady-state phase.
#
# HONEST CAVEAT: the container is CFS-capped at 8 CPUs (`ORFS_CPUS`) and the host
# is under external load, so reader counts above the effective core count contend
# rather than scale. The measured curve is reported as-is.
#
# Usage:
#   sh scripts/container-reader-scale64.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== reader-scale64: smoke (always-on, default gate) ==="
docker_run cargo test -p orfs --test reader_scale_64 reader_scale_64_smoke

echo "=== reader-scale64: full 64-thread sweep (release, representative build) ==="
docker_run sh -c 'ORFS_READER_SCALE64=1 cargo test --release -p orfs --test reader_scale_64 reader_scale_64_sweep -- --nocapture'

echo "evidence: evidence/performance/reader-scaling-64.json"
