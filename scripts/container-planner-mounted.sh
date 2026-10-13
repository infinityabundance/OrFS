#!/bin/sh
# Phase 66 — paired mounted planner benchmark runner.
#
# Runs `tests/planner_mounted.rs` inside the kernel-mount container, one container
# at a time (the ordinary project uid; manifestation does not need root).
#
# The court builds one heterogeneous committed history (hot/cold objects; three
# fragmentation levels; 1 B / 4 KiB / 64 KiB request sizes), manifests it, and
# mounts the *same* history twice — manifested and authoritative-only — while also
# measuring both arms in process. It writes
# evidence/performance/planner-mounted-paired.json. See docs/PERFORMANCE.md §29.
#
# Usage:
#   sh scripts/container-planner-mounted.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== planner-mounted: paired manifested vs authoritative-only over a real mount ==="
docker_run_kmount sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export CARGO_TARGET_DIR="$(pwd)/target/kmount-test"
    timeout -k 10 900 cargo test --test planner_mounted -- --nocapture --test-threads=1
'

echo "evidence: evidence/performance/planner-mounted-paired.json"
