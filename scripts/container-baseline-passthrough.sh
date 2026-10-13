#!/bin/sh
# Phase 66 — baseline-passthrough runner.
#
# Runs `tests/baseline_passthrough.rs` inside the **root** kernel-mount container,
# one container at a time. Root is required because the passthrough arm needs
# `capable(CAP_SYS_ADMIN)` at `FUSE_DEV_IOC_BACKING_OPEN` (Phase 21).
#
# The court runs the same `src/bench.rs` read workloads three ways over the same
# data — a plain host-ext4 scratch file, the OrFS FUSE passthrough snapshot, and
# OrFS's ordinary mounted read path — and writes
# evidence/performance/baseline-passthrough.json. See docs/PERFORMANCE.md §29.
#
# Usage:
#   sh scripts/container-baseline-passthrough.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== baseline-passthrough (root: passthrough needs CAP_SYS_ADMIN) ==="
docker_run_kmount_root sh -c '
    set -eu
    umask 0
    export ORFS_FUSE_TEST=1
    export CARGO_TARGET_DIR="$(pwd)/target/kmount-passthrough"
    timeout -k 10 900 cargo test --test baseline_passthrough -- --nocapture --test-threads=1
'

echo "evidence: evidence/performance/baseline-passthrough.json"
