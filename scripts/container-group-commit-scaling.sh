#!/bin/sh
# Phase 88 — the mounted group-commit **scaling** court (off / fixed / adaptive).
#
# Measures 4 KiB `write(2)+fsync(2)` appends through a real `orfs mount` across
# writers 1..64 in three arms, plus the bounded-admission/overload result and the
# durability/order proof. Writes
# `evidence/performance/group-commit-scaling.json`.
#
# Runs in the kernel-mount container (`--device /dev/fuse`, `CAP_SYS_ADMIN`,
# unconfined AppArmor/seccomp) with the `failpoints` feature enabled so the
# coupon's fault-injection arm (a failed barrier is refused, never acknowledged)
# is compiled in. One container at a time.
#
#   1. the bounded always-on smoke (correctness + durability + order + overload);
#   2. the opt-in release sweep (`ORFS_GC_SCALING=1`) that writes the receipt.
#
# Env knobs: ORFS_GC_SCALING_WRITERS (default 1,2,4,8,16,32,64),
#            ORFS_GC_SCALING_RECORDS (default 24, per writer).
#
# Usage:
#   sh scripts/container-group-commit-scaling.sh
set -eu
. "$(dirname "$0")/lib.sh"

SCALE_WRITERS="${ORFS_GC_SCALING_WRITERS:-1,2,4,8,16,32,64}"
SCALE_RECORDS="${ORFS_GC_SCALING_RECORDS:-24}"
SCALE_REPEATS="${ORFS_GC_SCALING_REPEATS:-3}"
BUILD_DIR="$ORFS_PROJECT_DIR/target/kmount-gc-scaling"

echo "=== group-commit-scaling: smoke (always-on, bounded; real OrFS mount, failpoints) ==="
docker_run_kmount sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export CARGO_TARGET_DIR="'"$BUILD_DIR"'"
    timeout -k 10 1800 cargo test --features failpoints --test group_commit_scaling \
        -- --nocapture --test-threads=1
'

echo "=== group-commit-scaling: sweep (release; writes the receipt) ==="
docker_run_kmount sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export ORFS_GC_SCALING=1
    export ORFS_GC_SCALING_WRITERS="'"$SCALE_WRITERS"'"
    export ORFS_GC_SCALING_RECORDS="'"$SCALE_RECORDS"'"
    export ORFS_GC_SCALING_REPEATS="'"$SCALE_REPEATS"'"
    export CARGO_TARGET_DIR="'"$BUILD_DIR"'"
    timeout -k 10 3600 cargo test --release --features failpoints --test group_commit_scaling \
        group_commit_scaling_sweep \
        -- --nocapture --test-threads=1
'

echo "evidence: evidence/performance/group-commit-scaling.json"
