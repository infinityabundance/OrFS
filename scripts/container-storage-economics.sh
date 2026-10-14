#!/bin/sh
# Phase 75 — storage-economics court runner.
#
# Makes indefinite retention *predictable and budgetable* (never reclaimed):
# `tests/storage_economics.rs` drives a known workload (a specified number of MiB
# written with a specified overwrite fraction, plus a manifested arm), proves the
# four byte categories partition the observed on-disk total, and validates the
# retained-growth forecast against the measured growth — predicted vs actual, with
# a stated tolerance. The crux is that an overwrite still appends, so retained
# growth tracks *written* bytes, not live bytes.
#
# Two bounded stages, one container at a time:
#   1. the always-on smoke (default `cargo test` build), then
#   2. the release sweep (representative build) which writes the receipt.
#
# Set ORFS_STORAGE_ECONOMICS=0 to run the smoke only.
#
# Usage:
#   sh scripts/container-storage-economics.sh
#   ORFS_STORAGE_ECONOMICS=0 sh scripts/container-storage-economics.sh
#
# One container runs at a time (`scripts/lib.sh`: 8 GiB, 2048 pids).
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== phase 75: storage economics (bounded smoke) ==="
docker_run cargo test -p orfs --test storage_economics storage_economics_smoke

if [ "${ORFS_STORAGE_ECONOMICS:-1}" = "0" ]; then
    echo "=== sweep skipped (ORFS_STORAGE_ECONOMICS=0) ==="
    echo "evidence: evidence/performance/storage-economics.json (unchanged)"
    exit 0
fi

echo "=== phase 75: storage economics (release sweep) ==="
docker_run sh -c 'ORFS_STORAGE_ECONOMICS=1 \
    cargo test --release -p orfs --test storage_economics storage_economics_sweep -- --nocapture'
echo "evidence: evidence/performance/storage-economics.json"
