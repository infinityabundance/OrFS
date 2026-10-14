#!/bin/sh
# Phase 76 — immutable tier-relocation court runner.
#
# Moves *sealed* (immutable) authoritative segments from the local backing store
# to a cheaper cold tier WITHOUT withdrawing authority: the local copy is deleted
# only after the tier copy is written, fsynced, read back, and digest-verified,
# and only after a durable `Released` transition (the Kafka KIP-405 discipline).
# `tests/tier_relocation.rs` proves byte-for-byte identity (every committed root),
# a stable committed root/watermark, idempotent copy/delete, a crash matrix, the
# typed `TierUnavailable` error, catalogue fail-closed behaviour, and mixed
# local+remote recovery — then writes `evidence/performance/tier-relocation.json`.
#
# Two bounded stages, one container at a time:
#   1. the always-on smoke (default `cargo test` build), then
#   2. the release sweep that writes the receipt, with the `failpoints` feature so
#      the crash matrix is exercised for real.
#
# Set ORFS_TIER_RELOCATION=0 to run the smoke only.
#
# Usage:
#   sh scripts/container-tier-relocation.sh
#   ORFS_TIER_RELOCATION=0 sh scripts/container-tier-relocation.sh
#
# One container runs at a time (`scripts/lib.sh`: 8 GiB, 2048 pids).
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== phase 76: tier relocation (bounded smoke) ==="
docker_run cargo test -p orfs --test tier_relocation tier_relocation_smoke

if [ "${ORFS_TIER_RELOCATION:-1}" = "0" ]; then
    echo "=== sweep skipped (ORFS_TIER_RELOCATION=0) ==="
    echo "evidence: evidence/performance/tier-relocation.json (unchanged)"
    exit 0
fi

echo "=== phase 76: tier relocation (release sweep; includes the crash matrix) ==="
docker_run sh -c 'ORFS_TIER_RELOCATION=1 \
    cargo test --release -p orfs --features failpoints --test tier_relocation tier_relocation_sweep -- --nocapture'
echo "evidence: evidence/performance/tier-relocation.json"
