#!/bin/sh
# Phase 77 — bounded-space recovery court runner.
#
# OrFS is non-withdrawal: the backing store fills monotonically and, at the
# reserve, commits are refused and the volume latches read-only. This court proves
# the operator has a documented, bounded way out that frees local space WITHOUT
# withdrawing one authoritative byte and without losing the newest committed
# generation — including during crash recovery on a nearly-full disk:
#
#   * `tests/bounded_recovery.rs` fills a volume to the edge, crashes after an
#     `fsync`, and runs the real `orfs recover` (newest valid committed generation,
#     nothing silently repaired); drives recovery to fail CLOSED with the typed
#     `RecoverySpaceExhausted` and an intact history; relocates sealed segments to a
#     cold tier on a SEPARATE filesystem (measured free-space increase, commits
#     resume, committed roots byte-identical); proves an unavailable tier cannot
#     free authority bytes; drops rebuildable manifestations (authority identical,
#     reads still identical); and opens read-only at zero free.
#
# Two bounded stages, one container at a time:
#   1. the always-on smoke (default `cargo test` build), then
#   2. the release sweep that writes the receipt.
#
# Set ORFS_BOUNDED_RECOVERY=0 to run the smoke only.
#
# Usage:
#   sh scripts/container-bounded-recovery.sh
#   ORFS_BOUNDED_RECOVERY=0 sh scripts/container-bounded-recovery.sh
#
# One container runs at a time (`scripts/lib.sh`: 8 GiB, 2048 pids).
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== phase 77: bounded recovery (always-on smoke) ==="
docker_run cargo test -p orfs --test bounded_recovery bounded_recovery_smoke

if [ "${ORFS_BOUNDED_RECOVERY:-1}" = "0" ]; then
    echo "=== sweep skipped (ORFS_BOUNDED_RECOVERY=0) ==="
    echo "evidence: evidence/performance/bounded-recovery.json (unchanged)"
    exit 0
fi

echo "=== phase 77: bounded recovery (release sweep) ==="
docker_run sh -c 'ORFS_BOUNDED_RECOVERY=1 \
    cargo test --release -p orfs --test bounded_recovery bounded_recovery_sweep -- --nocapture'
echo "evidence: evidence/performance/bounded-recovery.json"
