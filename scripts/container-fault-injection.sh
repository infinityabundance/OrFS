#!/bin/sh
# Phase 59 — run the OrFS-native fsx/fsstress-equivalent fault-injection court
# inside the pinned container.
#
# OrFS cannot run the external xfstests/fsx/fsstress tools in this environment
# (see evidence/correctness/xfstests.json); this script runs the explicitly
# labelled native equivalent (tests/fs_fault_injection.rs) instead.
#
# Two sequential passes, one container at a time:
#   1. the always-on smoke (default sizes) in the default debug profile;
#   2. the heavy sweep in release profile (ORFS_FSINJ_HEAVY=1, ORFS_FSSTRESS=1).
#
# The two passes write the same receipt; it merges by run kind, so the committed
# evidence/security/fault-injection.json carries both the smoke and heavy rows.
# The heavy sweep honours the reviewer's `-p 64 -n ...` shape through
# ORFS_FSSTRESS_P / ORFS_FSSTRESS_N (`-n` = operations per worker). The default N
# is bounded (a library-level commit is a full authoritative transaction, not a
# syscall into a block-device loop mount); see docs/PERFORMANCE.md §25.
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== phase 59: fsx/fsstress-equivalent fault injection — smoke (debug) ==="
docker_run cargo test -p orfs --test fs_fault_injection -- --nocapture --test-threads=1

echo "=== phase 59: fsx/fsstress-equivalent fault injection — heavy sweep (release) ==="
ORFS_FSSTRESS_P="${ORFS_FSSTRESS_P:-64}"
ORFS_FSSTRESS_N="${ORFS_FSSTRESS_N:-2000}"
docker_run sh -c "
    set -eu
    ORFS_FSINJ_HEAVY=1 \
    ORFS_FSSTRESS=1 \
    ORFS_FSSTRESS_P=$ORFS_FSSTRESS_P \
    ORFS_FSSTRESS_N=$ORFS_FSSTRESS_N \
    cargo test --release -p orfs --test fs_fault_injection -- --nocapture --test-threads=1
"
