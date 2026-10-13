#!/bin/sh
# Phase 72 — ENOSPC fault injection at the edge (reviewer item #13).
#
# Two sequential steps, one container at a time:
#
#   1. the always-on court (`tests/fault_enospc.rs`): drive a volume to the edge
#      of its usable capacity, then either `write + fsync` (clean commit or a
#      typed ENOSPC refusal with the previous root intact and the volume
#      read-only) or `write + fsync + crash` and then run the real `orfs recover`;
#   2. the opt-in heavier matrix (`ORFS_ENOSPC_SWEEP=1`) over free-space levels,
#      transaction sizes, and crash points.
#
# Both steps write `evidence/recovery/fault-enospc.json` (schema
# `orfs.recovery.fault-enospc.v1`); the sweep is recorded under `runs.sweep`.
# No large files and no host disk is filled: the fill is a declared capacity.
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== phase 72: ENOSPC at the edge — default court ==="
docker_run cargo test -p orfs --test fault_enospc -- --nocapture --test-threads=1

echo "=== phase 72: ENOSPC at the edge — release sweep ==="
docker_run sh -c "ORFS_ENOSPC_SWEEP=1 cargo test -p orfs --test fault_enospc write_fault_enospc_evidence -- --nocapture"
