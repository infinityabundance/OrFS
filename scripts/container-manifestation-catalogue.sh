#!/bin/sh
# Reviewer task — manifested-generation catalogue scaling court runner.
#
# Runs `tests/manifestation_catalogue.rs` inside the pinned container. The heavy
# sweep is opt-in (it is skipped, not failed, by an ordinary `cargo test`); this
# script enables it and runs it in the **release** build, which is the
# representative one for performance evidence (mirroring the
# `ORFS_E2E_SUFFIX=-release` convention used elsewhere).
#
# It publishes and recovers at 1 000 / 10 000 / 100 000 / 1 000 000 accumulated
# generations and records, per checkpoint: publication p50/p99, metadata bytes
# rewritten per publication, directory operations, recovery time (both the
# catalogue-accelerated path and a full validated scan), and resident memory. It
# asserts that per-publication work does not grow linearly with G (the decisive
# property) and that catalogue recovery equals a full scan on the recoverable
# set, and writes `evidence/performance/manifestation-catalogue.json`.
#
# Usage:
#   sh scripts/container-manifestation-catalogue.sh
#   ORFS_CATALOGUE_SCALING=0 sh scripts/container-manifestation-catalogue.sh  # smoke only
#
# One container runs at a time (`scripts/lib.sh`: 8 GiB, 2048 pids).
set -eu
. "$(dirname "$0")/lib.sh"

if [ "${ORFS_CATALOGUE_SCALING:-1}" = "0" ]; then
    echo "=== catalogue: bounded smoke only (ORFS_CATALOGUE_SCALING=0) ==="
    docker_run cargo test -p orfs --test manifestation_catalogue
else
    echo "=== catalogue: full sweep (release, representative build) ==="
    docker_run sh -c 'ORFS_CATALOGUE_SCALING=1 \
        cargo test --release -p orfs --test manifestation_catalogue catalogue_scaling_sweep -- --nocapture'
    echo "evidence: evidence/performance/manifestation-catalogue.json"
fi
