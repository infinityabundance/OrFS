#!/bin/sh
# Phase 58 — sealed historical inode-index integration sweep.
#
# Runs `tests/historical_index_integration.rs` inside the pinned container. The
# always-on smoke proves the sealed dense-ordinal spine answers identical
# lookups/ranges/readdir to the treap and is more compact, that the persisted
# accelerator yields it, and that the live writer spine is untouched. This runner
# additionally runs the opt-in measurement sweep (ORFS_HIST_INTEG=1, release) and
# writes `evidence/performance/historical-index-integrated.json`.
#
# Usage:
#   sh scripts/container-historical-integrate.sh
#   ORFS_HIST_INTEG_SCALES=10000,100000,1000000 sh scripts/container-historical-integrate.sh
#   ORFS_HIST_INTEG_PROFILE=debug sh scripts/container-historical-integrate.sh
#
# Env:
#   ORFS_HIST_INTEG_SCALES    comma-separated retained scales  (default 10000,100000,1000000)
#   ORFS_HIST_INTEG_LOOKUPS   point-lookup samples per scale   (default 100000)
#   ORFS_HIST_INTEG_PROFILE   release | debug                  (default release)
#
# One container runs at a time (`scripts/lib.sh`: 8 GiB, 2048 pids).
set -eu
. "$(dirname "$0")/lib.sh"

SCALES="${ORFS_HIST_INTEG_SCALES:-10000,100000,1000000}"
LOOKUPS="${ORFS_HIST_INTEG_LOOKUPS:-100000}"
PROFILE="${ORFS_HIST_INTEG_PROFILE:-release}"

echo "orfs: historical-index-integration sweep: scales=$SCALES lookups=$LOOKUPS profile=$PROFILE"

if [ "$PROFILE" = "release" ]; then
    docker_run sh -c "ORFS_HIST_INTEG=1 \
        ORFS_HIST_INTEG_SCALES='$SCALES' \
        ORFS_HIST_INTEG_LOOKUPS='$LOOKUPS' \
        cargo test --release -p orfs --test historical_index_integration -- --nocapture"
else
    docker_run sh -c "ORFS_HIST_INTEG=1 \
        ORFS_HIST_INTEG_SCALES='$SCALES' \
        ORFS_HIST_INTEG_LOOKUPS='$LOOKUPS' \
        cargo test -p orfs --test historical_index_integration -- --nocapture"
fi
echo "evidence: evidence/performance/historical-index-integrated.json"
