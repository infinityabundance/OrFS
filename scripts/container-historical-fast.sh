#!/bin/sh
# Phase-43 historical fast-path acceptance sweep (opt-in).
#
# Runs the bounded `tests/historical_fast.rs` court at a larger history scale in
# the pinned `orfs-build:1.99.0` container, so the plain `cargo test` gate stays
# bounded while the research §7 headline scale (an 8 000-op history, 2 000
# historical roots) can still be measured on demand.
#
# Usage:
#   sh scripts/container-historical-fast.sh
#   ORFS_HISTORICAL_FAST_OPS=2000 ORFS_HISTORICAL_FAST_ROOTS=200 \
#     sh scripts/container-historical-fast.sh
#
# Env:
#   ORFS_HISTORICAL_FAST_OPS               ops in the recovery history   (default 8000)
#   ORFS_HISTORICAL_FAST_CHECKPOINT_EVERY  checkpoint interval           (default 500)
#   ORFS_HISTORICAL_FAST_ROOT_OPS          ops in the roots history      (default 2000)
#   ORFS_HISTORICAL_FAST_ROOTS             distinct historical roots     (default 2000)
#   ORFS_HISTORICAL_FAST_WARM_SAMPLE       warm opens sampled            (default 64)
#   ORFS_HISTORICAL_FAST_PROFILE           release | debug               (default release)
#
# Evidence is written to evidence/performance/historical-fast.json.
set -eu
. "$(dirname "$0")/lib.sh"

OPS="${ORFS_HISTORICAL_FAST_OPS:-8000}"
CKEVERY="${ORFS_HISTORICAL_FAST_CHECKPOINT_EVERY:-500}"
ROOT_OPS="${ORFS_HISTORICAL_FAST_ROOT_OPS:-2000}"
ROOTS="${ORFS_HISTORICAL_FAST_ROOTS:-2000}"
WARM="${ORFS_HISTORICAL_FAST_WARM_SAMPLE:-64}"
PROFILE="${ORFS_HISTORICAL_FAST_PROFILE:-release}"

echo "orfs: historical-fast sweep: ops=$OPS checkpoint_every=$CKEVERY root_ops=$ROOT_OPS roots=$ROOTS warm=$WARM profile=$PROFILE"

if [ "$PROFILE" = "release" ]; then
    docker_run env \
        ORFS_HISTORICAL_FAST_OPS="$OPS" \
        ORFS_HISTORICAL_FAST_CHECKPOINT_EVERY="$CKEVERY" \
        ORFS_HISTORICAL_FAST_ROOT_OPS="$ROOT_OPS" \
        ORFS_HISTORICAL_FAST_ROOTS="$ROOTS" \
        ORFS_HISTORICAL_FAST_WARM_SAMPLE="$WARM" \
        cargo test --release -p orfs --test historical_fast -- --nocapture
else
    docker_run env \
        ORFS_HISTORICAL_FAST_OPS="$OPS" \
        ORFS_HISTORICAL_FAST_CHECKPOINT_EVERY="$CKEVERY" \
        ORFS_HISTORICAL_FAST_ROOT_OPS="$ROOT_OPS" \
        ORFS_HISTORICAL_FAST_ROOTS="$ROOTS" \
        ORFS_HISTORICAL_FAST_WARM_SAMPLE="$WARM" \
        cargo test -p orfs --test historical_fast -- --nocapture
fi
