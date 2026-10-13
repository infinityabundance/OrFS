#!/bin/sh
# Run the bounded Loom concurrency models (Phase 70) inside the pinned container.
#
# HARD RULE: all cargo runs inside Docker (scripts/lib.sh); one container at a
# time. The Loom build is a SEPARATE artifact set from the ordinary suite (it is
# compiled with `--cfg loom`), so it never perturbs the default `cargo test`
# build or its test count.
#
# The incantation:
#
#   RUSTFLAGS="--cfg loom" cargo test --test loom_concurrency
#
# `--cfg loom` activates the `[target.'cfg(loom)'.dependencies]` loom entry and
# selects `loom::sync` in `src/sync_model.rs`; the integration test
# `tests/loom_concurrency.rs` is `#![cfg(loom)]`, so it is empty (and adds
# nothing) in a normal build. Only the one model test target is built, keeping
# the run bounded.
#
# Heavier bounds are opt-in: ORFS_LOOM_FULL=1 plus the per-axis overrides
# ORFS_LOOM_{READERS,PUBLISHES,LOADS,SUBMITTERS,JOBS}. The run is bounded by a
# finite wall-clock timeout (ORFS_LOOM_TIMEOUT seconds, default 1800); after it
# elapses the container's cargo is terminated.
set -eu
. "$(dirname "$0")/lib.sh"

TIMEOUT="${ORFS_LOOM_TIMEOUT:-1800}"
ORFS_LOOM_FULL="${ORFS_LOOM_FULL:-0}"
ORFS_LOOM_READERS="${ORFS_LOOM_READERS:-}"
ORFS_LOOM_PUBLISHES="${ORFS_LOOM_PUBLISHES:-}"
ORFS_LOOM_LOADS="${ORFS_LOOM_LOADS:-}"
ORFS_LOOM_SUBMITTERS="${ORFS_LOOM_SUBMITTERS:-}"
ORFS_LOOM_JOBS="${ORFS_LOOM_JOBS:-}"

echo "orfs: loom: bounded model run (timeout ${TIMEOUT}s, ORFS_LOOM_FULL=${ORFS_LOOM_FULL})"

# `timeout` (coreutils, present in the image) bounds the run; `-k 10` follows a
# TERM with a KILL after a 10 s grace so a wedged model cannot hang the gate.
docker_run sh -c "
    ORFS_LOOM_FULL='${ORFS_LOOM_FULL}' \
    ORFS_LOOM_READERS='${ORFS_LOOM_READERS}' \
    ORFS_LOOM_PUBLISHES='${ORFS_LOOM_PUBLISHES}' \
    ORFS_LOOM_LOADS='${ORFS_LOOM_LOADS}' \
    ORFS_LOOM_SUBMITTERS='${ORFS_LOOM_SUBMITTERS}' \
    ORFS_LOOM_JOBS='${ORFS_LOOM_JOBS}' \
    RUSTFLAGS='--cfg loom' \
    timeout -k 10 ${TIMEOUT} cargo test --test loom_concurrency -- --nocapture
"
