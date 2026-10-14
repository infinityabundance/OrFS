#!/bin/sh
# Phase 81 — end-to-end application workloads with a real baseline.
#
# One container at a time, one image (`Dockerfile.appworkload`) that carries the
# real applications. It runs, in order:
#   1. the bounded always-on smoke (`ORFS_FUSE_TEST=1`): the same five workloads
#      at a tiny scale, so the court is cheap and reliable;
#   2. the opt-in sweep (release, `ORFS_APP_SWEEP=1`) that writes
#      evidence/performance/application-workloads.json.
#
# Both steps mount a REAL OrFS volume with `fuse::spawn` (the same code path as
# `orfs mount`) and drive the real applications (git, sqlite3, tar, make/gcc)
# against it, plus external baselines in the SAME container: a directory on the
# same bind-mounted host filesystem as the OrFS backing (the primary, fair
# comparator) and an in-container tmpfs reference arm.
#
# See docs/APPLICATIONS.md and docs/LIMITATIONS.md §20.
#
# Usage:
#   sh scripts/container-application-workloads.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== application-workloads: smoke (always-on, bounded subset; real mount) ==="
docker_run_app sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export CARGO_TARGET_DIR="$(pwd)/target/app-workloads"
    timeout -k 10 900 cargo test -p orfs --test application_workloads \
        application_workloads_smoke -- --nocapture --test-threads=1
'

echo "=== application-workloads: full sweep (release; writes the receipt) ==="
docker_run_app sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export ORFS_APP_SWEEP=1
    export CARGO_TARGET_DIR="$(pwd)/target/app-workloads"
    timeout -k 10 2400 cargo test --release -p orfs --test application_workloads \
        application_workloads_sweep -- --nocapture --test-threads=1
'

echo "evidence: evidence/performance/application-workloads.json"
