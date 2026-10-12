#!/bin/sh
# Opt-in group-commit sweep (this phase): adaptive vs fixed linger vs no grouping,
# plus the bounded-admission overload court.
#
# The tests run only when a real FUSE mount is available, so this uses the
# kernel-mount container (`docker_run_kmount` adds `--device /dev/fuse`,
# `CAP_SYS_ADMIN`, and unconfined AppArmor/seccomp). One container runs at a time.
#
# The default `cargo test` gate already *includes* these tests, but they skip when
# they cannot mount, so this is the court that actually exercises them and
# (re)generates `evidence/performance/group-commit-adaptive.json`.
#
# The sweep is deliberately modest by default so it can never be mistaken for the
# bounded default gate. Knobs (host env, interpolated into the container command):
#   ORFS_GC_COURT_THREADS        comma list of thread counts (default 1,2,4,8,16,32)
#   ORFS_GC_COURT_TARGET_ROUNDS  total rounds per thread count (default 384)
set -eu
. "$(dirname "$0")/lib.sh"

GC_THREADS="${ORFS_GC_COURT_THREADS:-1,2,4,8,16,32}"
GC_ROUNDS="${ORFS_GC_COURT_TARGET_ROUNDS:-384}"

docker_run_kmount sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export CARGO_TARGET_DIR="$(pwd)/target/kmount-gc"
    export ORFS_GC_COURT_THREADS='"$GC_THREADS"'
    export ORFS_GC_COURT_TARGET_ROUNDS='"$GC_ROUNDS"'
    echo "--- concurrency sweep: none / fixed linger / adaptive (threads=$ORFS_GC_COURT_THREADS, target rounds=$ORFS_GC_COURT_TARGET_ROUNDS) ---"
    timeout -k 10 1800 cargo test --test group_commit_adaptive -- --nocapture --test-threads=1
    echo "--- overload court: bounded admission past capacity ---"
    timeout -k 10 900 cargo test --test group_commit_e2e overload -- --nocapture --test-threads=1
'
