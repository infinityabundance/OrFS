#!/bin/sh
# Run the Phase 5 io_uring integration tests and the backing-I/O benchmark in a
# container whose seccomp profile permits io_uring_setup/io_uring_enter.
#
# WHICH PROFILE, PROVEN NOT ASSUMED:
#   The default Docker seccomp profile (the one scripts/container-test.sh uses)
#   blocks io_uring_setup with EPERM on this host. `--security-opt
#   seccomp=unconfined` permits it. This script re-proves that at run time with
#   scripts/uring-probe.c and only adds seccomp=unconfined when the default
#   profile is actually found to block io_uring.
#
# ORFS_REQUIRE_URING=1 makes a fallback a hard test failure, so a green run here
# proves that io_uring really ran (not that the tests skipped).
#
# One container runs at a time.
set -eu
. "$(dirname "$0")/lib.sh"

RUNNER=docker_run
if docker_probe_io_uring_default; then
    echo "container-uring-test: default seccomp profile permits io_uring_setup" >&2
else
    echo "container-uring-test: default seccomp profile blocks io_uring_setup; using seccomp=unconfined" >&2
    RUNNER=docker_run_uring
fi

$RUNNER sh -c '
    set -eu
    export ORFS_REQUIRE_URING=1
    echo "--- io_uring integration tests ---"
    timeout -k 10 900 cargo test --test uring_integration -- --nocapture --test-threads=1
    echo "--- backing I/O benchmark (writes evidence/performance/backing-uring.json) ---"
    timeout -k 10 900 cargo bench --bench backing_io
'
