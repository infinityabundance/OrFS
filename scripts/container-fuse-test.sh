#!/bin/sh
# Run the real FUSE integration tests inside the kernel-mount container.
#
# This is the only script that uses `docker_run_kmount` (it adds
# `--device /dev/fuse`, `--cap-add SYS_ADMIN`, and unconfined AppArmor/seccomp).
# One container runs at a time.
#
# The test builds inside the container with a container-local `CARGO_TARGET_DIR`
# so mount-test artifacts never leak into the shared `target/`. `ORFS_FUSE_TEST=1`
# makes a mount failure a hard test failure, so a green run here proves that a
# real mount happened and that every POSIX assertion passed.
#
# Phase 21 (FUSE passthrough) needs `capable(CAP_SYS_ADMIN)`, which the kernel
# requires at `FUSE_DEV_IOC_BACKING_OPEN` (`fs/fuse/backing.c`) and which Docker
# only retains for the root user. That one court therefore runs in a root
# container; every other court runs as the ordinary non-root project user.
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== phase 21: kernel FUSE passthrough for immutable snapshots (root) ==="
docker_run_kmount_root sh -c '
    set -eu
    umask 0
    export ORFS_FUSE_TEST=1
    export CARGO_TARGET_DIR="$(pwd)/target/kmount-passthrough"
    timeout -k 10 900 cargo test --test fuse_passthrough -- --nocapture --test-threads=1
'

docker_run_kmount sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    # Keep mount-test build output on the bind-mounted project drive (the file
    # TMPDIR is likewise set by lib.sh), never the container’s RAM-backed root.
    export CARGO_TARGET_DIR="$(pwd)/target/kmount-test"
    timeout -k 10 900 cargo test --test fuse_integration -- --nocapture --test-threads=1
    echo "--- snapshot read-only mount integration ---"
    timeout -k 10 900 cargo test --test snapshot_fuse -- --nocapture --test-threads=1
    echo "--- FUSE-over-io_uring transport equivalence + negotiation/fallback ---"
    timeout -k 10 900 cargo test --test fuse_uring -- --nocapture --test-threads=1
    echo "--- phase 32: end-to-end group commit through a real mount (create/write/unlink churn, concurrent writers, O_APPEND ordering, write-heavy measurement) ---"
    timeout -k 10 1200 cargo test --test group_commit_e2e -- --nocapture --test-threads=1
    echo "--- performance court: conventional baseline + F0/F1/E1 through real mounts ---"
    timeout -k 10 900 cargo test --test performance_court -- --nocapture --test-threads=1
    echo "--- phase 16: manifestation frontier end to end (byte reads, search, fragmented) ---"
    timeout -k 10 900 cargo test --test ekbloom_frontier_e2e -- --nocapture --test-threads=1
'
