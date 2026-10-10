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
set -eu
. "$(dirname "$0")/lib.sh"
docker_run_kmount sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export CARGO_TARGET_DIR=/tmp/orfs-kmount-target
    timeout -k 10 900 cargo test --test fuse_integration -- --nocapture --test-threads=1
    echo "--- snapshot read-only mount integration ---"
    timeout -k 10 900 cargo test --test snapshot_fuse -- --nocapture --test-threads=1
'
