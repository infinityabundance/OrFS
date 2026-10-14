#!/bin/sh
# Phase 79 — sustained adversarial concurrency court + a real-mount arm.
#
# One container at a time. It runs, in order:
#   1. the bounded always-on smoke (the default-gate subset);
#   2. the sustained opt-in sweep (release) that writes the receipt's
#      `in_process` section (native fsx/fsstress/fs_mark equivalents + a
#      rename/link/unlink storm, all against independent models);
#   3. the mounted arm through a REAL OrFS FUSE mount (`docker_run_kmount`), which
#      merges the `mounted` section into the same receipt.
#
# The real `fsx`/`fsstress`/`fs_mark`/`xfstests` tools are NOT runnable here; every
# court is a native Rust equivalent, labelled as such everywhere. See
# docs/POSIX-COMPAT.md and docs/LIMITATIONS.md §18.
#
# Receipt: evidence/correctness/adversarial-concurrency.json
#          (schema orfs.correctness.adversarial-concurrency.v1)
#
# Usage:
#   sh scripts/container-adversarial-concurrency.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== adversarial-concurrency: smoke (always-on, default gate) ==="
docker_run cargo test -p orfs --test adversarial_concurrency adversarial_concurrency_smoke

echo "=== adversarial-concurrency: sustained sweep (release; writes the in_process receipt section) ==="
docker_run sh -c '
    set -eu
    export ORFS_STRESS=1
    export ORFS_ADVERSARIAL_RECEIPT=1
    export ORFS_FSX_OPS=20000
    export ORFS_FSSTRESS_THREADS=64
    export ORFS_FSSTRESS_OPS=400
    export ORFS_FSMARK_FILES=4000
    export ORFS_STORM_THREADS=64
    export ORFS_STORM_OPS=400
    timeout -k 10 900 cargo test --release -p orfs --test adversarial_concurrency \
        adversarial_concurrency_sustained -- --nocapture --test-threads=1
'

echo "=== adversarial-concurrency: mounted arm (real FUSE mount; merges the mounted receipt section) ==="
# Keep the mount-test build output on the bind-mounted project drive, never the
# container's RAM-backed root (matches scripts/container-fuse-test.sh).
docker_run_kmount sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export ORFS_ADVERSARIAL_RECEIPT=1
    export ORFS_MOUNTED_THREADS=16
    export ORFS_MOUNTED_OPS=200
    export CARGO_TARGET_DIR="$(pwd)/target/kmount-test"
    timeout -k 10 900 cargo test -p orfs --test adversarial_concurrency \
        adversarial_mounted_fsstress -- --nocapture --test-threads=1
'

echo "evidence: evidence/correctness/adversarial-concurrency.json"
