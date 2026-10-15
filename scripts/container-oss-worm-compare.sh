#!/bin/sh
# Phase 87 — the same-machine open-source WORM comparison court.
#
# One container at a time, kernel-mount profile (`/dev/fuse` + `CAP_SYS_ADMIN`),
# running as **root** — exactly as the sibling Go court did (`oss-compare-court.sh`
# runs as root). Root is required because the OrFS volume root inode is committed
# `0755 root:root`, so a non-root driver cannot create the workload files; both
# arms run as root, so the setting is symmetric and is recorded in the receipt.
#   1. the bounded always-on smoke (`tests/oss_worm_compare.rs::oss_worm_compare_smoke`),
#      which mounts a real OrFS volume through the `orfs mount` code path, drives a
#      tiny append+fsync and random-read matrix, and proves a small retention sweep;
#   2. the opt-in sweep (`ORFS_OSS_WORM=1`, release) that measures OrFS-Rust and
#      SeaweedFS 3.99 on the same machine/device/caps and writes
#      `evidence/performance/oss-worm-compare.json`.
#
# SeaweedFS's `weed` binary is staged deterministically from the pinned image
# (recorded by digest) into `target/oss-worm/weed`, which the container already
# sees at the same absolute path (the project tree is bind-mounted). If it cannot
# be staged, the court still measures OrFS-Rust and records SeaweedFS as SKIPPED
# with the reason — never a silent omission.
#
# Env knobs (all optional): ORFS_WORM_SECONDS, ORFS_WORM_READ_SECONDS,
# ORFS_WORM_WRITERS, ORFS_WORM_READERS, ORFS_WORM_BLOCKS, ORFS_WORM_RECORD_BYTES,
# ORFS_WORM_READ_MIB, ORFS_WORM_MAX_APPEND_MIB, ORFS_WORM_SEED, ORFS_WORM_EPOCHS.
#
# Usage:
#   sh scripts/container-oss-worm-compare.sh
set -eu
. "$(dirname "$0")/lib.sh"

WEED_IMAGE="${ORFS_SEAWEEDFS_IMAGE:-chrislusf/seaweedfs:3.99}"
STAGE_DIR="$ORFS_PROJECT_DIR/target/oss-worm"
WEED_BIN="$STAGE_DIR/weed"
BUILD_DIR="$ORFS_PROJECT_DIR/target/oss-worm-build"

seaweedfs_digest() {
    docker image inspect --format '{{index .RepoDigests 0}}' "$WEED_IMAGE" 2>/dev/null \
        || echo unavailable
}

# stage_seaweedfs extracts the pinned `weed` binary from the image into the
# (bind-mounted) project tree so the court container can execute it. It never
# vendors or modifies SeaweedFS: only the shipped binary is copied out.
stage_seaweedfs() {
    [ -x "$WEED_BIN" ] && return 0
    command -v docker >/dev/null 2>&1 || return 1
    mkdir -p "$STAGE_DIR"
    docker pull --platform linux/amd64 "$WEED_IMAGE" >/dev/null 2>&1 || true
    _cid=$(docker create --platform linux/amd64 "$WEED_IMAGE" 2>/dev/null) || return 1
    if ! docker cp "$_cid:/usr/bin/weed" "$WEED_BIN" >/dev/null 2>&1; then
        docker rm -f "$_cid" >/dev/null 2>&1 || true
        return 1
    fi
    docker rm -f "$_cid" >/dev/null 2>&1 || true
    chmod +x "$WEED_BIN"
    [ -x "$WEED_BIN" ]
}

if [ ! -e /dev/fuse ]; then
    echo "container-oss-worm-compare: SKIPPED (no /dev/fuse on the host)"
    exit 0
fi

SW_DIGEST="unavailable"
if stage_seaweedfs; then
    SW_DIGEST=$(seaweedfs_digest)
    echo "container-oss-worm-compare: staged weed from $WEED_IMAGE ($SW_DIGEST) at $WEED_BIN"
else
    echo "container-oss-worm-compare: SKIPPED SeaweedFS (could not stage $WEED_IMAGE); OrFS-Rust will still be measured" >&2
fi

echo "=== oss-worm-compare: smoke (always-on, bounded; real OrFS mount) ==="
docker_run_kmount_root sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export ORFS_WORM_WEED="'"$WEED_BIN"'"
    export ORFS_WORM_SW_IMAGE="'"$WEED_IMAGE"'"
    export ORFS_WORM_SW_DIGEST="'"$SW_DIGEST"'"
    export CARGO_TARGET_DIR="'"$BUILD_DIR"'"
    timeout -k 10 900 cargo test --test oss_worm_compare oss_worm_compare_smoke \
        -- --nocapture --test-threads=1
'

echo "=== oss-worm-compare: sweep (release; writes the receipt) ==="
docker_run_kmount_root sh -c '
    set -eu
    export ORFS_FUSE_TEST=1
    export ORFS_OSS_WORM=1
    export ORFS_WORM_WEED="'"$WEED_BIN"'"
    export ORFS_WORM_SW_IMAGE="'"$WEED_IMAGE"'"
    export ORFS_WORM_SW_DIGEST="'"$SW_DIGEST"'"
    export CARGO_TARGET_DIR="'"$BUILD_DIR"'"
    timeout -k 10 3000 cargo test --release --test oss_worm_compare oss_worm_compare_sweep \
        -- --nocapture --test-threads=1
'

echo "evidence: evidence/performance/oss-worm-compare.json"
