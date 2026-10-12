#!/bin/sh
# Reviewer task (research §6) — index-layout competition court runner.
#
# Runs `tests/index_layout.rs` inside the pinned container. It holds several
# candidate representations for the numeric inode-id index — the production
# persistent treap, a prototype persistent segmented radix, and static sealed
# layouts (sorted array, direct ordinal, cache-line-packed pages) — in one
# benchmark and measures point lookup, ordered range enumeration, mutation,
# publication (clone vs seal-rebuild), structural bytes, build page faults and
# resident memory at retained scales 10 000 / 100 000 / 1 000 000.
#
# The sweep is opt-in (an ordinary `cargo test` skips it) and runs in the
# **release** build, the representative one for performance evidence. The
# 10 000 000 scale is a further opt-in (ORFS_INDEX_LAYOUT_10M=1) because it is
# memory heavy. Evidence is written to `evidence/performance/index-layout.json`.
#
# Usage:
#   sh scripts/container-index-layout.sh
#   ORFS_INDEX_LAYOUT_10M=1 sh scripts/container-index-layout.sh   # add 10M
#   ORFS_INDEX_LAYOUT_SCALES=10000 sh scripts/container-index-layout.sh
#
# One container runs at a time (`scripts/lib.sh`: 8 GiB, 2048 pids).
set -eu
. "$(dirname "$0")/lib.sh"

# Resolve the opt-in knobs on the host and bake them into the container command,
# because `docker_run` intentionally passes only its own fixed environment.
scales="${ORFS_INDEX_LAYOUT_SCALES:-}"
ten_m="${ORFS_INDEX_LAYOUT_10M:-0}"

echo "=== index-layout: full sweep (release, representative build) ==="
docker_run sh -c "ORFS_INDEX_LAYOUT=1 \
    ORFS_INDEX_LAYOUT_10M=$ten_m \
    ORFS_INDEX_LAYOUT_SCALES='$scales' \
    cargo test --release -p orfs --test index_layout index_layout_sweep -- --nocapture"
echo "evidence: evidence/performance/index-layout.json"
