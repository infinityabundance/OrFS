#!/bin/sh
# Reviewer item 4 — history-scaling court runner.
#
# Runs `tests/history_scaling.rs` inside the pinned container. The heavy sweep is
# opt-in (it is skipped, not failed, by an ordinary `cargo test`); this script
# enables it and runs it in the **release** build, which is the representative one
# for performance evidence (mirroring the `ORFS_E2E_SUFFIX=-release` convention
# used elsewhere).
#
# The court builds a deterministic growing committed history in two arms — OrFS
# with the concealed manifested plane enabled and OrFS with it disabled over the
# *same* history — and at epochs {0, 4, 12, 36} runs the same fixed read workload
# over the checkpoint's pinned committed root. It records foreground latency
# percentiles, throughput, physical bytes, resident memory, construction work,
# recovery time and unnecessary backing reads avoided, and asserts the two arms'
# pinned roots and per-checkpoint read digests are byte-identical. The evidence is
# written to `evidence/performance/history-scaling.json`.
#
# Usage:
#   sh scripts/container-history-scaling.sh
#   ORFS_HISTORY_SCALING=0 sh scripts/container-history-scaling.sh   # smoke only
#
# One container runs at a time (`scripts/lib.sh`: 8 GiB, 2048 pids).
set -eu
. "$(dirname "$0")/lib.sh"

if [ "${ORFS_HISTORY_SCALING:-1}" = "0" ]; then
    echo "=== history-scaling: bounded smoke only (ORFS_HISTORY_SCALING=0) ==="
    docker_run cargo test -p orfs --test history_scaling history_scaling_smoke
else
    echo "=== history-scaling: full sweep (release, representative build) ==="
    docker_run sh -c 'ORFS_HISTORY_SCALING=1 \
        cargo test --release -p orfs --test history_scaling history_scaling_sweep -- --nocapture'
    echo "evidence: evidence/performance/history-scaling.json"
fi
