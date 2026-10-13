#!/bin/sh
# Reviewer item 8 — endurance space-amplification court runner.
#
# Non-withdrawal means committed history is never GC'd, so space amplification
# grows forever. This runner drives `tests/endurance_amplification.rs`, which grows
# a committed history over many epochs (content-neutral rewrites) and samples the
# time series — logical bytes, authoritative physical bytes (segments + watermark),
# manifested bytes, total physical bytes, the amplification ratio, the segment
# count, the retained committed-root count and the manifested generation count —
# in two arms (concealed plane off and on).
#
# Two bounded stages, one container at a time:
#   1. the always-on smoke (default `cargo test` build), then
#   2. the release sweep (representative build) which writes the receipt.
#
# The sweep is BOUNDED in wall time and retained bytes by design; it is a surrogate
# for the multi-day run the reviewer's item ultimately needs (stated in the
# receipt). Set ORFS_ENDURANCE_AMPLIFICATION=0 to run the smoke only.
#
# Usage:
#   sh scripts/container-endurance-amplification.sh
#   ORFS_ENDURANCE_AMPLIFICATION=0 sh scripts/container-endurance-amplification.sh
#
# One container runs at a time (`scripts/lib.sh`: 8 GiB, 2048 pids).
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== phase 69: endurance space-amplification (bounded smoke) ==="
docker_run cargo test -p orfs --test endurance_amplification endurance_amplification_smoke

if [ "${ORFS_ENDURANCE_AMPLIFICATION:-1}" = "0" ]; then
    echo "=== sweep skipped (ORFS_ENDURANCE_AMPLIFICATION=0) ==="
    echo "evidence: evidence/performance/endurance-amplification.json (unchanged)"
    exit 0
fi

echo "=== phase 69: endurance space-amplification (release sweep) ==="
docker_run sh -c 'ORFS_ENDURANCE_AMPLIFICATION=1 \
    cargo test --release -p orfs --test endurance_amplification endurance_amplification_sweep -- --nocapture'
echo "evidence: evidence/performance/endurance-amplification.json"
