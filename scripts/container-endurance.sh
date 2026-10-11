#!/bin/sh
# Phase 27 endurance harness.
#
# Runs the large-scale endurance, publish-cost and recovery-acceleration workload
# (`benches/endurance.rs`, harness = false) inside the pinned container, then
# re-runs the correctness courts to prove the sustained run left no corruption,
# and records the post-court result as evidence.
#
# This script runs TWO containers in sequence. That is why `docker_run` in
# `scripts/lib.sh` does not `exec` the docker client: `exec` would replace this
# shell, making the post-endurance court dead code (Phase 30 fixed exactly that).
#
# The workload is memory/pid-capped exactly like every other container run
# (`scripts/lib.sh`: 8 GiB, 2048 pids, one container at a time). Scales are
# environment-tunable; the defaults fit the caps and are recorded in the evidence.
#
# Usage:
#   sh scripts/container-endurance.sh
#   ORFS_ENDURANCE_PUBLISH_SCALES=10000,100000,1000000 sh scripts/container-endurance.sh
#
# Environment (all optional):
#   ORFS_ENDURANCE_PUBLISH_SCALES  churn scales, comma-separated (default 10000,100000,1000000)
#   ORFS_ENDURANCE_DIRS            directories the churn is spread over (default 1024)
#   ORFS_ENDURANCE_EXTENTS         disjoint-extent scales (default 1000,10000,100000)
#   ORFS_ENDURANCE_ROOTS           historical snapshot roots (default 2000)
#   ORFS_ENDURANCE_REMOUNTS        remounts interleaved with activity (default 4)
#   ORFS_ENDURANCE_READERS         concurrent reader threads (default 4)
#   ORFS_ENDURANCE_RECOVERY        recovery history scales (default 500,2000,8000)
#   ORFS_ENDURANCE_CHECKPOINT_EVERY  ops between in-log checkpoints (default 500)
#   ORFS_ENDURANCE_RECOVERY_CHUNK  bytes per write in the recovery workload (default 32768)
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== phase 27: publish cost + endurance + recovery acceleration ==="
# The harness is feature-gated so the correctness `cargo test` gate never builds
# it (see Cargo.toml); enable it here explicitly.
docker_run cargo bench --features endurance --bench endurance

echo "=== phase 30: correctness courts re-run after endurance (no-corruption gate) ==="
# A SECOND container, which only runs because docker_run no longer `exec`s (see
# its comment in lib.sh). On success it writes the post-court receipt; a failing
# court aborts before the receipt is written, so the receipt is never fabricated.
docker_run sh -c '
    set -eu
    cargo test --lib \
        --test namespace_model \
        --test snapshot_model \
        --test concurrency_stress \
        --test transaction_model \
        --test recovery_adversarial
    mkdir -p evidence/performance
    printf "{\n  \"schema\": \"orfs.evidence.endurance-postcourt.v1\",\n  \"generated_by\": \"scripts/container-endurance.sh\",\n  \"captured_at_utc\": \"%s\",\n  \"ran\": true,\n  \"result\": \"pass\",\n  \"courts\": [\n    \"lib\",\n    \"namespace_model\",\n    \"snapshot_model\",\n    \"concurrency_stress\",\n    \"transaction_model\",\n    \"recovery_adversarial\"\n  ]\n}\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > evidence/performance/endurance-postcourt.json
    echo "post-endurance no-corruption court: PASS (recorded in evidence/performance/endurance-postcourt.json)"
'
