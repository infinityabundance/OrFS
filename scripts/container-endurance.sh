#!/bin/sh
# Phase 27 endurance harness.
#
# Runs the large-scale endurance, publish-cost and recovery-acceleration workload
# (`benches/endurance.rs`, harness = false) inside the pinned container, then
# re-runs the correctness courts to prove the sustained run left no corruption.
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

echo "=== phase 27: correctness courts re-run after endurance (no-corruption gate) ==="
docker_run cargo test --lib \
    --test namespace_model \
    --test snapshot_model \
    --test concurrency_stress \
    --test transaction_model \
    --test recovery_adversarial
