#!/bin/sh
# Phase 80 — durability qualification beyond the model.
#
# Three sequential steps, one container at a time:
#   1. the device-mapper probe, in an **elevated** container (root +
#      `--cap-add SYS_ADMIN --cap-add MKNOD` + `/dev/loop-control` /
#      `/dev/mapper/control` when the host has them), recording whether a real
#      `dm-flaky`/`dm-error` target could be built here — never faking success;
#   2. the bounded **always-on smoke** (the default-gate subset): the three
#      failure classes, the extended fault matrix, in-flight completions, torn
#      metadata, remount cycles, and the residual window;
#   3. the opt-in **sweep** (`ORFS_DQ_SWEEP=1`) over mode x class x profile, which
#      writes the receipt.
#
# Receipt: evidence/recovery/durability-qualification.json
#          (schema orfs.recovery.durability-qualification.v1)
#
# The device is the project's deterministic **simulated** model (src/powerloss.rs);
# a green run proves correctness relative to the model, NOT real-hardware
# durability. See docs/DURABILITY.md.
#
# Usage:
#   sh scripts/container-durability-qualification.sh
set -eu
. "$(dirname "$0")/lib.sh"

# A dedicated path (not the one the ordinary suite writes) so the root-run probe
# cannot leave a root-owned file a later non-root run cannot overwrite.
PROBE_JSON="$ORFS_PROJECT_DIR/target/dm-probe-elevated.json"
rm -f "$PROBE_JSON"

echo "=== phase 80: device-mapper fault-target probe (elevated container) ==="
docker_run_dm_probe sh -c "
    set -eu
    CARGO_TARGET_DIR=\"\$(pwd)/target/dm-probe\" \
    ORFS_DM_PROBE_MODE=elevated-container \
    ORFS_DM_PROBE_OUT=\"\$(pwd)/target/dm-probe-elevated.json\" \
        cargo test -p orfs --test verify_recover_faults write_dm_probe_receipt \
            -- --nocapture --test-threads=1
"
if [ ! -f "$PROBE_JSON" ]; then
    echo "orfs: the elevated dm probe wrote no $PROBE_JSON" >&2
    exit 1
fi

echo "=== phase 80: durability qualification — smoke (always-on) ==="
docker_run cargo test -p orfs --test durability_qualification -- --test-threads=1

echo "=== phase 80: durability qualification — sweep (writes the receipt) ==="
GIT_COMMIT="$(git -C "$ORFS_PROJECT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
docker_run sh -c "
    set -eu
    ORFS_DQ_SWEEP=1 \
    ORFS_DM_PROBE_JSON=$PROBE_JSON \
    ORFS_GIT_COMMIT=$GIT_COMMIT \
        cargo test -p orfs --test durability_qualification write_durability_qualification_evidence \
            -- --nocapture --test-threads=1
"

echo "evidence: evidence/recovery/durability-qualification.json"
