#!/bin/sh
# Phase 62 — device-fault evidence: `orfs verify --deep` + `orfs recover` after
# injected mid-log faults, plus the device-mapper (`dm-flaky` / `dm-error`) probe.
#
# Three sequential steps, one container at a time:
#
#   1. the device-mapper probe, in an **elevated** container (root +
#      `--cap-add SYS_ADMIN --cap-add MKNOD` + `/dev/loop-control` /
#      `/dev/mapper/control` when the host has them), so the recorded probe
#      reflects the most privileged attempt the sandbox allows;
#   2. the always-on fault-injection court (default) driving the real `orfs`
#      binary;
#   3. the opt-in heavier sweep (`ORFS_FAULT_SWEEP=1`).
#
# Steps 2 and 3 read the elevated probe from step 1 via `ORFS_DM_PROBE_JSON`.
# If the container environment cannot build a real device-mapper target (the
# likely outcome on this host), the probe records `ran: false` with the exact
# failing command; nothing is faked. See docs/RECOVERY.md §9.
set -eu
. "$(dirname "$0")/lib.sh"

# A dedicated path (not the one the ordinary suite writes) so the root-run probe
# cannot leave a root-owned file that a later non-root run cannot overwrite.
PROBE_JSON="$ORFS_PROJECT_DIR/target/dm-probe-elevated.json"
rm -f "$PROBE_JSON"

echo "=== phase 62: device-mapper fault-target probe (elevated container) ==="
# A container-local target dir keeps root-owned build artifacts out of the shared
# `target/` (the same discipline as the root FUSE court).
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

echo "=== phase 62: fault-injection verify/recover court (default) ==="
docker_run sh -c "
    ORFS_DM_PROBE_JSON=$PROBE_JSON \
        cargo test -p orfs --test verify_recover_faults verify_recover_after_injected_faults \
            -- --nocapture --test-threads=1
"

echo "=== phase 62: fault-injection verify/recover court (sweep) ==="
docker_run sh -c "
    set -eu
    ORFS_DM_PROBE_JSON=$PROBE_JSON ORFS_FAULT_SWEEP=1 \
        cargo test -p orfs --test verify_recover_faults verify_recover_after_injected_faults \
            -- --nocapture --test-threads=1
"
