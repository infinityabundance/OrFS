#!/bin/sh
# Phase 50 — CPU microarchitecture court runner (reviewer §11).
# Phase 83 — runs under the **probed PERFMON profile** so the counters are real.
#
# Runs `tests/microarch.rs` inside the pinned container, one container at a time:
#   1. a run-time PROOF of which container flags permit `perf_event_open`
#      (`scripts/pmu-probe.c`), least-privilege first;
#   2. the always-on smoke (bounded, default gate);
#   3. the full sweep (`ORFS_MICROARCH=1`) in the **release** build, the
#      representative build for performance evidence, which writes
#      `evidence/performance/microarch.json` — now with **real** hardware counters.
#
# This court is **not** PMU-free by necessity. The historical claim that hardware
# performance counters are unavailable "because `perf_event_paranoid=2`" was
# WRONG and was corrected in Phase 57: a user-space, per-thread counter
# (`pid=0`, `cpu=-1`, `exclude_kernel=1`) is permitted at level 2. The real gate is
# the container's seccomp profile, which denies `perf_event_open` with `EPERM` in
# the default container; `--cap-add PERFMON` (proven below at run time) makes the
# counters work. See `docs/PMU.md` and `docs/PERFORMANCE.md` §18/§23.
#
# Usage:
#   sh scripts/container-microarch.sh
set -eu
. "$(dirname "$0")/lib.sh"

# probe <label> [extra docker run flags...] — runs the C probe under the default
# docker_run flags plus the extras; exit 0 iff perf_event_open was permitted.
probe() {
    _label="$1"
    shift
    if docker run --rm \
        --memory="$ORFS_MEM_LIMIT" \
        --memory-swap="$ORFS_MEMSWAP_LIMIT" \
        --cpus="$ORFS_CPUS" \
        --pids-limit="$ORFS_PIDS" \
        --ulimit core=0 \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        "$@" \
        -v "$ORFS_PARENT_DIR":"$ORFS_PARENT_DIR" \
        -w "$ORFS_PROJECT_DIR" \
        -u "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        "$ORFS_IMAGE" \
        sh -c 'cc scripts/pmu-probe.c -o /tmp/orfs-pmu-probe && /tmp/orfs-pmu-probe'
    then
        echo "container-microarch: $_label -> PERMITTED"
        return 0
    else
        echo "container-microarch: $_label -> DENIED (errno above)"
        return 1
    fi
}

echo "=== microarch: prove which container flags permit perf_event_open ==="
EXTRA_FLAGS="--cap-add PERFMON"
if probe "(1) default profile (cap-drop ALL, default seccomp)"; then
    echo "container-microarch: default profile already permits perf_event_open"
    EXTRA_FLAGS=""
elif probe "(2) default seccomp + --cap-add PERFMON" --cap-add PERFMON; then
    EXTRA_FLAGS="--cap-add PERFMON"
elif probe "(3) default profile + seccomp=unconfined" --security-opt seccomp=unconfined; then
    EXTRA_FLAGS="--security-opt seccomp=unconfined"
else
    echo "container-microarch: fatal: perf_event_open blocked under every profile tried" >&2
    exit 1
fi
echo "container-microarch: kernel perf_event_paranoid (host): $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo unknown)"

# run_pmu <cmd...> — docker_run with exactly the flags proven above. Deliberately
# does NOT `exec`, so one script can drive the smoke and the sweep in sequence.
# shellcheck disable=SC2086  # intentional word-splitting of the proven flags
run_pmu() {
    docker run --rm \
        --memory="$ORFS_MEM_LIMIT" \
        --memory-swap="$ORFS_MEMSWAP_LIMIT" \
        --cpus="$ORFS_CPUS" \
        --pids-limit="$ORFS_PIDS" \
        --ulimit core=0 \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        $EXTRA_FLAGS \
        -v "$ORFS_PARENT_DIR":"$ORFS_PARENT_DIR" \
        -w "$ORFS_PROJECT_DIR" \
        -u "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        -e TMPDIR="$ORFS_TMP_DIR" \
        -e CARGO_HOME="$ORFS_CARGO_HOME" \
        -e RUSTUP_HOME=/usr/local/rustup \
        -e CARGO_TARGET_DIR="$ORFS_TARGET_DIR" \
        -e CARGO_TERM_COLOR=never \
        -e RUSTUP_TOOLCHAIN=1.99.0 \
        -e ORFS_IMAGE_DIGEST="$(_orfs_image_digest "$ORFS_IMAGE")" \
        "$ORFS_IMAGE" "$@"
}

echo "=== microarch: smoke (always-on, default gate) ==="
run_pmu cargo test -p orfs --test microarch microarch_smoke -- --nocapture

echo "=== microarch: full sweep (release, representative build; real counters) ==="
run_pmu sh -c 'ORFS_MICROARCH=1 cargo test --release -p orfs --test microarch microarch_sweep -- --nocapture'

echo "evidence: evidence/performance/microarch.json"
