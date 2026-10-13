#!/bin/sh
# Phase 50 — prove the PMU mechanism and run the hardware-counter court.
#
# This is the perf_event_open analogue of scripts/container-uring-test.sh.
#
# The project previously claimed "perf_event_paranoid=2, so no hardware
# counters and no flamegraphs". That is WRONG. A user-space, per-thread counter
# (pid=0, cpu=-1, exclude_kernel=1) is permitted at paranoid=2. The real gate on
# this host is the container profile: with `--cap-drop=ALL` and Docker's DEFAULT
# seccomp profile, `perf_event_open` is denied with EPERM.
#
# WHICH PROFILE, PROVEN NOT ASSUMED: this script probes `perf_event_open` at run
# time with scripts/pmu-probe.c under four container profiles —
#
#   (1) the DEFAULT profile (cap-drop ALL, default seccomp): expected EPERM;
#   (2) seccomp=unconfined: expected to work;
#   (3) default seccomp + --cap-add PERFMON: Docker's default seccomp profile
#       gates perf_event_open on CAP_PERFMON, so this is expected to work too;
#   (4) default seccomp + --cap-add SYS_ADMIN: likewise.
#
# and reports exactly which flags are required before running the smoke and the
# release sweep (which writes evidence/performance/pmu.json and the flamegraph).
#
# One container runs at a time.
set -eu
. "$(dirname "$0")/lib.sh"

# probe <label> [extra docker run flags...]
#
# Runs the C probe under the default flags plus any extras, and reports whether
# `perf_event_open` was permitted. Uses the same flags as docker_run, so the
# proof is about the exact profile docker uses by default.
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
        echo "container-pmu: $_label -> PERMITTED"
        return 0
    else
        echo "container-pmu: $_label -> DENIED (errno above)"
        return 1
    fi
}

echo "=== PMU probe: which container flags are actually required? ==="

DEFAULT_OK=0
if probe "(1) default profile (cap-drop ALL, default seccomp)"; then
    DEFAULT_OK=1
fi

UNCONFINED_OK=0
PERFMON_OK=0
SYSADMIN_OK=0
if [ "$DEFAULT_OK" = 0 ]; then
    if probe "(2) default profile + --security-opt seccomp=unconfined" \
        --security-opt seccomp=unconfined; then
        UNCONFINED_OK=1
    fi
    if probe "(3) default seccomp + --cap-add PERFMON" --cap-add PERFMON; then
        PERFMON_OK=1
    fi
    if probe "(4) default seccomp + --cap-add SYS_ADMIN" --cap-add SYS_ADMIN; then
        SYSADMIN_OK=1
    fi
fi

# The flags proven to permit perf_event_open, least-privilege first (a scoped
# capability is narrower than disabling the whole seccomp filter).
EXTRA_FLAGS=""
if [ "$DEFAULT_OK" = 1 ]; then
    echo "container-pmu: the default profile already permits perf_event_open"
    echo "container-pmu: required flags: none"
elif [ "$PERFMON_OK" = 1 ]; then
    # Docker's default seccomp profile allows perf_event_open when CAP_PERFMON is
    # present; this is the least-privilege grant that works.
    echo "container-pmu: --cap-add PERFMON is REQUIRED with the default seccomp profile"
    echo "container-pmu: (seccomp=unconfined works too: $UNCONFINED_OK; SYS_ADMIN works too: $SYSADMIN_OK)"
    EXTRA_FLAGS="--cap-add PERFMON"
elif [ "$UNCONFINED_OK" = 1 ]; then
    echo "container-pmu: seccomp=unconfined is REQUIRED (no capability grant sufficed)"
    EXTRA_FLAGS="--security-opt seccomp=unconfined"
elif [ "$SYSADMIN_OK" = 1 ]; then
    echo "container-pmu: --cap-add SYS_ADMIN is REQUIRED"
    EXTRA_FLAGS="--cap-add SYS_ADMIN"
else
    echo "container-pmu: fatal: perf_event_open is blocked under every profile tried" >&2
    exit 1
fi
echo "container-pmu: kernel perf_event_paranoid (host): $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo unknown)"

# run_pmu <cmd...> — docker_run with exactly the flags proven above. Deliberately
# does NOT `exec`, so one script can drive several containers in sequence.
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

echo "=== PMU smoke (always-on, default gate) ==="
run_pmu cargo test -p orfs --test microarch_pmu pmu_smoke -- --nocapture

echo "=== PMU flamegraph (debug build: unambiguous leaf symbols) ==="
# A debug build is used deliberately: LTO/codegen-unit merging in the release
# profile folds distinct functions onto shared addresses, which makes `addr2line`
# leaf attribution ambiguous. The debug profile has one symbol per function.
run_pmu sh -c 'ORFS_PMU=1 cargo test -p orfs --test microarch_pmu pmu_flamegraph -- --nocapture'

echo "=== PMU release sweep (counters -> evidence/performance/pmu.json) ==="
# Embeds the flamegraph sidecar written by the debug run above.
run_pmu sh -c 'ORFS_PMU=1 cargo test --release -p orfs --test microarch_pmu pmu_sweep -- --nocapture'

echo "evidence: evidence/performance/pmu.json"
echo "evidence: evidence/performance/flamegraph-microarch.folded"
echo "evidence: evidence/performance/flamegraph-microarch.svg"
