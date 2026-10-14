#!/bin/sh
# Reviewer task — io_uring ring-depth sweep with CQ/SQ mechanism counters.
#
# Runs tests/uring_depth.rs inside the pinned container, one container at a time:
#   1. the always-on smoke (bounded, default gate);
#   2. the full sweep (ORFS_URING_DEPTH=1) in the **release** build, the
#      representative build for performance evidence, which writes
#      evidence/performance/uring-depth.json.
#
# io_uring needs a seccomp profile that permits io_uring_setup. This uses
# `docker_run_uring` (unconfined seccomp); scripts/container-uring-test.sh proves
# at run time that the default profile blocks io_uring_setup on this host while
# `seccomp=unconfined` permits it, so `docker_run_uring` is always safe here.
#
# Hardware performance counters are **not** unavailable on this host: the claim
# that `perf_event_paranoid=2` blocks them was wrong and was corrected in Phase 57
# — a user-space, per-thread counter is permitted, and Docker's default seccomp
# profile is the real gate (see docs/PMU.md). This court does not need them, so it
# records the SQ-backpressure (`sq_full_events`) and CQ-depth (`cq_max_len`)
# counters as the mechanism evidence — see docs/PERFORMANCE.md §21.
#
# Usage:
#   sh scripts/container-uring-depth.sh
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== uring depth: smoke (always-on, default gate) ==="
docker_run_uring cargo test -p orfs --test uring_depth uring_depth_smoke -- --nocapture

echo "=== uring depth: full sweep (release, representative build) ==="
docker_run_uring sh -c 'ORFS_URING_DEPTH=1 cargo test --release -p orfs --test uring_depth uring_depth_sweep -- --nocapture'

echo "evidence: evidence/performance/uring-depth.json"
