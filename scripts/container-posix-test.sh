#!/bin/sh
# Phase 24 standard-POSIX court (host side).
#
# Runs the commit-pinned pjdfstest suite against a MOUNTED OrFS volume and
# against a reference directory on a trusted ordinary filesystem (the ext4
# project drive), then writes evidence/correctness/pjdfstest.json. See
# scripts/posix/pjdfstest.sh for the in-container work and the gate.
#
# This script requires an OrFS mount, so it uses `docker_run_posix`, which adds
# ONLY the device access, capabilities and unconfined profile a FUSE mount needs,
# runs as root (pjdfstest requires root), and uses the Dockerfile.posix image
# (which carries the pinned pjdfstest build). One container runs at a time.
#
# xfstests is assessed separately (docs/FUSE-SEMANTICS.md); its blocker is
# recorded in evidence/correctness/posix-results.json.
set -eu
. "$(dirname "$0")/lib.sh"

docker_run_posix sh scripts/posix/pjdfstest.sh
