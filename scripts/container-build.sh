#!/bin/sh
# Build OrFS inside the pinned container.
# Usage: scripts/container-build.sh [cargo build args...]
set -eu
. "$(dirname "$0")/lib.sh"
docker_run cargo build "$@"
