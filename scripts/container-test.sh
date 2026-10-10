#!/bin/sh
# Run the OrFS test suite inside the pinned container.
# Usage: scripts/container-test.sh [cargo test args...]
set -eu
. "$(dirname "$0")/lib.sh"
docker_run cargo test "$@"
