#!/bin/sh
# Reproduce: clean-build and test from scratch inside the pinned container.
set -eu
. "$(dirname "$0")/lib.sh"
docker_run sh -c 'cargo build --release && cargo test --release'
