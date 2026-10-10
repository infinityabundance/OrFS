#!/bin/sh
# clippy + fmt check inside the pinned container.
#
# Scope the fmt check to the OrFS package (`-p orfs`). `cargo fmt --all` also
# formats local path-based dependencies, which here means the sibling EKBLOOM
# crate. EKBLOOM is an independently versioned dependency that OrFS must not
# modify, so gating OrFS's build on EKBLOOM's formatting would be a false
# failure (and would reach outside this repository).
set -eu
. "$(dirname "$0")/lib.sh"
docker_run sh -c 'cargo fmt -p orfs --check && cargo clippy --all-targets -- -D warnings'
