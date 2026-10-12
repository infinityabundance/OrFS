#!/bin/sh
# The reproducible automated gate.
#
# One entry point for the cheap, deterministic gates, so a CI job (or a human)
# can run exactly what the project checks before a change is accepted:
#
#   1. `cargo fmt -p orfs --check` + `cargo clippy --all-targets -- -D warnings`
#      inside the pinned container (`container-check.sh`).
#   2. The docs <-> evidence receipts check (`check-docs-receipts.sh`, host-side;
#      it needs only POSIX `sh`, `git`, and `python3`).
#   3. The full test suite inside the pinned container (`container-test.sh`) —
#      skipped with `--fast`.
#
# The mounted FUSE and io_uring courts (`container-fuse-test.sh`,
# `container-uring-test.sh`, `container-posix-test.sh`) are deliberately NOT run
# here: they need `/dev/fuse`, `CAP_SYS_ADMIN` and an unconfined seccomp profile,
# which a hosted CI runner generally cannot grant. Run them explicitly. See
# `docs/RECEIPTS.md`.
#
# One container runs at a time (the helpers guarantee this).
#
# Usage:
#   sh scripts/check-all.sh          # fmt/lint + docs-receipts + full test suite
#   sh scripts/check-all.sh --fast   # fmt/lint + docs-receipts only
set -eu
DIR="$(dirname "$0")"

hdr() { printf '\n=== %s ===\n' "$1"; }

hdr "fmt + clippy (pinned container)"
sh "$DIR/container-check.sh"

hdr "docs <-> evidence receipts (host)"
sh "$DIR/check-docs-receipts.sh"

if [ "${1:-}" = "--fast" ]; then
    hdr "OK (fast: full test suite skipped)"
    exit 0
fi

hdr "full test suite (pinned container)"
sh "$DIR/container-test.sh"

hdr "OK"
