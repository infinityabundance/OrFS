#!/bin/sh
# Docs-from-receipts check.
#
# HOST-side check: it does NOT use Docker or cargo. It verifies that
#   (a) evidence provenance receipts (evidence/receipts/*.json) are not stale
#       relative to the repository, and
#   (b) the numbers quoted by a curated set of doc citations still match the
#       machine-generated evidence under evidence/.
#
# It only detects and reports drift: it never rewrites a receipt or a document.
# Exits 0 when everything matches, non-zero (with an itemised report) otherwise.
#
# Usage:
#   sh scripts/check-docs-receipts.sh
#   sh scripts/check-docs-receipts.sh --json
#
# The mapping (allowlist + covered citations) lives in scripts/docs-receipts.json.
# See docs/RECEIPTS.md for the scheme, coverage and how to add a citation.
set -eu
. "$(dirname "$0")/lib.sh"

if ! command -v python3 >/dev/null 2>&1; then
    echo "orfs: check-docs-receipts: python3 is required but was not found on PATH" >&2
    exit 2
fi

exec python3 "$ORFS_PROJECT_DIR/scripts/docs_receipts.py" \
    --root "$ORFS_PROJECT_DIR" \
    --config "$ORFS_PROJECT_DIR/scripts/docs-receipts.json" "$@"
