#!/bin/sh
# Phase 85 — crypto-erasure court runner.
#
# OrFS is non-withdrawal: `unlink`/`rmdir`/`truncate`/overwrite never physically
# remove authoritative history (`docs/RETENTION.md`). A "secure delete" promise
# therefore needs a *cryptographic* mechanism: seal content under a key and
# destroy the key, leaving the ciphertext bytes in place — unwithdrawn — but
# unreadable (`docs/ERASURE.md`).
#
# `tests/crypto_erasure.rs` drives a **dedicated encrypted volume** end to end
# through the real `orfs` binary: init -> append -> read -> rotate -> destroy ->
# prove the destroyed epoch's content is cryptographically inaccessible while
# the ciphertext bytes are unchanged, the surviving epoch still reads
# identically, a relocated (tiered) ciphertext copy is covered too, no key
# material reaches the authoritative area, and the default (unencrypted) path is
# untouched.
#
# Two bounded stages, one container at a time:
#   1. the always-on smoke (default `cargo test` build), then
#   2. the release sweep which writes the receipt.
#
# Set ORFS_CRYPTO_ERASURE=0 to run the smoke only.
#
# Usage:
#   sh scripts/container-crypto-erasure.sh
#   ORFS_CRYPTO_ERASURE=0 sh scripts/container-crypto-erasure.sh
#
# One container runs at a time (`scripts/lib.sh`: 8 GiB, 2048 pids).
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== phase 85: crypto-erasure (bounded smoke) ==="
docker_run cargo test -p orfs --test crypto_erasure crypto_erasure_smoke

if [ "${ORFS_CRYPTO_ERASURE:-1}" = "0" ]; then
    echo "=== sweep skipped (ORFS_CRYPTO_ERASURE=0) ==="
    echo "evidence: evidence/security/crypto-erasure.json (unchanged)"
    exit 0
fi

echo "=== phase 85: crypto-erasure (release sweep, writes the receipt) ==="
GIT_COMMIT="$(git -C "$ORFS_PROJECT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
docker_run sh -c "
    set -eu
    ORFS_CRYPTO_ERASURE=1 \
    ORFS_GIT_COMMIT=$GIT_COMMIT \
        cargo test --release -p orfs --test crypto_erasure crypto_erasure_sweep \
            -- --exact --nocapture --test-threads=1
"
echo "evidence: evidence/security/crypto-erasure.json"
