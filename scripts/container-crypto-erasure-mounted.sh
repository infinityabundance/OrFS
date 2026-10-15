#!/bin/sh
# Phase 86 — *mounted* crypto-erasure court runner.
#
# OrFS is non-withdrawal (`docs/RETENTION.md`): `unlink`/`rmdir`/`truncate`/
# overwrite never physically remove authoritative history. Secure deletion is
# therefore **cryptographic**: the authoritative store is sealed under a key and
# the key is destroyed, leaving the ciphertext bytes in place — unwithdrawn — but
# unreadable (`docs/ERASURE.md`).
#
# Phase 85 sealed the store in *frames* and could not serve it through FUSE.
# Phase 86 replaces that with a **length-preserving, per-segment positional
# keystream** applied at the `Segment`/`ReadAt` I/O seam, so the encrypted store
# *is* a real OrFS log and `orfs mount --key-file` serves it through the ordinary
# namespace/index/FUSE path.
#
# `tests/crypto_erasure_mounted.rs` proves that end to end **with a real
# `orfs mount`** (a spawned `orfs mount ... --key-file ...` child, driven through
# POSIX syscalls, then `orfs unmount`): mounted byte-identity vs an unencrypted
# volume; ciphertext on disk; retained ciphertext across epoch-key destruction;
# fail-closed mounts (no key / wrong key / after destruction); tier relocation
# preserves crypto-erasure; a forced rollover spans >1 segment; and the default
# unencrypted path is byte-identical. It writes
# `evidence/security/crypto-erasure-mounted.json`.
#
# Mounting requires /dev/fuse + CAP_SYS_ADMIN, so it runs under
# `docker_run_kmount` (one container at a time; the ordinary project uid).
# Every mount attempt inside the court is bounded and the whole stage is bounded
# by `timeout`.
#
# Two stages, one container at a time:
#   1. the always-on compile + skip smoke (default `cargo test` build), then
#   2. the real mount (writes the receipt).
#
# Set ORFS_CRYPTO_ERASURE_MOUNTED=0 to run the smoke only.
#
# Usage:
#   sh scripts/container-crypto-erasure-mounted.sh
#   ORFS_CRYPTO_ERASURE_MOUNTED=0 sh scripts/container-crypto-erasure-mounted.sh
#
# One container runs at a time (`scripts/lib.sh`: 8 GiB, 2048 pids).
set -eu
. "$(dirname "$0")/lib.sh"

echo "=== phase 86: mounted crypto-erasure (compile + skip smoke) ==="
docker_run cargo test -p orfs --test crypto_erasure_mounted

if [ "${ORFS_CRYPTO_ERASURE_MOUNTED:-1}" = "0" ]; then
    echo "=== mounted sweep skipped (ORFS_CRYPTO_ERASURE_MOUNTED=0) ==="
    echo "evidence: evidence/security/crypto-erasure-mounted.json (unchanged)"
    exit 0
fi

echo "=== phase 86: mounted crypto-erasure (real orfs mount; writes the receipt) ==="
GIT_COMMIT="$(git -C "$ORFS_PROJECT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
docker_run_kmount sh -c '
    set -eu
    ORFS_FUSE_TEST=1 \
    ORFS_GIT_COMMIT='"$GIT_COMMIT"' \
    CARGO_TARGET_DIR="$(pwd)/target/kmount-crypto-erasure" \
        timeout -k 10 1200 cargo test --test crypto_erasure_mounted \
            -- --exact --nocapture --test-threads=1
'
echo "evidence: evidence/security/crypto-erasure-mounted.json"
