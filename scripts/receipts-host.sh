#!/bin/sh
# Capture host-side execution receipts (read-only inspection only).
# Writes evidence/receipts/{environment,container,source-commit,ekbloom}.json
set -eu
. "$(dirname "$0")/lib.sh"
R="$ORFS_PROJECT_DIR/evidence/receipts"
mkdir -p "$R"

kcfg() { zgrep -E "^$1=" /proc/config.gz 2>/dev/null | head -n1 || true; }

# --- environment.json ------------------------------------------------------
{
  printf '{\n'
  printf '  "captured_at_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "orfs_version": "%s",\n' "$(sed -n 's/^version = "\(.*\)"/\1/p' "$ORFS_PROJECT_DIR/Cargo.toml" | head -n1)"
  printf '  "host_kernel": "%s",\n' "$(uname -r)"
  printf '  "host_machine": "%s",\n' "$(uname -m)"
  printf '  "host_nproc": %s,\n' "$(nproc)"
  printf '  "host_mem_total_kib": %s,\n' "$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
  printf '  "dev_fuse_present": %s,\n' "$(test -c /dev/fuse && echo true || echo false)"
  printf '  "io_uring_disabled": "%s",\n' "$(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo unknown)"
  printf '  "kernel_config": {\n'
  printf '    "CONFIG_FUSE_FS": "%s",\n' "$(kcfg CONFIG_FUSE_FS)"
  printf '    "CONFIG_FUSE_DAX": "%s",\n' "$(kcfg CONFIG_FUSE_DAX)"
  printf '    "CONFIG_FUSE_PASSTHROUGH": "%s",\n' "$(kcfg CONFIG_FUSE_PASSTHROUGH)"
  printf '    "CONFIG_FUSE_IO_URING": "%s",\n' "$(kcfg CONFIG_FUSE_IO_URING)"
  printf '    "CONFIG_IO_URING": "%s",\n' "$(kcfg CONFIG_IO_URING)"
  printf '    "CONFIG_IO_URING_ZCRX": "%s"\n' "$(kcfg CONFIG_IO_URING_ZCRX)"
  printf '  },\n'
  printf '  "docker_version": "%s"\n' "$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
  printf '}\n'
} > "$R/environment.json"

# --- container.json --------------------------------------------------------
BUILD_ID="$(docker image inspect -f '{{.Id}}' "$ORFS_IMAGE" 2>/dev/null || echo unknown)"
KMOUNT_ID="$(docker image inspect -f '{{.Id}}' "$ORFS_KMOUNT_IMAGE" 2>/dev/null || echo unknown)"
{
  printf '{\n'
  printf '  "captured_at_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "base_image": "%s",\n' "$ORFS_BASE_IMAGE"
  printf '  "base_image_index_digest": "sha256:2c3a22f0a5533ea2dd5a16627bc841228151faa2d4de2644ac9987e4a2f1f2fa",\n'
  printf '  "base_image_amd64_manifest_digest": "sha256:ba81bc3eaa4422af576c0262515d96b0111a628a6ccc2c86557cf55c9a4bbee0",\n'
  printf '  "base_image_debian_base_digest": "sha256:a4672c0cb26fbdde88e38fa2dfb6c681942306680e41e4378b28770b6e79ee91",\n'
  printf '  "build_image": "%s",\n' "$ORFS_IMAGE"
  printf '  "build_image_id": "%s",\n' "$BUILD_ID"
  printf '  "kmount_image": "%s",\n' "$ORFS_KMOUNT_IMAGE"
  printf '  "kmount_image_id": "%s",\n' "$KMOUNT_ID"
  printf '  "mem_limit": "%s",\n' "$ORFS_MEM_LIMIT"
  printf '  "memswap_limit": "%s",\n' "$ORFS_MEMSWAP_LIMIT"
  printf '  "cpus": "%s",\n' "$ORFS_CPUS"
  printf '  "pids_limit": "%s"\n' "$ORFS_PIDS"
  printf '}\n'
} > "$R/container.json"

# --- ekbloom.json (exact-version registry dependency) ----------------------
# Parsed from Cargo.toml so the receipt reflects the manifest, never a mutable
# sibling tree. Phase 35 moved EKBLOOM from a rev-pinned git dependency to the
# published crates.io release, so the pin is now `registry-exact`: the exact
# version plus the resolved checksum recorded in Cargo.lock.
EK_DEP_LINE="$(sed -n 's/^ekbloom *= *//p' "$ORFS_PROJECT_DIR/Cargo.toml" | head -n1)"
EK_VER="$(printf '%s' "$EK_DEP_LINE" | sed -n 's/^"=\([^"]*\)"$/\1/p')"
# The lockfile is the authoritative record of the resolved source + checksum.
EK_CHECKSUM="$(awk -F'"' '/name = "ekbloom"/{f=1} f&&/checksum/{print $2; exit}' "$ORFS_PROJECT_DIR/Cargo.lock")"
EK_PREV_REV="708c349128668bf26b50684ce473d8de4058dc31"
{
  printf '{\n'
  printf '  "schema": "orfs.evidence.ekbloom-pin.v2",\n'
  printf '  "captured_at_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "crate": "ekbloom",\n'
  printf '  "version": "%s",\n' "$EK_VER"
  printf '  "pin_kind": "registry-exact",\n'
  printf '  "registry": "https://github.com/rust-lang/crates.io-index",\n'
  printf '  "checksum": "sha256:%s",\n' "$EK_CHECKSUM"
  printf '  "checksum_sha256": "%s",\n' "$EK_CHECKSUM"
  printf '  "resolved_source": "registry+https://github.com/rust-lang/crates.io-index",\n'
  printf '  "cargo_dependency": "ekbloom = \\"=%s\\"",\n' "$EK_VER"
  printf '  "previous_git_pin": { "url": "https://github.com/infinityabundance/EKBLOOM", "rev": "%s", "note": "replaced in Phase 35 because crates.io rejects git dependencies; the published 0.3.0 is newer than this revision" },\n' "$EK_PREV_REV"
  printf '  "copied_into_orfs": false,\n'
  printf '  "reproducible_from_clean_checkout": true,\n'
  printf '  "why": "EKBLOOM is developed concurrently and independently; consuming the exact published crates.io release makes every clean OrFS checkout build with no sibling working tree, and is the only form crates.io accepts for publishing OrFS.",\n'
  printf '  "public_items_orfs_depends_on": [\n'
  printf '    "ManifestationProfile", "create", "write_body", "inspect", "EkbloomBody",\n'
  printf '    "verify", "VerificationReport", "machine_by_id", "MACHINE_NL2", "History",\n'
  printf '    "CheckpointSet", "Snapshot", "OrMachine", "NL2", "EkbloomError",\n'
  printf '    "bloom::{BloomKind, Certification, Outcome}", "bloom_global::GlobalBloom",\n'
  printf '    "bloom_path::PathBloom", "bloom_region::RegionTable", "checkpoint::CheckpointSet",\n'
  printf '    "reader::open_bytes", "format::FORMAT_MAJOR", "format::FORMAT_MINOR"\n'
  printf '  ]\n'
  printf '}\n'
} > "$R/ekbloom.json"

# --- source-commit.json (source provenance) --------------------------------
SRC_COMMIT="$(git -C "$ORFS_PROJECT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
SRC_SHORT="$(git -C "$ORFS_PROJECT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
SRC_BRANCH="$(git -C "$ORFS_PROJECT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
# Dirtiness of the *source* tree: ignore the receipt directory being regenerated
# (otherwise this script would always report itself as making the tree dirty).
if [ -n "$(git -C "$ORFS_PROJECT_DIR" status --porcelain -- ':!evidence/receipts' 2>/dev/null)" ]; then SRC_DIRTY=true; else SRC_DIRTY=false; fi
{
  printf '{\n'
  printf '  "schema": "orfs.evidence.source-commit.v1",\n'
  printf '  "captured_at_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "orfs_git_commit": "%s",\n' "$SRC_COMMIT"
  printf '  "orfs_git_commit_short": "%s",\n' "$SRC_SHORT"
  printf '  "orfs_git_branch": "%s",\n' "$SRC_BRANCH"
  printf '  "orfs_worktree_dirty": %s,\n' "$SRC_DIRTY"
  printf '  "ekbloom_pin_kind": "registry-exact",\n'
  printf '  "ekbloom_version": "%s",\n' "$EK_VER"
  printf '  "ekbloom_checksum_sha256": "%s",\n' "$EK_CHECKSUM"
  printf '  "ekbloom_repository": "https://github.com/infinityabundance/EKBLOOM"\n'
  printf '}\n'
} > "$R/source-commit.json"

echo "wrote host-side receipts to $R"
