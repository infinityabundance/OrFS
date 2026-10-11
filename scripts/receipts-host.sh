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

# --- ekbloom.json (rev-pinned dependency, public GitHub) -------------------
# The pin is parsed from Cargo.toml so the receipt always reflects the manifest
# rather than a mutable sibling working tree.
EK_DEP_LINE="$(sed -n 's/^ekbloom *= *//p' "$ORFS_PROJECT_DIR/Cargo.toml" | head -n1)"
EK_URL="$(printf '%s' "$EK_DEP_LINE" | sed -n 's/.*git *= *"\([^"]*\)".*/\1/p')"
EK_REV="$(printf '%s' "$EK_DEP_LINE" | sed -n 's/.*rev *= *"\([^"]*\)".*/\1/p')"
EK_VER="$(printf '%s' "$EK_DEP_LINE" | sed -n 's/.*version *= *"=\([^"]*\)".*/\1/p')"
EK_SHORT="$(printf '%s' "$EK_REV" | cut -c1-7)"
{
  printf '{\n'
  printf '  "schema": "orfs.evidence.ekbloom-pin.v1",\n'
  printf '  "captured_at_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "crate": "ekbloom",\n'
  printf '  "version": "%s",\n' "$EK_VER"
  printf '  "pin_kind": "git-rev-public",\n'
  printf '  "git_url": "%s",\n' "$EK_URL"
  printf '  "rev": "%s",\n' "$EK_REV"
  printf '  "rev_short": "%s",\n' "$EK_SHORT"
  printf '  "resolved_source": "git+%s?rev=%s#%s",\n' "$EK_URL" "$EK_REV" "$EK_REV"
  printf '  "cargo_dependency": "ekbloom = { git = \\"%s\\", rev = \\"%s\\", version = \\"=%s\\" }",\n' "$EK_URL" "$EK_REV" "$EK_VER"
  printf '  "version_pin_in_manifest": "%s",\n' "$EK_VER"
  printf '  "copied_into_orfs": false,\n'
  printf '  "reproducible_from_clean_checkout": true,\n'
  printf '  "why": "EKBLOOM is developed concurrently and independently; pinning to an immutable commit on the public origin/main makes every clean OrFS checkout build without any sibling working tree.",\n'
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
  printf '  "ekbloom_pin_rev": "%s",\n' "$EK_REV"
  printf '  "ekbloom_pin_url": "%s",\n' "$EK_URL"
  printf '  "ekbloom_pin_version": "%s"\n' "$EK_VER"
  printf '}\n'
} > "$R/source-commit.json"

echo "wrote host-side receipts to $R"
