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

# --- ekbloom.json (dependency fingerprint) ---------------------------------
EK_DIR="$ORFS_PARENT_DIR/EKBLOOM"
EK_VER="$(sed -n 's/^version = "\(.*\)"/\1/p' "$EK_DIR/Cargo.toml" | head -n1)"
EK_FP="$(cat "$EK_DIR"/src/*.rs 2>/dev/null | sha256sum | cut -d' ' -f1)"
{
  printf '{\n'
  printf '  "crate": "ekbloom",\n'
  printf '  "version": "%s",\n' "$EK_VER"
  printf '  "source_path": "%s",\n' "$EK_DIR"
  printf '  "source_fingerprint_sha256": "%s",\n' "$EK_FP"
  printf '  "consumed_as": "path dependency with version pin =0.3.0",\n'
  printf '  "copied_into_orfs": false\n'
  printf '}\n'
} > "$R/ekbloom.json"

echo "wrote host-side receipts to $R"
