#!/bin/sh
# Shared container settings for OrFS. Sourced by the other scripts.
#
# HARD RULE: project tooling (compilation, tests, fuzzers, benchmarks, mount
# experiments) runs ONLY inside these containers, never directly on the host.
#
# The host kernel is still used by containerized FUSE/io_uring; this workflow
# does not provide kernel isolation. See docs/LIMITATIONS.md.
set -eu

# Official Docker Hub Rust slim image, pinned by digest (multi-arch index).
# The derived OrFS images below are built FROM this base; keep the Dockerfile
# FROM digests in sync with this value.
ORFS_BASE_IMAGE="rust:1.99.0-slim-bookworm@sha256:2c3a22f0a5533ea2dd5a16627bc841228151faa2d4de2644ac9987e4a2f1f2fa"

# Derived images (built by scripts/container-image-build.sh from the Dockerfiles).
ORFS_IMAGE="${ORFS_IMAGE:-orfs-build:1.99.0}"
ORFS_KMOUNT_IMAGE="${ORFS_KMOUNT_IMAGE:-orfs-kmount:1.99.0}"

# Absolute paths. The OrFS project consumes the sibling EKBLOOM crate as a path
# dependency ($ORFS_PARENT/EKBLOOM), so the parent directory must be mounted at
# the SAME path inside the container for `../EKBLOOM` to resolve identically.
ORFS_PROJECT_DIR="$(cd "$(dirname "$0 2>/dev/null || echo .")/.." 2>/dev/null && pwd || pwd)"
# When lib.sh is sourced from an interactive shell, $0 may be the shell name;
# fall back to the current directory if the computed path is not the project.
if [ ! -f "$ORFS_PROJECT_DIR/Cargo.toml" ]; then
    ORFS_PROJECT_DIR="$(pwd)"
fi
ORFS_PARENT_DIR="$(cd "$ORFS_PROJECT_DIR/.." && pwd)"

# OOM protection: cap memory and swap so a runaway allocation cannot exhaust the
# host. One container runs at a time.
ORFS_MEM_LIMIT="${ORFS_MEM_LIMIT:-8g}"
ORFS_MEMSWAP_LIMIT="${ORFS_MEMSWAP_LIMIT:-8g}"
ORFS_CPUS="${ORFS_CPUS:-8}"
ORFS_PIDS="${ORFS_PIDS:-2048}"

# Cargo caches under the project (gitignored) persist between runs. Because the
# project is bind-mounted at the same absolute path inside the container, these
# resolve identically on host and container.
ORFS_CARGO_HOME="$ORFS_PROJECT_DIR/.cargo-home"
ORFS_TARGET_DIR="$ORFS_PROJECT_DIR/target"

mkdir -p "$ORFS_PROJECT_DIR/.cargo-home" "$ORFS_PROJECT_DIR/target"

# docker_run: unprivileged, memory/pid-capped, source tree bind-mounted read-write.
docker_run() {
    exec docker run --rm \
        --memory="$ORFS_MEM_LIMIT" \
        --memory-swap="$ORFS_MEMSWAP_LIMIT" \
        --cpus="$ORFS_CPUS" \
        --pids-limit="$ORFS_PIDS" \
        --ulimit core=0 \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        -v "$ORFS_PARENT_DIR":"$ORFS_PARENT_DIR" \
        -w "$ORFS_PROJECT_DIR" \
        -u "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        -e CARGO_HOME="$ORFS_CARGO_HOME" \
        -e RUSTUP_HOME=/usr/local/rustup \
        -e CARGO_TARGET_DIR="$ORFS_TARGET_DIR" \
        -e CARGO_TERM_COLOR=never \
        -e RUSTUP_TOOLCHAIN=1.99.0 \
        "$ORFS_IMAGE" "$@"
}

# docker_run_kmount: for tests that must actually mount FUSE. Adds only the
# device access, capabilities, and (where required) unconfined AppArmor profile
# that the FUSE mount tests demonstrably need. Never used by default.
docker_run_kmount() {
    exec docker run --rm \
        --memory="$ORFS_MEM_LIMIT" \
        --memory-swap="$ORFS_MEMSWAP_LIMIT" \
        --cpus="$ORFS_CPUS" \
        --pids-limit="$ORFS_PIDS" \
        --device /dev/fuse \
        --cap-add SYS_ADMIN \
        --security-opt apparmor=unconfined \
        --security-opt seccomp=unconfined \
        --ulimit core=0 \
        -v "$ORFS_PARENT_DIR":"$ORFS_PARENT_DIR" \
        -w "$ORFS_PROJECT_DIR" \
        -u "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        -e CARGO_HOME="$ORFS_CARGO_HOME" \
        -e RUSTUP_HOME=/usr/local/rustup \
        -e CARGO_TARGET_DIR="$ORFS_TARGET_DIR" \
        -e CARGO_TERM_COLOR=never \
        -e RUSTUP_TOOLCHAIN=1.99.0 \
        "$ORFS_KMOUNT_IMAGE" "$@"
}
