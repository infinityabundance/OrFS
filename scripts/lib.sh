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

# Absolute paths. The OrFS project consumes EKBLOOM as a rev-pinned git
# dependency on the public GitHub repository (see docs/LIMITATIONS.md §1).
#
# Resolve the project directory from the *invoking script's own location*, never
# from the current working directory alone, so every script works no matter what
# cwd it is launched from. `$0` is the path of the top-level script that sourced
# this file (`sh scripts/foo.sh`), because POSIX `.`/`source` preserves `$0`; when
# this file is sourced interactively, `$0` is the shell name and the search
# falls through to `$PWD`. A candidate wins only if it actually contains
# `Cargo.toml`; if none does, we fail loudly instead of silently operating on the
# wrong tree.
_orfs_is_project() { [ -n "$1" ] && [ -f "$1/Cargo.toml" ]; }

# Honor an explicit override only when it really points at the project.
if [ -n "${ORFS_PROJECT_DIR:-}" ] && ! _orfs_is_project "$ORFS_PROJECT_DIR"; then
    ORFS_PROJECT_DIR=""
fi

if [ -z "${ORFS_PROJECT_DIR:-}" ]; then
    _orfs_script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || true)"
    for _orfs_cand in "$_orfs_script_dir/.." "$_orfs_script_dir" "$(pwd)"; do
        if _orfs_is_project "$_orfs_cand"; then
            ORFS_PROJECT_DIR="$(CDPATH= cd -- "$_orfs_cand" && pwd)"
            break
        fi
    done
    unset _orfs_script_dir _orfs_cand
fi

if ! _orfs_is_project "${ORFS_PROJECT_DIR:-}"; then
    echo "orfs: fatal: cannot locate the OrFS project root — no Cargo.toml near \$0='$0' or \$PWD='$(pwd)'." >&2
    echo "orfs: set ORFS_PROJECT_DIR to the directory containing Cargo.toml." >&2
    exit 1
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
# Scratch for the toolchain (rustc/cc intermediate files) lives on the project's
# bind-mounted drive, not the container's RAM-backed writable layer. On this host
# Docker's data-root is a tmpfs; keeping TMPDIR off it prevents transient ENOSPC
# when several builds share the machine. See docs/LIMITATIONS.md.
ORFS_TMP_DIR="$ORFS_TARGET_DIR/.tmp"

mkdir -p "$ORFS_PROJECT_DIR/.cargo-home" "$ORFS_TARGET_DIR" "$ORFS_TMP_DIR"

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
        -e TMPDIR="$ORFS_TMP_DIR" \
        -e CARGO_HOME="$ORFS_CARGO_HOME" \
        -e RUSTUP_HOME=/usr/local/rustup \
        -e CARGO_TARGET_DIR="$ORFS_TARGET_DIR" \
        -e CARGO_TERM_COLOR=never \
        -e RUSTUP_TOOLCHAIN=1.99.0 \
        "$ORFS_IMAGE" "$@"
}

# docker_run_uring: identical to docker_run but with an unconfined seccomp
# profile. PROVEN NECESSARY, NOT ASSUMED: on this host the default Docker seccomp
# profile blocks `io_uring_setup` with EPERM, while `--security-opt
# seccomp=unconfined` permits it (see scripts/container-uring-test.sh, which
# re-proves this at run time with scripts/uring-probe.c).
docker_run_uring() {
    exec docker run --rm \
        --memory="$ORFS_MEM_LIMIT" \
        --memory-swap="$ORFS_MEMSWAP_LIMIT" \
        --cpus="$ORFS_CPUS" \
        --pids-limit="$ORFS_PIDS" \
        --ulimit core=0 \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        --security-opt seccomp=unconfined \
        -v "$ORFS_PARENT_DIR":"$ORFS_PARENT_DIR" \
        -w "$ORFS_PROJECT_DIR" \
        -u "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        -e TMPDIR="$ORFS_TMP_DIR" \
        -e CARGO_HOME="$ORFS_CARGO_HOME" \
        -e RUSTUP_HOME=/usr/local/rustup \
        -e CARGO_TARGET_DIR="$ORFS_TARGET_DIR" \
        -e CARGO_TERM_COLOR=never \
        -e RUSTUP_TOOLCHAIN=1.99.0 \
        "$ORFS_IMAGE" "$@"
}

# docker_probe_io_uring_default: returns 0 when the DEFAULT seccomp profile
# permits io_uring_setup (the probe compiles and runs scripts/uring-probe.c under
# the exact default flags). Does not `exec`, so it can be used as a test.
docker_probe_io_uring_default() {
    docker run --rm \
        --memory="$ORFS_MEM_LIMIT" \
        --cpus="$ORFS_CPUS" \
        --pids-limit="$ORFS_PIDS" \
        --ulimit core=0 \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        -v "$ORFS_PARENT_DIR":"$ORFS_PARENT_DIR" \
        -w "$ORFS_PROJECT_DIR" \
        -u "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        "$ORFS_IMAGE" sh -c 'cc scripts/uring-probe.c -o /tmp/orfs-uring-probe && /tmp/orfs-uring-probe' \
        >/dev/null 2>&1
}

# docker_run_kmount: for tests that must actually mount FUSE. Adds only the
# device access, capabilities, and (where required) unconfined AppArmor profile
# that the FUSE mount tests demonstrably need. Never used by default.
#
# Because the container runs as the (non-root) host uid, mounting goes through
# the setuid `fusermount3` helper. `fusermount3` resolves the invoking uid with
# `getpwuid`; minimal images ship no entry for that uid, so we bind a generated
# `/etc/passwd` (root + the current uid) read-only. Without it, mounting fails
# with "fusermount3: could not determine username".
docker_run_kmount() {
    ORFS_KMOUNT_PASSWD="$ORFS_PROJECT_DIR/target/.kmount-passwd"
    if [ ! -f "$ORFS_KMOUNT_PASSWD" ]; then
        printf 'root:x:0:0:root:/root:/bin/sh\norfs:x:%s:%s:OrFS:/tmp:/bin/sh\n' \
            "$(id -u)" "$(id -g)" > "$ORFS_KMOUNT_PASSWD"
    fi
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
        -v "$ORFS_KMOUNT_PASSWD:/etc/passwd:ro" \
        -w "$ORFS_PROJECT_DIR" \
        -u "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        -e TMPDIR="$ORFS_TMP_DIR" \
        -e CARGO_HOME="$ORFS_CARGO_HOME" \
        -e RUSTUP_HOME=/usr/local/rustup \
        -e CARGO_TARGET_DIR="$ORFS_TARGET_DIR" \
        -e CARGO_TERM_COLOR=never \
        -e RUSTUP_TOOLCHAIN=1.99.0 \
        "$ORFS_KMOUNT_IMAGE" "$@"
}
