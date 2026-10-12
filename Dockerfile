# OrFS build/test image.
#
# Derived from the official Docker Hub Rust slim image, pinned by digest.
# The digest below is the multi-arch image index digest for
#   rust:1.99.0-slim-bookworm
# resolved with `docker buildx imagetools inspect` on 2026-10-10.
# The linux/amd64 manifest digest resolved from that index is recorded in
# evidence/receipts/container.json.
#
# Keep the FROM digest in sync with scripts/lib.sh:ORFS_BASE_IMAGE.
#
# Build:  scripts/container-image-build.sh
# Run:    scripts/container-build.sh / container-test.sh / container-check.sh
FROM rust:1.99.0-slim-bookworm@sha256:2c3a22f0a5533ea2dd5a16627bc841228151faa2d4de2644ac9987e4a2f1f2fa

# Minimal tooling: the slim image already ships cc/ld for linking. We add only
# what the build/test workflow needs, plus `git` (used by tooling such as the
# provenance receipts; the EKBLOOM dependency now comes from crates.io) and the
# rustfmt/clippy components (which the base image omits).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
        file \
        git \
        valgrind \
    ; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    rustup component add rustfmt clippy; \
    rustc --version; \
    cargo fmt --version; \
    cargo clippy --version

ENV CARGO_TERM_COLOR=never \
    RUSTFLAGS=""

WORKDIR /work

CMD ["cargo", "build", "--release"]
