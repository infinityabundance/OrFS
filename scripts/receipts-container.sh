#!/bin/sh
# Capture container-side receipts. Run via: docker_run sh scripts/receipts-container.sh
# Writes evidence/receipts/toolchain.json and evidence/receipts/doctor.json
set -eu
# The container's working directory is the OrFS project root.
R="${ORFS_PROJECT_DIR:-$(pwd)}/evidence/receipts"
mkdir -p "$R"

# --- toolchain.json --------------------------------------------------------
RUSTC="$(rustc --version)"
CARGO="$(cargo --version)"
RUSTFMT="$(cargo fmt --version 2>/dev/null || echo absent)"
CLIPPY="$(cargo clippy --version 2>/dev/null || echo absent)"
DEP_TREE="$(cargo tree --depth 1 --edges normal 2>/dev/null | tail -n +2 || echo unavailable)"

cat > "$R/toolchain.json" <<EOF
{
  "captured_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rustc": "$RUSTC",
  "cargo": "$CARGO",
  "rustfmt": "$RUSTFMT",
  "clippy": "$CLIPPY",
  "toolchain": "1.99.0",
  "direct_dependencies": [$(printf '%s\n' "$DEP_TREE" | sed 's/^[^a-zA-Z0-9]*//' | awk '{printf "%s\"%s\"", (NR>1?",":""), $1}')]
}
EOF

# --- doctor.json -----------------------------------------------------------
cargo build --quiet 2>/dev/null || cargo build --quiet
./target/debug/orfs --json doctor > "$R/doctor.json" 2>/dev/null || \
    cargo run --quiet -- --json doctor > "$R/doctor.json"

echo "wrote container-side receipts to $R"
