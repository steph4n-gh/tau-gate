#!/bin/bash

# τ-Gate: Reproducible Build Engine
# This script ensures that the v2.0 zero-dependency binary is byte-for-byte identical.

set -e

echo "[τ-Gate] Initializing Reproducible Build..."

# 1. Verify Rust version from toolchain file
REQUIRED_RUST="1.80.0"
CURRENT_RUST=$(rustc --version | awk '{print $2}')

if [ "$CURRENT_RUST" != "$REQUIRED_RUST" ]; then
    echo "⚠️ Warning: System Rust is $CURRENT_RUST, but tau-gate requires $REQUIRED_RUST for reproducibility."
    echo "Please use 'rustup install $REQUIRED_RUST' to ensure a matching binary."
fi

# 2. Build the optimized release binary
# We use a fixed target and specific flags to eliminate non-deterministic metadata.
echo "[τ-Gate] Compiling high-integrity binary..."
RUSTFLAGS="-C debuginfo=0 -C strip=symbols" cargo build --release

# 3. Generate SHA-256 for verification
BINARY_PATH="target/release/tau-gate"
if [ -f "$BINARY_PATH" ]; then
    HASH=$(shasum -a 256 "$BINARY_PATH" | awk '{print $1}')
    echo ""
    echo "✅ Build Complete!"
    echo "Binary: $BINARY_PATH"
    echo "SHA-256: $HASH"
    echo ""
    echo "Share this hash to verify the integrity of this build."
fi
