#!/bin/bash

# τ-Gate Global Installer
# This script builds the τ-Gate and links it to /usr/local/bin

set -e

echo "[τ-Gate] Starting global installation..."

# 1. Build the release binary
echo "[τ-Gate] Building optimized Rust binary (Release)..."
cargo build --release

# 2. Determine target path
BINARY_PATH="$(pwd)/target/release/tau-gate"
TARGET_PATH="/usr/local/bin/tau-gate"

# 3. Create symlink (requires sudo)
echo "[τ-Gate] Creating global symlink at $TARGET_PATH..."
echo "[τ-Gate] This may require your administrator password."
sudo ln -sf "$BINARY_PATH" "$TARGET_PATH"

echo ""
echo "✅ Installation Complete!"
echo "You can now run 'tau-gate' from any directory."
echo ""
echo "Supported Runtimes:"
echo " - npm (package-lock.json)"
echo " - pnpm (pnpm-lock.yaml v6-v9)"
echo " - Bun (bun.lockb / bun.lock)"
echo " - Yarn Berry (yarn.lock v2+)"
echo ""
echo "Usage Example:"
echo "  cd your-node-project"
echo "  tau-gate"
