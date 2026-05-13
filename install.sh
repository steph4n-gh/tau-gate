#!/bin/bash

# τ-Gate: Global Installer & Bootstrapper
# This script handles both local and remote installation.

set -e

# Setup Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}[τ-Gate] Initializing Global Installation...${NC}"

# 1. Detect Environment
if [ -f "Cargo.toml" ] && grep -q 'name = "tau-gate"' "Cargo.toml"; then
    echo "[τ-Gate] Detected source tree. Building locally..."
    INSTALL_DIR=$(pwd)
else
    echo "[τ-Gate] Running as standalone installer. Cloning source to /tmp..."
    TEMP_DIR=$(mktemp -d)
    git clone --depth 1 https://github.com/steph4n-gh/tau-gate.git "$TEMP_DIR"
    INSTALL_DIR="$TEMP_DIR"
    cd "$INSTALL_DIR"
fi

# 2. Build the High-Integrity Binary
# We use the reproducible build flags by default for the global install.
echo "[τ-Gate] Compiling high-integrity binary (Release)..."
RUSTFLAGS="-C debuginfo=0 -C strip=symbols" cargo build --release

# 3. Determine target path
BINARY_PATH="$INSTALL_DIR/target/release/tau-gate"
TARGET_PATH="/usr/local/bin/tau-gate"

# 4. Install to System
echo -e "[τ-Gate] Installing binary to $TARGET_PATH..."
echo "[τ-Gate] This may require your administrator password."
sudo cp -f "$BINARY_PATH" "$TARGET_PATH"
sudo chmod +x "$TARGET_PATH"

echo -e "\n${GREEN}✅ Installation Complete!${NC}"
echo "You can now run 'tau-gate' from any directory."

# 5. Cleanup if needed
if [ -n "$TEMP_DIR" ]; then
    echo "[τ-Gate] Cleaning up temporary build artifacts..."
    rm -rf "$TEMP_DIR"
fi

echo -e "\n${BLUE}Supported Runtimes:${NC}"
echo " - npm (package-lock.json)"
echo " - pnpm (pnpm-lock.yaml)"
echo " - Bun (bun.lockb)"
echo " - Yarn Berry (yarn.lock)"
echo " - Rust (Cargo.toml)"
