#!/bin/bash

# τ-Gate: "ABSOLUTE ZERO" E2E Validation Suite
# This script stress-tests the zero-dependency engine against real-world complexity.

set -e

# Setup Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}--------------------------------------------------${NC}"
echo -e "${BLUE}   τ-Gate v2.0: Absolute Zero E2E Validation     ${NC}"
echo -e "${BLUE}--------------------------------------------------${NC}"

# 1. Build the Zero-Dependency Binary
echo -e "\n[1/6] Building Zero-Dependency Binary (std-only)..."
cargo build --release
GATE="$(pwd)/target/release/tau-gate"

# 2. Setup Staging
STAGING="$(pwd)/e2e_zero_staging"
rm -rf "$STAGING" && mkdir -p "$STAGING"
cd "$STAGING"

# --- TEST 1: Astro (npm) ---
echo -e "\n${BLUE}[TEST 1/5] Astro (NPM Registry Complexity)${NC}"
git clone --depth 1 https://github.com/withastro/astro.git astro_test > /dev/null 2>&1
cd astro_test
"$GATE" --dry-run
cd ..

# --- TEST 2: Hono (pnpm Workspace) ---
echo -e "\n${BLUE}[TEST 2/5] Hono (pnpm YAML Parsing)${NC}"
git clone --depth 1 https://github.com/honojs/hono.git hono_test > /dev/null 2>&1
cd hono_test
"$GATE" --dry-run
cd ..

# --- TEST 3: Elysia (Bun Binary Lockfile Fallback) ---
echo -e "\n${BLUE}[TEST 3/5] Elysia (Bun Metadata Recovery)${NC}"
git clone --depth 1 https://github.com/elysiajs/elysia.git elysia_test > /dev/null 2>&1
cd elysia_test
"$GATE" --dry-run
cd ..

# --- TEST 4: TanStack Query (Yarn Berry v4) ---
echo -e "\n${BLUE}[TEST 4/5] TanStack Query (Yarn Berry Recursive)${NC}"
git clone --depth 1 https://github.com/TanStack/query.git query_test > /dev/null 2>&1
cd query_test
"$GATE" --dry-run
cd ..

# --- TEST 5: Serde (Cargo Dogfooding) ---
echo -e "\n${BLUE}[TEST 5/5] Serde (Rust/Cargo Integration)${NC}"
git clone --depth 1 https://github.com/serde-rs/serde.git serde_test > /dev/null 2>&1
cd serde_test
"$GATE" --dry-run
cd ..

# Cleanup
cd ..
rm -rf "$STAGING"

echo -e "\n${GREEN}--------------------------------------------------${NC}"
echo -e "${GREEN}   E2E Validation Complete: 100% Success         ${NC}"
echo -e "${GREEN}   Zero Dependencies. Zero External Risk.        ${NC}"
echo -e "${GREEN}--------------------------------------------------${NC}"
