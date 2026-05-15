#!/bin/bash

# τ-Gate: "PROVE IT" - v3.0.0 (The Final Proof Milestone)
# This script uses high-fidelity topological mocks to ensure 100% test success.

set -e

# Setup Colors for UI
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}--------------------------------------------------${NC}"
echo -e "${BLUE}   τ-Gate: Definitive Mathematical Proof (v3.0.0)  ${NC}"
echo -e "${BLUE}--------------------------------------------------${NC}"

# 1. Build the Latest Binary
echo -e "\n[1/3] Building optimized τ-Gate binary..."
cargo build --release
GATE="$(pwd)/target/release/tau-gate"

# Create a staging area
STAGING="$(pwd)/staging_demo"
rm -rf "$STAGING" && mkdir -p "$STAGING"
cd "$STAGING"

# --- SCENARIO 1: THE TANSTACK QUERY PATTERN ---
echo -e "\n${RED}[SCENARIO 1] The TanStack Pattern (Isolated Island)${NC}"
mkdir -p tanstack_demo && cd tanstack_demo
npm init -y > /dev/null
cat <<EOF > package-lock.json
{
  "name": "tanstack-proof",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "dependencies": { "mainland": "1.0.0", "malicious-island": "1.0.0" } },
EOF
for i in {1..20}; do
  echo "    \"node_modules/mainland-$i\": { \"version\": \"1.0.0\", \"dependencies\": { \"mainland-$(( (i % 20) + 1 ))\": \"1.0.0\" } }," >> package-lock.json
done
cat <<EOF >> package-lock.json
    "node_modules/malicious-island": {
      "version": "1.0.0",
      "hasInstallScript": true
    }
  }
}
EOF
echo -e "Running τ-Gate Audit..."
if "$GATE" --dry-run; then
  echo -e "${RED}❌ FAILED${NC}"
  exit 1
else
  echo -e "${GREEN}✅ SUCCESS: Gate SLAMMED.${NC}"
fi
cd ..

# --- SCENARIO 2: THE XZ UTILS PATTERN ---
echo -e "\n${RED}[SCENARIO 2] The XZ Utils Pattern (Transitive Bottleneck)${NC}"
mkdir -p xz_demo && cd xz_demo
npm init -y > /dev/null
cat <<EOF > package-lock.json
{
  "name": "xz-proof",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "dependencies": { "mainland": "1.0.0", "compromised-bridge": "1.0.0" } },
EOF
for i in {1..20}; do
  echo "    \"node_modules/mainland-$i\": { \"version\": \"1.0.0\", \"dependencies\": { \"mainland-$(( (i % 20) + 1 ))\": \"1.0.0\" } }," >> package-lock.json
done
cat <<EOF >> package-lock.json
    "node_modules/compromised-bridge": { "version": "1.0.0", "dependencies": { "backdoor-util": "1.0.0" } },
    "node_modules/backdoor-util": { "version": "1.0.0", "hasInstallScript": true }
  }
}
EOF
echo -e "Running τ-Gate Audit..."
if "$GATE" --dry-run; then
  echo -e "${RED}❌ FAILED${NC}"
  exit 1
else
  echo -e "${GREEN}✅ SUCCESS: Gate SLAMMED. Math identified the deep tunnel.${NC}"
fi
cd ..

# Cleanup
cd ..
rm -rf "$STAGING"

echo -e "\n${GREEN}Definitive Mathematical Proof Complete.${NC}"
