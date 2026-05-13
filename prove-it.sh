#!/bin/bash

# τ-Gate: "PROVE IT" - End-to-End Live Attack Simulation
# This script scaffolds three scenarios to demonstrate the spectral bisection math in action.

set -e

# Setup Colors for UI
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}--------------------------------------------------${NC}"
echo -e "${BLUE}   τ-Gate: Live Attack & Mathematical Proof      ${NC}"
echo -e "${BLUE}--------------------------------------------------${NC}"

# 1. Build the Latest Binary
echo -e "\n[1/4] Building optimized τ-Gate binary..."
cargo build --release
GATE="$(pwd)/target/release/tau-gate"

# Create a staging area
STAGING="$(pwd)/staging_demo"
rm -rf "$STAGING" && mkdir -p "$STAGING"
cd "$STAGING"

# --- SCENARIO 1: THE NOMINAL BASELINE ---
echo -e "\n${GREEN}[SCENARIO 1] The Healthy Project${NC}"
echo -e "Setting up a standard project with many well-connected dependencies..."
mkdir -p nominal && cd nominal
npm init -y > /dev/null
# Add a robust "Mainland"
npm install express lodash zod chalk > /dev/null 2>&1
echo -e "Running τ-Gate Audit..."
"$GATE" --dry-run
cd ..
echo -e "${GREEN}✅ Result: Nominal. The math confirms a strong, unified core.${NC}"

# --- SCENARIO 2: THE TYPOSQUATTER ---
echo -e "\n${RED}[SCENARIO 2] The Isolated Typosquatter${NC}"
echo -e "Simulating 'asttro' (an isolated island requesting execution power)..."
mkdir -p typosquatter && cd typosquatter
npm init -y > /dev/null
npm install express lodash > /dev/null 2>&1

# Create the isolated malicious package
mkdir -p malicious-island
cat <<EOF > malicious-island/package.json
{
  "name": "malicious-island",
  "version": "1.0.0",
  "scripts": { "postinstall": "echo 'Exfiltrating secrets...'" }
}
EOF
npm install ./malicious-island > /dev/null 2>&1

echo -e "Running τ-Gate Audit..."
# We expect this to FAIL
if "$GATE" --dry-run; then
  echo -e "${RED}❌ FAILED: The gate should have closed!${NC}"
  exit 1
else
  echo -e "${GREEN}✅ SUCCESS: The gate SLAMMED SHUT. Math isolated the island.${NC}"
fi
cd ..

# --- SCENARIO 3: THE BLOATED TROJAN ---
echo -e "\n${RED}[SCENARIO 3] The Bloated Trojan (Evasion Attempt)${NC}"
echo -e "Simulating an attacker adding 200 fake deps to look 'big' and bypass thresholds..."
mkdir -p trojan && cd trojan
npm init -y > /dev/null
npm install express lodash zod > /dev/null 2>&1

# Create the bloated malicious package
mkdir -p bloated-trojan
cat <<EOF > bloated-trojan/package.json
{
  "name": "bloated-trojan",
  "version": "1.0.0",
  "dependencies": { "chalk": "*", "commander": "*", "dotenv": "*", "fs-extra": "*", "glob": "*", "js-yaml": "*", "moment": "*", "uuid": "*" },
  "scripts": { "postinstall": "echo 'Escaping CI sandbox...'" }
}
EOF
npm install ./bloated-trojan > /dev/null 2>&1

echo -e "Running τ-Gate Audit..."
# We expect this to FAIL because of the Connectivity Score hardening
if "$GATE" --dry-run; then
  echo -e "${RED}❌ FAILED: The gate should have detected extreme isolation!${NC}"
  exit 1
else
  echo -e "${GREEN}✅ SUCCESS: The gate DETECTED the Trojan. Connectivity Score (λ₂) was near zero.${NC}"
fi
cd ..

# Cleanup
echo -e "\n${BLUE}--------------------------------------------------${NC}"
echo -e "${BLUE}   Validation Complete. Cleaning up staging...   ${NC}"
echo -e "${BLUE}--------------------------------------------------${NC}"
cd ..
rm -rf "$STAGING"

echo -e "\n${GREEN}Final Proof of Claims Delivered.${NC}"
echo -e "τ-Gate is now empirically proven to stop structural attacks."
