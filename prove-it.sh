#!/usr/bin/env bash
# Demonstrate an explainable change, without claiming payload detection.
set -euo pipefail
cd "$(dirname "$0")"
"${TAU_GATE_BIN:-./target/release/tau-gate}" review --base examples/review/base.json --head examples/review/head.json
