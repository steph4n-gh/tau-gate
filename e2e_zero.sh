#!/usr/bin/env bash
# Bounded, network-free npm v3 fixture validation; never installs packages.
set -euo pipefail
cd "$(dirname "$0")"
binary="${TAU_GATE_BIN:-./target/release/tau-gate}"
"$binary" review --base examples/review/base.json --head examples/review/head.json --json
"$binary" audit --lock examples/review/head.json --dry-run --json
if "$binary" audit --lock examples/review/head.json --enforce --json; then
  echo 'Expected marker policy to block both unapproved candidates' >&2
  exit 1
else
  code=$?
  test "$code" -eq 1
fi
echo 'Bounded npm fixture validation passed; artifact safety is not inferred.'
