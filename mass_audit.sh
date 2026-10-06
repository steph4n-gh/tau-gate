#!/bin/bash
# Historical unqualified prototype: deliberately disabled to avoid resolution/install side effects.
echo "INCOMPLETE: retired prototype; use read-only npm review (README.md)" >&2
exit 2

# ==============================================================================
# τ-Gate: Mass Ecosystem Auditor (Benchmark Mode)
# Fetches the top JS/TS repositories, clones them (depth 1), and runs the math.
# ==============================================================================

set -e

# Number of top repos to audit
LIMIT=500
WORKSPACE="ecosystem_audit"
SUMMARY_FILE="benchmark_summary.txt"

echo "[τ-Gate] 🌐 Initializing Mass Ecosystem Benchmark (Top $LIMIT)..."
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"

# 1. Fetch Top Repos using GitHub CLI
echo "[τ-Gate] 📥 Fetching top $LIMIT JS/TS repositories from GitHub..."
REPOS=$(gh search repos --language javascript --language typescript --sort stars --limit $LIMIT --json fullName -q '.[].fullName')

TOTAL=0
PASS=0
FAIL=0

echo "--- τ-Gate Ecosystem Benchmark ---" > "$SUMMARY_FILE"
echo "Target: Top $LIMIT JS/TS Repositories" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

# 2. Iterate and Audit
for REPO in $REPOS; do
    echo "--------------------------------------------------"
    echo "🎯 TARGET: $REPO"
    
    # Extract folder name
    DIR_NAME=$(basename "$REPO")

    # Shallow clone to save time and disk space
    if [ ! -d "$DIR_NAME" ]; then
        git clone --depth 1 "https://github.com/$REPO.git" "$DIR_NAME" -q || {
            echo "⚠️ Failed to clone $REPO, skipping..."
            continue
        }
    fi

    cd "$DIR_NAME"

    # Run the audit and capture the exit code
    set +e
    ../../target/release/tau-gate -d > tau-gate.log 2>&1
    EXIT_CODE=$?
    set -e
    
    # Extract performance metrics from log
    PERF_METRIC=$(grep "Analyzed" tau-gate.log || echo "No metric")

    if [ $EXIT_CODE -eq 0 ]; then
        echo "✅ PASS: $REPO ($PERF_METRIC)"
        echo "PASS: $REPO | $PERF_METRIC" >> "../$SUMMARY_FILE"
        ((PASS++))
    else
        echo "❌ FAIL: $REPO (Anomaly Detected!)"
        echo "FAIL: $REPO | Anomaly Detected!" >> "../$SUMMARY_FILE"
        ((FAIL++))
    fi

    ((TOTAL++))
    cd ..
done

echo "" >> "$SUMMARY_FILE"
echo "--- Benchmark Complete ---" >> "$SUMMARY_FILE"
echo "Total Audited: $TOTAL" >> "$SUMMARY_FILE"
echo "Passed: $PASS" >> "$SUMMARY_FILE"
echo "Anomalies/Failed: $FAIL" >> "$SUMMARY_FILE"

echo "--------------------------------------------------"
echo "[τ-Gate] 🏁 Mass Audit Complete. Summary saved to ecosystem_audit/$SUMMARY_FILE."
