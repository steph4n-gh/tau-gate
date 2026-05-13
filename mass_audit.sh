#!/bin/bash

# ==============================================================================
# τ-Gate: Mass Ecosystem Auditor
# Fetches the top JS/TS repositories, clones them (depth 1), and runs the math.
# ==============================================================================

set -e

# Number of top repos to audit
LIMIT=5
WORKSPACE="ecosystem_audit"

echo "[τ-Gate] 🌐 Initializing Mass Ecosystem Audit..."
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"

# 1. Fetch Top Repos using GitHub CLI
echo "[τ-Gate] 📥 Fetching top $LIMIT JS/TS repositories from GitHub..."
REPOS=$(gh search repos --language javascript --language typescript --sort stars --limit $LIMIT --json fullName -q '.[].fullName')

# 2. Iterate and Audit
for REPO in $REPOS; do
    echo "--------------------------------------------------"
    echo "🎯 TARGET: $REPO"
    
    # Extract folder name
    DIR_NAME=$(basename "$REPO")

    # Shallow clone to save time and disk space
    if [ ! -d "$DIR_NAME" ]; then
        git clone --depth 1 "https://github.com/$REPO.git" "$DIR_NAME" -q
    else
        echo "📂 Already cloned. Skipping..."
    fi

    cd "$DIR_NAME"

    # Ensure dependencies are fetched if needed for specific engines, or rely on lockfiles
    # For a mass audit, we rely purely on the existence of lockfiles in the repository.

    # Run the audit and capture the exit code
    set +e
    tau-gate -d
    EXIT_CODE=$?
    set -e

    if [ $EXIT_CODE -eq 0 ]; then
        echo "✅ PASS: $REPO"
    else
        echo "❌ FAIL: $REPO (Anomaly Detected!)"
    fi

    cd ..
done

echo "--------------------------------------------------"
echo "[τ-Gate] 🏁 Mass Audit Complete."