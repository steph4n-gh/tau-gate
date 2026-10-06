#!/bin/bash
# Historical unqualified prototype: deliberately disabled to avoid resolution/install side effects.
echo "INCOMPLETE: retired prototype; use read-only npm review (README.md)" >&2
exit 2
cargo build --release

echo "Fetching Top 5 Go Repositories..."
GO_REPOS=$(gh search repos --language go --sort stars --limit 5 --json fullName -q '.[].fullName')

echo "Fetching Top 5 Rust Repositories..."
RUST_REPOS=$(gh search repos --language rust --sort stars --limit 5 --json fullName -q '.[].fullName')

mkdir -p go_rust_audit
cd go_rust_audit

SUMMARY="go_rust_summary.txt"
echo "--- Go & Rust Ecosystem Audit ---" > $SUMMARY
echo "" >> $SUMMARY

echo "--- Go Audits ---" >> $SUMMARY
for REPO in $GO_REPOS; do
    echo "Auditing Go repo: $REPO..."
    DIR_NAME=$(basename "$REPO")
    
    if [ ! -d "$DIR_NAME" ]; then
        git clone --depth 1 "https://github.com/$REPO.git" "$DIR_NAME" -q || continue
    fi
    
    cd "$DIR_NAME"
    ../../target/release/tau-gate -d > tau-gate.log 2>&1
    EXIT_CODE=$?
    
    PERF_METRIC=$(grep "Analyzed" tau-gate.log || echo "No metric")
    if [ $EXIT_CODE -eq 0 ]; then
        echo "✅ PASS: $REPO | $PERF_METRIC" >> "../$SUMMARY"
    elif grep -q "CRITICAL TOPOLOGICAL ANOMALY!" tau-gate.log; then
        echo "🛡️  ANOMALY DETECTED: $REPO | $PERF_METRIC" >> "../$SUMMARY"
    else
        echo "❌ ERROR: $REPO" >> "../$SUMMARY"
        grep "Lockfile Extraction Failed" tau-gate.log >> "../$SUMMARY" || true
    fi
    cd ..
done

echo "" >> $SUMMARY
echo "--- Rust Audits ---" >> $SUMMARY
for REPO in $RUST_REPOS; do
    echo "Auditing Rust repo: $REPO..."
    DIR_NAME=$(basename "$REPO")
    
    if [ ! -d "$DIR_NAME" ]; then
        git clone --depth 1 "https://github.com/$REPO.git" "$DIR_NAME" -q || continue
    fi
    
    cd "$DIR_NAME"
    ../../target/release/tau-gate -d > tau-gate.log 2>&1
    EXIT_CODE=$?
    
    PERF_METRIC=$(grep "Analyzed" tau-gate.log || echo "No metric")
    if [ $EXIT_CODE -eq 0 ]; then
        echo "✅ PASS: $REPO | $PERF_METRIC" >> "../$SUMMARY"
    elif grep -q "CRITICAL TOPOLOGICAL ANOMALY!" tau-gate.log; then
        echo "🛡️  ANOMALY DETECTED: $REPO | $PERF_METRIC" >> "../$SUMMARY"
    else
        echo "❌ ERROR: $REPO" >> "../$SUMMARY"
        grep "Lockfile Extraction Failed" tau-gate.log >> "../$SUMMARY" || true
    fi
    cd ..
done

echo "Audit Complete." >> $SUMMARY
