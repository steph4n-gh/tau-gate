#!/bin/bash
# Historical unqualified prototype: deliberately disabled to avoid resolution/install side effects.
echo "INCOMPLETE: retired prototype; use read-only npm review (README.md)" >&2
exit 2
cargo build --release

echo "Fetching obscure repositories (Stars < 5, Recently Updated)..."
# Fetch 100 recent repos with < 5 stars to find obscure/untested code
REPOS=$(gh search repos --language javascript --language typescript --stars "<5" --sort updated --limit 100 --json fullName -q '.[].fullName')

mkdir -p obscure_audit
cd obscure_audit

SUMMARY="obscure_summary.txt"
echo "--- Obscure Ecosystem Audit ---" > $SUMMARY
echo "Hunting for anomalies in low-visibility repositories..." >> $SUMMARY
echo "" >> $SUMMARY

TOTAL=100
CURRENT=0

for REPO in $REPOS; do
    CURRENT=$((CURRENT+1))
    echo "[$CURRENT/$TOTAL] Auditing $REPO..."
    DIR_NAME=$(basename "$REPO")
    
    if [ ! -d "$DIR_NAME" ]; then
        git clone --depth 1 "https://github.com/$REPO.git" "$DIR_NAME" -q || {
            echo "Skipped clone: $REPO"
            continue
        }
    fi
    
    cd "$DIR_NAME"
    # Run the purely in-memory network engine
    ../../target/release/tau-gate -d --network > tau-gate.log 2>&1
    EXIT_CODE=$?
    
    if grep -q "CRITICAL TOPOLOGICAL ANOMALY!" tau-gate.log; then
        echo "🚨 ANOMALY: $REPO" >> "../$SUMMARY"
        grep "Quarantined" -A 5 tau-gate.log >> "../$SUMMARY"
        echo "---" >> "../$SUMMARY"
    elif [ $EXIT_CODE -eq 0 ]; then
        # Only log passes if we want verbosity, let's keep it quiet to focus on anomalies
        echo "✅ PASS: $REPO" >> "../$SUMMARY"
    else
        echo "❌ PARSER/OTHER ERROR: $REPO" >> "../$SUMMARY"
    fi
    cd ..
done

echo "Audit Complete." >> $SUMMARY
