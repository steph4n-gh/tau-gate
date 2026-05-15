#!/bin/bash
cargo build --release

echo "Extracting list of parser failures..."
grep -l "Lockfile Extraction Failed" ecosystem_audit/*/tau-gate.log | cut -d/ -f2 > /tmp/extraction_failures.txt

TOTAL=$(wc -l < /tmp/extraction_failures.txt | awk '{print $1}')
CURRENT=0
SUMMARY="network_validation_summary.txt"

echo "--- v3.0 Network Engine Validation ---" > $SUMMARY
echo "Target: $TOTAL Repositories with parser failures" >> $SUMMARY
echo "" >> $SUMMARY

while IFS= read -r REPO; do
    CURRENT=$((CURRENT+1))
    echo "[$CURRENT/$TOTAL] Verifying $REPO via network..."
    cd "ecosystem_audit/$REPO"
    
    # Run the network engine
    ../../target/release/tau-gate -d --network > tau-gate-network.log 2>&1
    EXIT_CODE=$?
    
    PERF_METRIC=$(grep "Analyzed" tau-gate-network.log || echo "No metric")
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo "✅ PASS: $REPO | $PERF_METRIC" >> "../../$SUMMARY"
    else
        # Check if it was an anomaly (which is expected/good) or still an error
        if grep -q "CRITICAL TOPOLOGICAL ANOMALY!" tau-gate-network.log; then
            echo "🛡️  ANOMALY DETECTED: $REPO | $PERF_METRIC" >> "../../$SUMMARY"
        else
            echo "❌ STILL FAILING: $REPO" >> "../../$SUMMARY"
        fi
    fi
    cd ../..
done < /tmp/extraction_failures.txt

echo "" >> $SUMMARY
echo "--- Verification Complete ---" >> $SUMMARY
