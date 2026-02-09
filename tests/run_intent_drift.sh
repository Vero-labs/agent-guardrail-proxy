#!/bin/bash
# Intent Drift Test Runner
# Run adversarial tests against the intent analyzer

set -e

INTENT_URL="${INTENT_ANALYZER_URL:-http://localhost:8001}"
TEST_FILE="tests/intent_drift_tests.json"

echo "=== Intent Drift Test Suite ==="
echo "Analyzer: $INTENT_URL"
echo ""

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed."
    exit 1
fi

# Read test cases
TESTS=$(cat "$TEST_FILE")
TOTAL=$(echo "$TESTS" | jq '.test_cases | length')
PASSED=0
FAILED=0
FALSE_NEGATIVES=0

for i in $(seq 0 $((TOTAL-1))); do
    TEST=$(echo "$TESTS" | jq ".test_cases[$i]")
    ID=$(echo "$TEST" | jq -r '.id')
    INPUT=$(echo "$TEST" | jq -r '.input')
    EXPECTED=$(echo "$TEST" | jq -r '.expected_intent')
    NOTES=$(echo "$TEST" | jq -r '.notes')
    
    # Call intent analyzer
    RESULT=$(curl -s -X POST "$INTENT_URL/intent" \
        -H "Content-Type: application/json" \
        -d "{\"text\": \"$INPUT\"}")
    
    ACTUAL=$(echo "$RESULT" | jq -r '.intent')
    CONFIDENCE=$(echo "$RESULT" | jq -r '.confidence')
    
    # Check result
    if [ "$ACTUAL" == "$EXPECTED" ]; then
        STATUS="✅ PASS"
        ((PASSED++))
    else
        STATUS="❌ FAIL"
        ((FAILED++))
        
        # False negative = expected risky, got safe
        if [ "$EXPECTED" != "information_query" ] && [ "$EXPECTED" != "summarization" ]; then
            if [ "$ACTUAL" == "information_query" ] || [ "$ACTUAL" == "summarization" ] || [ "$ACTUAL" == "unknown" ]; then
                STATUS="🔴 FALSE NEGATIVE"
                ((FALSE_NEGATIVES++))
            fi
        fi
    fi
    
    echo "[$ID] $STATUS"
    echo "  Input:    \"$INPUT\""
    echo "  Expected: $EXPECTED"
    echo "  Actual:   $ACTUAL (confidence: $CONFIDENCE)"
    echo "  Notes:    $NOTES"
    echo ""
done

echo "=== Summary ==="
echo "Total:           $TOTAL"
echo "Passed:          $PASSED"
echo "Failed:          $FAILED"
echo "False Negatives: $FALSE_NEGATIVES (CRITICAL)"
echo ""

if [ $FALSE_NEGATIVES -gt 0 ]; then
    echo "⚠️  WARNING: False negatives detected. Review capability layer coverage."
    exit 1
fi

exit 0
