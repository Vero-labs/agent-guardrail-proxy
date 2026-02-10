#!/bin/bash
# Guardrail Benchmark Runner
# Runs all benchmark prompts and reports accuracy/latency

set -e

PROXY_URL="${PROXY_URL:-http://localhost:8080}"
BENCHMARK_FILE="tests/benchmark/prompts.json"
OUTPUT_FILE="tests/benchmark/results_$(date +%Y%m%d_%H%M%S).json"

echo "=== Guardrail Benchmark Suite ==="
echo "Proxy: $PROXY_URL"
echo "Prompts: $BENCHMARK_FILE"
echo ""

# Check dependencies
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required"
    exit 1
fi

# Read prompts
PROMPTS=$(cat "$BENCHMARK_FILE")
TOTAL=$(echo "$PROMPTS" | jq '.prompts | length')

# Counters
PASSED=0
FAILED=0
BLOCKED_CORRECT=0
ALLOWED_CORRECT=0
FALSE_POSITIVES=0
FALSE_NEGATIVES=0
TOTAL_LATENCY=0

# Results array
RESULTS="[]"

echo "Running $TOTAL prompts..."
echo ""

for i in $(seq 0 $((TOTAL-1))); do
    PROMPT_OBJ=$(echo "$PROMPTS" | jq ".prompts[$i]")
    ID=$(echo "$PROMPT_OBJ" | jq -r '.id')
    CATEGORY=$(echo "$PROMPT_OBJ" | jq -r '.category')
    PROMPT=$(echo "$PROMPT_OBJ" | jq -r '.prompt')
    EXPECTED_BLOCK=$(echo "$PROMPT_OBJ" | jq -r '.expected_block // "null"')
    
    # Skip empty prompts for API test
    if [ -z "$PROMPT" ] || [ "$PROMPT" == "   " ]; then
        echo "[$ID] SKIP (empty/whitespace)"
        continue
    fi
    
    # Time the request (macOS compatible)
    START=$(python3 -c "import time; print(int(time.time() * 1000))")
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$PROXY_URL/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"llama3.2:1b\",\"messages\":[{\"role\":\"user\",\"content\":$(echo "$PROMPT" | jq -Rs .)}]}" 2>/dev/null || echo -e "\n000")
    
    END=$(python3 -c "import time; print(int(time.time() * 1000))")
    LATENCY=$((END - START))

    TOTAL_LATENCY=$((TOTAL_LATENCY + LATENCY))
    
    # Parse response
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    # Determine if blocked
    if [ "$HTTP_CODE" == "403" ]; then
        ACTUAL_BLOCKED="true"
    else
        ACTUAL_BLOCKED="false"
    fi
    
    # Evaluate result
    if [ "$EXPECTED_BLOCK" == "true" ]; then
        if [ "$ACTUAL_BLOCKED" == "true" ]; then
            STATUS="✅ BLOCKED (correct)"
            ((BLOCKED_CORRECT++))
            ((PASSED++))
        else
            STATUS="🔴 ALLOWED (false negative)"
            ((FALSE_NEGATIVES++))
            ((FAILED++))
        fi
    elif [ "$EXPECTED_BLOCK" == "false" ]; then
        if [ "$ACTUAL_BLOCKED" == "false" ]; then
            STATUS="✅ ALLOWED (correct)"
            ((ALLOWED_CORRECT++))
            ((PASSED++))
        else
            STATUS="🟡 BLOCKED (false positive)"
            ((FALSE_POSITIVES++))
            ((FAILED++))
        fi
    else
        STATUS="⚪ UNKNOWN (no expectation)"
        ((PASSED++))
    fi
    
    echo "[$ID] $STATUS (${LATENCY}ms)"
    
    # Add to results
    RESULT=$(jq -n \
        --arg id "$ID" \
        --arg category "$CATEGORY" \
        --arg expected "$EXPECTED_BLOCK" \
        --arg actual "$ACTUAL_BLOCKED" \
        --arg status "$STATUS" \
        --argjson latency "$LATENCY" \
        '{id: $id, category: $category, expected_block: $expected, actual_blocked: $actual, status: $status, latency_ms: $latency}')
    
    RESULTS=$(echo "$RESULTS" | jq ". += [$RESULT]")
done

echo ""
echo "=== Summary ==="
echo "Total:           $TOTAL"
echo "Passed:          $PASSED"
echo "Failed:          $FAILED"
echo ""
echo "Blocked correctly:  $BLOCKED_CORRECT"
echo "Allowed correctly:  $ALLOWED_CORRECT"
echo "False positives:    $FALSE_POSITIVES"
echo "False negatives:    $FALSE_NEGATIVES (CRITICAL)"
echo ""
AVG_LATENCY=$((TOTAL_LATENCY / TOTAL))
echo "Avg latency:     ${AVG_LATENCY}ms"
echo ""

# Calculate metrics
if [ $((BLOCKED_CORRECT + FALSE_NEGATIVES)) -gt 0 ]; then
    BLOCK_ACCURACY=$(echo "scale=2; $BLOCKED_CORRECT * 100 / ($BLOCKED_CORRECT + $FALSE_NEGATIVES)" | bc)
else
    BLOCK_ACCURACY="N/A"
fi

if [ $((ALLOWED_CORRECT + FALSE_POSITIVES)) -gt 0 ]; then
    ALLOW_ACCURACY=$(echo "scale=2; $ALLOWED_CORRECT * 100 / ($ALLOWED_CORRECT + $FALSE_POSITIVES)" | bc)
else
    ALLOW_ACCURACY="N/A"
fi

echo "Block accuracy:  ${BLOCK_ACCURACY}%"
echo "Allow accuracy:  ${ALLOW_ACCURACY}%"

# Save results
SUMMARY=$(jq -n \
    --argjson total "$TOTAL" \
    --argjson passed "$PASSED" \
    --argjson failed "$FAILED" \
    --argjson blocked_correct "$BLOCKED_CORRECT" \
    --argjson allowed_correct "$ALLOWED_CORRECT" \
    --argjson false_positives "$FALSE_POSITIVES" \
    --argjson false_negatives "$FALSE_NEGATIVES" \
    --argjson avg_latency "$AVG_LATENCY" \
    --arg block_accuracy "$BLOCK_ACCURACY" \
    --arg allow_accuracy "$ALLOW_ACCURACY" \
    '{total: $total, passed: $passed, failed: $failed, blocked_correct: $blocked_correct, allowed_correct: $allowed_correct, false_positives: $false_positives, false_negatives: $false_negatives, avg_latency_ms: $avg_latency, block_accuracy: $block_accuracy, allow_accuracy: $allow_accuracy}')

echo "$SUMMARY" | jq --argjson results "$RESULTS" '. + {results: $results}' > "$OUTPUT_FILE"
echo ""
echo "Results saved to: $OUTPUT_FILE"

# Exit with error if false negatives
if [ $FALSE_NEGATIVES -gt 0 ]; then
    echo ""
    echo "⚠️  CRITICAL: $FALSE_NEGATIVES false negatives detected!"
    exit 1
fi

exit 0
