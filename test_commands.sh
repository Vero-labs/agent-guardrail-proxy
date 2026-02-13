#!/bin/bash

# Configuration
PROXY_URL="http://localhost:8080"
CHAT_ENDPOINT="$PROXY_URL/v1/chat/completions"

echo "=========================================="
echo "Agent Guardrail Proxy - Test Suite"
echo "=========================================="

# 1. Health Check
echo -e "\n[1] Testing Health Check..."
curl -s "$PROXY_URL/health" | jq .

# 2. Status Check
echo -e "\n[2] Testing Status Check..."
curl -s "$PROXY_URL/api/status" | jq .

# 3. Basic Chat (Permit)

curl -s -X POST "$CHAT_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama-3.1-8b-instant",
    "messages": [{"role": "user", "content": "Who is the president of US?"}]
  }' | jq .



echo -e "\n=========================================="
echo "Tests Completed"
echo "=========================================="
