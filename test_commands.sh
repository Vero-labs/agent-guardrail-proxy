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


curl -s -X POST "$CHAT_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "X-Guardrail-Role: recruiter" \
  -d '{"model":"llama-3.1-8b-instant","messages":[{"role":"user","content":"who is richest actor in hollywood?"}]}'



echo -e "\n=========================================="
echo "Tests Completed"
echo "=========================================="
