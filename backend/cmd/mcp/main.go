package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/analyzer"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/cedar"
	"github.com/blackrose-blackhat/agent-guardrail/backend/pkg/models"
)

const VERSION = "2.4.0"

// MCP JSON-RPC structures
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ToolInfo struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// Tool: check_prompt
type CheckPromptArgs struct {
	Prompt      string `json:"prompt"`
	Sensitivity string `json:"sensitivity,omitempty"` // "public" or "sensitive"
}

type CheckResult struct {
	Decision   string        `json:"decision"`
	Reason     string        `json:"reason"`
	Intent     string        `json:"intent"`
	Confidence float64       `json:"confidence"`
	RiskScore  float64       `json:"risk_score"`
	Signals    SignalsResult `json:"signals"`
	FastPath   bool          `json:"fast_path"` // True if heuristic matched
}

type SignalsResult struct {
	PII             []string `json:"pii"`
	Toxicity        float64  `json:"toxicity"`
	PromptInjection bool     `json:"prompt_injection"`
}

// Tool: check_messages (contextual analysis)
type CheckMessagesArgs struct {
	Messages    []MessageArg `json:"messages"`
	Sensitivity string       `json:"sensitivity,omitempty"`
}

type MessageArg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Tool: get_policy_info
type PolicyInfoResult struct {
	Version     string   `json:"version"`
	Permissions []string `json:"permissions"`
	Forbids     []string `json:"forbids"`
}

func main() {
	logger := log.New(os.Stderr, "[mcp] ", log.LstdFlags)

	// Initialize components
	signalAggregator := analyzer.NewSignalAggregator()
	heuristicAnalyzer := analyzer.NewHeuristicAnalyzer()

	// Initialize Intent Analyzer (connect to sidecar if available)
	intentAnalyzerURL := os.Getenv("INTENT_ANALYZER_URL")
	if intentAnalyzerURL == "" {
		intentAnalyzerURL = "http://localhost:8001" // Default
	}
	intentAnalyzer := analyzer.NewIntentAnalyzer(intentAnalyzerURL, "")

	// Initialize Cedar Engine
	policyPath := os.Getenv("POLICY_PATH")
	if policyPath == "" {
		policyPath = "backend/internal/cedar/policies.cedar"
	}
	cedarEngine, err := cedar.NewEngine(policyPath)
	if err != nil {
		logger.Fatalf("Failed to load Cedar policies: %v", err)
	}
	logger.Printf("MCP Server v%s starting...", VERSION)
	logger.Printf("Intent Analyzer: %s", intentAnalyzerURL)
	logger.Printf("Policy Path: %s", policyPath)

	scanner := bufio.NewScanner(os.Stdin)
	// Increase buffer size for large prompts
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024) // 1MB max

	for scanner.Scan() {
		line := scanner.Text()
		var req MCPRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue
		}

		var resp MCPResponse
		resp.JSONRPC = "2.0"
		resp.ID = req.ID

		switch req.Method {
		case "initialize":
			resp.Result = map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools":     map[string]interface{}{},
					"resources": map[string]interface{}{},
					"prompts":   map[string]interface{}{},
				},
				"serverInfo": map[string]interface{}{
					"name":    "agent-guardrail",
					"version": VERSION,
				},
			}

		case "resources/list":
			// Return empty resources list (we don't expose resources)
			resp.Result = map[string]interface{}{
				"resources": []interface{}{},
			}

		case "prompts/list":
			// Return empty prompts list (we don't expose prompts)
			resp.Result = map[string]interface{}{
				"prompts": []interface{}{},
			}

		case "tools/list":
			resp.Result = map[string]interface{}{
				"tools": []ToolInfo{
					{
						Name:        "check_prompt",
						Description: "Validates a single prompt against security guardrails. Uses heuristic fast-path for common patterns, falls back to semantic analysis. Returns decision (ALLOW/DENY), detected signals (PII, toxicity, injection), and intent classification.",
						InputSchema: json.RawMessage(`{
							"type": "object",
							"properties": {
								"prompt": {
									"type": "string",
									"description": "The user prompt to validate"
								},
								"sensitivity": {
									"type": "string",
									"enum": ["public", "sensitive"],
									"default": "public",
									"description": "Asset sensitivity level for policy evaluation"
								}
							},
							"required": ["prompt"]
						}`),
					},
					{
						Name:        "check_messages",
						Description: "Validates a full conversation context (system + user messages) for contextual drift and prompt injection attacks. Provides role-weighted intent analysis.",
						InputSchema: json.RawMessage(`{
							"type": "object",
							"properties": {
								"messages": {
									"type": "array",
									"items": {
										"type": "object",
										"properties": {
											"role": {"type": "string", "enum": ["system", "user", "assistant"]},
											"content": {"type": "string"}
										},
										"required": ["role", "content"]
									},
									"description": "Array of conversation messages"
								},
								"sensitivity": {
									"type": "string",
									"enum": ["public", "sensitive"],
									"default": "public"
								}
							},
							"required": ["messages"]
						}`),
					},
					{
						Name:        "get_policy_info",
						Description: "Returns information about the loaded Cedar security policy, including version and rule summaries.",
						InputSchema: json.RawMessage(`{"type": "object", "properties": {}}`),
					},
				},
			}

		case "tools/call":
			var params ToolCallParams
			if err := json.Unmarshal(req.Params, &params); err != nil {
				resp.Error = &MCPError{Code: -32602, Message: "Invalid params"}
				break
			}

			switch params.Name {
			case "check_prompt":
				resp = handleCheckPrompt(params.Arguments, signalAggregator, heuristicAnalyzer, intentAnalyzer, cedarEngine)
				resp.ID = req.ID

			case "check_messages":
				resp = handleCheckMessages(params.Arguments, signalAggregator, heuristicAnalyzer, intentAnalyzer, cedarEngine)
				resp.ID = req.ID

			case "get_policy_info":
				resp.Result = map[string]interface{}{
					"content": []map[string]interface{}{
						{"type": "text", "text": fmt.Sprintf("Policy Version: %s\nLoaded from: %s\n\nThe policy enforces:\n- Block high-risk intents (code.exploit, system)\n- Block prompt injection attempts\n- Block PII exposure\n- Require low toxicity\n- Asset sensitivity controls", cedarEngine.PolicyVersion, policyPath)},
					},
				}

			default:
				resp.Error = &MCPError{Code: -32601, Message: "Unknown tool: " + params.Name}
			}

		case "notifications/initialized":
			// Acknowledgement, no response needed
			continue

		default:
			resp.Result = map[string]interface{}{}
		}

		output, _ := json.Marshal(resp)
		fmt.Println(string(output))
	}
}

func handleCheckPrompt(args json.RawMessage, signalAgg *analyzer.SignalAggregator, heuristic *analyzer.HeuristicAnalyzer, intent *analyzer.IntentAnalyzer, cedar *cedar.Engine) MCPResponse {
	var params CheckPromptArgs
	if err := json.Unmarshal(args, &params); err != nil {
		return MCPResponse{JSONRPC: "2.0", Error: &MCPError{Code: -32602, Message: "Invalid arguments"}}
	}

	sensitivity := params.Sensitivity
	if sensitivity == "" {
		sensitivity = "public"
	}

	// Build request
	llmReq := &models.LLMRequest{
		Messages: []models.Message{{Role: "user", Content: params.Prompt}},
	}

	// Generate signals
	signals := signalAgg.Aggregate(llmReq)

	// Build context
	ctx := &analyzer.Context{
		Signals:             *signals,
		ResourceSensitivity: sensitivity,
	}

	var fastPath bool
	var intentStr string
	var confidence float64

	// 1. Heuristic Fast-Path
	if heuristicSignal := heuristic.Analyze(params.Prompt); heuristicSignal != nil {
		ctx.AttachIntent(heuristicSignal, "user")
		fastPath = true
		intentStr = heuristicSignal.Intent
		confidence = heuristicSignal.Confidence
	} else {
		// 2. Semantic Intent Analysis (BART sidecar)
		if intentSignal, err := intent.Analyze(params.Prompt); err == nil {
			ctx.AttachIntent(intentSignal, "user")
			intentStr = intentSignal.Intent
			confidence = intentSignal.Confidence
		} else {
			intentStr = "unknown"
			confidence = 0.5
		}
	}

	// 3. Cedar Policy Evaluation
	decision, reason, _ := cedar.EvaluateContext(ctx)

	result := CheckResult{
		Decision:   string(decision),
		Reason:     reason,
		Intent:     intentStr,
		Confidence: confidence,
		RiskScore:  ctx.RiskScore,
		FastPath:   fastPath,
		Signals: SignalsResult{
			PII:             signals.PII,
			Toxicity:        signals.Toxicity,
			PromptInjection: signals.PromptInjection,
		},
	}

	// Format output
	text := fmt.Sprintf("**Decision:** %s\n**Reason:** %s\n\n**Intent:** %s (%.0f%% confidence)\n**Risk Score:** %.2f\n**Fast Path:** %v\n\n**Signals:**\n- PII Detected: %v\n- Toxicity: %.2f\n- Prompt Injection: %v",
		result.Decision, result.Reason, result.Intent, result.Confidence*100, result.RiskScore, result.FastPath,
		result.Signals.PII, result.Signals.Toxicity, result.Signals.PromptInjection)

	return MCPResponse{
		JSONRPC: "2.0",
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": text},
			},
		},
	}
}

func handleCheckMessages(args json.RawMessage, signalAgg *analyzer.SignalAggregator, heuristic *analyzer.HeuristicAnalyzer, intent *analyzer.IntentAnalyzer, cedar *cedar.Engine) MCPResponse {
	var params CheckMessagesArgs
	if err := json.Unmarshal(args, &params); err != nil {
		return MCPResponse{JSONRPC: "2.0", Error: &MCPError{Code: -32602, Message: "Invalid arguments"}}
	}

	sensitivity := params.Sensitivity
	if sensitivity == "" {
		sensitivity = "public"
	}

	// Convert to models.Message
	messages := make([]models.Message, len(params.Messages))
	for i, m := range params.Messages {
		messages[i] = models.Message{Role: m.Role, Content: m.Content}
	}

	llmReq := &models.LLMRequest{Messages: messages}

	// Generate signals
	signals := signalAgg.Aggregate(llmReq)

	// Build context
	ctx := &analyzer.Context{
		Signals:             *signals,
		ResourceSensitivity: sensitivity,
	}

	// Contextual analysis with message history
	if intentSignal, err := intent.AnalyzeMessages(messages); err == nil {
		ctx.AttachIntent(intentSignal, "aggregate")
	}

	// Also analyze user messages specifically
	for _, m := range messages {
		if m.Role == "user" {
			if heuristicSignal := heuristic.Analyze(m.Content); heuristicSignal != nil {
				ctx.AttachIntent(heuristicSignal, "user")
			} else if intentSignal, err := intent.Analyze(m.Content); err == nil {
				ctx.AttachIntent(intentSignal, "user")
			}
		}
	}

	// Cedar Policy Evaluation
	decision, reason, _ := cedar.EvaluateContext(ctx)

	text := fmt.Sprintf("**Decision:** %s\n**Reason:** %s\n\n**Context Analysis:**\n- Aggregate Intent: %s\n- User Intent: %s\n- Risk Score: %.2f\n\n**Signals:**\n- PII: %v\n- Toxicity: %.2f\n- Prompt Injection: %v",
		decision, reason, ctx.Intent, ctx.UserIntent, ctx.RiskScore,
		signals.PII, signals.Toxicity, signals.PromptInjection)

	return MCPResponse{
		JSONRPC: "2.0",
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": text},
			},
		},
	}
}
