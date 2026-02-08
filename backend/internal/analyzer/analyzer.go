package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/provider"
	"github.com/blackrose-blackhat/agent-guardrail/backend/pkg/models"
)

const systemPrompt = `You are a security intent analyzer. Analyze the following user prompt for intent, risk, and sensitivity.
Return your analysis strictly as a JSON object with the following fields:
- intent: (string) A short description of the user's goal.
- risk: (float) A score from 0.0 to 1.0 representing the potential harm or policy violation risk.
- confidence: (float) A score from 0.0 to 1.0 representing your confidence in this analysis.
- sensitive: (boolean) True if the prompt contains PII or sensitive data.
- topic: (string) The main topic or category of the prompt.

Prompt:
%s

JSON Output:`

// Analyzer handles the extraction of facts from LLM requests
type Analyzer struct {
	provider provider.Provider
}

// NewAnalyzer creates a new Analyzer
func NewAnalyzer(p provider.Provider) *Analyzer {
	return &Analyzer{provider: p}
}

// Analyze extracts facts from an LLMRequest
func (a *Analyzer) Analyze(req *models.LLMRequest) (*Facts, error) {
	if len(req.Messages) == 0 {
		return nil, fmt.Errorf("no messages to analyze")
	}

	// Extract last message content for analysis
	lastMessage := req.Messages[len(req.Messages)-1].Content
	formattedPrompt := fmt.Sprintf(systemPrompt, lastMessage)

	// Create analysis request
	analysisReq := models.LLMRequest{
		Model: req.Model,
		Messages: []models.Message{
			{Role: "user", Content: formattedPrompt},
		},
		Temperature: 0.1, // Low temperature for consistent JSON
	}

	body, err := json.Marshal(analysisReq)
	if err != nil {
		return nil, err
	}

	// Build HTTP request
	targetURL := "/v1/chat/completions" // Standard endpoint
	httpReq, err := http.NewRequest("POST", targetURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.provider.ForwardRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	parsedResp, err := a.provider.ParseResponse(rawResp)
	if err != nil {
		return nil, fmt.Errorf("parse error: %v, body: %s", err, string(rawResp))
	}

	if len(parsedResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices returned from analyzer. Body: %s", string(rawResp))
	}

	content := parsedResp.Choices[0].Message.Content

	// Robustly extract JSON block
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start == -1 || end == -1 || start > end {
		return nil, fmt.Errorf("failed to find JSON object in analyzer response: %s", content)
	}
	jsonContent := content[start : end+1]

	var facts Facts
	if err := json.Unmarshal([]byte(jsonContent), &facts); err != nil {
		return nil, fmt.Errorf("failed to parse analyzer JSON: %v, content: %s", err, content)
	}

	return &facts, nil
}
