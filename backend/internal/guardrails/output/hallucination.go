package output

import (
	"encoding/json"
	"strings"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
)

// HallucinationGuardrail detects potential hallucinations in LLM output
// by checking for common hallucination indicators
type HallucinationGuardrail struct {
	config           policy.HallucinationConfig
	groundingSources []GroundingSource
	enabled          bool
}

// GroundingSource provides context for fact-checking
type GroundingSource interface {
	Name() string
	Query(claim string) ([]Evidence, error)
}

// Evidence represents supporting or contradicting evidence
type Evidence struct {
	Source     string  `json:"source"`
	Content    string  `json:"content"`
	Confidence float64 `json:"confidence"`
	Supports   bool    `json:"supports"`
}

// NewHallucinationGuardrail creates a new hallucination detection guardrail
func NewHallucinationGuardrail(config policy.HallucinationConfig) *HallucinationGuardrail {
	return &HallucinationGuardrail{
		config:           config,
		groundingSources: make([]GroundingSource, 0),
		enabled:          config.Enabled,
	}
}

// AddGroundingSource adds a source for fact-checking
func (g *HallucinationGuardrail) AddGroundingSource(source GroundingSource) {
	g.groundingSources = append(g.groundingSources, source)
}

// Name returns the guardrail identifier
func (g *HallucinationGuardrail) Name() string {
	return "hallucination_detection"
}

// Type returns the guardrail type (output)
func (g *HallucinationGuardrail) Type() chain.GuardrailType {
	return chain.GuardrailTypeOutput
}

// Execute checks the LLM response for potential hallucinations
func (g *HallucinationGuardrail) Execute(ctx *chain.Context) (*chain.Result, error) {
	if !g.enabled {
		return &chain.Result{Passed: true}, nil
	}

	// Get response content
	content := ""
	if ctx.Response != nil {
		content = ctx.Response.Content
	} else {
		content = string(ctx.GetResponseToProcess())
	}

	// Run hallucination detection heuristics
	indicators := g.detectHallucinationIndicators(content)

	// If no context was provided in request, we can't do grounding verification
	// Just use heuristics
	if len(indicators) > 0 {
		violation := chain.Violation{
			GuardrailName: g.Name(),
			Type:          "potential_hallucination",
			Message:       "Response may contain unverified or hallucinated content",
			Severity:      chain.SeverityMedium,
			Action:        chain.ActionType(g.config.Action),
			Details: map[string]interface{}{
				"indicators":  indicators,
				"has_context": ctx.Request != nil && len(ctx.Request.Messages) > 1,
			},
		}

		action := chain.ActionWarn
		if g.config.Action == "block" {
			action = chain.ActionBlock
		} else if g.config.Action == "log" {
			action = chain.ActionLog
		}

		// Add warning to response if applicable
		modifiedResponse := content
		if action == chain.ActionWarn {
			modifiedResponse = g.addWarningToResponse(content, indicators)
		}

		return &chain.Result{
			Passed:          action != chain.ActionBlock,
			Action:          action,
			Message:         "Potential hallucination detected",
			Violations:      []chain.Violation{violation},
			ModifiedContent: []byte(modifiedResponse),
		}, nil
	}

	return &chain.Result{Passed: true}, nil
}

// detectHallucinationIndicators checks for common hallucination patterns
func (g *HallucinationGuardrail) detectHallucinationIndicators(content string) []string {
	indicators := []string{}
	lowerContent := strings.ToLower(content)

	// Check for fabricated citations or references
	citationPatterns := []string{
		"according to a study",
		"research shows that",
		"scientists have found",
		"experts say",
		"a recent report",
	}
	for _, pattern := range citationPatterns {
		if strings.Contains(lowerContent, pattern) {
			// Check if there's an actual citation following
			if !containsActualCitation(content) {
				indicators = append(indicators, "unsupported_claim")
				break
			}
		}
	}

	// Check for specific dates, statistics without context
	if containsSpecificStatistics(content) {
		indicators = append(indicators, "specific_statistics")
	}

	// Check for fabricated quotes
	if containsFabricatedQuotes(content) {
		indicators = append(indicators, "unverified_quotes")
	}

	// Check for overly confident absolute statements
	absolutePatterns := []string{
		"it is a fact that",
		"it is proven that",
		"everyone knows that",
		"it is certain that",
		"always",
		"never",
		"100%",
	}
	for _, pattern := range absolutePatterns {
		if strings.Contains(lowerContent, pattern) {
			indicators = append(indicators, "absolute_claim")
			break
		}
	}

	// Check for common hallucination disclaimers the model might have missed
	// (sometimes models say accurate things but with wrong confidence)
	if strings.Contains(lowerContent, "i think") ||
		strings.Contains(lowerContent, "i believe") ||
		strings.Contains(lowerContent, "i'm not sure") {
		// This is actually good - model is expressing uncertainty
		// Remove any indicators that might have been added
	}

	return indicators
}

// containsActualCitation checks if text has proper citations
func containsActualCitation(content string) bool {
	// Check for URL patterns
	if strings.Contains(content, "http://") || strings.Contains(content, "https://") {
		return true
	}
	// Check for citation formats like [1], (Author, Year)
	if strings.Contains(content, "[") && strings.Contains(content, "]") {
		return true
	}
	if strings.Contains(content, "(") && strings.Contains(content, ")") {
		// Check for year pattern like (2023) or (Author, 2023)
		// Simplified check
		return strings.Contains(content, "20") || strings.Contains(content, "19")
	}
	return false
}

// containsSpecificStatistics checks for specific numbers that might be fabricated
func containsSpecificStatistics(content string) bool {
	// Look for percentage patterns followed by claims
	percentagePatterns := []string{
		"% of",
		"percent of",
		"out of every",
	}
	for _, pattern := range percentagePatterns {
		if strings.Contains(strings.ToLower(content), pattern) {
			return true
		}
	}
	return false
}

// containsFabricatedQuotes checks for quotes without attribution
func containsFabricatedQuotes(content string) bool {
	// Count quote marks
	quoteCount := strings.Count(content, "\"")
	if quoteCount >= 2 {
		// Check if there's attribution after the quote
		parts := strings.Split(content, "\"")
		for i := 2; i < len(parts); i += 2 {
			// Check if attribution follows
			if i < len(parts) {
				nextPart := strings.ToLower(parts[i])
				hasAttribution := strings.Contains(nextPart, "said") ||
					strings.Contains(nextPart, "wrote") ||
					strings.Contains(nextPart, "stated") ||
					strings.Contains(nextPart, "-") ||
					strings.Contains(nextPart, "—")
				if !hasAttribution && len(strings.TrimSpace(parts[i-1])) > 20 {
					return true
				}
			}
		}
	}
	return false
}

// addWarningToResponse adds a warning notice to the response
func (g *HallucinationGuardrail) addWarningToResponse(content string, indicators []string) string {
	// Try to parse as JSON and add warning field
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(content), &jsonResponse); err == nil {
		jsonResponse["_guardrail_warning"] = map[string]interface{}{
			"type":       "potential_hallucination",
			"indicators": indicators,
			"message":    "This response may contain unverified information. Please verify important facts.",
		}
		if modified, err := json.Marshal(jsonResponse); err == nil {
			return string(modified)
		}
	}

	// For plain text, add warning at the end
	return content + "\n\n⚠️ Note: This response may contain unverified information. Please verify important facts."
}

// Priority returns the execution order
func (g *HallucinationGuardrail) Priority() int {
	return 10 // Run first in output chain
}

// IsEnabled returns whether this guardrail is active
func (g *HallucinationGuardrail) IsEnabled() bool {
	return g.enabled
}
