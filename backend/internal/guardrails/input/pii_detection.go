package input

import (
	"regexp"
	"strings"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
)

// PII type constants
const (
	PIITypeEmail      = "email"
	PIITypePhone      = "phone"
	PIITypeSSN        = "ssn"
	PIITypeCreditCard = "credit_card"
	PIITypeIPAddress  = "ip_address"
	PIITypeName       = "name"
	PIITypeAddress    = "address"
)

// PII detection patterns
var piiPatterns = map[string]*regexp.Regexp{
	PIITypeEmail:      regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
	PIITypePhone:      regexp.MustCompile(`(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`),
	PIITypeSSN:        regexp.MustCompile(`\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`),
	PIITypeCreditCard: regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{16}\b`),
	PIITypeIPAddress:  regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
}

// PIIMatch represents a detected PII instance
type PIIMatch struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Position int    `json:"position"`
	Length   int    `json:"length"`
}

// PIIDetectionGuardrail detects and optionally redacts PII from input
type PIIDetectionGuardrail struct {
	config       policy.PIIDetectionConfig
	enabledTypes map[string]bool
	enabled      bool
}

// NewPIIDetectionGuardrail creates a new PII detection guardrail
func NewPIIDetectionGuardrail(config policy.PIIDetectionConfig) *PIIDetectionGuardrail {
	g := &PIIDetectionGuardrail{
		config:       config,
		enabledTypes: make(map[string]bool),
		enabled:      config.Enabled,
	}

	// Enable specified types
	for _, t := range config.Types {
		g.enabledTypes[strings.ToLower(t)] = true
	}

	// If no types specified, enable all
	if len(config.Types) == 0 {
		for t := range piiPatterns {
			g.enabledTypes[t] = true
		}
	}

	return g
}

// Name returns the guardrail identifier
func (g *PIIDetectionGuardrail) Name() string {
	return "pii_detection"
}

// Type returns the guardrail type (input)
func (g *PIIDetectionGuardrail) Type() chain.GuardrailType {
	return chain.GuardrailTypeInput
}

// Execute checks the request for PII and optionally redacts it
func (g *PIIDetectionGuardrail) Execute(ctx *chain.Context) (*chain.Result, error) {
	if !g.enabled {
		return &chain.Result{Passed: true}, nil
	}

	content := string(ctx.GetBodyToProcess())
	var matches []PIIMatch

	// Detect PII for each enabled type
	for piiType, pattern := range piiPatterns {
		if !g.enabledTypes[piiType] {
			continue
		}

		locs := pattern.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			matches = append(matches, PIIMatch{
				Type:     piiType,
				Value:    content[loc[0]:loc[1]],
				Position: loc[0],
				Length:   loc[1] - loc[0],
			})
		}
	}

	// If no PII found, pass
	if len(matches) == 0 {
		return &chain.Result{Passed: true}, nil
	}

	// Determine action
	action := chain.ActionType(g.config.Action)
	result := &chain.Result{
		Passed:  action != chain.ActionBlock,
		Action:  action,
		Message: "PII detected in request",
	}

	// Create violation for logging
	types := make([]string, 0)
	for _, m := range matches {
		types = append(types, m.Type)
	}

	violation := chain.Violation{
		GuardrailName: g.Name(),
		Type:          "pii_detected",
		Message:       "Personally identifiable information detected",
		Severity:      chain.SeverityMedium,
		Action:        action,
		Details: map[string]interface{}{
			"pii_types":   unique(types),
			"match_count": len(matches),
		},
	}
	result.Violations = []chain.Violation{violation}

	// If action is redact, modify the content
	if action == chain.ActionRedact || g.config.Action == "redact" {
		redactedContent := g.redactContent(content, matches)
		result.ModifiedContent = []byte(redactedContent)
		result.Passed = true // Allow to pass after redaction
	}

	return result, nil
}

// redactContent replaces PII with redaction markers
func (g *PIIDetectionGuardrail) redactContent(content string, matches []PIIMatch) string {
	// Sort matches by position descending to replace from end
	sortedMatches := make([]PIIMatch, len(matches))
	copy(sortedMatches, matches)

	// Simple bubble sort for small arrays
	for i := 0; i < len(sortedMatches)-1; i++ {
		for j := i + 1; j < len(sortedMatches); j++ {
			if sortedMatches[i].Position < sortedMatches[j].Position {
				sortedMatches[i], sortedMatches[j] = sortedMatches[j], sortedMatches[i]
			}
		}
	}

	result := content
	for _, m := range sortedMatches {
		redaction := "[" + strings.ToUpper(m.Type) + "_REDACTED]"
		result = result[:m.Position] + redaction + result[m.Position+m.Length:]
	}

	return result
}

// Priority returns the execution order
func (g *PIIDetectionGuardrail) Priority() int {
	return 20 // Run after prompt injection
}

// IsEnabled returns whether this guardrail is active
func (g *PIIDetectionGuardrail) IsEnabled() bool {
	return g.enabled
}

// unique returns unique strings from a slice
func unique(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
