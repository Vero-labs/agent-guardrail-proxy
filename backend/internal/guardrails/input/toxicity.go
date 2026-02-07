package input

import (
	"strings"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
)

// Common toxic/profane words (basic list - in production, use a proper profanity filter library)
var toxicWords = []string{
	// This is a minimal placeholder list
	// In production, integrate with a proper toxicity detection service
	// or use libraries like https://github.com/TwinProduction/go-away
}

// ToxicityGuardrail detects toxic, profane, or abusive content
type ToxicityGuardrail struct {
	config    policy.ToxicityConfig
	threshold float64
	enabled   bool
}

// NewToxicityGuardrail creates a new toxicity detection guardrail
func NewToxicityGuardrail(config policy.ToxicityConfig) *ToxicityGuardrail {
	threshold := config.Threshold
	if threshold == 0 {
		threshold = 0.7 // Default threshold
	}

	return &ToxicityGuardrail{
		config:    config,
		threshold: threshold,
		enabled:   config.Enabled,
	}
}

// Name returns the guardrail identifier
func (g *ToxicityGuardrail) Name() string {
	return "toxicity"
}

// Type returns the guardrail type (input)
func (g *ToxicityGuardrail) Type() chain.GuardrailType {
	return chain.GuardrailTypeInput
}

// Execute checks the request for toxic content
func (g *ToxicityGuardrail) Execute(ctx *chain.Context) (*chain.Result, error) {
	if !g.enabled {
		return &chain.Result{Passed: true}, nil
	}

	content := strings.ToLower(string(ctx.GetBodyToProcess()))

	// Also check parsed messages if available
	if ctx.Request != nil {
		for _, msg := range ctx.Request.Messages {
			content += " " + strings.ToLower(msg.Content)
		}
	}

	// Calculate toxicity score using basic heuristics
	// In production, this should call an ML model or external API
	score, matches := g.calculateToxicityScore(content)

	// If score exceeds threshold, flag as violation
	if score >= g.threshold {
		violation := chain.Violation{
			GuardrailName: g.Name(),
			Type:          "toxic_content",
			Message:       "Toxic or abusive content detected",
			Severity:      chain.SeverityHigh,
			Action:        chain.ActionType(g.config.Action),
			Details: map[string]interface{}{
				"toxicity_score": score,
				"threshold":      g.threshold,
				"indicators":     matches,
			},
		}

		action := chain.ActionBlock
		if g.config.Action == "warn" {
			action = chain.ActionWarn
		} else if g.config.Action == "log" {
			action = chain.ActionLog
		}

		return &chain.Result{
			Passed:     action != chain.ActionBlock,
			Action:     action,
			Message:    "Request blocked due to toxic content",
			Violations: []chain.Violation{violation},
		}, nil
	}

	return &chain.Result{Passed: true}, nil
}

// calculateToxicityScore calculates a toxicity score based on content analysis
// This is a simplified implementation - production should use ML models
func (g *ToxicityGuardrail) calculateToxicityScore(content string) (float64, []string) {
	score := 0.0
	matches := []string{}

	// Check for toxic words
	for _, word := range toxicWords {
		if strings.Contains(content, word) {
			score += 0.2
			matches = append(matches, word)
		}
	}

	// Check for all-caps yelling (indicator of aggression)
	words := strings.Fields(content)
	capsCount := 0
	for _, word := range words {
		if len(word) > 3 && word == strings.ToUpper(word) {
			capsCount++
		}
	}
	if len(words) > 0 && float64(capsCount)/float64(len(words)) > 0.3 {
		score += 0.1
		matches = append(matches, "excessive_caps")
	}

	// Check for excessive punctuation (!!!???)
	exclamations := strings.Count(content, "!")
	questions := strings.Count(content, "?")
	if exclamations > 3 || questions > 3 {
		score += 0.05
		matches = append(matches, "excessive_punctuation")
	}

	// Check for threatening language patterns
	threatPatterns := []string{
		"i will find you", "watch your back", "you'll regret",
		"i'll make you", "you're dead", "gonna hurt",
	}
	for _, pattern := range threatPatterns {
		if strings.Contains(content, pattern) {
			score += 0.3
			matches = append(matches, "threatening_language")
			break
		}
	}

	// Cap score at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score, matches
}

// Priority returns the execution order
func (g *ToxicityGuardrail) Priority() int {
	return 40 // Run after topic boundary
}

// IsEnabled returns whether this guardrail is active
func (g *ToxicityGuardrail) IsEnabled() bool {
	return g.enabled
}
