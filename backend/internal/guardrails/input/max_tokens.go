package input

import (
	"time"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
)

// MaxTokensConfig holds configuration for token limits
type MaxTokensConfig struct {
	Enabled         bool `yaml:"enabled" json:"enabled"`
	MaxInputTokens  int  `yaml:"max_input_tokens" json:"max_input_tokens"`
	MaxOutputTokens int  `yaml:"max_output_tokens" json:"max_output_tokens"`
	MaxTotalTokens  int  `yaml:"max_total_tokens" json:"max_total_tokens"`
}

// MaxTokensGuardrail enforces deterministic token limits
// This is NOT a signal - it is a hard operational control
type MaxTokensGuardrail struct {
	config MaxTokensConfig
}

// NewMaxTokensGuardrail creates a new max tokens guardrail
func NewMaxTokensGuardrail(config MaxTokensConfig) *MaxTokensGuardrail {
	// Set defaults
	if config.MaxInputTokens == 0 {
		config.MaxInputTokens = 8192
	}
	if config.MaxOutputTokens == 0 {
		config.MaxOutputTokens = 4096
	}
	if config.MaxTotalTokens == 0 {
		config.MaxTotalTokens = 16384
	}

	return &MaxTokensGuardrail{
		config: config,
	}
}

// Name returns the guardrail identifier
func (g *MaxTokensGuardrail) Name() string {
	return "max_tokens"
}

// Type returns the guardrail type
func (g *MaxTokensGuardrail) Type() chain.GuardrailType {
	return chain.GuardrailTypeInput
}

// Priority returns execution priority (token check runs early - priority 3)
func (g *MaxTokensGuardrail) Priority() int {
	return 3
}

// IsEnabled returns whether this guardrail is active
func (g *MaxTokensGuardrail) IsEnabled() bool {
	return g.config.Enabled
}

// Execute performs the deterministic token limit check
func (g *MaxTokensGuardrail) Execute(ctx *chain.Context) (*chain.Result, error) {
	now := time.Now()

	if ctx.Request == nil {
		return &chain.Result{Passed: true}, nil
	}

	// Estimate tokens (rough: ~4 chars per token for English)
	// In production, you'd use a proper tokenizer
	estimatedTokens := g.estimateTokens(ctx)

	if estimatedTokens > g.config.MaxInputTokens {
		return &chain.Result{
			Passed:  false,
			Action:  chain.ActionBlock,
			Message: "Token limit exceeded: input too long",
			Violations: []chain.Violation{{
				GuardrailName: g.Name(),
				Type:          "token_limit_exceeded",
				Message:       "Deterministic limit: estimated input tokens exceeded",
				Severity:      "critical",
				Action:        chain.ActionBlock,
				Details: map[string]interface{}{
					"estimated_tokens": estimatedTokens,
					"max_tokens":       g.config.MaxInputTokens,
					"deterministic":    true,
				},
				Timestamp: now,
			}},
		}, nil
	}

	// Check if requested output tokens exceed limit
	if ctx.Request.MaxTokens > 0 && ctx.Request.MaxTokens > g.config.MaxOutputTokens {
		return &chain.Result{
			Passed:  false,
			Action:  chain.ActionBlock,
			Message: "Token limit exceeded: requested output too large",
			Violations: []chain.Violation{{
				GuardrailName: g.Name(),
				Type:          "output_token_limit_exceeded",
				Message:       "Deterministic limit: requested max_tokens exceeded policy limit",
				Severity:      "critical",
				Action:        chain.ActionBlock,
				Details: map[string]interface{}{
					"requested_tokens": ctx.Request.MaxTokens,
					"max_tokens":       g.config.MaxOutputTokens,
					"deterministic":    true,
				},
				Timestamp: now,
			}},
		}, nil
	}

	return &chain.Result{
		Passed: true,
	}, nil
}

// estimateTokens provides a rough token estimate
// In production, use tiktoken or similar
func (g *MaxTokensGuardrail) estimateTokens(ctx *chain.Context) int {
	totalChars := 0
	for _, msg := range ctx.Request.Messages {
		totalChars += len(msg.Content)
		totalChars += len(msg.Role) + 4 // role overhead
	}
	// Rough estimate: 4 characters per token
	return totalChars / 4
}
