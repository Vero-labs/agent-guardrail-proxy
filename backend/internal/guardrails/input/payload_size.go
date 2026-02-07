package input

import (
	"time"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
)

// PayloadSizeConfig holds configuration for payload size limits
type PayloadSizeConfig struct {
	Enabled        bool  `yaml:"enabled" json:"enabled"`
	MaxRequestSize int64 `yaml:"max_request_size" json:"max_request_size"` // bytes
	MaxMessageSize int64 `yaml:"max_message_size" json:"max_message_size"` // bytes per message
	MaxMessages    int   `yaml:"max_messages" json:"max_messages"`         // messages per request
}

// PayloadSizeGuardrail enforces deterministic size limits
// This is NOT a signal - it is a hard operational control
type PayloadSizeGuardrail struct {
	config PayloadSizeConfig
}

// NewPayloadSizeGuardrail creates a new payload size guardrail
func NewPayloadSizeGuardrail(config PayloadSizeConfig) *PayloadSizeGuardrail {
	// Set defaults
	if config.MaxRequestSize == 0 {
		config.MaxRequestSize = 10 * 1024 * 1024 // 10MB
	}
	if config.MaxMessageSize == 0 {
		config.MaxMessageSize = 1 * 1024 * 1024 // 1MB per message
	}
	if config.MaxMessages == 0 {
		config.MaxMessages = 100
	}

	return &PayloadSizeGuardrail{
		config: config,
	}
}

// Name returns the guardrail identifier
func (g *PayloadSizeGuardrail) Name() string {
	return "payload_size"
}

// Type returns the guardrail type
func (g *PayloadSizeGuardrail) Type() chain.GuardrailType {
	return chain.GuardrailTypeInput
}

// Priority returns execution priority (size check runs FIRST - priority 2)
func (g *PayloadSizeGuardrail) Priority() int {
	return 2
}

// IsEnabled returns whether this guardrail is active
func (g *PayloadSizeGuardrail) IsEnabled() bool {
	return g.config.Enabled
}

// Execute performs the deterministic payload size check
func (g *PayloadSizeGuardrail) Execute(ctx *chain.Context) (*chain.Result, error) {
	now := time.Now()

	// Check total request size
	requestSize := int64(len(ctx.OriginalBody))
	if requestSize > g.config.MaxRequestSize {
		return &chain.Result{
			Passed:  false,
			Action:  chain.ActionBlock,
			Message: "Payload size exceeded: request too large",
			Violations: []chain.Violation{{
				GuardrailName: g.Name(),
				Type:          "payload_size_exceeded",
				Message:       "Deterministic limit: request payload size exceeded",
				Severity:      "critical",
				Action:        chain.ActionBlock,
				Details: map[string]interface{}{
					"actual_size":   requestSize,
					"max_size":      g.config.MaxRequestSize,
					"deterministic": true,
				},
				Timestamp: now,
			}},
		}, nil
	}

	// Check message count
	if ctx.Request != nil && len(ctx.Request.Messages) > g.config.MaxMessages {
		return &chain.Result{
			Passed:  false,
			Action:  chain.ActionBlock,
			Message: "Payload size exceeded: too many messages",
			Violations: []chain.Violation{{
				GuardrailName: g.Name(),
				Type:          "message_count_exceeded",
				Message:       "Deterministic limit: message count exceeded",
				Severity:      "critical",
				Action:        chain.ActionBlock,
				Details: map[string]interface{}{
					"actual_count":  len(ctx.Request.Messages),
					"max_count":     g.config.MaxMessages,
					"deterministic": true,
				},
				Timestamp: now,
			}},
		}, nil
	}

	// Check individual message sizes
	if ctx.Request != nil {
		for i, msg := range ctx.Request.Messages {
			msgSize := int64(len(msg.Content))
			if msgSize > g.config.MaxMessageSize {
				return &chain.Result{
					Passed:  false,
					Action:  chain.ActionBlock,
					Message: "Payload size exceeded: message too large",
					Violations: []chain.Violation{{
						GuardrailName: g.Name(),
						Type:          "message_size_exceeded",
						Message:       "Deterministic limit: individual message size exceeded",
						Severity:      "critical",
						Action:        chain.ActionBlock,
						Details: map[string]interface{}{
							"message_index": i,
							"actual_size":   msgSize,
							"max_size":      g.config.MaxMessageSize,
							"deterministic": true,
						},
						Timestamp: now,
					}},
				}, nil
			}
		}
	}

	return &chain.Result{
		Passed: true,
	}, nil
}
