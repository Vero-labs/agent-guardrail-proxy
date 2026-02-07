package input

import (
	"regexp"
	"strings"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
)

// Common prompt injection patterns
var (
	// High sensitivity patterns - clear injection attempts
	highSensitivityPatterns = []string{
		`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)`,
		`(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)`,
		`(?i)forget\s+(all\s+)?(previous|prior|above|everything)`,
		`(?i)you\s+are\s+now\s+(a|an|in)\s+`,
		`(?i)act\s+as\s+if\s+you\s+(have\s+no|don'?t\s+have)\s+(restrictions?|limits?|rules?)`,
		`(?i)you\s+must\s+obey\s+me`,
		`(?i)bypass\s+(your\s+)?(safety|security|rules?|restrictions?)`,
		`(?i)jailbreak`,
		`(?i)DAN\s+mode`,
		`(?i)\[system\]|\[SYSTEM\]`,
		`(?i)<<<.*>>>`, // Common delimiter escape attempt
	}

	// Medium sensitivity patterns - suspicious but might be legitimate
	mediumSensitivityPatterns = []string{
		`(?i)pretend\s+(you\s+are|to\s+be)`,
		`(?i)roleplay\s+as`,
		`(?i)override\s+(your\s+)?(programming|training|instructions?)`,
		`(?i)new\s+instructions?:`,
		`(?i)from\s+now\s+on`,
		`(?i)the\s+following\s+is\s+your\s+new\s+`,
		`(?i)admin\s+(mode|access|override)`,
		`(?i)developer\s+mode`,
		`(?i)sudo\s+`,
	}

	// Low sensitivity patterns - might catch legitimate use
	lowSensitivityPatterns = []string{
		`(?i)you\s+are\s+a`,
		`(?i)imagine\s+you\s+are`,
		`(?i)suppose\s+you`,
	}
)

// PromptInjectionGuardrail detects and blocks prompt injection attempts
type PromptInjectionGuardrail struct {
	config   policy.PromptInjectionConfig
	patterns []*regexp.Regexp
	enabled  bool
}

// NewPromptInjectionGuardrail creates a new prompt injection guardrail
func NewPromptInjectionGuardrail(config policy.PromptInjectionConfig) *PromptInjectionGuardrail {
	g := &PromptInjectionGuardrail{
		config:  config,
		enabled: config.Enabled,
	}

	// Compile patterns based on sensitivity level
	var patternStrings []string

	switch strings.ToLower(config.Sensitivity) {
	case "low":
		patternStrings = append(patternStrings, highSensitivityPatterns...)
		patternStrings = append(patternStrings, mediumSensitivityPatterns...)
		patternStrings = append(patternStrings, lowSensitivityPatterns...)
	case "medium":
		patternStrings = append(patternStrings, highSensitivityPatterns...)
		patternStrings = append(patternStrings, mediumSensitivityPatterns...)
	case "high":
		fallthrough
	default:
		patternStrings = append(patternStrings, highSensitivityPatterns...)
	}

	// Add custom patterns
	patternStrings = append(patternStrings, config.CustomPatterns...)

	// Compile all patterns
	for _, p := range patternStrings {
		if compiled, err := regexp.Compile(p); err == nil {
			g.patterns = append(g.patterns, compiled)
		}
	}

	return g
}

// Name returns the guardrail identifier
func (g *PromptInjectionGuardrail) Name() string {
	return "prompt_injection"
}

// Type returns the guardrail type (input)
func (g *PromptInjectionGuardrail) Type() chain.GuardrailType {
	return chain.GuardrailTypeInput
}

// Execute checks the request for prompt injection patterns
func (g *PromptInjectionGuardrail) Execute(ctx *chain.Context) (*chain.Result, error) {
	if !g.enabled {
		return &chain.Result{Passed: true}, nil
	}

	// Get the text to analyze
	content := string(ctx.GetBodyToProcess())

	// Also check parsed messages if available
	if ctx.Request != nil {
		for _, msg := range ctx.Request.Messages {
			content += " " + msg.Content
		}
	}

	// Check each pattern
	var matches []string
	for _, pattern := range g.patterns {
		if match := pattern.FindString(content); match != "" {
			matches = append(matches, match)
		}
	}

	// If matches found, create violation
	if len(matches) > 0 {
		violation := chain.Violation{
			GuardrailName: g.Name(),
			Type:          "prompt_injection",
			Message:       "Potential prompt injection detected",
			Severity:      chain.SeverityHigh,
			Action:        chain.ActionType(g.config.Action),
			Details: map[string]interface{}{
				"matches":     matches,
				"sensitivity": g.config.Sensitivity,
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
			Message:    "Prompt injection attempt detected and blocked",
			Violations: []chain.Violation{violation},
		}, nil
	}

	return &chain.Result{Passed: true}, nil
}

// Priority returns the execution order (run early)
func (g *PromptInjectionGuardrail) Priority() int {
	return 10 // High priority, run first
}

// IsEnabled returns whether this guardrail is active
func (g *PromptInjectionGuardrail) IsEnabled() bool {
	return g.enabled
}
