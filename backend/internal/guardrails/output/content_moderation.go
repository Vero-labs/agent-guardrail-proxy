package output

import (
	"encoding/json"
	"strings"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
)

// Content moderation categories
const (
	CategoryHate     = "hate"
	CategoryViolence = "violence"
	CategorySelfHarm = "self_harm"
	CategorySexual   = "sexual"
	CategoryDrugs    = "drugs"
	CategoryWeapons  = "weapons"
)

// Category keywords for basic content moderation
var categoryKeywords = map[string][]string{
	CategoryHate: {
		"racist", "racism", "sexist", "sexism", "bigot", "slur",
		"discrimination", "supremacist", "nazi", "hate speech",
	},
	CategoryViolence: {
		"kill", "murder", "attack", "assault", "bomb", "shoot",
		"stab", "torture", "massacre", "execute",
	},
	CategorySelfHarm: {
		"suicide", "self-harm", "cut myself", "end my life",
		"kill myself", "harm myself", "overdose",
	},
	CategorySexual: {
		"explicit", "pornographic", "nsfw", "xxx", "sexual content",
	},
	CategoryDrugs: {
		"how to make drugs", "drug recipe", "synthesize",
		"cook meth", "make cocaine",
	},
	CategoryWeapons: {
		"how to make a bomb", "build explosives", "weapon tutorial",
		"3d print gun", "make poison",
	},
}

// ContentModerationGuardrail filters inappropriate content from LLM responses
type ContentModerationGuardrail struct {
	config            policy.ContentModerationConfig
	enabledCategories map[string]bool
	enabled           bool
}

// NewContentModerationGuardrail creates a new content moderation guardrail
func NewContentModerationGuardrail(config policy.ContentModerationConfig) *ContentModerationGuardrail {
	g := &ContentModerationGuardrail{
		config:            config,
		enabledCategories: make(map[string]bool),
		enabled:           config.Enabled,
	}

	// Enable specified categories
	for _, cat := range config.Categories {
		g.enabledCategories[strings.ToLower(cat)] = true
	}

	// If no categories specified, enable all
	if len(config.Categories) == 0 {
		for cat := range categoryKeywords {
			g.enabledCategories[cat] = true
		}
	}

	return g
}

// Name returns the guardrail identifier
func (g *ContentModerationGuardrail) Name() string {
	return "content_moderation"
}

// Type returns the guardrail type (output)
func (g *ContentModerationGuardrail) Type() chain.GuardrailType {
	return chain.GuardrailTypeOutput
}

// Execute checks the LLM response for inappropriate content
func (g *ContentModerationGuardrail) Execute(ctx *chain.Context) (*chain.Result, error) {
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

	lowerContent := strings.ToLower(content)

	// Check for violations in each enabled category
	violations := make(map[string][]string)

	for category, keywords := range categoryKeywords {
		if !g.enabledCategories[category] {
			continue
		}

		matchedKeywords := []string{}
		for _, keyword := range keywords {
			if strings.Contains(lowerContent, keyword) {
				matchedKeywords = append(matchedKeywords, keyword)
			}
		}

		if len(matchedKeywords) > 0 {
			violations[category] = matchedKeywords
		}
	}

	// If violations found
	if len(violations) > 0 {
		categories := make([]string, 0, len(violations))
		for cat := range violations {
			categories = append(categories, cat)
		}

		violation := chain.Violation{
			GuardrailName: g.Name(),
			Type:          "inappropriate_content",
			Message:       "Response contains potentially inappropriate content",
			Severity:      chain.SeverityHigh,
			Action:        chain.ActionType(g.config.Action),
			Details: map[string]interface{}{
				"categories": categories,
				"matches":    violations,
			},
		}

		action := chain.ActionType(g.config.Action)
		if action == "" {
			action = chain.ActionWarn
		}

		result := &chain.Result{
			Passed:     action != chain.ActionBlock,
			Action:     action,
			Message:    "Content moderation triggered for categories: " + strings.Join(categories, ", "),
			Violations: []chain.Violation{violation},
		}

		// If action is filter/modify, sanitize the response
		if action == chain.ActionRedact || g.config.Action == "filter" {
			result.ModifiedContent = []byte(g.sanitizeContent(content, violations))
			result.Passed = true
		}

		return result, nil
	}

	return &chain.Result{Passed: true}, nil
}

// sanitizeContent removes or masks inappropriate content
func (g *ContentModerationGuardrail) sanitizeContent(content string, violations map[string][]string) string {
	result := content

	// Replace matched keywords with [FILTERED]
	for _, keywords := range violations {
		for _, keyword := range keywords {
			// Case-insensitive replacement
			result = replaceIgnoreCase(result, keyword, "[FILTERED]")
		}
	}

	// Add moderation notice
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(result), &jsonResponse); err == nil {
		jsonResponse["_content_filtered"] = true
		jsonResponse["_filter_notice"] = "Some content in this response has been filtered for policy compliance."
		if modified, err := json.Marshal(jsonResponse); err == nil {
			return string(modified)
		}
	}

	return result + "\n\n[Some content has been filtered for policy compliance]"
}

// replaceIgnoreCase replaces all occurrences of a pattern case-insensitively
func replaceIgnoreCase(str, pattern, replacement string) string {
	lowerStr := strings.ToLower(str)
	lowerPattern := strings.ToLower(pattern)

	result := str
	for {
		idx := strings.Index(strings.ToLower(result), lowerPattern)
		if idx == -1 {
			break
		}
		result = result[:idx] + replacement + result[idx+len(pattern):]
		// Update lowerStr for next search
		lowerStr = strings.ToLower(result)
		_ = lowerStr // Use in next iteration
	}

	return result
}

// Priority returns the execution order
func (g *ContentModerationGuardrail) Priority() int {
	return 20 // Run after hallucination detection
}

// IsEnabled returns whether this guardrail is active
func (g *ContentModerationGuardrail) IsEnabled() bool {
	return g.enabled
}
