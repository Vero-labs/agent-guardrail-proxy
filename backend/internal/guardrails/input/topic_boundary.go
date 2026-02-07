package input

import (
	"strings"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
)

// Built-in blocked topics and their associated keywords
var topicKeywords = map[string][]string{
	"violence": {
		"kill", "murder", "attack", "weapon", "bomb", "explosive", "assassinate",
		"harm", "hurt", "injure", "shoot", "stab", "torture", "abuse",
	},
	"illegal_activity": {
		"hack", "hacking", "crack", "pirate", "piracy", "drug", "drugs",
		"counterfeit", "fraud", "steal", "theft", "launder", "smuggle",
		"bribe", "blackmail", "extort",
	},
	"harmful_content": {
		"suicide", "self-harm", "eating disorder", "anorexia", "bulimia",
		"cutting", "overdose",
	},
	"explicit_content": {
		"porn", "pornography", "nsfw", "xxx", "nude", "naked", "sexual",
	},
	"hate_speech": {
		"racist", "racism", "sexist", "sexism", "homophobic", "transphobic",
		"slur", "bigot", "supremacist", "nazi", "fascist",
	},
	"misinformation": {
		"fake news", "conspiracy", "hoax", "anti-vax", "flat earth",
		"election fraud", "false flag",
	},
}

// TopicBoundaryGuardrail enforces allowed/blocked topic restrictions
type TopicBoundaryGuardrail struct {
	config        policy.TopicBoundaryConfig
	blockedTopics map[string][]string
	allowedTopics map[string]bool
	enabled       bool
}

// NewTopicBoundaryGuardrail creates a new topic boundary guardrail
func NewTopicBoundaryGuardrail(config policy.TopicBoundaryConfig) *TopicBoundaryGuardrail {
	g := &TopicBoundaryGuardrail{
		config:        config,
		blockedTopics: make(map[string][]string),
		allowedTopics: make(map[string]bool),
		enabled:       config.Enabled,
	}

	// Add blocked topics
	for _, topic := range config.BlockedTopics {
		topic = strings.ToLower(topic)
		if keywords, ok := topicKeywords[topic]; ok {
			g.blockedTopics[topic] = keywords
		} else {
			// Custom topic - use the topic name as keyword
			g.blockedTopics[topic] = []string{topic}
		}
	}

	// Add allowed topics
	for _, topic := range config.AllowedTopics {
		g.allowedTopics[strings.ToLower(topic)] = true
	}

	return g
}

// Name returns the guardrail identifier
func (g *TopicBoundaryGuardrail) Name() string {
	return "topic_boundary"
}

// Type returns the guardrail type (input)
func (g *TopicBoundaryGuardrail) Type() chain.GuardrailType {
	return chain.GuardrailTypeInput
}

// Execute checks the request for blocked topics
func (g *TopicBoundaryGuardrail) Execute(ctx *chain.Context) (*chain.Result, error) {
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

	// Check for blocked topics
	var violations []chain.Violation
	detectedTopics := make(map[string][]string)

	for topic, keywords := range g.blockedTopics {
		matchedKeywords := []string{}
		for _, keyword := range keywords {
			if strings.Contains(content, keyword) {
				matchedKeywords = append(matchedKeywords, keyword)
			}
		}
		if len(matchedKeywords) > 0 {
			detectedTopics[topic] = matchedKeywords
		}
	}

	// If blocked topics detected, create violations
	if len(detectedTopics) > 0 {
		topicNames := make([]string, 0, len(detectedTopics))
		for topic := range detectedTopics {
			topicNames = append(topicNames, topic)
		}

		violation := chain.Violation{
			GuardrailName: g.Name(),
			Type:          "blocked_topic",
			Message:       "Request contains blocked topic content",
			Severity:      chain.SeverityHigh,
			Action:        chain.ActionType(g.config.Action),
			Details: map[string]interface{}{
				"detected_topics": topicNames,
				"matches":         detectedTopics,
			},
		}
		violations = append(violations, violation)

		action := chain.ActionBlock
		if g.config.Action == "warn" {
			action = chain.ActionWarn
		} else if g.config.Action == "log" {
			action = chain.ActionLog
		}

		return &chain.Result{
			Passed:     action != chain.ActionBlock,
			Action:     action,
			Message:    "Request blocked due to restricted topic: " + strings.Join(topicNames, ", "),
			Violations: violations,
		}, nil
	}

	return &chain.Result{Passed: true}, nil
}

// Priority returns the execution order
func (g *TopicBoundaryGuardrail) Priority() int {
	return 30 // Run after PII detection
}

// IsEnabled returns whether this guardrail is active
func (g *TopicBoundaryGuardrail) IsEnabled() bool {
	return g.enabled
}
