package policy

// TopicConfig defines how a topic is detected
type TopicConfig struct {
	Keywords []string `yaml:"keywords"`
}

// GuardrailPolicy is the root configuration structure
type GuardrailPolicy struct {
	Version             string                    `yaml:"version"`
	Safety              SafetyConfig              `yaml:"safety"`
	Pii                 PIIConfig                 `yaml:"pii"`
	Capabilities        CapabilitiesConfig        `yaml:"capabilities"`
	Intents             map[string]IntentRule     `yaml:"intents"`
	UserIntentOverrides map[string]IntentOverride `yaml:"user_intent_overrides"`
	Topics              map[string]TopicConfig    `yaml:"topics"` // NEW: Configurable topic definitions
	Roles               map[string]RoleConfig     `yaml:"roles"`
	AgentLimits         AgentLimitsConfig         `yaml:"agent_limits"`
	SourceTrust         map[string]SourceRule     `yaml:"source_trust"`
}

// SafetyConfig holds global safety thresholds
type SafetyConfig struct {
	PromptInjection   string  `yaml:"prompt_injection"`   // "block" | "log" | "off"
	ToxicityThreshold float64 `yaml:"toxicity_threshold"` // 0.0–1.0
	MaxRiskScore      float64 `yaml:"max_risk_score"`     // 0.0–1.0
}

// PIIConfig defines PII handling rules
type PIIConfig struct {
	Block  []string `yaml:"block"`  // PII types to block (e.g. ssn, credit_card)
	Redact []string `yaml:"redact"` // PII types to redact (e.g. email, phone)
}

// CapabilitiesConfig defines capability blocking
type CapabilitiesConfig struct {
	Block []string `yaml:"block"` // capability names to block
}

// IntentRule defines policy for a specific intent class
type IntentRule struct {
	Action    string           `yaml:"action"`    // "block" | "log" | "allow"
	Threshold int              `yaml:"threshold"` // confidence 0–100
	When      *IntentCondition `yaml:"when,omitempty"`
}

// IntentCondition adds conditional logic to an intent rule
type IntentCondition struct {
	Sensitivity string `yaml:"sensitivity,omitempty"` // "sensitive" | "public"
}

// IntentOverride allows stricter thresholds for user-originated intents
type IntentOverride struct {
	Threshold int `yaml:"threshold"` // confidence 0–100
}

// RoleConfig defines what a specific role can and cannot do
type RoleConfig struct {
	Description               string   `yaml:"description"`
	AllowActions              []string `yaml:"allow_actions"`               // first-class action verbs: query, summarize, greeting, etc.
	AllowedTopics             []string `yaml:"allowed_topics"`              // domain nouns: recruitment, hr, etc.
	BlockIntents              []string `yaml:"block_intents"`               // explicitly blocked intents
	BlockTopics               []string `yaml:"block_topics"`                // explicitly blocked topics
	DomainConfidenceThreshold float64  `yaml:"domain_confidence_threshold"` // 0.0-1.0, default 0.6
	ActionConfidenceThreshold float64  `yaml:"action_confidence_threshold"` // 0.0-1.0, default 0.65
}

// AgentLimitsConfig controls agentic workflow budgets
type AgentLimitsConfig struct {
	MaxSteps           int `yaml:"max_steps"`
	TokenBudget        int `yaml:"token_budget"`
	TightenAfterStep   int `yaml:"tighten_after_step"`
	TightenedThreshold int `yaml:"tightened_threshold"`
}

// SourceRule defines what intents to block for a specific content source
type SourceRule struct {
	BlockIntents []string `yaml:"block_intents"`
}
