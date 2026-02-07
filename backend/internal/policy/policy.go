package policy

import (
	"time"
)

// Policy defines the complete guardrail configuration for an application
type Policy struct {
	ID          string            `yaml:"id" json:"id"`
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description" json:"description"`
	Version     string            `yaml:"version" json:"version"`
	Guardrails  GuardrailConfig   `yaml:"guardrails" json:"guardrails"`
	Actions     map[string]Action `yaml:"actions" json:"actions"`
	Logging     LoggingConfig     `yaml:"logging" json:"logging"`
	CreatedAt   time.Time         `yaml:"created_at" json:"created_at"`
	UpdatedAt   time.Time         `yaml:"updated_at" json:"updated_at"`
}

// GuardrailConfig contains configuration for input and output guardrails
// IMPORTANT DISTINCTION:
// - Input/Output contain SIGNAL-based guardrails (heuristic, may have false positives)
// - DeterministicControls contain HARD limits (no ambiguity, operational controls)
type GuardrailConfig struct {
	Input                 InputConfig                 `yaml:"input" json:"input"`
	Output                OutputConfig                `yaml:"output" json:"output"`
	DeterministicControls DeterministicControlsConfig `yaml:"deterministic_controls" json:"deterministic_controls"`
}

// DeterministicControlsConfig holds configuration for hard operational limits
// These are NOT signals - they are absolute limits with no false positives
type DeterministicControlsConfig struct {
	RateLimit   RateLimitControlConfig   `yaml:"rate_limit" json:"rate_limit"`
	PayloadSize PayloadSizeControlConfig `yaml:"payload_size" json:"payload_size"`
	MaxTokens   MaxTokensControlConfig   `yaml:"max_tokens" json:"max_tokens"`
	Timeout     TimeoutControlConfig     `yaml:"timeout" json:"timeout"`
}

// RateLimitControlConfig - DETERMINISTIC: hard request rate limits
type RateLimitControlConfig struct {
	Enabled           bool   `yaml:"enabled" json:"enabled"`
	RequestsPerMinute int    `yaml:"requests_per_minute" json:"requests_per_minute"`
	RequestsPerHour   int    `yaml:"requests_per_hour" json:"requests_per_hour"`
	BurstSize         int    `yaml:"burst_size" json:"burst_size"`
	KeyBy             string `yaml:"key_by" json:"key_by"` // global, user, app, ip
}

// PayloadSizeControlConfig - DETERMINISTIC: hard size limits
type PayloadSizeControlConfig struct {
	Enabled        bool  `yaml:"enabled" json:"enabled"`
	MaxRequestSize int64 `yaml:"max_request_size" json:"max_request_size"`
	MaxMessageSize int64 `yaml:"max_message_size" json:"max_message_size"`
	MaxMessages    int   `yaml:"max_messages" json:"max_messages"`
}

// MaxTokensControlConfig - DETERMINISTIC: hard token limits
type MaxTokensControlConfig struct {
	Enabled         bool `yaml:"enabled" json:"enabled"`
	MaxInputTokens  int  `yaml:"max_input_tokens" json:"max_input_tokens"`
	MaxOutputTokens int  `yaml:"max_output_tokens" json:"max_output_tokens"`
}

// TimeoutControlConfig - DETERMINISTIC: hard timeout limits
type TimeoutControlConfig struct {
	Enabled         bool `yaml:"enabled" json:"enabled"`
	RequestTimeout  int  `yaml:"request_timeout" json:"request_timeout"`   // seconds
	ProviderTimeout int  `yaml:"provider_timeout" json:"provider_timeout"` // seconds
}

// InputConfig holds configuration for all input guardrails
type InputConfig struct {
	PromptInjection PromptInjectionConfig `yaml:"prompt_injection" json:"prompt_injection"`
	PIIDetection    PIIDetectionConfig    `yaml:"pii_detection" json:"pii_detection"`
	TopicBoundary   TopicBoundaryConfig   `yaml:"topic_boundary" json:"topic_boundary"`
	Toxicity        ToxicityConfig        `yaml:"toxicity" json:"toxicity"`
}

// OutputConfig holds configuration for all output guardrails
type OutputConfig struct {
	HallucinationDetection HallucinationConfig     `yaml:"hallucination_detection" json:"hallucination_detection"`
	FormatValidation       FormatValidationConfig  `yaml:"format_validation" json:"format_validation"`
	ContentModeration      ContentModerationConfig `yaml:"content_moderation" json:"content_moderation"`
}

// PromptInjectionConfig configures prompt injection detection
type PromptInjectionConfig struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	Sensitivity    string   `yaml:"sensitivity" json:"sensitivity"` // low, medium, high
	Action         string   `yaml:"action" json:"action"`
	CustomPatterns []string `yaml:"custom_patterns" json:"custom_patterns"`
}

// PIIDetectionConfig configures PII detection and handling
type PIIDetectionConfig struct {
	Enabled bool     `yaml:"enabled" json:"enabled"`
	Types   []string `yaml:"types" json:"types"` // email, phone, ssn, credit_card, etc.
	Action  string   `yaml:"action" json:"action"`
}

// TopicBoundaryConfig configures topic/domain restrictions
type TopicBoundaryConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	AllowedTopics []string `yaml:"allowed_topics" json:"allowed_topics"` // Empty = allow all
	BlockedTopics []string `yaml:"blocked_topics" json:"blocked_topics"`
	Action        string   `yaml:"action" json:"action"`
}

// ToxicityConfig configures toxicity/profanity detection
type ToxicityConfig struct {
	Enabled   bool    `yaml:"enabled" json:"enabled"`
	Threshold float64 `yaml:"threshold" json:"threshold"` // 0.0 - 1.0
	Action    string  `yaml:"action" json:"action"`
}

// HallucinationConfig configures hallucination detection
type HallucinationConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	GroundingSources []string `yaml:"grounding_sources" json:"grounding_sources"`
	Action           string   `yaml:"action" json:"action"`
}

// FormatValidationConfig configures output format validation
type FormatValidationConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	Schema     string `yaml:"schema" json:"schema"` // JSON schema
	StrictMode bool   `yaml:"strict_mode" json:"strict_mode"`
	Action     string `yaml:"action" json:"action"`
}

// ContentModerationConfig configures output content moderation
type ContentModerationConfig struct {
	Enabled    bool     `yaml:"enabled" json:"enabled"`
	Categories []string `yaml:"categories" json:"categories"` // violence, nsfw, hate, etc.
	Action     string   `yaml:"action" json:"action"`
}

// Action defines what happens when a guardrail triggers
type Action struct {
	Type       string `yaml:"type" json:"type"` // reject, modify, pass
	Message    string `yaml:"message" json:"message"`
	AddWarning bool   `yaml:"add_warning" json:"add_warning"`
	LogLevel   string `yaml:"log_level" json:"log_level"` // debug, info, warn, error
}

// LoggingConfig configures audit logging
type LoggingConfig struct {
	Level         string `yaml:"level" json:"level"` // debug, info, warn, error
	IncludeBody   bool   `yaml:"include_body" json:"include_body"`
	RetentionDays int    `yaml:"retention_days" json:"retention_days"`
}

// DefaultPolicy returns a sensible default policy
func DefaultPolicy() *Policy {
	return &Policy{
		ID:          "default",
		Name:        "Default Security Policy",
		Description: "A balanced security policy for general use",
		Version:     "1.0.0",
		Guardrails: GuardrailConfig{
			Input: InputConfig{
				PromptInjection: PromptInjectionConfig{
					Enabled:     true,
					Sensitivity: "medium",
					Action:      "block",
				},
				PIIDetection: PIIDetectionConfig{
					Enabled: true,
					Types:   []string{"email", "phone", "ssn", "credit_card"},
					Action:  "redact",
				},
				TopicBoundary: TopicBoundaryConfig{
					Enabled:       true,
					BlockedTopics: []string{"violence", "illegal_activity", "harmful_content"},
					Action:        "block",
				},
				Toxicity: ToxicityConfig{
					Enabled:   true,
					Threshold: 0.7,
					Action:    "block",
				},
			},
			Output: OutputConfig{
				HallucinationDetection: HallucinationConfig{
					Enabled: true,
					Action:  "warn",
				},
				FormatValidation: FormatValidationConfig{
					Enabled: false,
				},
				ContentModeration: ContentModerationConfig{
					Enabled:    true,
					Categories: []string{"hate", "violence", "self_harm"},
					Action:     "filter",
				},
			},
			DeterministicControls: DeterministicControlsConfig{
				RateLimit: RateLimitControlConfig{
					Enabled:           true,
					RequestsPerMinute: 5, // Set low for easy testing
					RequestsPerHour:   100,
					KeyBy:             "global",
				},
				PayloadSize: PayloadSizeControlConfig{
					Enabled:        true,
					MaxRequestSize: 1024 * 1024, // 1MB
					MaxMessages:    50,
				},
				MaxTokens: MaxTokensControlConfig{
					Enabled:        true,
					MaxInputTokens: 4096,
				},
			},
		},
		Actions: map[string]Action{
			"block": {
				Type:     "reject",
				Message:  "Request blocked due to policy violation",
				LogLevel: "warn",
			},
			"redact": {
				Type:     "modify",
				LogLevel: "info",
			},
			"warn": {
				Type:       "pass",
				AddWarning: true,
				LogLevel:   "info",
			},
			"filter": {
				Type:     "modify",
				LogLevel: "info",
			},
		},
		Logging: LoggingConfig{
			Level:         "info",
			IncludeBody:   false,
			RetentionDays: 30,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}
