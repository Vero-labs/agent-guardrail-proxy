package chain

import (
	"time"

	"github.com/google/uuid"
)

// GuardrailType indicates whether the guardrail runs on input or output
type GuardrailType string

const (
	GuardrailTypeInput  GuardrailType = "input"
	GuardrailTypeOutput GuardrailType = "output"
)

// ActionType defines what action to take when a guardrail triggers
type ActionType string

const (
	ActionBlock  ActionType = "block"  // Reject the request entirely
	ActionRedact ActionType = "redact" // Modify content to remove violations
	ActionWarn   ActionType = "warn"   // Allow but add warning
	ActionLog    ActionType = "log"    // Just log, no action
	ActionPass   ActionType = "pass"   // Allow through
)

// Severity indicates the severity level of a violation
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Violation represents a policy violation detected by a guardrail
type Violation struct {
	GuardrailName string                 `json:"guardrail_name"`
	Type          string                 `json:"type"`
	Message       string                 `json:"message"`
	Severity      Severity               `json:"severity"`
	Action        ActionType             `json:"action"`
	Details       map[string]interface{} `json:"details,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
}

// LLMMessage represents a single message in the conversation
type LLMMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// LLMRequest represents a normalized LLM request across providers
type LLMRequest struct {
	Model       string                 `json:"model"`
	Messages    []LLMMessage           `json:"messages"`
	Temperature float64                `json:"temperature,omitempty"`
	MaxTokens   int                    `json:"max_tokens,omitempty"`
	Stream      bool                   `json:"stream,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// LLMResponse represents a normalized LLM response across providers
type LLMResponse struct {
	Content      string   `json:"content"`
	FinishReason string   `json:"finish_reason"`
	Model        string   `json:"model"`
	Usage        *Usage   `json:"usage,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// Usage tracks token usage for cost calculation
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

// Context carries request information through the guardrail chain
type Context struct {
	// Request identification
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`

	// Original and potentially modified request
	OriginalBody []byte      `json:"original_body,omitempty"`
	ModifiedBody []byte      `json:"modified_body,omitempty"`
	Request      *LLMRequest `json:"request,omitempty"`

	// Response (populated after LLM call)
	OriginalResponse []byte       `json:"original_response,omitempty"`
	ModifiedResponse []byte       `json:"modified_response,omitempty"`
	Response         *LLMResponse `json:"response,omitempty"`

	// Authorization info
	UserID   string `json:"user_id,omitempty"`
	AppID    string `json:"app_id,omitempty"`
	APIKeyID string `json:"api_key_id,omitempty"`

	// Provider routing
	ProviderName string `json:"provider_name,omitempty"`

	// Policy and violations
	PolicyID   string      `json:"policy_id,omitempty"`
	Violations []Violation `json:"violations,omitempty"`

	// Arbitrary metadata for passing data between guardrails
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Flags
	Blocked  bool   `json:"blocked"`
	BlockMsg string `json:"block_message,omitempty"`
}

// NewContext creates a new context for a request
func NewContext() *Context {
	return &Context{
		RequestID:  uuid.New().String(),
		Timestamp:  time.Now(),
		Violations: make([]Violation, 0),
		Metadata:   make(map[string]interface{}),
	}
}

// AddViolation records a policy violation
func (c *Context) AddViolation(v Violation) {
	v.Timestamp = time.Now()
	c.Violations = append(c.Violations, v)
}

// HasViolations returns true if any violations were recorded
func (c *Context) HasViolations() bool {
	return len(c.Violations) > 0
}

// HasBlockingViolation returns true if any violation requires blocking
func (c *Context) HasBlockingViolation() bool {
	for _, v := range c.Violations {
		if v.Action == ActionBlock {
			return true
		}
	}
	return false
}

// GetBodyToProcess returns the current body to process (modified if available, original otherwise)
func (c *Context) GetBodyToProcess() []byte {
	if c.ModifiedBody != nil {
		return c.ModifiedBody
	}
	return c.OriginalBody
}

// GetResponseToProcess returns the current response to process
func (c *Context) GetResponseToProcess() []byte {
	if c.ModifiedResponse != nil {
		return c.ModifiedResponse
	}
	return c.OriginalResponse
}
