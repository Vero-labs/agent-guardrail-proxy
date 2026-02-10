package analyzer

// Signals contains all deterministic security signals
type Signals struct {
	PII             []string `json:"pii"`
	Toxicity        float64  `json:"toxicity"`
	PromptInjection bool     `json:"prompt_injection"`
	Topic           string   `json:"topic"`
	Capabilities    []string `json:"capabilities"`
	UserText        string   `json:"user_text"`   // Extracted user content
	SystemText      string   `json:"system_text"` // Extracted system content
	FullText        string   `json:"full_text"`   // Combined for overall analysis
}

// RequestInfo contains metadata about the request
type RequestInfo struct {
	Streaming bool `json:"streaming"`
	Tokens    int  `json:"tokens"`
}

// AgentState tracks agentic workflow state for step/token budgeting
type AgentState struct {
	CurrentStep int `json:"current_step"` // Current step in agent loop
	MaxSteps    int `json:"max_steps"`    // Maximum allowed steps (0 = unlimited)
	TotalTokens int `json:"total_tokens"` // Tokens consumed so far
	TokenBudget int `json:"token_budget"` // Maximum token budget (0 = unlimited)
}

// SourceData tracks content origin for indirect injection defense
type SourceData struct {
	Origin  string `json:"origin"`  // "user", "system", "tool_output", "untrusted_web"
	Trusted bool   `json:"trusted"` // Whether the content is from a trusted source
}

// Context is the structured input to Cedar policy evaluation
type Context struct {
	// Semantic signals from LLM analyzer
	Intent              string  `json:"intent"`        // Aggregate intent
	UserIntent          string  `json:"user_intent"`   // Intent extracted from user messages ONLY
	SystemIntent        string  `json:"system_intent"` // Intent extracted from system messages ONLY
	RiskScore           float64 `json:"risk_score"`
	Confidence          float64 `json:"confidence"`
	ResourceSensitivity string  `json:"resource_sensitivity"` // "public" or "sensitive"

	// Deterministic signals from local detectors
	Signals Signals `json:"signals"`

	// Request metadata
	Request RequestInfo `json:"request"`

	// Agentic workflow state (Phase 2)
	AgentState AgentState `json:"agent_state"`

	// Content origin tracking (Phase 3 - indirect injection defense)
	SourceData SourceData `json:"source_data"`

	// Provider info
	Provider string `json:"provider"`
}

// Facts represents the structured information extracted from a user prompt
// Deprecated: Use Context instead for new code
type Facts struct {
	Intent     string  `json:"intent"`
	Risk       float64 `json:"risk"`       // 0.0 to 1.0
	Confidence float64 `json:"confidence"` // 0.0 to 1.0
	Sensitive  bool    `json:"sensitive"`
	Topic      string  `json:"topic"`
}

// ToContext converts legacy Facts to the new Context structure
func (f *Facts) ToContext() *Context {
	return &Context{
		Intent:     f.Intent,
		RiskScore:  f.Risk,
		Confidence: f.Confidence,
		Signals: Signals{
			Topic: f.Topic,
		},
	}
}

// AttachIntent adds intent signal to context.
// NOTE: Role-based weighting has been moved to Cedar policies.
// This function is now policy-neutral - it just attaches signals for Cedar to evaluate.
func (c *Context) AttachIntent(sig *IntentSignal, role string) {
	// Set role-specific intent for Cedar to evaluate separately
	switch role {
	case "user":
		c.UserIntent = sig.Intent
	case "system":
		c.SystemIntent = sig.Intent
	}

	// Calculate risk from confidence (no hardcoded intent weighting)
	currentRisk := RiskFromIntent(sig.Intent, sig.Confidence)

	// Aggregate: highest confidence wins (Cedar applies intent-specific thresholds)
	if currentRisk >= c.RiskScore || c.Intent == "" {
		c.Intent = sig.Intent
		c.Confidence = sig.Confidence
		c.RiskScore = currentRisk
	}
}

// AttachSignals merges deterministic signals with highest-risk-wins semantics
func (c *Context) AttachSignals(signals *Signals) {
	// PII: merge, never remove
	seen := make(map[string]bool)
	for _, p := range c.Signals.PII {
		seen[p] = true
	}
	for _, p := range signals.PII {
		if !seen[p] {
			c.Signals.PII = append(c.Signals.PII, p)
		}
	}

	// Toxicity: highest wins
	if signals.Toxicity > c.Signals.Toxicity {
		c.Signals.Toxicity = signals.Toxicity
	}

	// Injection: once true, always true
	if signals.PromptInjection {
		c.Signals.PromptInjection = true
	}

	// Topic: first non-empty wins
	if c.Signals.Topic == "" && signals.Topic != "" {
		c.Signals.Topic = signals.Topic
	}

	// Capabilities: merge
	capSeen := make(map[string]bool)
	for _, cap := range c.Signals.Capabilities {
		capSeen[cap] = true
	}
	for _, cap := range signals.Capabilities {
		if !capSeen[cap] {
			c.Signals.Capabilities = append(c.Signals.Capabilities, cap)
		}
	}
}
