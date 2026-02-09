package cedar

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/analyzer"
	"github.com/cedar-policy/cedar-go"
)

// Decision represents the result of a policy evaluation
type Decision string

const (
	ALLOW     Decision = "ALLOW"
	DENY      Decision = "DENY"
	CONSTRAIN Decision = "CONSTRAIN"
)

// Engine wraps the Cedar policy engine
type Engine struct {
	policySet     *cedar.PolicySet
	PolicyVersion string // SHA256 of the policy file (first 12 chars)
	PolicyPath    string
}

// NewEngine creates a new Engine and loads policies from a file
func NewEngine(policyPath string) (*Engine, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %v", err)
	}

	// Compute policy version hash
	hash := sha256.Sum256(data)
	version := hex.EncodeToString(hash[:])[:12]

	ps := cedar.NewPolicySet()

	// Split policies by semicolon as a rudimentary parser
	chunks := strings.Split(string(data), ";")
	for i, chunk := range chunks {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}

		fullPolicy := chunk + ";"

		var policy cedar.Policy
		if err := policy.UnmarshalCedar([]byte(fullPolicy)); err != nil {
			return nil, fmt.Errorf("failed to unmarshal cedar policy part %d: %v", i, err)
		}

		ps.Add(cedar.PolicyID(fmt.Sprintf("policy%d", i)), &policy)
	}

	return &Engine{
		policySet:     ps,
		PolicyVersion: version,
		PolicyPath:    policyPath,
	}, nil
}

// Evaluate checks the facts against the policies (legacy interface)
func (e *Engine) Evaluate(facts *analyzer.Facts) (Decision, string, error) {
	ctx := facts.ToContext()
	return e.EvaluateContext(ctx)
}

// EvaluateContext checks the context against the policies (new interface)
func (e *Engine) EvaluateContext(ctx *analyzer.Context) (Decision, string, error) {
	// Build LLM resource with attributes
	entities := cedar.EntityMap{
		cedar.NewEntityUID("LLM", "default"): cedar.Entity{
			UID: cedar.NewEntityUID("LLM", "default"),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"sensitivity": cedar.String(ctx.ResourceSensitivity),
			}),
		},
	}

	// Build PII set - cedar.Set is immutable, use variadic constructor
	piiValues := make([]cedar.Value, len(ctx.Signals.PII))
	for i, pii := range ctx.Signals.PII {
		piiValues[i] = cedar.String(pii)
	}
	piiSet := cedar.NewSet(piiValues...)

	// Build Capabilities set
	capValues := make([]cedar.Value, len(ctx.Signals.Capabilities))
	for i, cap := range ctx.Signals.Capabilities {
		capValues[i] = cedar.String(cap)
	}
	capSet := cedar.NewSet(capValues...)

	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", "default"),
		Action:    cedar.NewEntityUID("Action", "chat"),
		Resource:  cedar.NewEntityUID("LLM", "default"),
		Context: cedar.NewRecord(cedar.RecordMap{
			// Semantic signals
			"intent":        cedar.String(ctx.Intent),
			"user_intent":   cedar.String(ctx.UserIntent),
			"system_intent": cedar.String(ctx.SystemIntent),
			"risk_score":    cedar.Long(int64(ctx.RiskScore * 100)),
			"confidence":    cedar.Long(int64(ctx.Confidence * 100)),
			// Deterministic signals
			"pii":              piiSet,
			"toxicity":         cedar.Long(int64(ctx.Signals.Toxicity * 100)),
			"prompt_injection": cedar.Boolean(ctx.Signals.PromptInjection),
			"topic":            cedar.String(ctx.Signals.Topic),
			"capabilities":     capSet,
			// Request metadata
			"streaming": cedar.Boolean(ctx.Request.Streaming),
			"tokens":    cedar.Long(int64(ctx.Request.Tokens)),
			// Provider
			"provider": cedar.String(ctx.Provider),
		}),
	}

	ok, _ := cedar.Authorize(e.policySet, entities, req)

	if ok {
		return ALLOW, "Policy allowed the request", nil
	}

	return DENY, "Policy denied the request", nil
}
