package cedar

import (
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
	policySet *cedar.PolicySet
}

// NewEngine creates a new Engine and loads policies from a file
func NewEngine(policyPath string) (*Engine, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %v", err)
	}

	ps := cedar.NewPolicySet()

	// Split policies by semicolon as a rudimentary parser
	// This assumes no semicolons in strings/comments, which is true for our current policies
	chunks := strings.Split(string(data), ";")
	for i, chunk := range chunks {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}

		// Append back the semicolon for valid syntax if needed,
		// but UnmarshalCedar might usually expect the statement without trailing semicolon?
		// Actually Cedar syntax requires semicolon. Unmarshal might expect it.
		// Let's try adding it back.
		fullPolicy := chunk + ";"

		var policy cedar.Policy
		if err := policy.UnmarshalCedar([]byte(fullPolicy)); err != nil {
			// If it fails, maybe it was a comment or something?
			// For now, fail hard to detect issues.
			return nil, fmt.Errorf("failed to unmarshal cedar policy part %d: %v", i, err)
		}

		ps.Add(cedar.PolicyID(fmt.Sprintf("policy%d", i)), &policy)
	}

	return &Engine{policySet: ps}, nil
}

// Evaluate checks the facts against the policies
func (e *Engine) Evaluate(facts *analyzer.Facts) (Decision, string, error) {
	entities := cedar.EntityMap{}

	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", "default"),
		Action:    cedar.NewEntityUID("Action", "chat"),
		Resource:  cedar.NewEntityUID("LLM", "default"),
		Context: cedar.NewRecord(cedar.RecordMap{
			"risk":       cedar.Long(int64(facts.Risk * 100)),
			"confidence": cedar.Long(int64(facts.Confidence * 100)),
			"sensitive":  cedar.Boolean(facts.Sensitive),
			"topic":      cedar.String(facts.Topic),
			"intent":     cedar.String(facts.Intent),
		}),
	}

	ok, _ := cedar.Authorize(e.policySet, entities, req)

	if ok {
		return ALLOW, "Policy allowed the request", nil
	}

	return DENY, "Policy denied the request", nil
}
