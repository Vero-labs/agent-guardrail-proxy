package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads and parses a guardrail.yaml file
func Load(path string) (*GuardrailPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", path, err)
	}

	var policy GuardrailPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	if policy.Version == "" {
		return nil, fmt.Errorf("policy file missing required 'version' field")
	}

	// Set defaults
	if policy.Safety.PromptInjection == "" {
		policy.Safety.PromptInjection = "block"
	}
	if policy.Safety.ToxicityThreshold == 0 {
		policy.Safety.ToxicityThreshold = 0.50
	}
	if policy.Safety.MaxRiskScore == 0 {
		policy.Safety.MaxRiskScore = 0.85
	}

	return &policy, nil
}
