package analyzer

import (
	"github.com/blackrose-blackhat/agent-guardrail/backend/pkg/models"
)

// SignalAggregator runs all deterministic detectors and aggregates signals
type SignalAggregator struct {
	pii          *PIIDetector
	toxicity     *ToxicityDetector
	injection    *InjectionDetector
	capabilities *CapabilityScanner
}

// NewSignalAggregator creates a new SignalAggregator with all detectors
func NewSignalAggregator() *SignalAggregator {
	return &SignalAggregator{
		pii:          NewPIIDetector(),
		toxicity:     NewToxicityDetector(),
		injection:    NewInjectionDetector(),
		capabilities: NewCapabilityScanner(),
	}
}

// Aggregate runs all detectors on the request and returns aggregated signals
func (s *SignalAggregator) Aggregate(req *models.LLMRequest) *Signals {
	if len(req.Messages) == 0 {
		return &Signals{}
	}

	var fullText, userText, systemText string
	for _, msg := range req.Messages {
		fullText += msg.Content + " "
		switch msg.Role {
		case "user":
			userText += msg.Content + " "
		case "system":
			systemText += msg.Content + " "
		}
	}

	return &Signals{
		PII:             s.pii.Detect(fullText),
		Toxicity:        s.toxicity.Score(fullText),
		PromptInjection: s.injection.Detect(fullText),
		Capabilities:    s.capabilities.Scan(fullText),
		UserText:        userText,
		SystemText:      systemText,
		FullText:        fullText,
	}
}

// DetectPII runs PII detection on arbitrary text (used for output-side scanning)
func (s *SignalAggregator) DetectPII(text string) []string {
	return s.pii.Detect(text)
}

// RedactPII masks PII in arbitrary text
func (s *SignalAggregator) RedactPII(text string, types []string) string {
	return s.pii.Redact(text, types)
}
