package analyzer

import (
	"regexp"
	"strings"
)

// InjectionDetector detects prompt injection attempts
type InjectionDetector struct {
	patterns []*regexp.Regexp
}

// NewInjectionDetector creates a new InjectionDetector
func NewInjectionDetector() *InjectionDetector {
	patternStrings := []string{
		// Direct instruction override
		`(?i)ignore\s+(all\s+)?(previous|above|prior)?\s*(instructions?|prompts?|rules?)`,
		`(?i)disregard\s+(all\s+)?(previous|above|prior)?`,
		`(?i)forget\s+(everything|all|what|your)`,
		// Role manipulation
		`(?i)you\s+are\s+now\s+(a|an|the)`,
		`(?i)pretend\s+(to\s+be|you\s+are|you\s+have)`,
		`(?i)act\s+as\s+(a|an|if|though)`,
		`(?i)roleplay\s+as`,
		// Restriction bypass
		`(?i)(have|with)\s*no\s+(restrictions?|limits?|rules?)`,
		`(?i)without\s+(any\s+)?(restrictions?|filters?|limits?|rules?)`,
		`(?i)remove\s+(all\s+)?(restrictions?|filters?|limits?)`,
		`(?i)bypass\s+(your\s+)?(restrictions?|filters?|safety)`,
		`(?i)as\s+if\s+(you\s+were\s+)?jailbroken`,
		// System prompt extraction
		`(?i)(reveal|show|display|output|print)\s+(your|the|system)\s+(prompt|instructions?)`,
		`(?i)what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?)`,
		// Jailbreak patterns
		`(?i)do\s+anything\s+now`,
		`(?i)DAN\s+mode`,
		`(?i)developer\s+mode`,
		`(?i)jailbreak`,
		// Delimiter injection
		`<\|im_start\|>`,
		`<\|im_end\|>`,
		`\[INST\]`,
		`\[/INST\]`,
		`<<SYS>>`,
		`<</SYS>>`,
	}

	compiled := make([]*regexp.Regexp, len(patternStrings))
	for i, p := range patternStrings {
		compiled[i] = regexp.MustCompile(p)
	}

	return &InjectionDetector{patterns: compiled}
}

// Detect returns true if prompt injection is detected
func (d *InjectionDetector) Detect(text string) bool {
	text = strings.ToLower(text)

	for _, pattern := range d.patterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

// DetectWithDetails returns detection result and matched pattern
func (d *InjectionDetector) DetectWithDetails(text string) (bool, string) {
	text = strings.ToLower(text)

	for _, pattern := range d.patterns {
		if match := pattern.FindString(text); match != "" {
			return true, match
		}
	}
	return false, ""
}
