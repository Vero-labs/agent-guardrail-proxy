package analyzer

import (
	"regexp"
)

var (
	emailRegex      = regexp.MustCompile(`(?i)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	phoneRegex      = regexp.MustCompile(`(\+\d{1,2}\s?)?1?\-?\.?\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}`)
	ssnRegex        = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	creditCardRegex = regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`)
)

// PIIDetector provides deterministic PII signal detection
type PIIDetector struct{}

// NewPIIDetector creates a new PIIDetector
func NewPIIDetector() *PIIDetector {
	return &PIIDetector{}
}

// Detect scans text for PII and returns a list of detected types
func (p *PIIDetector) Detect(text string) []string {
	detected := make(map[string]bool)

	if emailRegex.MatchString(text) {
		detected["email"] = true
	}
	if phoneRegex.MatchString(text) {
		detected["phone"] = true
	}
	if ssnRegex.MatchString(text) {
		detected["ssn"] = true
	}
	if creditCardRegex.MatchString(text) {
		detected["credit_card"] = true
	}

	var results []string
	for k := range detected {
		results = append(results, k)
	}
	return results
}

// Redact masks PII in text for specific types
func (p *PIIDetector) Redact(text string, types []string) string {
	redacted := text
	typeMap := make(map[string]bool)
	for _, t := range types {
		typeMap[t] = true
	}

	if typeMap["email"] {
		redacted = emailRegex.ReplaceAllString(redacted, "[EMAIL]")
	}
	if typeMap["phone"] {
		redacted = phoneRegex.ReplaceAllString(redacted, "[PHONE]")
	}
	if typeMap["ssn"] {
		redacted = ssnRegex.ReplaceAllString(redacted, "[SSN]")
	}
	if typeMap["credit_card"] {
		redacted = creditCardRegex.ReplaceAllString(redacted, "[CREDIT_CARD]")
	}
	return redacted
}
