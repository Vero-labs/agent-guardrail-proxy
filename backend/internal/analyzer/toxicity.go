package analyzer

import (
	"regexp"
	"strings"
)

// ToxicityDetector provides toxicity signal scoring using keyword matching
type ToxicityDetector struct {
	toxicPatterns []*regexp.Regexp
	weights       []float64
}

// NewToxicityDetector creates a new ToxicityDetector
func NewToxicityDetector() *ToxicityDetector {
	patterns := []string{
		`(?i)\b(kill|murder|attack|destroy|harm)\b`,
		`(?i)\b(hate|racist|sexist|bigot)\b`,
		`(?i)\b(suicide|self-harm|cut myself)\b`,
		`(?i)\b(fuck|shit|damn|ass|bitch)\b`,
		`(?i)\b(threat|threaten|bomb|terror)\b`,
		// Weapons and violence
		`(?i)\b(weapon|explosive|poison|gun|knife)\b`,
		`(?i)\bmake\s+a\s+(bomb|weapon|explosive)\b`,
		// Hacking and malware
		`(?i)\b(malware|virus|trojan|ransomware|keylogger)\b`,
		`(?i)\b(hack|exploit|breach|crack)\s+(into|password|account|system)\b`,
		`(?i)bypass\s+(security|authentication|firewall|protection)\b`,
		// Illegal activities
		`(?i)\b(steal|fraud|scam|phishing)\b`,
	}

	compiled := make([]*regexp.Regexp, len(patterns))
	weights := []float64{0.3, 0.35, 0.4, 0.15, 0.4, 0.5, 0.5, 0.5, 0.5, 0.5, 0.4}

	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}

	return &ToxicityDetector{
		toxicPatterns: compiled,
		weights:       weights,
	}
}

// Score returns a toxicity score between 0.0 and 1.0
func (t *ToxicityDetector) Score(text string) float64 {
	text = strings.ToLower(text)
	var totalScore float64

	for i, pattern := range t.toxicPatterns {
		matches := pattern.FindAllString(text, -1)
		if len(matches) > 0 {
			// Increase score based on number of matches, capped at weight
			matchScore := t.weights[i] * float64(min(len(matches), 3)) / 3.0
			totalScore += matchScore
		}
	}

	// Cap at 1.0
	if totalScore > 1.0 {
		totalScore = 1.0
	}
	return totalScore
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
