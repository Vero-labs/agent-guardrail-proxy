package analyzer

import (
	"regexp"
)

// Capability represents a dangerous lexical capability
type Capability string

const (
	CapFileDelete   Capability = "file_delete"   // rm, delete, wipe
	CapPrivRead     Capability = "privileged_read" // /etc/shadow, /etc/passwd, secrets
	CapProcessCtrl  Capability = "process_control" // kill, restart, shutdown, systemctl
	CapPrivEscalate Capability = "privilege_escalation" // sudo, chmod, chown
)

// CapabilityScanner performs lexical analysis to detect dangerous intents
type CapabilityScanner struct {
	rules map[Capability][]*regexp.Regexp
}

// NewCapabilityScanner creates a new scanner with pre-defined rules
func NewCapabilityScanner() *CapabilityScanner {
	rules := make(map[Capability][]*regexp.Regexp)

	// File Deletion
	rules[CapFileDelete] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(rm|delete|wipe|erase|unlink)\b`),
		regexp.MustCompile(`(?i)\brm\s+-rf\b`),
	}

	// Privileged Read
	rules[CapPrivRead] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/etc/(passwd|shadow|gshadow|ssh|security)`),
		regexp.MustCompile(`(?i)\.env\b`),
		regexp.MustCompile(`(?i)\bsecrets?\b`),
	}

	// Process Control
	rules[CapProcessCtrl] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(kill|shutdown|reboot|restart|halt)\b`),
		regexp.MustCompile(`(?i)systemctl\b`),
		regexp.MustCompile(`(?i)service\s+\w+\s+(stop|restart)`),
	}

	// Privilege Escalation
	rules[CapPrivEscalate] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bsudo\b`),
		regexp.MustCompile(`(?i)\bchmod\b`),
		regexp.MustCompile(`(?i)\bchown\b`),
		regexp.MustCompile(`(?i)\bsu\s+-`),
	}

	return &CapabilityScanner{rules: rules}
}

// Scan checks the text for all capabilities
func (s *CapabilityScanner) Scan(text string) []string {
	detected := make([]string, 0)
	
	for capName, patterns := range s.rules {
		for _, pattern := range patterns {
			if pattern.MatchString(text) {
				detected = append(detected, string(capName))
				break // Found one pattern for this capability, move to next cap
			}
		}
	}
	
	return detected
}
