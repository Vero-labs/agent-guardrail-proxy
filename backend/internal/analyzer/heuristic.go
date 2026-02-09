package analyzer

import (
	"regexp"
	"strings"
)

// HeuristicAnalyzer provides fast, deterministic intent detection using regex.
// This is used as the first tier in a multi-tier classification pipeline.
type HeuristicAnalyzer struct {
	greeterRegexp *regexp.Regexp
	exploitRegexp *regexp.Regexp
	sysCtrlRegexp *regexp.Regexp
}

// NewHeuristicAnalyzer initializes the fast-path regex detectors.
func NewHeuristicAnalyzer() *HeuristicAnalyzer {
	return &HeuristicAnalyzer{
		// Common greetings and small talk
		greeterRegexp: regexp.MustCompile(`(?i)^(hi|hello|hey|greetings|howdy|yo|morning|afternoon|evening|hola|bonjour)(\s+.*)?$`),

		// Blatant exploit/malicious strings (fast-fail)
		exploitRegexp: regexp.MustCompile(`(?i)(shellcode|nopsled|\\x90|0xdeadbeef|syscall|execve|/bin/sh|ptrace|buffer\s+overflow|stack\s+smashing)`),

		// System control keywords
		sysCtrlRegexp: regexp.MustCompile(`(?i)^(restart|shutdown|reboot|halt|poweroff|stop\s+service|systemctl\s+stop)\b|(?i)(ignore\s+all\s+instructions|do\s+anything\s+now|DAN\s+mode|jailbreak|unfiltered\s+response)`),
	}
}

// Analyze returns an IntentSignal if a high-confidence match is found.
// Returns nil if no heuristic match is confident enough.
func (h *HeuristicAnalyzer) Analyze(text string) *IntentSignal {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return &IntentSignal{Intent: IntentUnknown, Confidence: 1.0}
	}

	// 1. Check for Greetings (High Confidence Fast-Path)
	if h.greeterRegexp.MatchString(trimmed) {
		return &IntentSignal{
			Intent:     IntentConvGreeting,
			Confidence: 0.95,
		}
	}

	// 2. Check for Blatant Exploit (High Confidence Fast-Fail)
	if h.exploitRegexp.MatchString(trimmed) {
		return &IntentSignal{
			Intent:     IntentCodeExploit,
			Confidence: 0.90,
		}
	}

	// 3. Check for System Control / Jailbreak (High Confidence Fast-Fail)
	if h.sysCtrlRegexp.MatchString(trimmed) {
		return &IntentSignal{
			Intent:     IntentSystem,
			Confidence: 0.95,
		}
	}

	return nil
}
