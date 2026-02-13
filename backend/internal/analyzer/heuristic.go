package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
)

// HeuristicAnalyzer provides fast, deterministic intent detection using regex.
// This is used as the first tier in a multi-tier classification pipeline.
type HeuristicAnalyzer struct {
	greeterRegexp *regexp.Regexp
	exploitRegexp *regexp.Regexp
	sysCtrlRegexp *regexp.Regexp
	// Configurable topics
	topics map[string]*regexp.Regexp
}

// NewHeuristicAnalyzer initializes the fast-path detectors.
func NewHeuristicAnalyzer(topicConfigs map[string]policy.TopicConfig) *HeuristicAnalyzer {
	h := &HeuristicAnalyzer{
		greeterRegexp: regexp.MustCompile(`(?i)^(hi|hello|hey|greetings|howdy|yo|morning|afternoon|evening|hola|bonjour)(\s+.*)?$`),
		exploitRegexp: regexp.MustCompile(`(?i)(shellcode|nopsled|\\x90|0xdeadbeef|syscall|execve|/bin/sh|ptrace|buffer\s+overflow|stack\s+smashing)`),
		sysCtrlRegexp: regexp.MustCompile(`(?i)^(restart|shutdown|reboot|halt|poweroff|stop\s+service|systemctl\s+stop)\b|(?i)(ignore\s+all\s+instructions|do\s+anything\s+now|DAN\s+mode|jailbreak|unfiltered\s+response)`),
		topics:        make(map[string]*regexp.Regexp),
	}

	// Compile user-defined topics from YAML
	for name, config := range topicConfigs {
		if len(config.Keywords) > 0 {
			// Join keywords with word boundaries: \b(k1|k2|k3)\b
			pattern := fmt.Sprintf(`(?i)\b(%s)\b`, strings.Join(config.Keywords, "|"))
			re, err := regexp.Compile(pattern)
			if err == nil {
				h.topics[name] = re
			}
		}
	}

	return h
}

// DetectTopic identifies the topic of the text based on configured keywords
func (h *HeuristicAnalyzer) DetectTopic(text string) string {
	trimmed := strings.TrimSpace(text)
	for name, re := range h.topics {
		if re.MatchString(trimmed) {
			return name
		}
	}
	return ""
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
