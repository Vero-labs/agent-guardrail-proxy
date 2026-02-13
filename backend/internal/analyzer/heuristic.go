package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
)

// intentToAction maps intent prefixes to first-class action verbs.
// This is the canonical mapping — never parse intent strings elsewhere.
var intentToAction = map[string]string{
	IntentInfoQuery:     "query",
	IntentInfoQueryPII:  "query",
	IntentInfoSummarize: "summarize",
	IntentCodeGenerate:  "generate",
	IntentCodeExploit:   "exploit",
	IntentToolSafe:      "tool",
	IntentToolRisk:      "tool",
	IntentFileRead:      "read",
	IntentFileWrite:     "write",
	IntentSystem:        "control",
	IntentConvGreeting:  "greeting",
	IntentConvOther:     "other",
	IntentUnknown:       "",
}

// ActionForIntent returns the first-class action verb for an intent.
func ActionForIntent(intent string) string {
	if a, ok := intentToAction[intent]; ok {
		return a
	}
	return ""
}

// HeuristicAnalyzer provides fast, deterministic intent detection using regex.
// This is used as the first tier in a multi-tier classification pipeline.
type HeuristicAnalyzer struct {
	greeterRegexp *regexp.Regexp
	exploitRegexp *regexp.Regexp
	sysCtrlRegexp *regexp.Regexp
	// Configurable topics: name -> list of compiled keyword regexps
	topics map[string][]*regexp.Regexp
	// Keep the combined regex for backward compat with AnalyzeWithDomain fast-path match
	topicFast map[string]*regexp.Regexp
}

// NewHeuristicAnalyzer initializes the fast-path detectors.
func NewHeuristicAnalyzer(topicConfigs map[string]policy.TopicConfig) *HeuristicAnalyzer {
	h := &HeuristicAnalyzer{
		greeterRegexp: regexp.MustCompile(`(?i)^(hi|hello|hey|greetings|howdy|yo|morning|afternoon|evening|hola|bonjour)(\s+.*)?$`),
		exploitRegexp: regexp.MustCompile(`(?i)(shellcode|nopsled|\\x90|0xdeadbeef|syscall|execve|/bin/sh|ptrace|buffer\s+overflow|stack\s+smashing)`),
		sysCtrlRegexp: regexp.MustCompile(`(?i)^(restart|shutdown|reboot|halt|poweroff|stop\s+service|systemctl\s+stop)\b|(?i)(ignore\s+all\s+instructions|do\s+anything\s+now|DAN\s+mode|jailbreak|unfiltered\s+response)`),
		topics:        make(map[string][]*regexp.Regexp),
		topicFast:     make(map[string]*regexp.Regexp),
	}

	// Compile user-defined topics from YAML
	for name, config := range topicConfigs {
		if len(config.Keywords) > 0 {
			// Combined regex for fast-path match check
			pattern := fmt.Sprintf(`(?i)\b(%s)\b`, strings.Join(config.Keywords, "|"))
			re, err := regexp.Compile(pattern)
			if err == nil {
				h.topicFast[name] = re
			}
			// Individual keyword regexps for scoring
			for _, kw := range config.Keywords {
				kwPattern := fmt.Sprintf(`(?i)\b%s\b`, regexp.QuoteMeta(kw))
				kwRe, err := regexp.Compile(kwPattern)
				if err == nil {
					h.topics[name] = append(h.topics[name], kwRe)
				}
			}
		}
	}

	return h
}

// DetectTopic identifies the topic of the text based on configured keywords.
// When multiple topics match, returns the topic with the most distinct keyword hits
// to prevent domain drift attacks (e.g., single "hiring" anchor overriding
// actual political content with multiple political keyword matches).
func (h *HeuristicAnalyzer) DetectTopic(text string) string {
	trimmed := strings.TrimSpace(text)
	bestTopic := ""
	bestCount := 0

	for name, kwRegexps := range h.topics {
		matchCount := 0
		for _, kwRe := range kwRegexps {
			if kwRe.MatchString(trimmed) {
				matchCount++
			}
		}
		if matchCount > bestCount {
			bestCount = matchCount
			bestTopic = name
		}
	}
	return bestTopic
}

// Analyze returns an IntentSignal if a high-confidence match is found.
// Returns nil if no heuristic match is confident enough.
func (h *HeuristicAnalyzer) Analyze(text string) *IntentSignal {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return &IntentSignal{Intent: IntentUnknown, Confidence: 1.0, Action: ""}
	}

	// 1. Check for Greetings (High Confidence Fast-Path)
	if h.greeterRegexp.MatchString(trimmed) {
		return &IntentSignal{
			Intent:     IntentConvGreeting,
			Confidence: 0.95,
			Action:     "greeting",
		}
	}

	// 2. Check for Blatant Exploit (High Confidence Fast-Fail)
	if h.exploitRegexp.MatchString(trimmed) {
		return &IntentSignal{
			Intent:     IntentCodeExploit,
			Confidence: 0.90,
			Action:     "exploit",
		}
	}

	// 3. Check for System Control / Jailbreak (High Confidence Fast-Fail)
	if h.sysCtrlRegexp.MatchString(trimmed) {
		return &IntentSignal{
			Intent:     IntentSystem,
			Confidence: 0.95,
			Action:     "control",
		}
	}

	return nil
}

// AnalyzeWithDomain combines intent detection with topic detection to
// produce a fully populated IntentSignal with Action and Domain.
func (h *HeuristicAnalyzer) AnalyzeWithDomain(text string) *IntentSignal {
	sig := h.Analyze(text)

	// Detect domain regardless of intent match
	domain := h.DetectTopic(text)

	if sig != nil {
		sig.Domain = domain
		if domain != "" {
			sig.DomainConfidence = 0.90 // heuristic keyword match = high confidence
		}
		return sig
	}

	// No intent match, but if we have a domain, return minimal signal
	if domain != "" {
		return &IntentSignal{
			Domain:           domain,
			DomainConfidence: 0.90,
		}
	}

	return nil
}
