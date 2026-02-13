package analyzer

// Intent taxonomy - Hierarchical v2.0
const (
	// 1. Informational (Low Risk)
	IntentInfoQuery     = "info.query"
	IntentInfoQueryPII  = "info.query.pii"
	IntentInfoSummarize = "info.summarize"

	// 2. Capabilities (Medium-High Risk)
	IntentCodeGenerate = "code.generate"
	IntentCodeExploit  = "code.exploit"   // Malicious, injection-related code
	IntentToolSafe     = "tool.safe"      // Calc, weather, search
	IntentToolRisk     = "tool.dangerous" // RM, sudo, db access

	// 3. Restricted (High Risk)
	IntentFileRead  = "file.read"
	IntentFileWrite = "file.write"
	IntentSystem    = "sys.control"

	// 4. Conversational (Zero Risk)
	IntentConvGreeting = "conv.greeting"
	IntentConvOther    = "conv.other"

	IntentUnknown = "unknown"
)

// IntentSignal represents the semantic analysis result
type IntentSignal struct {
	Intent           string  `json:"intent"`            // one of the hierarchical intents above
	Confidence       float64 `json:"confidence"`        // 0.0 to 1.0
	Action           string  `json:"action"`            // first-class verb: "query", "summarize", "generate", etc.
	Domain           string  `json:"domain"`            // first-class noun: "recruitment", "politics", etc.
	DomainConfidence float64 `json:"domain_confidence"` // confidence in domain classification
	ActionConfidence float64 `json:"action_confidence"` // confidence in action classification
	RiskScore        float64 `json:"risk_score"`        // sidecar-computed risk score
	IsAmbiguous      bool    `json:"is_ambiguous"`      // sidecar flags ambiguous classifications
	// Sidecar evaluation result (propagated from Python evaluator)
	SidecarDecision string `json:"decision"` // "allow" | "block" — the sidecar's own verdict
	SidecarReason   string `json:"reason"`   // why the sidecar blocked/allowed
}

// intentForAction maps sidecar action verbs to Cedar-compatible intent taxonomy.
func intentForAction(action string) string {
	switch action {
	case "query":
		return IntentInfoQuery
	case "summarize":
		return IntentInfoSummarize
	case "generate":
		return IntentCodeGenerate
	case "control":
		return IntentSystem
	case "greet":
		return IntentConvGreeting
	case "modify":
		return IntentFileWrite
	default:
		return IntentUnknown
	}
}

// RiskFromIntent returns the confidence as the risk signal.
// NOTE: All intent-specific risk weighting has been moved to Cedar policies.
// This function is now policy-neutral - Cedar evaluates intent + confidence directly.
func RiskFromIntent(intent string, confidence float64) float64 {
	// Return confidence directly - Cedar policies handle intent-specific thresholds
	// Example Cedar policy for high-risk intents:
	//   forbid when context.intent == "code.exploit" && context.confidence > 40
	return confidence
}
