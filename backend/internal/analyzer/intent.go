package analyzer

// Intent taxonomy - Hierarchical v2.0
const (
	// 1. Informational (Low Risk)
	IntentInfoQuery     = "info.query"
	IntentInfoQueryPII  = "info.query.pii"
	IntentInfoSummarize = "info.summarize"

	// 2. Capabilities (Medium-High Risk)
	IntentCodeGenerate = "code.generate"
	IntentCodeExploit  = "code.exploit" // Malicious, injection-related code
	IntentToolSafe     = "tool.safe"     // Calc, weather, search
	IntentToolRisk     = "tool.dangerous" // RM, sudo, db access

	// 3. Restricted (High Risk)
	IntentFileRead    = "file.read"
	IntentFileWrite   = "file.write"
	IntentSystem      = "sys.control"

	// 4. Conversational (Zero Risk)
	IntentConvGreeting = "conv.greeting"
	IntentConvOther    = "conv.other"

	IntentUnknown = "unknown"
)

// IntentSignal represents the semantic analysis result
type IntentSignal struct {
	Intent     string  `json:"intent"`     // one of the hierarchical intents above
	Confidence float64 `json:"confidence"` // 0.0 to 1.0
}

// RiskFromIntent derives risk score from intent class and confidence
func RiskFromIntent(intent string, confidence float64) float64 {
	baseRisk := 0.0

	// Weighted Risk Matrix
	switch intent {
	case IntentSystem, IntentFileWrite, IntentToolRisk, IntentCodeExploit:
		baseRisk = 0.85 // Critical operations

	case IntentInfoQueryPII, IntentFileRead:
		baseRisk = 0.60 // Sensitive data access

	case IntentCodeGenerate:
		baseRisk = 0.40 // Potential for injection/exploits

	case IntentUnknown:
		baseRisk = 0.35 // Ambiguity penalty

	case IntentToolSafe:
		baseRisk = 0.20 // Safe utility usage

	case IntentInfoQuery, IntentInfoSummarize:
		baseRisk = 0.10 // Pure informational

	case IntentConvGreeting, IntentConvOther:
		baseRisk = 0.05 // Safe conversational
	}

	// Ambiguity Risk Adjustment
	// Low confidence in high-risk intents increases risk exponentially
	if confidence < 0.7 {
		penalty := (0.7 - confidence) * 0.5
		baseRisk += penalty
	}

	// Cap at 1.0
	if baseRisk > 1.0 {
		baseRisk = 1.0
	}

	return baseRisk
}
