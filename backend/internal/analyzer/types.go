package analyzer

// Facts represents the structured information extracted from a user prompt
type Facts struct {
	Intent     string  `json:"intent"`
	Risk       float64 `json:"risk"`       // 0.0 to 1.0
	Confidence float64 `json:"confidence"` // 0.0 to 1.0
	Sensitive  bool    `json:"sensitive"`
	Topic      string  `json:"topic"`
}
