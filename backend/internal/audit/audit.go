package audit

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// Principal represents the entity making the request
type Principal struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	Type string `json:"type"` // "user", "agent", "system"
}

// AuditEntry represents a structured audit log entry
type AuditEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	RequestID   string                 `json:"request_id"`
	Principal   Principal              `json:"principal"`
	Action      string                 `json:"action"`
	Resource    string                 `json:"resource"`
	Signals     map[string]interface{} `json:"signals"`
	Decision    string                 `json:"decision"`
	PolicyID    string                 `json:"policy_id,omitempty"`
	Reason      string                 `json:"reason,omitempty"`
	Obligations []string               `json:"obligations,omitempty"`
	Latency     time.Duration          `json:"latency_ns"`
	Provider    string                 `json:"provider,omitempty"`
}

// Logger handles structured audit logging
type Logger struct {
	mu       sync.Mutex
	file     *os.File
	encoder  *json.Encoder
	fallback *log.Logger
}

// NewLogger creates a new audit logger
// If filePath is empty, logs to stdout in JSON format
func NewLogger(filePath string) (*Logger, error) {
	var file *os.File
	var err error

	if filePath != "" {
		file, err = os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
	} else {
		file = os.Stdout
	}

	return &Logger{
		file:     file,
		encoder:  json.NewEncoder(file),
		fallback: log.New(os.Stderr, "[AUDIT] ", log.LstdFlags),
	}, nil
}

// Log writes an audit entry
func (l *Logger) Log(entry AuditEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	if err := l.encoder.Encode(entry); err != nil {
		l.fallback.Printf("Failed to write audit entry: %v, entry: %+v", err, entry)
	}
}

// LogRequest is a convenience method for logging a complete request cycle
func (l *Logger) LogRequest(
	requestID string,
	principal Principal,
	action string,
	resource string,
	signals map[string]interface{},
	decision string,
	reason string,
	latency time.Duration,
) {
	l.Log(AuditEntry{
		Timestamp: time.Now().UTC(),
		RequestID: requestID,
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Signals:   signals,
		Decision:  decision,
		Reason:    reason,
		Latency:   latency,
	})
}

// Close closes the audit log file
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil && l.file != os.Stdout {
		return l.file.Close()
	}
	return nil
}

// BuildSignalsMap creates a signals map from context for audit logging
func BuildSignalsMap(
	intent string,
	confidence float64,
	pii []string,
	toxicity float64,
	injection bool,
	capabilities []string,
) map[string]interface{} {
	return map[string]interface{}{
		"intent":           intent,
		"confidence":       confidence,
		"pii":              pii,
		"toxicity":         toxicity,
		"prompt_injection": injection,
		"capabilities":     capabilities,
	}
}
