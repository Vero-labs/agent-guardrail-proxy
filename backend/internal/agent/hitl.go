package agent

import (
	"encoding/json"
	"time"
)

// ApprovalStatus represents the status of a HITL approval request
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalDenied   ApprovalStatus = "denied"
	ApprovalExpired  ApprovalStatus = "expired"
)

// HITLRequest represents a request for human approval
type HITLRequest struct {
	ID          string          `json:"id"`
	RequestID   string          `json:"request_id"`
	AgentID     string          `json:"agent_id"`
	SessionID   string          `json:"session_id"`
	Action      string          `json:"action"`  // What action requires approval
	Context     json.RawMessage `json:"context"` // Full context for review
	Reason      string          `json:"reason"`  // Why approval is needed
	RequestedAt time.Time       `json:"requested_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
	Status      ApprovalStatus  `json:"status"`
	ApprovedBy  string          `json:"approved_by,omitempty"`
	ApprovedAt  *time.Time      `json:"approved_at,omitempty"`
	DenialNote  string          `json:"denial_note,omitempty"`
}

// HITLCallback defines the interface for HITL notification delivery
type HITLCallback interface {
	// OnApprovalRequired is called when an action requires human approval
	OnApprovalRequired(req *HITLRequest) error
	// OnApprovalExpired is called when an approval request expires
	OnApprovalExpired(req *HITLRequest) error
}

// HITLConfig configures the HITL workflow
type HITLConfig struct {
	DefaultTimeout  time.Duration // Default timeout for approval requests
	WebhookURL      string        // Optional webhook for notifications
	SlackWebhookURL string        // Optional Slack webhook
	EmailNotify     string        // Optional email for notifications
}

// HITLManager manages human-in-the-loop approval workflows
type HITLManager struct {
	config   HITLConfig
	requests map[string]*HITLRequest // In-memory store (replace with DB for production)
	callback HITLCallback
}

// NewHITLManager creates a new HITLManager
func NewHITLManager(config HITLConfig) *HITLManager {
	return &HITLManager{
		config:   config,
		requests: make(map[string]*HITLRequest),
	}
}

// SetCallback sets the callback for HITL events
func (m *HITLManager) SetCallback(cb HITLCallback) {
	m.callback = cb
}

// RequestApproval creates a new HITL approval request
func (m *HITLManager) RequestApproval(
	agentID, sessionID, action, reason string,
	contextData interface{},
) (*HITLRequest, error) {
	// Marshal context
	ctxJSON, err := json.Marshal(contextData)
	if err != nil {
		ctxJSON = []byte("{}")
	}

	timeout := m.config.DefaultTimeout
	if timeout == 0 {
		timeout = 5 * time.Minute // Default 5 minute timeout
	}

	req := &HITLRequest{
		ID:          generateID(),
		AgentID:     agentID,
		SessionID:   sessionID,
		Action:      action,
		Context:     ctxJSON,
		Reason:      reason,
		RequestedAt: time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(timeout),
		Status:      ApprovalPending,
	}

	m.requests[req.ID] = req

	// Trigger callback if set
	if m.callback != nil {
		if err := m.callback.OnApprovalRequired(req); err != nil {
			// Log but don't fail - approval is still created
		}
	}

	return req, nil
}

// GetRequest retrieves an approval request by ID
func (m *HITLManager) GetRequest(id string) (*HITLRequest, bool) {
	req, ok := m.requests[id]
	if !ok {
		return nil, false
	}

	// Check expiration
	if req.Status == ApprovalPending && time.Now().After(req.ExpiresAt) {
		req.Status = ApprovalExpired
		if m.callback != nil {
			m.callback.OnApprovalExpired(req)
		}
	}

	return req, true
}

// Approve approves a pending request
func (m *HITLManager) Approve(id, approvedBy string) (*HITLRequest, error) {
	req, ok := m.requests[id]
	if !ok {
		return nil, ErrNotFound
	}

	if req.Status != ApprovalPending {
		return nil, ErrInvalidStatus
	}

	if time.Now().After(req.ExpiresAt) {
		req.Status = ApprovalExpired
		return nil, ErrExpired
	}

	now := time.Now().UTC()
	req.Status = ApprovalApproved
	req.ApprovedBy = approvedBy
	req.ApprovedAt = &now

	return req, nil
}

// Deny denies a pending request
func (m *HITLManager) Deny(id, deniedBy, note string) (*HITLRequest, error) {
	req, ok := m.requests[id]
	if !ok {
		return nil, ErrNotFound
	}

	if req.Status != ApprovalPending {
		return nil, ErrInvalidStatus
	}

	now := time.Now().UTC()
	req.Status = ApprovalDenied
	req.ApprovedBy = deniedBy
	req.ApprovedAt = &now
	req.DenialNote = note

	return req, nil
}

// WaitForApproval blocks until approval, denial, or expiration
func (m *HITLManager) WaitForApproval(id string, checkInterval time.Duration) (*HITLRequest, error) {
	for {
		req, ok := m.GetRequest(id)
		if !ok {
			return nil, ErrNotFound
		}

		switch req.Status {
		case ApprovalApproved:
			return req, nil
		case ApprovalDenied:
			return req, ErrDenied
		case ApprovalExpired:
			return req, ErrExpired
		}

		time.Sleep(checkInterval)
	}
}

// Errors
type HITLError string

func (e HITLError) Error() string { return string(e) }

const (
	ErrNotFound      = HITLError("approval request not found")
	ErrInvalidStatus = HITLError("approval request is not pending")
	ErrExpired       = HITLError("approval request has expired")
	ErrDenied        = HITLError("approval request was denied")
)

// generateID creates a unique ID (simplified - use UUID in production)
func generateID() string {
	return time.Now().Format("20060102150405.999999999")
}
