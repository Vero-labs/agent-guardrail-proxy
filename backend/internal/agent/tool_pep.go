package agent

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/analyzer"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/audit"
	cedarPkg "github.com/blackrose-blackhat/agent-guardrail/backend/internal/cedar"
	"github.com/google/uuid"
)

// ToolRequest represents an agent's request to invoke a tool
type ToolRequest struct {
	Tool      string                 `json:"tool"`
	Arguments map[string]interface{} `json:"arguments"`
	AgentID   string                 `json:"agent_id,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
}

// ToolResponse represents the result of a tool authorization check
type ToolResponse struct {
	Allowed     bool                  `json:"allowed"`
	Reason      string                `json:"reason,omitempty"`
	RequestID   string                `json:"request_id"`
	Obligations []cedarPkg.Obligation `json:"obligations,omitempty"`
}

// ToolPEP is the Policy Enforcement Point for tool invocations
type ToolPEP struct {
	cedarEngine *cedarPkg.Engine
	auditLogger *audit.Logger
	logger      *log.Logger
}

// NewToolPEP creates a new ToolPEP
func NewToolPEP(engine *cedarPkg.Engine, auditLogger *audit.Logger, logger *log.Logger) *ToolPEP {
	return &ToolPEP{
		cedarEngine: engine,
		auditLogger: auditLogger,
		logger:      logger,
	}
}

func (pep *ToolPEP) Authorize(ctx *analyzer.Context, req *ToolRequest) *ToolResponse {
	requestID := uuid.New().String()
	startTime := time.Now()

	// Build a minimal context for Cedar evaluation with tool-specific fields
	toolCtx := &analyzer.Context{
		Intent:     ctx.Intent,
		Confidence: ctx.Confidence,
		AgentState: ctx.AgentState,
		SourceData: ctx.SourceData,
		Signals:    ctx.Signals,
		Provider:   ctx.Provider,
	}

	// For tool authorization, we evaluate against Cedar policies
	// The policy file should include rules like:
	//   permit(principal, action == Action::"invoke_tool", resource == Tool::"search")
	//   forbid(principal, action == Action::"invoke_tool", resource) when { context.agent_state.current_step > 10 }

	// Use the standard context evaluation - policies should handle tool-specific logic
	result := pep.cedarEngine.EvaluateContextWithResult(toolCtx)

	response := &ToolResponse{
		Allowed:     result.Decision == cedarPkg.ALLOW,
		RequestID:   requestID,
		Reason:      result.Reason,
		Obligations: result.Obligations,
	}

	if !response.Allowed {
		response.Reason = fmt.Sprintf("Policy denied tool invocation: %s - %s", req.Tool, result.Reason)
		pep.logInfo("Tool invocation DENIED: %s (request=%s)", req.Tool, requestID)
	} else {
		pep.logInfo("Tool invocation ALLOWED: %s (request=%s)", req.Tool, requestID)
	}

	// Audit log
	if pep.auditLogger != nil {
		decision := "DENY"
		if response.Allowed {
			decision = "ALLOW"
		}
		pep.auditLogger.Log(audit.AuditEntry{
			Timestamp: time.Now().UTC(),
			RequestID: requestID,
			Principal: audit.Principal{
				ID:   req.AgentID,
				Type: "agent",
			},
			Action:   "invoke_tool",
			Resource: req.Tool,
			Signals: map[string]interface{}{
				"tool":        req.Tool,
				"arguments":   req.Arguments,
				"agent_state": ctx.AgentState,
				"source_data": ctx.SourceData,
			},
			Decision: decision,
			Reason:   response.Reason,
			Latency:  time.Since(startTime),
		})
	}

	return response
}

// Handler creates an HTTP handler for tool authorization requests
func (pep *ToolPEP) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ToolRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Build minimal context from headers
		ctx := &analyzer.Context{
			Provider: r.Header.Get("X-Agent-ID"),
			AgentState: analyzer.AgentState{
				CurrentStep: parseIntHeader(r, "X-Agent-Step", 0),
				MaxSteps:    parseIntHeader(r, "X-Agent-Max-Steps", 0),
			},
			SourceData: analyzer.SourceData{
				Origin:  r.Header.Get("X-Source-Origin"),
				Trusted: r.Header.Get("X-Source-Trusted") == "true",
			},
		}

		response := pep.Authorize(ctx, &req)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Guardrail-Request-ID", response.RequestID)
		if !response.Allowed {
			w.WriteHeader(http.StatusForbidden)
		}
		json.NewEncoder(w).Encode(response)
	}
}

func (pep *ToolPEP) logInfo(format string, args ...interface{}) {
	if pep.logger != nil {
		pep.logger.Printf("[INFO] [ToolPEP] "+format, args...)
	}
}

func parseIntHeader(r *http.Request, header string, defaultVal int) int {
	val := r.Header.Get(header)
	if val == "" {
		return defaultVal
	}
	var result int
	fmt.Sscanf(val, "%d", &result)
	return result
}
