package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/analyzer"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/cedar"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/config"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/provider"
	"github.com/blackrose-blackhat/agent-guardrail/backend/pkg/models"
	"github.com/google/uuid"
)

// HandlerConfig holds configuration for the proxy handler
type HandlerConfig struct {
	Config      *config.Config
	Provider    provider.Provider
	Analyzer    *analyzer.Analyzer
	CedarEngine *cedar.Engine
	Logger      *log.Logger
}

// GuardrailErrorResponse is returned when a request is blocked
type GuardrailErrorResponse struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// Handler creates an HTTP handler with guardrail integration
func Handler(hc *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		requestID := uuid.New().String()

		// Read request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			hc.logError("Failed to read request body: %v", err)
			sendErrorResponse(w, http.StatusBadRequest, "invalid_request", "Failed to read request body", requestID)
			return
		}
		r.Body.Close()

		// Parse request for processing
		var parsedReq *models.LLMRequest
		if hc.Provider != nil {
			parsedReq, err = hc.Provider.ParseRequest(body)
			if err != nil {
				hc.logError("Failed to parse request: %v", err)
			}
		}

		// LLM Intent Analyzer
		if hc.Analyzer != nil && parsedReq != nil {
			facts, err := hc.Analyzer.Analyze(parsedReq)
			if err != nil {
				hc.logError("Analyzer error: %v", err)
			} else {
				hc.logInfo("Facts: %+v", facts)

				// Cedar Policy Engine
				if hc.CedarEngine != nil {
					decision, reason, err := hc.CedarEngine.Evaluate(facts)
					if err != nil {
						hc.logError("Cedar error: %v", err)
					} else {
						hc.logInfo("Decision: %s (Reason: %s)", decision, reason)

						if decision == cedar.DENY {
							hc.logInfo("Blocking request %s: %s", requestID, reason)
							sendErrorResponse(w, http.StatusForbidden, "guardrail_blocked", reason, requestID)
							return
						}
					}
				}
			}
		}

		// For now, we just pass through
		requestBody := body

		// Build target URL
		targetURL := hc.Config.ProviderUrl + r.URL.Path

		// Create forwarding request
		req, err := http.NewRequest(r.Method, targetURL, bytes.NewBuffer(requestBody))
		if err != nil {
			hc.logError("Failed to build request: %v", err)
			sendErrorResponse(w, http.StatusInternalServerError, "proxy_error", "Failed to build request", requestID)
			return
		}

		// Copy headers
		for key, values := range r.Header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		// Set authorization if configured
		if hc.Config.ProviderKey != "" {
			req.Header.Set("Authorization", "Bearer "+hc.Config.ProviderKey)
		}
		req.Header.Set("Content-Type", "application/json")

		// Forward request to provider
		resp, err := hc.Provider.ForwardRequest(req)
		if err != nil {
			hc.logError("Provider request failed: %v", err)
			sendErrorResponse(w, http.StatusBadGateway, "provider_error", "Failed to connect to provider", requestID)
			return
		}
		defer resp.Body.Close()

		// Read response body
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			hc.logError("Failed to read provider response: %v", err)
			sendErrorResponse(w, http.StatusBadGateway, "provider_error", "Failed to read provider response", requestID)
			return
		}

		// Parse response for processing
		if hc.Provider != nil {
			_, err := hc.Provider.ParseResponse(respBody)
			if err != nil {
				hc.logError("Failed to parse response: %v", err)
			}
		}

		// Copy response headers
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		// Add custom headers
		w.Header().Set("X-Guardrail-Request-ID", requestID)

		// Write response
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)

		// Log request completion
		duration := time.Since(startTime)
		hc.logInfo("Request %s completed in %v", requestID, duration)
	}
}

// sendErrorResponse sends a JSON error response
func sendErrorResponse(w http.ResponseWriter, status int, code, message, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Guardrail-Request-ID", requestID)
	w.WriteHeader(status)

	resp := GuardrailErrorResponse{
		Error:     code,
		Code:      code,
		Message:   message,
		RequestID: requestID,
	}
	json.NewEncoder(w).Encode(resp)
}

// Logging helpers
func (hc *HandlerConfig) logInfo(format string, args ...interface{}) {
	if hc.Logger != nil {
		hc.Logger.Printf("[INFO] "+format, args...)
	}
}

func (hc *HandlerConfig) logError(format string, args ...interface{}) {
	if hc.Logger != nil {
		hc.Logger.Printf("[ERROR] "+format, args...)
	}
}
