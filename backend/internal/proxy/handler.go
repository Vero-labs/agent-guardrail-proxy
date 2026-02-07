package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/config"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/provider"
)

// HandlerConfig holds configuration for the proxy handler
type HandlerConfig struct {
	Config         *config.Config
	Provider       provider.Provider
	GuardrailChain *chain.GuardrailChain
	Logger         *log.Logger
}

// GuardrailErrorResponse is returned when a request is blocked
type GuardrailErrorResponse struct {
	Error      string            `json:"error"`
	Code       string            `json:"code"`
	Message    string            `json:"message"`
	Violations []chain.Violation `json:"violations,omitempty"`
	RequestID  string            `json:"request_id"`
}

// Handler creates an HTTP handler with guardrail integration
func Handler(hc *HandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// Create guardrail context
		ctx := chain.NewContext()

		// Read request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			hc.logError("Failed to read request body: %v", err)
			sendErrorResponse(w, http.StatusBadRequest, "invalid_request", "Failed to read request body", ctx.RequestID)
			return
		}
		r.Body.Close()
		ctx.OriginalBody = body

		// Parse request for guardrail processing
		if hc.Provider != nil {
			parsedReq, err := hc.Provider.ParseRequest(body)
			if err == nil {
				ctx.Request = parsedReq
			}
		}

		// Execute input guardrails
		if hc.GuardrailChain != nil {
			if err := hc.GuardrailChain.ExecuteInput(ctx); err != nil {
				hc.logError("Input guardrail error: %v", err)
				sendErrorResponse(w, http.StatusInternalServerError, "guardrail_error", "Internal guardrail error", ctx.RequestID)
				return
			}

			// Check if request was blocked
			if ctx.Blocked {
				hc.logInfo("Request %s blocked: %s", ctx.RequestID, ctx.BlockMsg)
				sendGuardrailBlockedResponse(w, ctx)
				return
			}
		}

		// Use modified body if available
		requestBody := ctx.GetBodyToProcess()

		// Build target URL
		targetURL := hc.Config.ProviderUrl + r.URL.Path

		// Create forwarding request
		req, err := http.NewRequest(r.Method, targetURL, bytes.NewBuffer(requestBody))
		if err != nil {
			hc.logError("Failed to build request: %v", err)
			sendErrorResponse(w, http.StatusInternalServerError, "proxy_error", "Failed to build request", ctx.RequestID)
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
			sendErrorResponse(w, http.StatusBadGateway, "provider_error", "Failed to connect to provider", ctx.RequestID)
			return
		}
		defer resp.Body.Close()

		// Read response body
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			hc.logError("Failed to read provider response: %v", err)
			sendErrorResponse(w, http.StatusBadGateway, "provider_error", "Failed to read provider response", ctx.RequestID)
			return
		}
		ctx.OriginalResponse = respBody

		// Parse response for guardrail processing
		if hc.Provider != nil {
			parsedResp, err := hc.Provider.ParseResponse(respBody)
			if err == nil {
				ctx.Response = parsedResp
			}
		}

		// Execute output guardrails
		if hc.GuardrailChain != nil {
			if err := hc.GuardrailChain.ExecuteOutput(ctx); err != nil {
				hc.logError("Output guardrail error: %v", err)
				sendErrorResponse(w, http.StatusInternalServerError, "guardrail_error", "Internal guardrail error", ctx.RequestID)
				return
			}

			// Check if response was blocked
			if ctx.Blocked {
				hc.logInfo("Response %s blocked: %s", ctx.RequestID, ctx.BlockMsg)
				sendGuardrailBlockedResponse(w, ctx)
				return
			}
		}

		// Use modified response if available
		responseBody := ctx.GetResponseToProcess()

		// Add guardrail metadata to response if there were warnings
		if len(ctx.Violations) > 0 && !ctx.Blocked {
			responseBody = addGuardrailMetadata(responseBody, ctx)
		}

		// Copy response headers
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		// Add custom headers
		w.Header().Set("X-Guardrail-Request-ID", ctx.RequestID)
		if len(ctx.Violations) > 0 {
			w.Header().Set("X-Guardrail-Warnings", "true")
		}

		// Write response
		w.WriteHeader(resp.StatusCode)
		w.Write(responseBody)

		// Log request completion
		duration := time.Since(startTime)
		hc.logInfo("Request %s completed in %v, violations: %d", ctx.RequestID, duration, len(ctx.Violations))
	}
}

// LegacyHandler provides backward compatibility with the original handler signature
func LegacyHandler(cfg *config.Config, p *provider.OllamaProvider) http.HandlerFunc {
	hc := &HandlerConfig{
		Config:   cfg,
		Provider: p,
		Logger:   log.Default(),
	}
	return Handler(hc)
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

// sendGuardrailBlockedResponse sends a response when request is blocked by guardrails
func sendGuardrailBlockedResponse(w http.ResponseWriter, ctx *chain.Context) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Guardrail-Request-ID", ctx.RequestID)
	w.Header().Set("X-Guardrail-Blocked", "true")
	w.WriteHeader(http.StatusForbidden)

	resp := GuardrailErrorResponse{
		Error:      "guardrail_blocked",
		Code:       "guardrail_blocked",
		Message:    ctx.BlockMsg,
		Violations: ctx.Violations,
		RequestID:  ctx.RequestID,
	}
	json.NewEncoder(w).Encode(resp)
}

// addGuardrailMetadata adds guardrail warnings to the response
func addGuardrailMetadata(body []byte, ctx *chain.Context) []byte {
	// Try to parse as JSON and add metadata
	var jsonResp map[string]interface{}
	if err := json.Unmarshal(body, &jsonResp); err == nil {
		// Add guardrail metadata
		warnings := make([]map[string]interface{}, len(ctx.Violations))
		for i, v := range ctx.Violations {
			warnings[i] = map[string]interface{}{
				"guardrail": v.GuardrailName,
				"type":      v.Type,
				"message":   v.Message,
				"severity":  v.Severity,
			}
		}
		jsonResp["_guardrail"] = map[string]interface{}{
			"request_id": ctx.RequestID,
			"warnings":   warnings,
		}

		if modified, err := json.Marshal(jsonResp); err == nil {
			return modified
		}
	}

	// Return original if not JSON
	return body
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
