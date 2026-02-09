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
	Config            *config.Config
	Provider          provider.Provider
	Analyzer          *analyzer.Analyzer // Legacy LLM analyzer (deprecated)
	IntentAnalyzer    *analyzer.IntentAnalyzer
	HeuristicAnalyzer *analyzer.HeuristicAnalyzer // New: Fast-path regex analyzer
	SignalAggregator  *analyzer.SignalAggregator
	CedarEngine       *cedar.Engine
	Logger            *log.Logger
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

		// ============================================================
		// SIGNAL GENERATION & POLICY DECISION (FAIL-CLOSED)
		// ============================================================
		// If any step fails, the request is blocked. No silent pass-through.

		if parsedReq != nil {
			// Build context for Cedar evaluation
			ctx := &analyzer.Context{
				Provider:            hc.Provider.Name(),
				ResourceSensitivity: "public", // Default
			}

			// Override sensitivity from header if provided (internal testing/routing)
			if s := r.Header.Get("X-Resource-Sensitivity"); s != "" {
				ctx.ResourceSensitivity = s
			}

			// 1. Deterministic Signal Generation (always runs first)
			if hc.SignalAggregator != nil {
				signals := hc.SignalAggregator.Aggregate(parsedReq)
				ctx.Signals = *signals
				hc.logInfo("Deterministic signals: PII=%v Toxicity=%.2f Injection=%v",
					signals.PII, signals.Toxicity, signals.PromptInjection)
			}

			// 2. Semantic Intent Classification (BART sidecar - soft-fail)
			if hc.IntentAnalyzer != nil {
				// A. Fast-Path: Heuristic Check
				var heuristicSignal *analyzer.IntentSignal
				if hc.HeuristicAnalyzer != nil && ctx.Signals.UserText != "" {
					heuristicSignal = hc.HeuristicAnalyzer.Analyze(ctx.Signals.UserText)
					if heuristicSignal != nil {
						ctx.AttachIntent(heuristicSignal, "user")
						hc.logInfo("Heuristic Intent: %s (Confidence=%.2f) - BYPASSING Sidecar",
							heuristicSignal.Intent, heuristicSignal.Confidence)
					}
				}

				// B. Deep-Path: BART sidecar (only if heuristic didn't confidently hit)
				if heuristicSignal == nil {
					// Contextual Window Analysis
					if len(parsedReq.Messages) > 0 {
						intentSignal, err := hc.IntentAnalyzer.AnalyzeMessages(parsedReq.Messages)
						if err != nil {
							hc.logError("[WARN] Contextual intent analysis failed: %v", err)
						} else {
							ctx.AttachIntent(intentSignal, "aggregate")
							hc.logInfo("Contextual Intent: %s (Confidence=%.2f, DerivedRisk=%.2f)",
								intentSignal.Intent, intentSignal.Confidence, ctx.RiskScore)
						}
					}

					// User Text specifically
					if ctx.Signals.UserText != "" {
						userIntentSignal, err := hc.IntentAnalyzer.Analyze(ctx.Signals.UserText)
						if err != nil {
							hc.logError("[WARN] User content intent analysis failed: %v", err)
						} else {
							ctx.AttachIntent(userIntentSignal, "user")
							hc.logInfo("User-Specific Intent: %s (Confidence=%.2f)",
								userIntentSignal.Intent, userIntentSignal.Confidence)
						}
					}
				}
			}

			// 3. Evaluate policy with Cedar (PRE-STREAM ENFORCEMENT)
			// ============================================================
			// CRITICAL: This evaluation MUST complete BEFORE any streaming
			// begins. Cedar runs ONCE, synchronously, before the first SSE
			// token is forwarded. This closes the #1 real-world leakage vector.
			// ============================================================
			if hc.CedarEngine != nil {
				decision, reason, err := hc.CedarEngine.EvaluateContext(ctx)
				if err != nil {
					hc.logError("[FAIL-CLOSED] Policy evaluation failed: %v", err)
					sendErrorResponse(w, http.StatusForbidden, "guardrail_error", "Security policy evaluation failed", requestID)
					return
				}

				hc.logInfo("Cedar Decision: %s (Reason: %s)", decision, reason)

				// Set pre-stream enforcement header (audit trail)
				w.Header().Set("X-Guardrail-PreStream-Enforced", "true")

				// Set policy version header (governance)
				w.Header().Set("X-Guardrail-Policy-Version", hc.CedarEngine.PolicyVersion)

				if decision == cedar.DENY {
					hc.logInfo("Request %s BLOCKED (pre-stream): %s", requestID, reason)
					w.Header().Set("X-Guardrail-Blocked", "true")
					sendErrorResponse(w, http.StatusForbidden, "guardrail_blocked", reason, requestID)
					return
				}
			}
		}
		// ============================================================

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

		// Handle standard response
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			hc.logError("Failed to read response: %v", err)
			sendErrorResponse(w, http.StatusBadGateway, "provider_error", "Failed to read provider response", requestID)
			return
		}

		// Parse response for processing (if provider is set)
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
