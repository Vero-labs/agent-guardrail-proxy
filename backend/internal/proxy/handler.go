package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/analyzer"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/cedar"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/config"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/metrics"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/provider"
	"github.com/blackrose-blackhat/agent-guardrail/backend/pkg/models"
	"github.com/google/uuid"
)

// HandlerConfig holds configuration for the proxy handler
type HandlerConfig struct {
	Config            *config.Config
	Provider          provider.Provider
	IntentAnalyzer    *analyzer.IntentAnalyzer
	HeuristicAnalyzer *analyzer.HeuristicAnalyzer
	SignalAggregator  *analyzer.SignalAggregator
	CedarEngine       *cedar.Engine
	Logger            *log.Logger
	Policy            *policy.GuardrailPolicy // Loaded guardrail.yaml for Go-level enforcement
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

		// METRIC: Record request start
		metrics.RequestsTotal.Inc()

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

			// Operational context: Extract Role from header (Phase 4)
			if role := r.Header.Get("X-Guardrail-Role"); role != "" {
				ctx.Role = role
				hc.logInfo("Request Role detected: %s", role)
			}

			// 1. Deterministic Signal Generation (always runs first)
			if hc.SignalAggregator != nil {
				signals := hc.SignalAggregator.Aggregate(parsedReq)
				ctx.Signals = *signals
				hc.logInfo("Deterministic signals: PII=%v Toxicity=%.2f Injection=%v",
					signals.PII, signals.Toxicity, signals.PromptInjection)

				// METRIC: Record detected signals
				if len(signals.PII) > 0 {
					metrics.RecordSignalDetected("pii")
				}
				// 1.5 Topic Detection (Fast-Path)
				if hc.HeuristicAnalyzer != nil && ctx.Signals.UserText != "" {
					topic := hc.HeuristicAnalyzer.DetectTopic(ctx.Signals.UserText)
					if topic != "" {
						ctx.Signals.Topic = topic
						hc.logInfo("Heuristic Topic detected: %s", topic)
					}
				}

				if signals.Toxicity > 0.5 {
					metrics.RecordSignalDetected("toxicity")
				} // Threshold example
				if signals.PromptInjection {
					metrics.RecordSignalDetected("injection")
				}
			}

			// 2. Semantic Intent Classification (BART sidecar - soft-fail)
			if hc.IntentAnalyzer != nil {
				// A. Fast-Path: Heuristic Check (domain + intent)
				hasConfidentIntent := false
				if hc.HeuristicAnalyzer != nil && ctx.Signals.UserText != "" {
					heuristicSignal := hc.HeuristicAnalyzer.AnalyzeWithDomain(ctx.Signals.UserText)
					if heuristicSignal != nil {
						// Always attach domain info from heuristic
						if heuristicSignal.Domain != "" {
							ctx.Domain = heuristicSignal.Domain
							ctx.DomainConfidence = heuristicSignal.DomainConfidence
							hc.logInfo("Heuristic domain: %s (Confidence=%.2f)", heuristicSignal.Domain, heuristicSignal.DomainConfidence)
						}
						// Only bypass sidecar if we have a confident INTENT match
						if heuristicSignal.Intent != "" {
							ctx.AttachIntent(heuristicSignal, "user")
							hc.logInfo("Heuristic Intent: %s Action: %s (Confidence=%.2f) - BYPASSING Sidecar",
								heuristicSignal.Intent, heuristicSignal.Action, heuristicSignal.Confidence)
							metrics.RecordIntent(heuristicSignal.Intent)
							hasConfidentIntent = true
						}
					}
				}

				// B. Deep-Path: BART sidecar (only if heuristic didn't confidently classify intent)
				if !hasConfidentIntent {
					intentFailed := false

					// Track sidecar block decisions
					var sidecarBlocked bool
					var sidecarBlockReason string

					// Contextual Window Analysis
					if len(parsedReq.Messages) > 0 {
						intentSignal, err := hc.IntentAnalyzer.AnalyzeMessages(parsedReq.Messages)
						if err != nil {
							hc.logError("[WARN] Contextual intent analysis failed: %v", err)
							intentFailed = true
						} else {
							// Populate Action from canonical map if sidecar didn't provide it
							if intentSignal.Action == "" {
								intentSignal.Action = analyzer.ActionForIntent(intentSignal.Intent)
							}
							ctx.AttachIntent(intentSignal, "aggregate")
							hc.logInfo("Contextual Intent: %s Action: %s Domain: %s (Confidence=%.2f, DerivedRisk=%.2f)",
								intentSignal.Intent, intentSignal.Action, intentSignal.Domain, intentSignal.Confidence, ctx.RiskScore)
							// METRIC: Record intent
							metrics.RecordIntent(intentSignal.Intent)
							// Check sidecar's own evaluation decision
							if intentSignal.SidecarDecision == "block" {
								sidecarBlocked = true
								sidecarBlockReason = intentSignal.SidecarReason
							}
						}
					}

					// User Text specifically
					if ctx.Signals.UserText != "" {
						userIntentSignal, err := hc.IntentAnalyzer.Analyze(ctx.Signals.UserText)
						if err != nil {
							hc.logError("[WARN] User content intent analysis failed: %v", err)
							intentFailed = true
						} else {
							// Populate Action from canonical map if sidecar didn't provide it
							if userIntentSignal.Action == "" {
								userIntentSignal.Action = analyzer.ActionForIntent(userIntentSignal.Intent)
							}
							ctx.AttachIntent(userIntentSignal, "user")
							hc.logInfo("User-Specific Intent: %s Action: %s Domain: %s (Confidence=%.2f, SidecarDecision: %s)",
								userIntentSignal.Intent, userIntentSignal.Action, userIntentSignal.Domain,
								userIntentSignal.Confidence, userIntentSignal.SidecarDecision)
							// Check sidecar's own evaluation decision (user-specific takes precedence)
							if userIntentSignal.SidecarDecision == "block" {
								sidecarBlocked = true
								sidecarBlockReason = userIntentSignal.SidecarReason
							}
						}
					}

					// ?????? SIDECAR DECISION ENFORCEMENT ??????
					// If the sidecar's own evaluator blocked the request, enforce it
					if sidecarBlocked {
						hc.logDecision("DENY", sidecarBlockReason, "sidecar-evaluation")
						w.Header().Set("X-Guardrail-Blocked", "true")
						sendErrorResponse(w, http.StatusForbidden, "sidecar_blocked", sidecarBlockReason, requestID)
						return
					}

					// FAIL-CLOSED: If intent analysis completely failed, mark context
					if intentFailed && ctx.Intent == "" {
						ctx.Intent = "unknown"
						ctx.UserIntent = "unknown"
						ctx.Confidence = 0.5
						ctx.RiskScore = 0.5
						ctx.AnalyzerFailed = true // Distinct from model-said-unknown
						hc.logInfo("Intent analysis unavailable — defaulting to unknown (fail-closed)")
					}

					// Detect domain from heuristic if sidecar didn't provide one
					if ctx.Domain == "" && hc.HeuristicAnalyzer != nil && ctx.Signals.UserText != "" {
						detectedDomain := hc.HeuristicAnalyzer.DetectTopic(ctx.Signals.UserText)
						if detectedDomain != "" {
							ctx.Domain = detectedDomain
							ctx.DomainConfidence = 0.90 // keyword match = high confidence
							hc.logInfo("Heuristic domain detection: %s (Confidence=0.90)", detectedDomain)
						}
					}
				}
			}

			// ============================================================
			// STEP 4: ROLE-DOMAIN ENFORCEMENT (Go-level, pre-Cedar)
			// ============================================================
			if ctx.Role != "" && hc.Policy != nil {
				if decision, reason := hc.enforceRolePolicy(ctx); decision == "DENY" {
					hc.logDecision("DENY", reason, "role-enforcement")
					w.Header().Set("X-Guardrail-Blocked", "true")
					sendErrorResponse(w, http.StatusForbidden, "role_policy_blocked", reason, requestID)
					return
				}
			}

			// ============================================================
			// STEP 5-6: CEDAR EVALUATION (content risk only)
			// ============================================================
			// Cedar evaluates: intent thresholds, PII obligations, capabilities,
			// source trust. Cedar has NO role awareness.
			// ============================================================
			if hc.CedarEngine != nil {
				result := hc.CedarEngine.EvaluateContextWithResult(ctx)
				decision := result.Decision
				reason := result.Reason

				hc.logDecision(string(decision), reason, "cedar")

				// METRIC: Record decision
				metrics.RecordDecision(string(decision))

				// Set pre-stream enforcement header (audit trail)
				w.Header().Set("X-Guardrail-PreStream-Enforced", "true")

				// Set policy version header (governance)
				w.Header().Set("X-Guardrail-Policy-Version", hc.CedarEngine.PolicyVersion())

				if decision == cedar.DENY {
					hc.logDecision("DENY", reason, "cedar")
					w.Header().Set("X-Guardrail-Blocked", "true")
					sendErrorResponse(w, http.StatusForbidden, "guardrail_blocked", reason, requestID)
					return
				}

				// Handle obligations (Phase 4 Optimization)
				for _, obs := range result.Obligations {
					if obs.Type == "REDACT" && parsedReq != nil {
						hc.logInfo("Applying REDACT obligation on input: %v", obs.Fields)
						// Redact messages in the parsed request
						for i := range parsedReq.Messages {
							parsedReq.Messages[i].Content = hc.SignalAggregator.RedactPII(parsedReq.Messages[i].Content, obs.Fields)
						}
						// Re-marshal the redacted request
						newBody, err := json.Marshal(parsedReq)
						if err == nil {
							body = newBody // Use redacted body for forwarding
							hc.logInfo("Input REDACTED successfully")
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

		// Parse response for processing (if provider is set)
		var responseContent string
		if hc.Provider != nil {
			parsedResp, err := hc.Provider.ParseResponse(respBody)
			if err != nil {
				hc.logError("Failed to parse response: %v", err)
			} else if len(parsedResp.Choices) > 0 {
				responseContent = parsedResp.Choices[0].Message.Content
			}
		}

		// ============================================================
		// OUTPUT-SIDE GUARDRAILS (Phase 1)
		// ============================================================
		// Scan response content for PII before returning to client
		if responseContent != "" && hc.SignalAggregator != nil {
			// Reuse existing PII detector on response content
			outputPII := hc.SignalAggregator.DetectPII(responseContent)
			if len(outputPII) > 0 {
				// Block if critical PII (SSN, credit card) found in output
				for _, piiType := range outputPII {
					if piiType == "ssn" || piiType == "credit_card" {
						hc.logError("Output blocked: %s detected in LLM response", piiType)
						w.Header().Set("X-Guardrail-Output-Blocked", "true")
						sendErrorResponse(w, http.StatusForbidden, "output_guardrail_blocked",
							"Response contained sensitive data and was blocked", requestID)
						return
					}
				}
				// Log warning for other PII types (email, phone) but allow through
				hc.logInfo("Output warning: PII detected in response: %v", outputPII)
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
		metrics.LatencyHistogram.Observe(duration.Seconds())
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

// logDecision outputs structured enforcement decisions for auditability.
// Format: Decision: ALLOW|DENY | Reason: <why> | Step: <enforcement-step>
func (hc *HandlerConfig) logDecision(decision, reason, step string) {
	if hc.Logger != nil {
		hc.Logger.Printf("[DECISION] Decision: %s | Reason: %s | Step: %s", decision, reason, step)
	}
}

// enforceRolePolicy applies Go-level role-domain and role-action enforcement
// BEFORE Cedar evaluation. Returns ("DENY", reason) or ("ALLOW", "").
//
// Enforcement order within this function:
//  1. Analyzer health check (fail-closed under constrained roles)
//  2. Domain enforcement (empty domain = deny under constrained roles)
//  3. Domain confidence check
//  4. Action enforcement (empty action = deny under constrained roles)
//  5. Action confidence check
//  6. Unknown intent check
func (hc *HandlerConfig) enforceRolePolicy(ctx *analyzer.Context) (string, string) {
	if hc.Policy == nil || ctx.Role == "" {
		return "ALLOW", ""
	}

	roleCfg, exists := hc.Policy.Roles[ctx.Role]
	if !exists {
		// Unknown role = no constraints (pass through to Cedar)
		return "ALLOW", ""
	}

	isConstrained := len(roleCfg.AllowedTopics) > 0 || len(roleCfg.AllowActions) > 0

	// Default thresholds if not set in YAML
	domainThreshold := roleCfg.DomainConfidenceThreshold
	if domainThreshold == 0 {
		domainThreshold = 0.6
	}
	actionThreshold := roleCfg.ActionConfidenceThreshold
	if actionThreshold == 0 {
		actionThreshold = 0.65
	}

	// ── 1. Analyzer health check ──
	if ctx.AnalyzerFailed && isConstrained {
		return "DENY", "Analyzer unavailable — fail-closed for constrained role '" + ctx.Role + "'"
	}

	// ── 2. Domain enforcement ──
	if len(roleCfg.AllowedTopics) > 0 {
		domain := ctx.Domain
		if domain == "" {
			// Also check legacy topic signal as fallback
			domain = ctx.Signals.Topic
		}

		if domain == "" {
			// Empty domain under constrained role = DENY (no silent bypass)
			return "DENY", "Unknown domain — denied for constrained role '" + ctx.Role + "'"
		}

		if !contains(roleCfg.AllowedTopics, domain) {
			return "DENY", "Domain '" + domain + "' not allowed for role '" + ctx.Role + "'"
		}

		// ── 3. Domain confidence check ──
		if ctx.DomainConfidence > 0 && ctx.DomainConfidence < domainThreshold {
			return "DENY", "Domain confidence " + formatFloat(ctx.DomainConfidence) + " below threshold " + formatFloat(domainThreshold) + " for role '" + ctx.Role + "'"
		}
	}

	// ── 4. Explicit topic blocks ──
	if len(roleCfg.BlockTopics) > 0 {
		domain := ctx.Domain
		if domain == "" {
			domain = ctx.Signals.Topic
		}
		if domain != "" && contains(roleCfg.BlockTopics, domain) {
			return "DENY", "Domain '" + domain + "' explicitly blocked for role '" + ctx.Role + "'"
		}
	}

	// ── 5. Action enforcement ──
	if len(roleCfg.AllowActions) > 0 {
		action := ctx.Action
		if action == "" {
			// Derive from intent as last resort using canonical map
			action = analyzer.ActionForIntent(ctx.Intent)
		}

		if action == "" && isConstrained {
			return "DENY", "Unknown action — denied for constrained role '" + ctx.Role + "'"
		}

		if action != "" && !contains(roleCfg.AllowActions, action) {
			return "DENY", "Action '" + action + "' not allowed for role '" + ctx.Role + "'"
		}

		// ── 6. Action confidence check ──
		if ctx.ActionConfidence > 0 && ctx.ActionConfidence < actionThreshold {
			return "DENY", "Action confidence " + formatFloat(ctx.ActionConfidence) + " below threshold " + formatFloat(actionThreshold) + " for role '" + ctx.Role + "'"
		}
	}

	// ── 7. Explicit intent blocks ──
	if len(roleCfg.BlockIntents) > 0 && ctx.Intent != "" {
		if contains(roleCfg.BlockIntents, ctx.Intent) {
			return "DENY", "Intent '" + ctx.Intent + "' explicitly blocked for role '" + ctx.Role + "'"
		}
	}

	// ── 8. Unknown intent under constrained role ──
	if ctx.Intent == "unknown" && isConstrained {
		return "DENY", "Unknown intent denied for constrained role '" + ctx.Role + "'"
	}

	return "ALLOW", ""
}

// contains checks if a string slice contains a specific value
func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// formatFloat formats a float64 with 2 decimal places for log output
func formatFloat(f float64) string {
	return fmt.Sprintf("%.2f", f)
}
