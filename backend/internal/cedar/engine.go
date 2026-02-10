package cedar

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/analyzer"
	"github.com/cedar-policy/cedar-go"
	"github.com/fsnotify/fsnotify"
)

// Decision represents the result of a policy evaluation
type Decision string

const (
	ALLOW     Decision = "ALLOW"
	DENY      Decision = "DENY"
	CONSTRAIN Decision = "CONSTRAIN"
)

// Obligation represents an action the PEP must take
type Obligation struct {
	Type   string   `json:"type"`   // "REDACT", "RequireApproval", "RateLimit"
	Fields []string `json:"fields"` // For REDACT: fields to redact
}

// EvaluationResult contains the decision and any obligations
type EvaluationResult struct {
	Decision    Decision
	Reason      string
	PolicyID    string
	Obligations []Obligation
}

// Engine wraps the Cedar policy engine with hot-reloading support
type Engine struct {
	policySet     atomic.Pointer[cedar.PolicySet]
	policyVersion atomic.Pointer[string]
	PolicyPath    string

	watcher    *fsnotify.Watcher
	stopWatch  chan struct{}
	logger     *log.Logger
	reloadLock sync.Mutex
}

// PolicyVersion returns the current policy version (thread-safe)
func (e *Engine) PolicyVersion() string {
	v := e.policyVersion.Load()
	if v == nil {
		return ""
	}
	return *v
}

// NewEngine creates a new Engine and loads policies from a file
func NewEngine(policyPath string) (*Engine, error) {
	return NewEngineWithLogger(policyPath, log.Default())
}

// NewEngineWithLogger creates a new Engine with a custom logger
func NewEngineWithLogger(policyPath string, logger *log.Logger) (*Engine, error) {
	e := &Engine{
		PolicyPath: policyPath,
		stopWatch:  make(chan struct{}),
		logger:     logger,
	}

	// Initial policy load
	if err := e.reload(); err != nil {
		return nil, err
	}

	return e, nil
}

// StartHotReload enables fsnotify file watching for policy hot-reloading
func (e *Engine) StartHotReload() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}
	e.watcher = watcher

	if err := watcher.Add(e.PolicyPath); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to watch policy file: %w", err)
	}

	go e.watchLoop()

	e.logger.Printf("[Cedar] Hot-reload enabled for: %s", e.PolicyPath)
	return nil
}

// StopHotReload stops the file watcher
func (e *Engine) StopHotReload() {
	if e.watcher != nil {
		close(e.stopWatch)
		e.watcher.Close()
	}
}

func (e *Engine) watchLoop() {
	// Debounce timer to handle rapid file saves
	var debounceTimer *time.Timer
	debounce := 500 * time.Millisecond

	for {
		select {
		case event, ok := <-e.watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				// Reset debounce timer
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(debounce, func() {
					e.reloadLock.Lock()
					defer e.reloadLock.Unlock()

					oldVersion := e.PolicyVersion()
					if err := e.reload(); err != nil {
						e.logger.Printf("[Cedar] Hot-reload FAILED: %v", err)
					} else {
						e.logger.Printf("[Cedar] Hot-reload SUCCESS: %s -> %s", oldVersion, e.PolicyVersion())
					}
				})
			}
		case err, ok := <-e.watcher.Errors:
			if !ok {
				return
			}
			e.logger.Printf("[Cedar] Watcher error: %v", err)
		case <-e.stopWatch:
			return
		}
	}
}

// reload loads/reloads policies from the file
func (e *Engine) reload() error {
	data, err := os.ReadFile(e.PolicyPath)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	// Compute policy version hash
	hash := sha256.Sum256(data)
	version := hex.EncodeToString(hash[:])[:12]

	ps := cedar.NewPolicySet()

	// Split policies by semicolon as a rudimentary parser
	chunks := strings.Split(string(data), ";")
	for i, chunk := range chunks {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}

		fullPolicy := chunk + ";"

		var policy cedar.Policy
		if err := policy.UnmarshalCedar([]byte(fullPolicy)); err != nil {
			return fmt.Errorf("failed to unmarshal cedar policy part %d: %w", i, err)
		}

		ps.Add(cedar.PolicyID(fmt.Sprintf("policy%d", i)), &policy)
	}

	// Atomic swap
	e.policySet.Store(ps)
	e.policyVersion.Store(&version)

	return nil
}

// Evaluate checks the facts against the policies (legacy interface)
func (e *Engine) Evaluate(facts *analyzer.Facts) (Decision, string, error) {
	ctx := facts.ToContext()
	return e.EvaluateContext(ctx)
}

// EvaluateContext checks the context against the policies
func (e *Engine) EvaluateContext(ctx *analyzer.Context) (Decision, string, error) {
	result := e.EvaluateContextWithResult(ctx)
	return result.Decision, result.Reason, nil
}

// EvaluateContextWithResult returns full evaluation result including obligations
func (e *Engine) EvaluateContextWithResult(ctx *analyzer.Context) EvaluationResult {
	ps := e.policySet.Load()
	if ps == nil {
		return EvaluationResult{
			Decision: DENY,
			Reason:   "Policy engine not initialized",
		}
	}

	// Build LLM resource with attributes
	entities := cedar.EntityMap{
		cedar.NewEntityUID("LLM", "default"): cedar.Entity{
			UID: cedar.NewEntityUID("LLM", "default"),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"sensitivity": cedar.String(ctx.ResourceSensitivity),
			}),
		},
	}

	// Build PII set
	piiValues := make([]cedar.Value, len(ctx.Signals.PII))
	for i, pii := range ctx.Signals.PII {
		piiValues[i] = cedar.String(pii)
	}
	piiSet := cedar.NewSet(piiValues...)

	// Build Capabilities set
	capValues := make([]cedar.Value, len(ctx.Signals.Capabilities))
	for i, cap := range ctx.Signals.Capabilities {
		capValues[i] = cedar.String(cap)
	}
	capSet := cedar.NewSet(capValues...)

	// Build agent state (for agentic workflows)
	agentStateMap := cedar.RecordMap{
		"current_step": cedar.Long(int64(ctx.AgentState.CurrentStep)),
		"max_steps":    cedar.Long(int64(ctx.AgentState.MaxSteps)),
		"total_tokens": cedar.Long(int64(ctx.AgentState.TotalTokens)),
		"token_budget": cedar.Long(int64(ctx.AgentState.TokenBudget)),
	}

	// Build source data (for indirect injection defense)
	sourceDataMap := cedar.RecordMap{
		"origin":  cedar.String(ctx.SourceData.Origin),
		"trusted": cedar.Boolean(ctx.SourceData.Trusted),
	}

	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", "default"),
		Action:    cedar.NewEntityUID("Action", "chat"),
		Resource:  cedar.NewEntityUID("LLM", "default"),
		Context: cedar.NewRecord(cedar.RecordMap{
			// Semantic signals
			"intent":        cedar.String(ctx.Intent),
			"user_intent":   cedar.String(ctx.UserIntent),
			"system_intent": cedar.String(ctx.SystemIntent),
			"risk_score":    cedar.Long(int64(ctx.RiskScore * 100)),
			"confidence":    cedar.Long(int64(ctx.Confidence * 100)),
			// Deterministic signals
			"pii":              piiSet,
			"toxicity":         cedar.Long(int64(ctx.Signals.Toxicity * 100)),
			"prompt_injection": cedar.Boolean(ctx.Signals.PromptInjection),
			"topic":            cedar.String(ctx.Signals.Topic),
			"capabilities":     capSet,
			// Request metadata
			"streaming": cedar.Boolean(ctx.Request.Streaming),
			"tokens":    cedar.Long(int64(ctx.Request.Tokens)),
			// Provider
			"provider": cedar.String(ctx.Provider),
			// Agentic state (Phase 2)
			"agent_state": cedar.NewRecord(agentStateMap),
			// Source data (Phase 3)
			"source_data": cedar.NewRecord(sourceDataMap),
		}),
	}

	ok, diagnostics := cedar.Authorize(ps, entities, req)

	var obligations []Obligation
	var policyID string

	if len(diagnostics.Reasons) > 0 {
		// Take the first policy that contributed to the decision
		reason := diagnostics.Reasons[0]
		policyID = string(reason.PolicyID)

		// Extract annotations as obligations
		p := ps.Get(reason.PolicyID)
		if p != nil {
			annotations := p.Annotations()
			if typeVal, ok := annotations["obligation"]; ok {
				obs := Obligation{
					Type: string(typeVal),
				}
				// Optional fields annotation for redaction
				if fieldsVal, ok := annotations["fields"]; ok {
					obs.Fields = strings.Split(string(fieldsVal), ",")
					for i := range obs.Fields {
						obs.Fields[i] = strings.TrimSpace(obs.Fields[i])
					}
				}
				obligations = append(obligations, obs)
			}
		}
	}

	if ok {
		return EvaluationResult{
			Decision:    ALLOW,
			Reason:      "Policy allowed the request",
			PolicyID:    policyID,
			Obligations: obligations,
		}
	}

	return EvaluationResult{
		Decision:    DENY,
		Reason:      "Policy denied the request",
		PolicyID:    policyID,
		Obligations: obligations,
	}
}
