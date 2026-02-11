package analyzer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/blackrose-blackhat/agent-guardrail/backend/pkg/models"
)

// IntentAnalyzer calls the Python sidecar for semantic intent classification
type IntentAnalyzer struct {
	endpoint      string
	cacheEndpoint string
	client        *http.Client

	// Local LRU-style cache
	cache      map[string]*IntentSignal
	cacheLock  sync.RWMutex
	maxEntries int
}

// NewIntentAnalyzer creates a new IntentAnalyzer
func NewIntentAnalyzer(endpoint string, cacheEndpoint string) *IntentAnalyzer {
	return &IntentAnalyzer{
		endpoint:      endpoint,
		cacheEndpoint: cacheEndpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache:      make(map[string]*IntentSignal),
		maxEntries: 1000,
	}
}

func (a *IntentAnalyzer) computeHash(text string) string {
	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:])
}

func (a *IntentAnalyzer) computeMessagesHash(messages []models.Message) string {
	h := sha256.New()
	for _, m := range messages {
		h.Write([]byte(m.Role))
		h.Write([]byte(m.Content))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// intentRequest matches the Python sidecar's expected input
type intentRequest struct {
	Text     string           `json:"text,omitempty"`
	Messages []models.Message `json:"messages,omitempty"`
}

// Analyze extracts intent from text using BART-MNLI sidecar
func (a *IntentAnalyzer) Analyze(text string) (*IntentSignal, error) {
	return a.callSidecar(intentRequest{Text: text})
}

// AnalyzeMessages extracts intent from a full conversation window
func (a *IntentAnalyzer) AnalyzeMessages(messages []models.Message) (*IntentSignal, error) {
	return a.callSidecar(intentRequest{Messages: messages})
}

func (a *IntentAnalyzer) callSidecar(req intentRequest) (*IntentSignal, error) {
	// Cache Check
	var cacheKey string
	if req.Text != "" {
		cacheKey = "text:" + a.computeHash(req.Text)
	} else if len(req.Messages) > 0 {
		cacheKey = "msg:" + a.computeMessagesHash(req.Messages)
	}

	if cacheKey != "" {
		a.cacheLock.RLock()
		if sig, ok := a.cache[cacheKey]; ok {
			a.cacheLock.RUnlock()
			return sig, nil
		}
		a.cacheLock.RUnlock()
	}

	reqBytes, _ := json.Marshal(req)
	resp, err := a.client.Post(a.endpoint+"/intent", "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("intent sidecar request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("intent sidecar returned status %d", resp.StatusCode)
	}

	var signal IntentSignal
	if err := json.NewDecoder(resp.Body).Decode(&signal); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Validate intent is in taxonomy
	if !isValidIntent(signal.Intent) {
		signal.Intent = IntentUnknown
	}

	// Cache Result
	if cacheKey != "" {
		a.cacheLock.Lock()
		if len(a.cache) >= a.maxEntries {
			// Rudimentary eviction: clear map if full
			a.cache = make(map[string]*IntentSignal)
		}
		a.cache[cacheKey] = &signal
		a.cacheLock.Unlock()
	}

	return &signal, nil
}

// Health checks if the sidecar is available
func (a *IntentAnalyzer) Health() bool {
	resp, err := a.client.Get(a.endpoint + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// isValidIntent checks if intent is in the hierarchical taxonomy
func isValidIntent(intent string) bool {
	switch intent {
	case IntentInfoQuery, IntentInfoQueryPII, IntentInfoSummarize,
		IntentCodeGenerate, IntentCodeExploit,
		IntentToolSafe, IntentToolRisk,
		IntentFileRead, IntentFileWrite,
		IntentSystem,
		IntentConvGreeting, IntentConvOther,
		"safety.toxicity", // Added to support sidecar's toxicity label
		IntentUnknown:
		return true
	default:
		return false
	}
}
