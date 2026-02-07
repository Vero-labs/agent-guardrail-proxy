package provider

import (
	"errors"
	"sync"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/config"
)

// Router manages multiple providers and routes requests to the appropriate one
type Router struct {
	providers map[string]Provider
	rules     []RoutingRule
	fallback  string
	mu        sync.RWMutex
}

// RoutingRule defines a condition for routing to a specific provider
type RoutingRule struct {
	Name      string
	Condition func(*chain.LLMRequest) bool
	Target    string
	Priority  int
}

// NewRouter creates a new provider router
func NewRouter() *Router {
	return &Router{
		providers: make(map[string]Provider),
		rules:     make([]RoutingRule, 0),
	}
}

// NewRouterFromConfig creates a router initialized with providers from config
func NewRouterFromConfig(cfg *config.Config) (*Router, error) {
	router := NewRouter()

	for name, provConfig := range cfg.Providers {
		var p Provider

		switch provConfig.Type {
		case "ollama":
			p = NewOllamaProviderWithConfig(provConfig.BaseURL, provConfig.APIKey)
		case "openai":
			p = NewOpenAIProvider(provConfig.BaseURL, provConfig.APIKey)
		// Add more providers as implemented
		default:
			// Default to OpenAI-compatible
			p = NewOpenAIProvider(provConfig.BaseURL, provConfig.APIKey)
		}

		router.RegisterProvider(name, p)

		if provConfig.Default {
			router.SetFallback(name)
		}
	}

	// If no fallback set, use "default" or first available
	if router.fallback == "" {
		if _, ok := router.providers["default"]; ok {
			router.fallback = "default"
		} else {
			for name := range router.providers {
				router.fallback = name
				break
			}
		}
	}

	return router, nil
}

// RegisterProvider adds a provider to the router
func (r *Router) RegisterProvider(name string, provider Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[name] = provider
}

// SetFallback sets the default provider to use when no rules match
func (r *Router) SetFallback(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fallback = name
}

// AddRule adds a routing rule
func (r *Router) AddRule(rule RoutingRule) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Insert in priority order (lower priority first)
	inserted := false
	for i, existing := range r.rules {
		if rule.Priority < existing.Priority {
			r.rules = append(r.rules[:i], append([]RoutingRule{rule}, r.rules[i:]...)...)
			inserted = true
			break
		}
	}
	if !inserted {
		r.rules = append(r.rules, rule)
	}
}

// Route selects the appropriate provider for a request
func (r *Router) Route(req *chain.LLMRequest) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check routing rules
	for _, rule := range r.rules {
		if rule.Condition(req) {
			if p, ok := r.providers[rule.Target]; ok {
				return p, nil
			}
		}
	}

	// Use fallback
	if r.fallback != "" {
		if p, ok := r.providers[r.fallback]; ok {
			return p, nil
		}
	}

	// Return first available provider
	for _, p := range r.providers {
		return p, nil
	}

	return nil, errors.New("no provider available")
}

// GetProvider returns a specific provider by name
func (r *Router) GetProvider(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

// ListProviders returns all registered provider names
func (r *Router) ListProviders() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}
