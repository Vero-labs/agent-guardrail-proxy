package input

import (
	"sync"
	"time"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
)

// RateLimitConfig holds configuration for rate limiting
type RateLimitConfig struct {
	Enabled           bool   `yaml:"enabled" json:"enabled"`
	RequestsPerMinute int    `yaml:"requests_per_minute" json:"requests_per_minute"`
	RequestsPerHour   int    `yaml:"requests_per_hour" json:"requests_per_hour"`
	BurstSize         int    `yaml:"burst_size" json:"burst_size"`
	KeyBy             string `yaml:"key_by" json:"key_by"` // "ip", "user", "app", "global"
}

// RateLimitGuardrail enforces deterministic rate limits
// This is NOT a signal - it is a hard operational control
type RateLimitGuardrail struct {
	config   RateLimitConfig
	counters map[string]*rateLimitCounter
	mu       sync.RWMutex
}

type rateLimitCounter struct {
	minuteCount int
	hourCount   int
	minuteReset time.Time
	hourReset   time.Time
}

// NewRateLimitGuardrail creates a new rate limit guardrail
func NewRateLimitGuardrail(config RateLimitConfig) *RateLimitGuardrail {
	// Set defaults
	if config.RequestsPerMinute == 0 {
		config.RequestsPerMinute = 60
	}
	if config.RequestsPerHour == 0 {
		config.RequestsPerHour = 1000
	}
	if config.BurstSize == 0 {
		config.BurstSize = 10
	}
	if config.KeyBy == "" {
		config.KeyBy = "global"
	}

	return &RateLimitGuardrail{
		config:   config,
		counters: make(map[string]*rateLimitCounter),
	}
}

// Name returns the guardrail identifier
func (g *RateLimitGuardrail) Name() string {
	return "rate_limit"
}

// Type returns the guardrail type
func (g *RateLimitGuardrail) Type() chain.GuardrailType {
	return chain.GuardrailTypeInput
}

// Priority returns execution priority (rate limit runs FIRST - priority 1)
func (g *RateLimitGuardrail) Priority() int {
	return 1
}

// IsEnabled returns whether this guardrail is active
func (g *RateLimitGuardrail) IsEnabled() bool {
	return g.config.Enabled
}

// Execute performs the deterministic rate limit check
func (g *RateLimitGuardrail) Execute(ctx *chain.Context) (*chain.Result, error) {
	key := g.getKey(ctx)
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

	counter, exists := g.counters[key]
	if !exists {
		counter = &rateLimitCounter{
			minuteReset: now.Add(time.Minute),
			hourReset:   now.Add(time.Hour),
		}
		g.counters[key] = counter
	}

	// Reset counters if windows have passed
	if now.After(counter.minuteReset) {
		counter.minuteCount = 0
		counter.minuteReset = now.Add(time.Minute)
	}
	if now.After(counter.hourReset) {
		counter.hourCount = 0
		counter.hourReset = now.Add(time.Hour)
	}

	// Check minute limit
	if counter.minuteCount >= g.config.RequestsPerMinute {
		retryAfter := counter.minuteReset.Sub(now).Seconds()
		return &chain.Result{
			Passed:  false,
			Action:  chain.ActionBlock,
			Message: "Rate limit exceeded: too many requests per minute",
			Violations: []chain.Violation{{
				GuardrailName: g.Name(),
				Type:          "rate_limit_exceeded",
				Message:       "Deterministic rate limit: requests per minute exceeded",
				Severity:      "critical",
				Action:        chain.ActionBlock,
				Details: map[string]interface{}{
					"limit":         g.config.RequestsPerMinute,
					"window":        "minute",
					"retry_after":   retryAfter,
					"deterministic": true,
				},
				Timestamp: now,
			}},
		}, nil
	}

	// Check hour limit
	if counter.hourCount >= g.config.RequestsPerHour {
		retryAfter := counter.hourReset.Sub(now).Seconds()
		return &chain.Result{
			Passed:  false,
			Action:  chain.ActionBlock,
			Message: "Rate limit exceeded: too many requests per hour",
			Violations: []chain.Violation{{
				GuardrailName: g.Name(),
				Type:          "rate_limit_exceeded",
				Message:       "Deterministic rate limit: requests per hour exceeded",
				Severity:      "critical",
				Action:        chain.ActionBlock,
				Details: map[string]interface{}{
					"limit":         g.config.RequestsPerHour,
					"window":        "hour",
					"retry_after":   retryAfter,
					"deterministic": true,
				},
				Timestamp: now,
			}},
		}, nil
	}

	// Increment counters
	counter.minuteCount++
	counter.hourCount++

	return &chain.Result{
		Passed: true,
	}, nil
}

// getKey determines the rate limit key based on configuration
func (g *RateLimitGuardrail) getKey(ctx *chain.Context) string {
	switch g.config.KeyBy {
	case "user":
		if ctx.UserID != "" {
			return "user:" + ctx.UserID
		}
		return "user:anonymous"
	case "app":
		if ctx.AppID != "" {
			return "app:" + ctx.AppID
		}
		return "app:default"
	case "ip":
		// Would need to extract from context/headers
		return "ip:unknown"
	default:
		return "global"
	}
}

// GetStats returns current rate limit statistics
func (g *RateLimitGuardrail) GetStats() map[string]interface{} {
	g.mu.RLock()
	defer g.mu.RUnlock()

	stats := make(map[string]interface{})
	for key, counter := range g.counters {
		stats[key] = map[string]interface{}{
			"minute_count": counter.minuteCount,
			"hour_count":   counter.hourCount,
		}
	}
	return stats
}
