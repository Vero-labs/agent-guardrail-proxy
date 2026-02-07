package proxy

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// CircuitState represents the state of the circuit breaker
type CircuitState int

const (
	CircuitClosed   CircuitState = iota // Normal operation
	CircuitOpen                         // Failing, reject requests
	CircuitHalfOpen                     // Testing if service recovered
)

// CircuitBreakerConfig holds circuit breaker settings
type CircuitBreakerConfig struct {
	Enabled          bool
	FailureThreshold int           // Number of failures before opening
	SuccessThreshold int           // Number of successes to close from half-open
	Timeout          time.Duration // How long to stay open before half-open
	MaxConcurrent    int           // Max concurrent requests (0 = unlimited)
}

// CircuitBreaker implements the circuit breaker pattern for provider calls
type CircuitBreaker struct {
	config      CircuitBreakerConfig
	state       CircuitState
	failures    int
	successes   int
	lastFailure time.Time
	concurrent  int
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	if config.FailureThreshold == 0 {
		config.FailureThreshold = 5
	}
	if config.SuccessThreshold == 0 {
		config.SuccessThreshold = 2
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	return &CircuitBreaker{
		config: config,
		state:  CircuitClosed,
	}
}

// ErrCircuitOpen is returned when the circuit is open
var ErrCircuitOpen = errors.New("circuit breaker is open: provider unavailable")

// ErrTooManyConcurrent is returned when max concurrent requests exceeded
var ErrTooManyConcurrent = errors.New("too many concurrent requests")

// Execute wraps a provider call with circuit breaker logic
func (cb *CircuitBreaker) Execute(fn func() (*http.Response, error)) (*http.Response, error) {
	if !cb.config.Enabled {
		return fn()
	}

	// Check circuit state
	switch cb.state {
	case CircuitOpen:
		// Check if timeout has passed
		if time.Since(cb.lastFailure) > cb.config.Timeout {
			cb.state = CircuitHalfOpen
			cb.successes = 0
		} else {
			return nil, ErrCircuitOpen
		}
	}

	// Check concurrent limit
	if cb.config.MaxConcurrent > 0 && cb.concurrent >= cb.config.MaxConcurrent {
		return nil, ErrTooManyConcurrent
	}

	cb.concurrent++
	defer func() { cb.concurrent-- }()

	// Execute the function
	resp, err := fn()

	// Update circuit state based on result
	if err != nil || (resp != nil && resp.StatusCode >= 500) {
		cb.recordFailure()
	} else {
		cb.recordSuccess()
	}

	return resp, err
}

// ExecuteWithTimeout wraps a provider call with timeout and circuit breaker
func (cb *CircuitBreaker) ExecuteWithTimeout(ctx context.Context, timeout time.Duration, fn func() (*http.Response, error)) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resultCh := make(chan struct {
		resp *http.Response
		err  error
	}, 1)

	go func() {
		resp, err := cb.Execute(fn)
		resultCh <- struct {
			resp *http.Response
			err  error
		}{resp, err}
	}()

	select {
	case <-ctx.Done():
		cb.recordFailure()
		return nil, errors.New("provider timeout exceeded")
	case result := <-resultCh:
		return result.resp, result.err
	}
}

func (cb *CircuitBreaker) recordFailure() {
	cb.failures++
	cb.lastFailure = time.Now()

	if cb.state == CircuitHalfOpen {
		cb.state = CircuitOpen
		return
	}

	if cb.failures >= cb.config.FailureThreshold {
		cb.state = CircuitOpen
	}
}

func (cb *CircuitBreaker) recordSuccess() {
	if cb.state == CircuitHalfOpen {
		cb.successes++
		if cb.successes >= cb.config.SuccessThreshold {
			cb.state = CircuitClosed
			cb.failures = 0
		}
	} else {
		cb.failures = 0
	}
}

// State returns the current circuit state
func (cb *CircuitBreaker) State() CircuitState {
	return cb.state
}

// Stats returns circuit breaker statistics
func (cb *CircuitBreaker) Stats() map[string]interface{} {
	stateStr := "closed"
	switch cb.state {
	case CircuitOpen:
		stateStr = "open"
	case CircuitHalfOpen:
		stateStr = "half-open"
	}

	return map[string]interface{}{
		"state":      stateStr,
		"failures":   cb.failures,
		"concurrent": cb.concurrent,
	}
}
