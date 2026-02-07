package chain

import (
	"fmt"
	"log"
	"sort"
)

// Result represents the outcome of a guardrail execution
type Result struct {
	Passed     bool        `json:"passed"`
	Action     ActionType  `json:"action"`
	Message    string      `json:"message,omitempty"`
	Violations []Violation `json:"violations,omitempty"`
	// If the guardrail modified the content, this is the new content
	ModifiedContent []byte `json:"modified_content,omitempty"`
}

// Guardrail is the interface that all guardrails must implement
type Guardrail interface {
	// Name returns the unique identifier for this guardrail
	Name() string

	// Type returns whether this is an input or output guardrail
	Type() GuardrailType

	// Execute runs the guardrail check against the context
	Execute(ctx *Context) (*Result, error)

	// Priority returns the execution order (lower = earlier)
	Priority() int

	// IsEnabled returns whether this guardrail is currently active
	IsEnabled() bool
}

// GuardrailChain manages and executes a collection of guardrails
type GuardrailChain struct {
	inputGuardrails  []Guardrail
	outputGuardrails []Guardrail
	logger           *log.Logger
}

// NewGuardrailChain creates a new chain with the given guardrails
func NewGuardrailChain(guardrails []Guardrail, logger *log.Logger) *GuardrailChain {
	chain := &GuardrailChain{
		inputGuardrails:  make([]Guardrail, 0),
		outputGuardrails: make([]Guardrail, 0),
		logger:           logger,
	}

	// Separate and sort guardrails by type and priority
	for _, g := range guardrails {
		if !g.IsEnabled() {
			continue
		}

		switch g.Type() {
		case GuardrailTypeInput:
			chain.inputGuardrails = append(chain.inputGuardrails, g)
		case GuardrailTypeOutput:
			chain.outputGuardrails = append(chain.outputGuardrails, g)
		}
	}

	// Sort by priority (lower first)
	sort.Slice(chain.inputGuardrails, func(i, j int) bool {
		return chain.inputGuardrails[i].Priority() < chain.inputGuardrails[j].Priority()
	})
	sort.Slice(chain.outputGuardrails, func(i, j int) bool {
		return chain.outputGuardrails[i].Priority() < chain.outputGuardrails[j].Priority()
	})

	return chain
}

// ExecuteInput runs all input guardrails in priority order
func (c *GuardrailChain) ExecuteInput(ctx *Context) error {
	c.logDebug("Executing %d input guardrails for request %s", len(c.inputGuardrails), ctx.RequestID)

	for _, guardrail := range c.inputGuardrails {
		c.logDebug("Running input guardrail: %s", guardrail.Name())

		result, err := guardrail.Execute(ctx)
		if err != nil {
			c.logError("Guardrail %s failed with error: %v", guardrail.Name(), err)
			return fmt.Errorf("guardrail %s error: %w", guardrail.Name(), err)
		}

		// Handle the result
		if result != nil {
			// Record any violations
			for _, v := range result.Violations {
				ctx.AddViolation(v)
			}

			// Apply modifications if any
			if result.ModifiedContent != nil {
				ctx.ModifiedBody = result.ModifiedContent
			}

			// Check if we should block
			if !result.Passed && result.Action == ActionBlock {
				ctx.Blocked = true
				ctx.BlockMsg = result.Message
				c.logDebug("Request blocked by guardrail %s: %s", guardrail.Name(), result.Message)
				return nil // Not an error, but blocked
			}
		}
	}

	c.logDebug("Input guardrails completed for request %s, violations: %d", ctx.RequestID, len(ctx.Violations))
	return nil
}

// ExecuteOutput runs all output guardrails in priority order
func (c *GuardrailChain) ExecuteOutput(ctx *Context) error {
	c.logDebug("Executing %d output guardrails for request %s", len(c.outputGuardrails), ctx.RequestID)

	for _, guardrail := range c.outputGuardrails {
		c.logDebug("Running output guardrail: %s", guardrail.Name())

		result, err := guardrail.Execute(ctx)
		if err != nil {
			c.logError("Guardrail %s failed with error: %v", guardrail.Name(), err)
			return fmt.Errorf("guardrail %s error: %w", guardrail.Name(), err)
		}

		// Handle the result
		if result != nil {
			// Record any violations
			for _, v := range result.Violations {
				ctx.AddViolation(v)
			}

			// Apply modifications if any
			if result.ModifiedContent != nil {
				ctx.ModifiedResponse = result.ModifiedContent
			}

			// Check if we should block the response
			if !result.Passed && result.Action == ActionBlock {
				ctx.Blocked = true
				ctx.BlockMsg = result.Message
				c.logDebug("Response blocked by guardrail %s: %s", guardrail.Name(), result.Message)
				return nil
			}
		}
	}

	c.logDebug("Output guardrails completed for request %s, violations: %d", ctx.RequestID, len(ctx.Violations))
	return nil
}

// AddGuardrail adds a guardrail to the chain at runtime
func (c *GuardrailChain) AddGuardrail(g Guardrail) {
	if !g.IsEnabled() {
		return
	}

	switch g.Type() {
	case GuardrailTypeInput:
		c.inputGuardrails = append(c.inputGuardrails, g)
		sort.Slice(c.inputGuardrails, func(i, j int) bool {
			return c.inputGuardrails[i].Priority() < c.inputGuardrails[j].Priority()
		})
	case GuardrailTypeOutput:
		c.outputGuardrails = append(c.outputGuardrails, g)
		sort.Slice(c.outputGuardrails, func(i, j int) bool {
			return c.outputGuardrails[i].Priority() < c.outputGuardrails[j].Priority()
		})
	}
}

// GetInputGuardrails returns the list of input guardrails
func (c *GuardrailChain) GetInputGuardrails() []Guardrail {
	return c.inputGuardrails
}

// GetOutputGuardrails returns the list of output guardrails
func (c *GuardrailChain) GetOutputGuardrails() []Guardrail {
	return c.outputGuardrails
}

// logging helpers
func (c *GuardrailChain) logDebug(format string, args ...interface{}) {
	if c.logger != nil {
		c.logger.Printf("[DEBUG] "+format, args...)
	}
}

func (c *GuardrailChain) logError(format string, args ...interface{}) {
	if c.logger != nil {
		c.logger.Printf("[ERROR] "+format, args...)
	}
}
