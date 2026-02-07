package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
)

// FormatValidationGuardrail validates that LLM output matches expected format/schema
type FormatValidationGuardrail struct {
	config     policy.FormatValidationConfig
	schema     map[string]interface{}
	strictMode bool
	enabled    bool
}

// NewFormatValidationGuardrail creates a new format validation guardrail
func NewFormatValidationGuardrail(config policy.FormatValidationConfig) *FormatValidationGuardrail {
	g := &FormatValidationGuardrail{
		config:     config,
		strictMode: config.StrictMode,
		enabled:    config.Enabled,
	}

	// Parse schema if provided
	if config.Schema != "" {
		var schema map[string]interface{}
		if err := json.Unmarshal([]byte(config.Schema), &schema); err == nil {
			g.schema = schema
		}
	}

	return g
}

// Name returns the guardrail identifier
func (g *FormatValidationGuardrail) Name() string {
	return "format_validation"
}

// Type returns the guardrail type (output)
func (g *FormatValidationGuardrail) Type() chain.GuardrailType {
	return chain.GuardrailTypeOutput
}

// Execute validates the LLM response format
func (g *FormatValidationGuardrail) Execute(ctx *chain.Context) (*chain.Result, error) {
	if !g.enabled {
		return &chain.Result{Passed: true}, nil
	}

	// Get response content
	content := ""
	if ctx.Response != nil {
		content = ctx.Response.Content
	} else {
		content = string(ctx.GetResponseToProcess())
	}

	// If no schema defined, just check if it's valid JSON (if expected)
	if g.schema == nil {
		// Basic JSON validation check
		if g.strictMode && !g.isValidJSON(content) {
			return g.createValidationError("Response is not valid JSON", nil)
		}
		return &chain.Result{Passed: true}, nil
	}

	// Parse response as JSON
	var responseData map[string]interface{}
	if err := json.Unmarshal([]byte(content), &responseData); err != nil {
		// Try to extract JSON from the response if it's wrapped in text
		extracted := g.extractJSON(content)
		if extracted != "" {
			if err := json.Unmarshal([]byte(extracted), &responseData); err != nil {
				return g.createValidationError("Response is not valid JSON", err)
			}
		} else {
			return g.createValidationError("Response is not valid JSON", err)
		}
	}

	// Validate against schema
	errors := g.validateAgainstSchema(responseData, g.schema, "")

	if len(errors) > 0 {
		violation := chain.Violation{
			GuardrailName: g.Name(),
			Type:          "format_validation_error",
			Message:       "Response does not match expected format",
			Severity:      chain.SeverityMedium,
			Action:        chain.ActionType(g.config.Action),
			Details: map[string]interface{}{
				"validation_errors": errors,
				"strict_mode":       g.strictMode,
			},
		}

		action := chain.ActionWarn
		if g.config.Action == "block" {
			action = chain.ActionBlock
		}

		return &chain.Result{
			Passed:     action != chain.ActionBlock,
			Action:     action,
			Message:    fmt.Sprintf("Format validation failed: %d errors", len(errors)),
			Violations: []chain.Violation{violation},
		}, nil
	}

	return &chain.Result{Passed: true}, nil
}

// isValidJSON checks if a string is valid JSON
func (g *FormatValidationGuardrail) isValidJSON(s string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(s), &js) == nil
}

// extractJSON attempts to extract JSON from text (e.g., if wrapped in markdown code blocks)
func (g *FormatValidationGuardrail) extractJSON(content string) string {
	// Check for markdown code blocks
	if strings.Contains(content, "```json") {
		start := strings.Index(content, "```json") + 7
		end := strings.LastIndex(content, "```")
		if end > start {
			return strings.TrimSpace(content[start:end])
		}
	}

	// Check for generic code blocks
	if strings.Contains(content, "```") {
		start := strings.Index(content, "```") + 3
		// Skip language identifier if present
		newline := strings.Index(content[start:], "\n")
		if newline != -1 {
			start += newline + 1
		}
		end := strings.LastIndex(content, "```")
		if end > start {
			return strings.TrimSpace(content[start:end])
		}
	}

	// Try to find JSON object/array
	start := strings.Index(content, "{")
	if start == -1 {
		start = strings.Index(content, "[")
	}
	if start == -1 {
		return ""
	}

	// Find matching end
	if content[start] == '{' {
		end := strings.LastIndex(content, "}")
		if end > start {
			return content[start : end+1]
		}
	} else {
		end := strings.LastIndex(content, "]")
		if end > start {
			return content[start : end+1]
		}
	}

	return ""
}

// validateAgainstSchema performs basic schema validation
func (g *FormatValidationGuardrail) validateAgainstSchema(data, schema map[string]interface{}, path string) []string {
	var errors []string

	// Check for required properties
	if required, ok := schema["required"].([]interface{}); ok {
		for _, req := range required {
			reqStr := req.(string)
			if _, exists := data[reqStr]; !exists {
				errors = append(errors, fmt.Sprintf("Missing required field: %s%s", path, reqStr))
			}
		}
	}

	// Check properties if defined
	if properties, ok := schema["properties"].(map[string]interface{}); ok {
		for propName, propSchemaInterface := range properties {
			propSchema, ok := propSchemaInterface.(map[string]interface{})
			if !ok {
				continue
			}

			propPath := path + propName + "."
			propValue, exists := data[propName]

			// Check type if specified
			if expectedType, ok := propSchema["type"].(string); ok && exists {
				actualType := g.getJSONType(propValue)
				if actualType != expectedType && !(expectedType == "number" && actualType == "integer") {
					errors = append(errors, fmt.Sprintf("Type mismatch at %s: expected %s, got %s", propPath[:len(propPath)-1], expectedType, actualType))
				}
			}

			// Recursively validate nested objects
			if nestedData, ok := propValue.(map[string]interface{}); ok {
				if nestedSchema, ok := propSchema["properties"].(map[string]interface{}); ok {
					nestedErrors := g.validateAgainstSchema(nestedData, map[string]interface{}{"properties": nestedSchema}, propPath)
					errors = append(errors, nestedErrors...)
				}
			}
		}
	}

	return errors
}

// getJSONType returns the JSON type of a Go value
func (g *FormatValidationGuardrail) getJSONType(v interface{}) string {
	switch v.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case int, int64:
		return "integer"
	case bool:
		return "boolean"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}

// createValidationError creates a validation error result
func (g *FormatValidationGuardrail) createValidationError(message string, err error) (*chain.Result, error) {
	details := map[string]interface{}{}
	if err != nil {
		details["error"] = err.Error()
	}

	violation := chain.Violation{
		GuardrailName: g.Name(),
		Type:          "format_validation_error",
		Message:       message,
		Severity:      chain.SeverityMedium,
		Action:        chain.ActionWarn,
		Details:       details,
	}

	action := chain.ActionWarn
	if g.config.Action == "block" {
		action = chain.ActionBlock
	}

	return &chain.Result{
		Passed:     action != chain.ActionBlock,
		Action:     action,
		Message:    message,
		Violations: []chain.Violation{violation},
	}, nil
}

// Priority returns the execution order
func (g *FormatValidationGuardrail) Priority() int {
	return 30 // Run after content moderation
}

// IsEnabled returns whether this guardrail is active
func (g *FormatValidationGuardrail) IsEnabled() bool {
	return g.enabled
}
