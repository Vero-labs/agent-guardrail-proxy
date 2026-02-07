package main

import (
	"log"
	"os"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/config"
	inputGuardrails "github.com/blackrose-blackhat/agent-guardrail/backend/internal/guardrails/input"
	outputGuardrails "github.com/blackrose-blackhat/agent-guardrail/backend/internal/guardrails/output"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/mcp"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	godotenv.Load()

	// Initialize logger (log to stderr because stdout is for MCP)
	logger := log.New(os.Stderr, "[mcp-server] ", log.LstdFlags)

	// Load configuration
	cfg := config.Load()

	// Load policies
	policyLoader := policy.NewLoader(cfg.Policies.Directory, logger)
	if err := policyLoader.Load(); err != nil {
		logger.Fatalf("Failed to load policies: %v", err)
	}

	// Get default policy
	defaultPolicy := policyLoader.GetDefaultPolicy()

	// Create guardrails
	guardrails := createGuardrails(defaultPolicy, logger)

	// Create guardrail chain
	guardrailChain := chain.NewGuardrailChain(guardrails, logger)

	// Start MCP Server (on Stdio)
	server := mcp.NewServer(guardrailChain, policyLoader, logger)

	logger.Println("MCP Server starting on stdio...")
	server.StartStdio()
}

// createGuardrails initializes all guardrails based on policy configuration
// (Shared logic with proxy main)
func createGuardrails(p *policy.Policy, logger *log.Logger) []chain.Guardrail {
	guardrails := make([]chain.Guardrail, 0)

	// Input guardrails
	if p.Guardrails.Input.PromptInjection.Enabled {
		guardrails = append(guardrails, inputGuardrails.NewPromptInjectionGuardrail(p.Guardrails.Input.PromptInjection))
	}
	if p.Guardrails.Input.PIIDetection.Enabled {
		guardrails = append(guardrails, inputGuardrails.NewPIIDetectionGuardrail(p.Guardrails.Input.PIIDetection))
	}
	if p.Guardrails.Input.TopicBoundary.Enabled {
		guardrails = append(guardrails, inputGuardrails.NewTopicBoundaryGuardrail(p.Guardrails.Input.TopicBoundary))
	}
	if p.Guardrails.Input.Toxicity.Enabled {
		guardrails = append(guardrails, inputGuardrails.NewToxicityGuardrail(p.Guardrails.Input.Toxicity))
	}

	// Deterministic Controls
	if p.Guardrails.DeterministicControls.RateLimit.Enabled {
		config := inputGuardrails.RateLimitConfig{
			Enabled:           p.Guardrails.DeterministicControls.RateLimit.Enabled,
			RequestsPerMinute: p.Guardrails.DeterministicControls.RateLimit.RequestsPerMinute,
			RequestsPerHour:   p.Guardrails.DeterministicControls.RateLimit.RequestsPerHour,
			BurstSize:         p.Guardrails.DeterministicControls.RateLimit.BurstSize,
			KeyBy:             p.Guardrails.DeterministicControls.RateLimit.KeyBy,
		}
		guardrails = append(guardrails, inputGuardrails.NewRateLimitGuardrail(config))
	}
	if p.Guardrails.DeterministicControls.PayloadSize.Enabled {
		config := inputGuardrails.PayloadSizeConfig{
			Enabled:        p.Guardrails.DeterministicControls.PayloadSize.Enabled,
			MaxRequestSize: p.Guardrails.DeterministicControls.PayloadSize.MaxRequestSize,
			MaxMessageSize: p.Guardrails.DeterministicControls.PayloadSize.MaxMessageSize,
			MaxMessages:    p.Guardrails.DeterministicControls.PayloadSize.MaxMessages,
		}
		guardrails = append(guardrails, inputGuardrails.NewPayloadSizeGuardrail(config))
	}

	// Output guardrails
	if p.Guardrails.Output.HallucinationDetection.Enabled {
		guardrails = append(guardrails, outputGuardrails.NewHallucinationGuardrail(p.Guardrails.Output.HallucinationDetection))
	}
	if p.Guardrails.Output.ContentModeration.Enabled {
		guardrails = append(guardrails, outputGuardrails.NewContentModerationGuardrail(p.Guardrails.Output.ContentModeration))
	}

	return guardrails
}
