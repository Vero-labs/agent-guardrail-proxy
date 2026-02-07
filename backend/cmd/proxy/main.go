package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/config"
	inputGuardrails "github.com/blackrose-blackhat/agent-guardrail/backend/internal/guardrails/input"
	outputGuardrails "github.com/blackrose-blackhat/agent-guardrail/backend/internal/guardrails/output"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/provider"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/proxy"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	godotenv.Load()

	// Initialize logger
	logger := log.New(os.Stdout, "[guardrail] ", log.LstdFlags|log.Lshortfile)

	// Load configuration
	cfg := config.Load()
	logger.Println("Configuration loaded")

	// Load policies
	policyLoader := policy.NewLoader(cfg.Policies.Directory, logger)
	if err := policyLoader.Load(); err != nil {
		logger.Printf("Warning: Failed to load policies: %v", err)
	}

	// Get default policy
	defaultPolicy := policyLoader.GetDefaultPolicy()
	logger.Printf("Using policy: %s (version %s)", defaultPolicy.Name, defaultPolicy.Version)

	// Create guardrails based on policy
	guardrails := createGuardrails(defaultPolicy, logger)
	logger.Printf("Initialized %d guardrails", len(guardrails))

	// Create guardrail chain
	guardrailChain := chain.NewGuardrailChain(guardrails, logger)
	logger.Printf("Guardrail chain ready: %d input, %d output",
		len(guardrailChain.GetInputGuardrails()),
		len(guardrailChain.GetOutputGuardrails()))

	// Create provider (using OpenAI for Groq compatibility)
	var p provider.Provider
	providerType := os.Getenv("PROVIDER_TYPE")
	if providerType == "openai" {
		p = provider.NewOpenAIProvider(cfg.ProviderUrl, cfg.ProviderKey)
	} else {
		p = provider.NewOllamaProvider()
	}
	logger.Printf("Provider: %s (%s)", p.Name(), cfg.ProviderUrl)

	// Create handler config
	handlerConfig := &proxy.HandlerConfig{
		Config:         cfg,
		Provider:       p,
		GuardrailChain: guardrailChain,
		Logger:         logger,
	}

	// Setup routes
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","service":"agent-guardrail"}`))
	})

	http.HandleFunc("/api/chat", proxy.Handler(handlerConfig))

	// Also handle OpenAI-compatible endpoints
	http.HandleFunc("/v1/chat/completions", proxy.Handler(handlerConfig))

	// Status endpoint
	http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status := fmt.Sprintf(`{
			"status": "ok",
			"policy": "%s",
			"policy_version": "%s",
			"input_guardrails": %d,
			"output_guardrails": %d,
			"provider": "%s"
		}`, defaultPolicy.Name, defaultPolicy.Version,
			len(guardrailChain.GetInputGuardrails()),
			len(guardrailChain.GetOutputGuardrails()),
			p.Name())
		w.Write([]byte(status))
	})

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Println("=================================")
	logger.Println("Agent Guardrail Proxy Starting")
	logger.Println("=================================")
	logger.Printf("Server:   http://%s", addr)
	logger.Printf("Provider: %s", cfg.ProviderUrl)
	logger.Printf("Policy:   %s", defaultPolicy.Name)
	logger.Println("=================================")

	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}

// createGuardrails initializes all guardrails based on policy configuration
func createGuardrails(p *policy.Policy, logger *log.Logger) []chain.Guardrail {
	guardrails := make([]chain.Guardrail, 0)

	// Input guardrails
	if p.Guardrails.Input.PromptInjection.Enabled {
		g := inputGuardrails.NewPromptInjectionGuardrail(p.Guardrails.Input.PromptInjection)
		guardrails = append(guardrails, g)
		logger.Printf("  + Enabled: %s (input)", g.Name())
	}

	if p.Guardrails.Input.PIIDetection.Enabled {
		g := inputGuardrails.NewPIIDetectionGuardrail(p.Guardrails.Input.PIIDetection)
		guardrails = append(guardrails, g)
		logger.Printf("  + Enabled: %s (input)", g.Name())
	}

	if p.Guardrails.Input.TopicBoundary.Enabled {
		g := inputGuardrails.NewTopicBoundaryGuardrail(p.Guardrails.Input.TopicBoundary)
		guardrails = append(guardrails, g)
		logger.Printf("  + Enabled: %s (input)", g.Name())
	}

	if p.Guardrails.Input.Toxicity.Enabled {
		g := inputGuardrails.NewToxicityGuardrail(p.Guardrails.Input.Toxicity)
		guardrails = append(guardrails, g)
		logger.Printf("  + Enabled: %s (input)", g.Name())
	}

	// Output guardrails
	if p.Guardrails.Output.HallucinationDetection.Enabled {
		g := outputGuardrails.NewHallucinationGuardrail(p.Guardrails.Output.HallucinationDetection)
		guardrails = append(guardrails, g)
		logger.Printf("  + Enabled: %s (output)", g.Name())
	}

	if p.Guardrails.Output.ContentModeration.Enabled {
		g := outputGuardrails.NewContentModerationGuardrail(p.Guardrails.Output.ContentModeration)
		guardrails = append(guardrails, g)
		logger.Printf("  + Enabled: %s (output)", g.Name())
	}

	if p.Guardrails.Output.FormatValidation.Enabled {
		g := outputGuardrails.NewFormatValidationGuardrail(p.Guardrails.Output.FormatValidation)
		guardrails = append(guardrails, g)
		logger.Printf("  + Enabled: %s (output)", g.Name())
	}

	// Deterministic Controls (Operational Necessity)
	if p.Guardrails.DeterministicControls.RateLimit.Enabled {
		config := inputGuardrails.RateLimitConfig{
			Enabled:           p.Guardrails.DeterministicControls.RateLimit.Enabled,
			RequestsPerMinute: p.Guardrails.DeterministicControls.RateLimit.RequestsPerMinute,
			RequestsPerHour:   p.Guardrails.DeterministicControls.RateLimit.RequestsPerHour,
			BurstSize:         p.Guardrails.DeterministicControls.RateLimit.BurstSize,
			KeyBy:             p.Guardrails.DeterministicControls.RateLimit.KeyBy,
		}
		g := inputGuardrails.NewRateLimitGuardrail(config)
		guardrails = append(guardrails, g)
		logger.Printf("  + Enabled: %s (deterministic)", g.Name())
	}
	if p.Guardrails.DeterministicControls.PayloadSize.Enabled {
		config := inputGuardrails.PayloadSizeConfig{
			Enabled:        p.Guardrails.DeterministicControls.PayloadSize.Enabled,
			MaxRequestSize: p.Guardrails.DeterministicControls.PayloadSize.MaxRequestSize,
			MaxMessageSize: p.Guardrails.DeterministicControls.PayloadSize.MaxMessageSize,
			MaxMessages:    p.Guardrails.DeterministicControls.PayloadSize.MaxMessages,
		}
		g := inputGuardrails.NewPayloadSizeGuardrail(config)
		guardrails = append(guardrails, g)
		logger.Printf("  + Enabled: %s (deterministic)", g.Name())
	}
	if p.Guardrails.DeterministicControls.MaxTokens.Enabled {
		config := inputGuardrails.MaxTokensConfig{
			Enabled:         p.Guardrails.DeterministicControls.MaxTokens.Enabled,
			MaxInputTokens:  p.Guardrails.DeterministicControls.MaxTokens.MaxInputTokens,
			MaxOutputTokens: p.Guardrails.DeterministicControls.MaxTokens.MaxOutputTokens,
		}
		g := inputGuardrails.NewMaxTokensGuardrail(config)
		guardrails = append(guardrails, g)
		logger.Printf("  + Enabled: %s (deterministic)", g.Name())
	}

	return guardrails
}
