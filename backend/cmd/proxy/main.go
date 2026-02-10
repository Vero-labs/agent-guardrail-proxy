package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/analyzer"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/cedar"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/config"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/provider"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/proxy"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// Load environment variables
	godotenv.Load()

	// Initialize logger
	logger := log.New(os.Stdout, "[guardrail] ", log.LstdFlags|log.Lshortfile)

	// Load configuration
	cfg := config.Load()
	logger.Println("Configuration loaded")

	// Create provider (using OpenAI for Groq compatibility)
	var p provider.Provider
	providerType := os.Getenv("PROVIDER_TYPE")
	if providerType == "openai" {
		p = provider.NewOpenAIProvider(cfg.ProviderUrl, cfg.ProviderKey)
	} else {
		p = provider.NewOllamaProvider()
	}
	logger.Printf("Provider: %s (%s)", p.Name(), cfg.ProviderUrl)

	// Initialize LLM Intent Analyzer
	intentAnalyzer := analyzer.NewAnalyzer(p)

	// Initialize Cedar Policy Engine
	cedarEngine, err := cedar.NewEngine("backend/internal/cedar/policies.cedar")
	if err != nil {
		logger.Fatalf("Failed to initialize Cedar Engine: %v", err)
	}

	// Create handler config
	handlerConfig := &proxy.HandlerConfig{
		Config:      cfg,
		Provider:    p,
		Analyzer:    intentAnalyzer,
		CedarEngine: cedarEngine,
		Logger:      logger,
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
			"provider": "%s"
		}`, p.Name())
		w.Write([]byte(status))
	})

	// Metrics endpoint (Prometheus)
	http.Handle("/metrics", promhttp.Handler())

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Println("=================================")
	logger.Println("Agent Guardrail Proxy Starting")
	logger.Println("=================================")
	logger.Printf("Server:   http://%s", addr)
	logger.Printf("Provider: %s", cfg.ProviderUrl)
	logger.Println("=================================")

	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}
