package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/analyzer"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/cedar"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/config"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
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
	var prov provider.Provider
	providerType := os.Getenv("PROVIDER_TYPE")
	if providerType == "openai" {
		prov = provider.NewOpenAIProvider(cfg.ProviderUrl, cfg.ProviderKey)
	} else {
		prov = provider.NewOllamaProvider()
	}
	logger.Printf("Provider: %s (%s)", prov.Name(), cfg.ProviderUrl)

	// 1. Initialize Policy Engine
	// Priority: guardrail.yaml (unified) > POLICY_PATH env > legacy Cedar file
	var cedarEngine *cedar.Engine
	var gPolicy policy.GuardrailPolicy
	guardrailPath := os.Getenv("GUARDRAIL_POLICY")
	if guardrailPath == "" {
		guardrailPath = "guardrail.yaml"
	}

	if _, err := os.Stat(guardrailPath); err == nil {
		// Load unified YAML policy
		lp, err := policy.Load(guardrailPath)
		if err != nil {
			logger.Fatalf("Failed to load guardrail policy: %v", err)
		}
		gPolicy = *lp

		cedarText, err := policy.Compile(lp)
		if err != nil {
			logger.Fatalf("Failed to compile guardrail policy: %v", err)
		}

		// Write compiled Cedar to temp file for the engine
		tmpFile, err := os.CreateTemp("", "guardrail-compiled-*.cedar")
		if err != nil {
			logger.Fatalf("Failed to create temp policy file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(cedarText); err != nil {
			logger.Fatalf("Failed to write compiled policy: %v", err)
		}
		tmpFile.Close()

		cedarEngine, err = cedar.NewEngineWithLogger(tmpFile.Name(), logger)
		if err != nil {
			logger.Fatalf("Failed to initialize Cedar Engine from compiled policy: %v", err)
		}
		logger.Printf("✅ Unified policy loaded from %s (compiled to Cedar)", guardrailPath)
	} else {
		// Fallback to legacy Cedar file
		policyPath := os.Getenv("POLICY_PATH")
		if policyPath == "" {
			policyPath = "backend/internal/cedar/policies.cedar"
		}

		var err error
		cedarEngine, err = cedar.NewEngineWithLogger(policyPath, logger)
		if err != nil {
			logger.Fatalf("Failed to initialize Cedar Engine: %v", err)
		}
		logger.Printf("⚠️  Legacy Cedar policy loaded from %s (migrate to guardrail.yaml)", policyPath)
	}

	// 2. Initialize Analyzers
	// Initialize new BART-based Intent Analyzer (Semantic Classification)
	var bartIntentAnalyzer *analyzer.IntentAnalyzer
	if cfg.IntentAnalyzerURL != "" {
		bartIntentAnalyzer = analyzer.NewIntentAnalyzer(cfg.IntentAnalyzerURL, cfg.SemanticCacheURL)
		logger.Printf("Intent Analyzer (BART) initialized at: %s (Cache: %s)", cfg.IntentAnalyzerURL, cfg.SemanticCacheURL)
	}

	// Initialize Deterministic Signal Aggregator
	signalAggregator := analyzer.NewSignalAggregator()
	logger.Println("Signal aggregator initialized (PII, Toxicity, Injection)")

	// Initialize Heuristic Analyzer (Fast-Path) with configurable topics
	heuristicAnalyzer := analyzer.NewHeuristicAnalyzer(gPolicy.Topics)
	logger.Println("Heuristic Analyzer (Fast-Path) initialized")

	// Create handler config
	handlerConfig := &proxy.HandlerConfig{
		Config:            cfg,
		Provider:          prov,
		IntentAnalyzer:    bartIntentAnalyzer,
		HeuristicAnalyzer: heuristicAnalyzer,
		SignalAggregator:  signalAggregator,
		CedarEngine:       cedarEngine,
		Logger:            logger,
		Policy:            &gPolicy,
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
		}`, prov.Name())
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
