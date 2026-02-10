package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/analyzer"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/cedar"
	"github.com/blackrose-blackhat/agent-guardrail/backend/pkg/models"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func main() {
	fmt.Println(colorCyan + colorBold + `
╔═══════════════════════════════════════════════════════════╗
║          AGENT GUARDRAIL - Interactive CLI v2.4           ║
║          Type your prompts to check if ALLOWED/BLOCKED    ║
║          Type 'exit' or 'quit' to exit                    ║
╚═══════════════════════════════════════════════════════════╝` + colorReset)
	fmt.Println()

	// Initialize components
	signalAggregator := analyzer.NewSignalAggregator()
	heuristicAnalyzer := analyzer.NewHeuristicAnalyzer()

	// Initialize Intent Analyzer
	intentAnalyzerURL := os.Getenv("INTENT_ANALYZER_URL")
	if intentAnalyzerURL == "" {
		intentAnalyzerURL = "http://localhost:8001"
	}
	intentAnalyzer := analyzer.NewIntentAnalyzer(intentAnalyzerURL, "")

	// Initialize Cedar Engine
	policyPath := os.Getenv("POLICY_PATH")
	if policyPath == "" {
		policyPath = "backend/internal/cedar/policies.cedar"
	}
	cedarEngine, err := cedar.NewEngine(policyPath)
	if err != nil {
		fmt.Printf("%sError: Failed to load Cedar policies: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	fmt.Printf("%s[✓] Components initialized%s\n", colorGreen, colorReset)
	fmt.Printf("    Intent Analyzer: %s\n", intentAnalyzerURL)
	fmt.Printf("    Policy: %s (v%s)\n", policyPath, cedarEngine.PolicyVersion)
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Printf("%s%s> %s", colorBold, colorBlue, colorReset)

		if !scanner.Scan() {
			break
		}

		prompt := strings.TrimSpace(scanner.Text())
		if prompt == "" {
			continue
		}

		if prompt == "exit" || prompt == "quit" {
			fmt.Println(colorCyan + "Goodbye! 👋" + colorReset)
			break
		}

		// Process prompt
		result := checkPrompt(prompt, signalAggregator, heuristicAnalyzer, intentAnalyzer, cedarEngine)
		printResult(result)
		fmt.Println()
	}
}

type CheckResult struct {
	Decision        string
	Reason          string
	Intent          string
	Confidence      float64
	RiskScore       float64
	FastPath        bool
	PII             []string
	Toxicity        float64
	PromptInjection bool
}

func checkPrompt(prompt string, signalAgg *analyzer.SignalAggregator, heuristic *analyzer.HeuristicAnalyzer, intent *analyzer.IntentAnalyzer, cedarEng *cedar.Engine) CheckResult {
	// Build request
	llmReq := &models.LLMRequest{
		Messages: []models.Message{{Role: "user", Content: prompt}},
	}

	// Generate signals
	signals := signalAgg.Aggregate(llmReq)

	// Build context
	ctx := &analyzer.Context{
		Signals:             *signals,
		ResourceSensitivity: "public",
	}

	var fastPath bool
	var intentStr string
	var confidence float64

	// 1. Heuristic Fast-Path
	if heuristicSignal := heuristic.Analyze(prompt); heuristicSignal != nil {
		ctx.AttachIntent(heuristicSignal, "user")
		fastPath = true
		intentStr = heuristicSignal.Intent
		confidence = heuristicSignal.Confidence
	} else {
		// 2. Semantic Intent Analysis
		if intentSignal, err := intent.Analyze(prompt); err == nil {
			ctx.AttachIntent(intentSignal, "user")
			intentStr = intentSignal.Intent
			confidence = intentSignal.Confidence
		} else {
			intentStr = "unknown"
			confidence = 0.5
		}
	}

	// 3. Cedar Policy Evaluation
	decision, reason, _ := cedarEng.EvaluateContext(ctx)

	return CheckResult{
		Decision:        string(decision),
		Reason:          reason,
		Intent:          intentStr,
		Confidence:      confidence,
		RiskScore:       ctx.RiskScore,
		FastPath:        fastPath,
		PII:             signals.PII,
		Toxicity:        signals.Toxicity,
		PromptInjection: signals.PromptInjection,
	}
}

func printResult(r CheckResult) {
	fmt.Println()

	// Decision banner
	if r.Decision == "ALLOW" {
		fmt.Printf("%s%s  ✅ ALLOWED  %s\n", colorBold, colorGreen, colorReset)
	} else {
		fmt.Printf("%s%s  🛑 BLOCKED  %s\n", colorBold, colorRed, colorReset)
	}

	fmt.Printf("%sReason:%s %s\n", colorBold, colorReset, r.Reason)
	fmt.Println()

	// Details
	fmt.Printf("%s┌─ Analysis ─────────────────────────────────────────%s\n", colorYellow, colorReset)

	pathType := "Semantic (BART)"
	if r.FastPath {
		pathType = "Heuristic (Fast-Path)"
	}
	fmt.Printf("│ Path:       %s\n", pathType)
	fmt.Printf("│ Intent:     %s (%.0f%% confidence)\n", r.Intent, r.Confidence*100)
	fmt.Printf("│ Risk Score: %.2f\n", r.RiskScore)
	fmt.Printf("%s└────────────────────────────────────────────────────%s\n", colorYellow, colorReset)

	// Signals
	fmt.Printf("%s┌─ Signals ──────────────────────────────────────────%s\n", colorCyan, colorReset)

	piiStr := "None"
	if len(r.PII) > 0 {
		piiStr = fmt.Sprintf("%s%v%s", colorRed, r.PII, colorReset)
	}
	fmt.Printf("│ PII:              %s\n", piiStr)

	toxStr := fmt.Sprintf("%.2f", r.Toxicity)
	if r.Toxicity > 0.5 {
		toxStr = fmt.Sprintf("%s%.2f%s", colorRed, r.Toxicity, colorReset)
	}
	fmt.Printf("│ Toxicity:         %s\n", toxStr)

	injStr := "No"
	if r.PromptInjection {
		injStr = fmt.Sprintf("%sYes%s", colorRed, colorReset)
	}
	fmt.Printf("│ Prompt Injection: %s\n", injStr)
	fmt.Printf("%s└────────────────────────────────────────────────────%s\n", colorCyan, colorReset)
}
