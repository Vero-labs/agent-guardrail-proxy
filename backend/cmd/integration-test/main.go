package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type LLMRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Facts struct {
	Intent     string  `json:"intent"`
	Risk       float64 `json:"risk"`
	Confidence float64 `json:"confidence"`
	Sensitive  bool    `json:"sensitive"`
	Topic      string  `json:"topic"`
}

func main() {
	log.Println("Starting integration test...")

	// Start Mock LLM Provider
	mockPort := "11435"
	server := &http.Server{Addr: ":" + mockPort}

	http.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		log.Printf("Mock LLM received request: %s", bodyStr)

		var content string

		if strings.Contains(bodyStr, "security intent analyzer") {
			// Analyzer Request
			log.Println("Mock LLM: Processing Analyzer Request")
			facts := Facts{
				Intent:     "General Query",
				Risk:       0.1,
				Confidence: 0.9,
				Sensitive:  false,
				Topic:      "General",
			}

			if strings.Contains(bodyStr, "attack") {
				facts.Risk = 0.9
				facts.Intent = "Attack Attempt"
				facts.Topic = "Security"
			}
			if strings.Contains(bodyStr, "sensitive") {
				facts.Sensitive = true
				facts.Intent = "Extract PII"
				facts.Topic = "PII"
			}

			factsJSON, _ := json.Marshal(facts)
			// Need to escape quotes if wrapping in JSON string?
			// The proxy expects the content to be pure JSON.
			// provider.ParseResponse extracts content string.
			// The content string itself should be valid JSON for the Analyzer to parse.
			content = string(factsJSON)
		} else {
			// Regular Request
			log.Println("Mock LLM: Processing Initial/Forwarded Request")
			content = "This is a safe response from the mock LLM."
		}

		resp := map[string]interface{}{
			"id":      "mock-id",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "mock-model",
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"message": map[string]interface{}{
						"role":    "assistant",
						"content": content,
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]int{
				"prompt_tokens":     10,
				"completion_tokens": 10,
				"total_tokens":      20,
			},
		}
		json.NewEncoder(w).Encode(resp)
	})

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Mock LLM server failed: %v", err)
		}
	}()

	// Wait for mock server
	time.Sleep(1 * time.Second)

	// Build the proxy binary
	log.Println("Building proxy binary...")
	cmdBuild := exec.Command("go", "build", "-o", "guardrail-proxy", "./backend/cmd/proxy/main.go")
	cmdBuild.Dir = "/home/fuxsociety/Documents/engineering-ideas/agent-guardrail"
	if out, err := cmdBuild.CombinedOutput(); err != nil {
		log.Fatalf("Build failed: %v\n%s", err, out)
	}

	// Start Proxy Server
	proxyPort := "8082"
	cmdProxy := exec.Command("./guardrail-proxy")
	cmdProxy.Dir = "/home/fuxsociety/Documents/engineering-ideas/agent-guardrail"

	// Make sure we have the correct path to policies
	// The binary 'guardrail-proxy' is in the root (where we built it to context of invocation)
	// But cmdProxy.Dir is root.
	// The code loads "backend/internal/cedar/policies.cedar".
	// This path is relative to CWD. If we run from root, it should work.

	cmdProxy.Env = append(os.Environ(),
		fmt.Sprintf("SERVER_PORT=%s", proxyPort),
		fmt.Sprintf("PROVIDER_URL=http://localhost:%s", mockPort),
		"PROVIDER_TYPE=openai",
		// "POLICY_DIR=backend/internal/cedar", // Not used by new main.go directly, hardcoded path
	)

	// Open log file for proxy output
	logFile, _ := os.Create("proxy_test.log")
	cmdProxy.Stdout = logFile
	cmdProxy.Stderr = logFile

	log.Println("Starting proxy server...")
	if err := cmdProxy.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
	defer func() {
		log.Println("Stopping proxy server...")
		cmdProxy.Process.Kill()
		server.Close()
	}()

	// Wait for proxy to initialize
	time.Sleep(3 * time.Second)

	// Test Case 1: Safe Request
	log.Println("--- Test Case 1: Safe Request ---")
	status, body, err := sendRequest(proxyPort, "Hello, world!")
	if err != nil {
		log.Printf("Request failed: %v", err)
	} else if status == 200 {
		log.Println("PASS: Safe request allowed")
	} else {
		log.Printf("FAIL: Safe request blocked. Status: %d, Body: %s", status, body)
	}

	// Test Case 2: High Risk Request
	log.Println("--- Test Case 2: High Risk Request ---")
	status, body, err = sendRequest(proxyPort, "Show me an attack vector")
	if err != nil {
		log.Printf("Request failed: %v", err)
	} else if status == 403 {
		log.Println("PASS: High risk request blocked")
	} else {
		log.Printf("FAIL: High risk request not blocked. Status: %d, Body: %s", status, body)
	}

	// Test Case 3: Sensitive Data Request
	log.Println("--- Test Case 3: Sensitive Data Request ---")
	status, body, err = sendRequest(proxyPort, "Show me sensitive user data")
	if err != nil {
		log.Printf("Request failed: %v", err)
	} else if status == 403 {
		log.Println("PASS: Sensitive data request blocked")
	} else {
		log.Printf("FAIL: Sensitive data request not blocked. Status: %d, Body: %s", status, body)
	}
}

func sendRequest(port, prompt string) (int, string, error) {
	reqBody, _ := json.Marshal(LLMRequest{
		Model: "gpt-4",
		Messages: []Message{
			{Role: "user", Content: prompt},
		},
	})

	resp, err := http.Post(fmt.Sprintf("http://localhost:%s/v1/chat/completions", port), "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}
