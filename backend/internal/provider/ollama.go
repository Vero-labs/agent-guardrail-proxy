package provider

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
)

// OllamaProvider implements the Provider interface for Ollama
type OllamaProvider struct {
	*BaseProvider
}

// OllamaChatRequest represents an Ollama chat request
type OllamaChatRequest struct {
	Model    string                 `json:"model"`
	Messages []OllamaChatMessage    `json:"messages"`
	Stream   bool                   `json:"stream"`
	Options  map[string]interface{} `json:"options,omitempty"`
}

// OllamaChatMessage represents a message in Ollama format
type OllamaChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OllamaChatResponse represents an Ollama chat response
type OllamaChatResponse struct {
	Model           string            `json:"model"`
	Message         OllamaChatMessage `json:"message"`
	Done            bool              `json:"done"`
	TotalDuration   int64             `json:"total_duration"`
	LoadDuration    int64             `json:"load_duration"`
	PromptEvalCount int               `json:"prompt_eval_count"`
	EvalCount       int               `json:"eval_count"`
}

// NewOllamaProvider creates a new Ollama provider
func NewOllamaProvider() *OllamaProvider {
	baseURL := os.Getenv("PROVIDER_URL")
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return &OllamaProvider{
		BaseProvider: NewBaseProvider(baseURL, ""),
	}
}

// NewOllamaProviderWithConfig creates a new Ollama provider with explicit config
func NewOllamaProviderWithConfig(baseURL, apiKey string) *OllamaProvider {
	return &OllamaProvider{
		BaseProvider: NewBaseProvider(baseURL, apiKey),
	}
}

// Name returns the provider identifier
func (o *OllamaProvider) Name() string {
	return "ollama"
}

// ForwardRequest sends the request to Ollama
func (o *OllamaProvider) ForwardRequest(r *http.Request) (*http.Response, error) {
	return o.Client.Do(r)
}

// ParseRequest parses raw request body into normalized LLMRequest
func (o *OllamaProvider) ParseRequest(body []byte) (*chain.LLMRequest, error) {
	var ollamaReq OllamaChatRequest
	if err := json.Unmarshal(body, &ollamaReq); err != nil {
		return nil, err
	}

	messages := make([]chain.LLMMessage, len(ollamaReq.Messages))
	for i, msg := range ollamaReq.Messages {
		messages[i] = chain.LLMMessage{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}

	return &chain.LLMRequest{
		Model:    ollamaReq.Model,
		Messages: messages,
		Stream:   ollamaReq.Stream,
	}, nil
}

// ParseResponse parses raw response body into normalized LLMResponse
func (o *OllamaProvider) ParseResponse(body []byte) (*chain.LLMResponse, error) {
	var ollamaResp OllamaChatResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return nil, err
	}

	return &chain.LLMResponse{
		Content: ollamaResp.Message.Content,
		Model:   ollamaResp.Model,
		Usage: &chain.Usage{
			InputTokens:  ollamaResp.PromptEvalCount,
			OutputTokens: ollamaResp.EvalCount,
			TotalTokens:  ollamaResp.PromptEvalCount + ollamaResp.EvalCount,
		},
	}, nil
}

// SupportsStreaming returns whether Ollama supports streaming
func (o *OllamaProvider) SupportsStreaming() bool {
	return true
}

// GetUsage extracts usage information from a response
func (o *OllamaProvider) GetUsage(resp *chain.LLMResponse) *chain.Usage {
	return resp.Usage
}
