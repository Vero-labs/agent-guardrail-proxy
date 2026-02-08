package provider

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/blackrose-blackhat/agent-guardrail/backend/pkg/models"
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
	ID              string            `json:"id"`
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
func (o *OllamaProvider) ParseRequest(body []byte) (*models.LLMRequest, error) {
	var ollamaReq OllamaChatRequest
	if err := json.Unmarshal(body, &ollamaReq); err != nil {
		return nil, err
	}

	messages := make([]models.Message, len(ollamaReq.Messages))
	for i, msg := range ollamaReq.Messages {
		messages[i] = models.Message{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}

	return &models.LLMRequest{
		Model:    ollamaReq.Model,
		Messages: messages,
		Stream:   ollamaReq.Stream,
	}, nil
}

// ParseResponse parses raw response body into normalized LLMResponse
func (o *OllamaProvider) ParseResponse(body []byte) (*models.LLMResponse, error) {
	var ollamaResp OllamaChatResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return nil, err
	}

	return &models.LLMResponse{
		ID:    ollamaResp.ID,
		Model: ollamaResp.Model,
		Choices: []models.Choice{
			{
				Index: 0,
				Message: models.Message{
					Role:    ollamaResp.Message.Role,
					Content: ollamaResp.Message.Content,
				},
			},
		},
		Usage: models.Usage{
			PromptTokens:     ollamaResp.PromptEvalCount,
			CompletionTokens: ollamaResp.EvalCount,
			TotalTokens:      ollamaResp.PromptEvalCount + ollamaResp.EvalCount,
		},
	}, nil
}

// SupportsStreaming returns whether Ollama supports streaming
func (o *OllamaProvider) SupportsStreaming() bool {
	return true
}

// GetUsage extracts usage information from a response
func (o *OllamaProvider) GetUsage(resp *models.LLMResponse) *models.Usage {
	return &resp.Usage
}
