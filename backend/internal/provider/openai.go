package provider

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/blackrose-blackhat/agent-guardrail/backend/pkg/models"
)

// OpenAIProvider implements the Provider interface for OpenAI and OpenAI-compatible APIs
type OpenAIProvider struct {
	*BaseProvider
}

// OpenAIChatRequest represents an OpenAI chat completion request
type OpenAIChatRequest struct {
	Model       string              `json:"model"`
	Messages    []OpenAIChatMessage `json:"messages"`
	Temperature float32             `json:"temperature,omitempty"`
	MaxTokens   int                 `json:"max_tokens,omitempty"`
	Stream      bool                `json:"stream,omitempty"`
	TopP        float64             `json:"top_p,omitempty"`
	N           int                 `json:"n,omitempty"`
}

// OpenAIChatMessage represents a message in OpenAI format
type OpenAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIChatResponse represents an OpenAI chat completion response
type OpenAIChatResponse struct {
	ID      string             `json:"id"`
	Object  string             `json:"object"`
	Created int64              `json:"created"`
	Model   string             `json:"model"`
	Choices []OpenAIChatChoice `json:"choices"`
	Usage   OpenAIUsage        `json:"usage"`
}

// OpenAIChatChoice represents a choice in the response
type OpenAIChatChoice struct {
	Index        int               `json:"index"`
	Message      OpenAIChatMessage `json:"message"`
	FinishReason string            `json:"finish_reason"`
}

// OpenAIUsage represents token usage in the response
type OpenAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// NewOpenAIProvider creates a new OpenAI provider
func NewOpenAIProvider(baseURL, apiKey string) *OpenAIProvider {
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	return &OpenAIProvider{
		BaseProvider: NewBaseProvider(baseURL, apiKey),
	}
}

// Name returns the provider identifier
func (o *OpenAIProvider) Name() string {
	return "openai"
}

// ForwardRequest sends the request to OpenAI
func (o *OpenAIProvider) ForwardRequest(r *http.Request) (*http.Response, error) {
	// Handle relative URLs
	if r.URL.Scheme == "" {
		baseURL, err := url.Parse(o.BaseURL)
		if err != nil {
			return nil, err
		}
		// Use JoinPath to append the relative path to the base path
		// This preserves the base path (e.g. /openai)
		fullPath, err := url.JoinPath(baseURL.Path, r.URL.Path)
		if err != nil {
			return nil, err
		}

		// Create a copy of the base URL and update the path
		newURL := *baseURL
		newURL.Path = fullPath
		newURL.RawQuery = r.URL.RawQuery
		r.URL = &newURL
	}

	// Add authorization header if not present
	if r.Header.Get("Authorization") == "" && o.APIKey != "" {
		r.Header.Set("Authorization", "Bearer "+o.APIKey)
	}
	return o.Client.Do(r)
}

// ParseRequest parses raw request body into normalized LLMRequest
func (o *OpenAIProvider) ParseRequest(body []byte) (*models.LLMRequest, error) {
	var openaiReq OpenAIChatRequest
	if err := json.Unmarshal(body, &openaiReq); err != nil {
		return nil, err
	}

	messages := make([]models.Message, len(openaiReq.Messages))
	for i, msg := range openaiReq.Messages {
		messages[i] = models.Message{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}

	return &models.LLMRequest{
		Model:       openaiReq.Model,
		Messages:    messages,
		Temperature: openaiReq.Temperature,
		MaxTokens:   openaiReq.MaxTokens,
		Stream:      openaiReq.Stream,
	}, nil
}

// ParseResponse parses raw response body into normalized LLMResponse
func (o *OpenAIProvider) ParseResponse(body []byte) (*models.LLMResponse, error) {
	var openaiResp OpenAIChatResponse
	if err := json.Unmarshal(body, &openaiResp); err != nil {
		return nil, err
	}

	choices := make([]models.Choice, len(openaiResp.Choices))
	for i, c := range openaiResp.Choices {
		choices[i] = models.Choice{
			Index: c.Index,
			Message: models.Message{
				Role:    c.Message.Role,
				Content: c.Message.Content,
			},
		}
	}

	return &models.LLMResponse{
		ID:      openaiResp.ID,
		Model:   openaiResp.Model,
		Choices: choices,
		Usage: models.Usage{
			PromptTokens:     openaiResp.Usage.PromptTokens,
			CompletionTokens: openaiResp.Usage.CompletionTokens,
			TotalTokens:      openaiResp.Usage.TotalTokens,
		},
	}, nil
}

// SupportsStreaming returns whether OpenAI supports streaming
func (o *OpenAIProvider) SupportsStreaming() bool {
	return true
}

// GetUsage extracts usage information from a response
func (o *OpenAIProvider) GetUsage(resp *models.LLMResponse) *models.Usage {
	return &resp.Usage
}
