package provider

import (
	"encoding/json"
	"net/http"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
)

// OpenAIProvider implements the Provider interface for OpenAI and OpenAI-compatible APIs
type OpenAIProvider struct {
	*BaseProvider
}

// OpenAIChatRequest represents an OpenAI chat completion request
type OpenAIChatRequest struct {
	Model       string              `json:"model"`
	Messages    []OpenAIChatMessage `json:"messages"`
	Temperature float64             `json:"temperature,omitempty"`
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
	// Add authorization header if not present
	if r.Header.Get("Authorization") == "" && o.APIKey != "" {
		r.Header.Set("Authorization", "Bearer "+o.APIKey)
	}
	return o.Client.Do(r)
}

// ParseRequest parses raw request body into normalized LLMRequest
func (o *OpenAIProvider) ParseRequest(body []byte) (*chain.LLMRequest, error) {
	var openaiReq OpenAIChatRequest
	if err := json.Unmarshal(body, &openaiReq); err != nil {
		return nil, err
	}

	messages := make([]chain.LLMMessage, len(openaiReq.Messages))
	for i, msg := range openaiReq.Messages {
		messages[i] = chain.LLMMessage{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}

	return &chain.LLMRequest{
		Model:       openaiReq.Model,
		Messages:    messages,
		Temperature: openaiReq.Temperature,
		MaxTokens:   openaiReq.MaxTokens,
		Stream:      openaiReq.Stream,
	}, nil
}

// ParseResponse parses raw response body into normalized LLMResponse
func (o *OpenAIProvider) ParseResponse(body []byte) (*chain.LLMResponse, error) {
	var openaiResp OpenAIChatResponse
	if err := json.Unmarshal(body, &openaiResp); err != nil {
		return nil, err
	}

	content := ""
	finishReason := ""
	if len(openaiResp.Choices) > 0 {
		content = openaiResp.Choices[0].Message.Content
		finishReason = openaiResp.Choices[0].FinishReason
	}

	return &chain.LLMResponse{
		Content:      content,
		FinishReason: finishReason,
		Model:        openaiResp.Model,
		Usage: &chain.Usage{
			InputTokens:  openaiResp.Usage.PromptTokens,
			OutputTokens: openaiResp.Usage.CompletionTokens,
			TotalTokens:  openaiResp.Usage.TotalTokens,
		},
	}, nil
}

// SupportsStreaming returns whether OpenAI supports streaming
func (o *OpenAIProvider) SupportsStreaming() bool {
	return true
}

// GetUsage extracts usage information from a response
func (o *OpenAIProvider) GetUsage(resp *chain.LLMResponse) *chain.Usage {
	return resp.Usage
}
