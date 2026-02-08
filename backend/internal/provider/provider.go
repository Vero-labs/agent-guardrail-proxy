package provider

import (
	"net/http"

	"github.com/blackrose-blackhat/agent-guardrail/backend/pkg/models"
)

// Provider is the interface that all LLM providers must implement
type Provider interface {
	// Name returns the provider identifier
	Name() string

	// ForwardRequest sends the request to the provider and returns the response
	ForwardRequest(r *http.Request) (*http.Response, error)

	// ParseRequest parses raw request body into normalized LLMRequest
	ParseRequest(body []byte) (*models.LLMRequest, error)

	// ParseResponse parses raw response body into normalized LLMResponse
	ParseResponse(body []byte) (*models.LLMResponse, error)

	// SupportsStreaming returns whether this provider supports SSE streaming
	SupportsStreaming() bool

	// GetUsage extracts usage information from a response
	GetUsage(resp *models.LLMResponse) *models.Usage
}

// BaseProvider provides common functionality for all providers
type BaseProvider struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
}

// NewBaseProvider creates a new base provider
func NewBaseProvider(baseURL, apiKey string) *BaseProvider {
	return &BaseProvider{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Client:  &http.Client{},
	}
}
