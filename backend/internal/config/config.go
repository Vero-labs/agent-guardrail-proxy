package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration
type Config struct {
	Server    ServerConfig
	Providers map[string]ProviderConfig
	Database  DatabaseConfig
	Policies  PolicyConfig
	Logging   LoggingConfig
	Metrics   MetricsConfig

	// Sidecar Analyzers
	IntentAnalyzerURL string
	SemanticCacheURL  string

	// Legacy fields for backward compatibility
	ProviderUrl string
	ProviderKey string
}

// ServerConfig holds HTTP server settings
type ServerConfig struct {
	Host           string
	Port           int
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxRequestSize int64
}

// ProviderConfig holds configuration for a single LLM provider
type ProviderConfig struct {
	Type    string // openai, anthropic, gemini, ollama
	BaseURL string
	APIKey  string
	Default bool
	Timeout time.Duration
}

// DatabaseConfig holds database connection settings
type DatabaseConfig struct {
	Type     string // sqlite, postgres
	Host     string
	Port     int
	Database string
	Username string
	Password string
	SSLMode  string
}

// PolicyConfig holds policy loading settings
type PolicyConfig struct {
	Directory    string
	DefaultID    string
	WatchChanges bool
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level    string // debug, info, warn, error
	Format   string // json, text
	Output   string // stdout, file path
	AuditDir string // Directory for audit logs
}

// MetricsConfig holds metrics/monitoring settings
type MetricsConfig struct {
	Enabled  bool
	Port     int
	Endpoint string
}

// Load reads configuration from environment variables
func Load() *Config {
	cfg := &Config{
		Server: ServerConfig{
			Host:           getEnv("SERVER_HOST", "0.0.0.0"),
			Port:           getEnvInt("SERVER_PORT", 8080),
			ReadTimeout:    time.Duration(getEnvInt("SERVER_READ_TIMEOUT_SEC", 30)) * time.Second,
			WriteTimeout:   time.Duration(getEnvInt("SERVER_WRITE_TIMEOUT_SEC", 60)) * time.Second,
			MaxRequestSize: int64(getEnvInt("SERVER_MAX_REQUEST_SIZE", 10*1024*1024)), // 10MB default
		},
		Providers: make(map[string]ProviderConfig),
		Database: DatabaseConfig{
			Type:     getEnv("DB_TYPE", "sqlite"),
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnvInt("DB_PORT", 5432),
			Database: getEnv("DB_NAME", "guardrail.db"),
			Username: getEnv("DB_USER", ""),
			Password: getEnv("DB_PASSWORD", ""),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		Policies: PolicyConfig{
			Directory:    getEnv("POLICY_DIR", "configs/policies"),
			DefaultID:    getEnv("POLICY_DEFAULT_ID", "default"),
			WatchChanges: getEnvBool("POLICY_WATCH_CHANGES", true),
		},
		Logging: LoggingConfig{
			Level:    getEnv("LOG_LEVEL", "info"),
			Format:   getEnv("LOG_FORMAT", "text"),
			Output:   getEnv("LOG_OUTPUT", "stdout"),
			AuditDir: getEnv("AUDIT_LOG_DIR", "logs/audit"),
		},
		Metrics: MetricsConfig{
			Enabled:  getEnvBool("METRICS_ENABLED", false),
			Port:     getEnvInt("METRICS_PORT", 9090),
			Endpoint: getEnv("METRICS_ENDPOINT", "/metrics"),
		},
		IntentAnalyzerURL: getEnv("INTENT_ANALYZER_URL", "https://huggingface.co/spaces/Blackrose-Blackhat/intent_analyzer"),
		SemanticCacheURL:  getEnv("SEMANTIC_CACHE_URL", ""),
	}

	// Load legacy provider config (backward compatibility)
	providerKey := os.Getenv("PROVIDER_KEY")
	if providerKey == "" {
		providerKey = os.Getenv("PROVIDE_KEY")
	}
	cfg.ProviderUrl = os.Getenv("PROVIDER_URL")
	cfg.ProviderKey = providerKey

	// Configure default provider based on legacy config
	if cfg.ProviderUrl != "" {
		cfg.Providers["default"] = ProviderConfig{
			Type:    detectProviderType(cfg.ProviderUrl),
			BaseURL: cfg.ProviderUrl,
			APIKey:  providerKey,
			Default: true,
			Timeout: 60 * time.Second,
		}
	}

	// Load additional providers from environment
	cfg.loadProviderConfigs()

	return cfg
}

// loadProviderConfigs loads provider configurations from environment
func (c *Config) loadProviderConfigs() {
	providerTypes := []string{"openai", "anthropic", "gemini", "ollama"}

	for _, pType := range providerTypes {
		envPrefix := "PROVIDER_" + pType + "_"
		baseURL := os.Getenv(envPrefix + "URL")
		apiKey := os.Getenv(envPrefix + "KEY")

		if baseURL != "" {
			c.Providers[pType] = ProviderConfig{
				Type:    pType,
				BaseURL: baseURL,
				APIKey:  apiKey,
				Default: getEnvBool(envPrefix+"DEFAULT", false),
				Timeout: time.Duration(getEnvInt(envPrefix+"TIMEOUT_SEC", 60)) * time.Second,
			}
		}
	}
}

// GetDefaultProvider returns the default provider config
func (c *Config) GetDefaultProvider() *ProviderConfig {
	// First check for explicitly marked default
	for _, p := range c.Providers {
		if p.Default {
			return &p
		}
	}
	// Fall back to "default" key
	if p, ok := c.Providers["default"]; ok {
		return &p
	}
	// Fall back to first available
	for _, p := range c.Providers {
		return &p
	}
	return nil
}

// detectProviderType attempts to identify the provider from URL
func detectProviderType(url string) string {
	switch {
	case contains(url, "openai"):
		return "openai"
	case contains(url, "anthropic"):
		return "anthropic"
	case contains(url, "generativelanguage.googleapis.com"):
		return "gemini"
	case contains(url, "localhost") || contains(url, "127.0.0.1") || contains(url, "ollama"):
		return "ollama"
	default:
		return "openai" // Default to OpenAI-compatible
	}
}

// contains is a simple string contains helper
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Helper functions for environment variable parsing
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}
