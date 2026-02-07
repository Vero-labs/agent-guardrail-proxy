package policy

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// Loader manages loading and caching of policy files
type Loader struct {
	configDir string
	policies  map[string]*Policy
	defaultID string
	mu        sync.RWMutex
	logger    *log.Logger
}

// NewLoader creates a new policy loader
func NewLoader(configDir string, logger *log.Logger) *Loader {
	return &Loader{
		configDir: configDir,
		policies:  make(map[string]*Policy),
		logger:    logger,
	}
}

// Load reads all policy files from the config directory
func (l *Loader) Load() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Clear existing policies
	l.policies = make(map[string]*Policy)

	// Check if directory exists
	if _, err := os.Stat(l.configDir); os.IsNotExist(err) {
		l.logInfo("Policy directory does not exist: %s, using default policy", l.configDir)
		// Use default policy if no directory
		defaultPolicy := DefaultPolicy()
		l.policies[defaultPolicy.ID] = defaultPolicy
		l.defaultID = defaultPolicy.ID
		return nil
	}

	// Find all YAML files
	files, err := filepath.Glob(filepath.Join(l.configDir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("failed to list policy files: %w", err)
	}

	// Also check for .yml files
	ymlFiles, err := filepath.Glob(filepath.Join(l.configDir, "*.yml"))
	if err != nil {
		return fmt.Errorf("failed to list policy files: %w", err)
	}
	files = append(files, ymlFiles...)

	// If no files found, use default
	if len(files) == 0 {
		l.logInfo("No policy files found, using default policy")
		defaultPolicy := DefaultPolicy()
		l.policies[defaultPolicy.ID] = defaultPolicy
		l.defaultID = defaultPolicy.ID
		return nil
	}

	// Load each file
	for _, file := range files {
		policy, err := l.loadFile(file)
		if err != nil {
			l.logError("Failed to load policy file %s: %v", file, err)
			continue
		}

		l.policies[policy.ID] = policy
		l.logInfo("Loaded policy: %s (version %s)", policy.Name, policy.Version)

		// Set default if this is the default policy
		if policy.ID == "default" {
			l.defaultID = policy.ID
		}
	}

	// If no default was set, use the first one
	if l.defaultID == "" && len(l.policies) > 0 {
		for id := range l.policies {
			l.defaultID = id
			break
		}
	}

	l.logInfo("Loaded %d policies, default: %s", len(l.policies), l.defaultID)
	return nil
}

// loadFile reads and parses a single policy file
func (l *Loader) loadFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Validate required fields
	if policy.ID == "" {
		return nil, fmt.Errorf("policy ID is required")
	}
	if policy.Name == "" {
		policy.Name = policy.ID
	}
	if policy.Version == "" {
		policy.Version = "1.0.0"
	}

	return &policy, nil
}

// GetPolicy returns a policy by ID
func (l *Loader) GetPolicy(id string) *Policy {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.policies[id]
}

// GetDefaultPolicy returns the default policy
func (l *Loader) GetDefaultPolicy() *Policy {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.defaultID == "" {
		return DefaultPolicy()
	}
	return l.policies[l.defaultID]
}

// ListPolicies returns all loaded policies
func (l *Loader) ListPolicies() []*Policy {
	l.mu.RLock()
	defer l.mu.RUnlock()

	policies := make([]*Policy, 0, len(l.policies))
	for _, p := range l.policies {
		policies = append(policies, p)
	}
	return policies
}

// Reload reloads all policies from disk
func (l *Loader) Reload() error {
	l.logInfo("Reloading policies...")
	return l.Load()
}

// SavePolicy saves a policy to disk
func (l *Loader) SavePolicy(policy *Policy) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Ensure directory exists
	if err := os.MkdirAll(l.configDir, 0755); err != nil {
		return fmt.Errorf("failed to create policy directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	// Write to file
	filename := filepath.Join(l.configDir, policy.ID+".yaml")
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	// Update cache
	l.policies[policy.ID] = policy
	l.logInfo("Saved policy: %s", policy.ID)

	return nil
}

// DeletePolicy removes a policy from disk and cache
func (l *Loader) DeletePolicy(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if id == "default" {
		return fmt.Errorf("cannot delete the default policy")
	}

	filename := filepath.Join(l.configDir, id+".yaml")
	if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete policy file: %w", err)
	}

	delete(l.policies, id)
	l.logInfo("Deleted policy: %s", id)

	return nil
}

// logging helpers
func (l *Loader) logInfo(format string, args ...interface{}) {
	if l.logger != nil {
		l.logger.Printf("[INFO] "+format, args...)
	}
}

func (l *Loader) logError(format string, args ...interface{}) {
	if l.logger != nil {
		l.logger.Printf("[ERROR] "+format, args...)
	}
}
