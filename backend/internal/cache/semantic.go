package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// SemanticCache provides embedding-based caching for LLM responses
// Uses exact-match as baseline; semantic similarity can be added with FAISS later
type SemanticCache struct {
	mu       sync.RWMutex
	entries  map[string]*CacheEntry
	maxSize  int
	ttl      time.Duration
}

// CacheEntry represents a cached response
type CacheEntry struct {
	Key       string
	Response  []byte
	CreatedAt time.Time
	Hits      int
}

// NewSemanticCache creates a new cache with given max size and TTL
func NewSemanticCache(maxSize int, ttl time.Duration) *SemanticCache {
	return &SemanticCache{
		entries: make(map[string]*CacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// HashKey generates a deterministic hash for a prompt
func HashKey(prompt string) string {
	hash := sha256.Sum256([]byte(prompt))
	return hex.EncodeToString(hash[:])
}

// Get retrieves a cached response if available and not expired
func (c *SemanticCache) Get(prompt string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := HashKey(prompt)
	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	// Check TTL
	if time.Since(entry.CreatedAt) > c.ttl {
		return nil, false
	}

	entry.Hits++
	return entry.Response, true
}

// Set stores a response in the cache
func (c *SemanticCache) Set(prompt string, response []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := HashKey(prompt)

	// Evict oldest if at capacity
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[key] = &CacheEntry{
		Key:       key,
		Response:  response,
		CreatedAt: time.Now(),
		Hits:      0,
	}
}

// evictOldest removes the oldest entry (LRU-like)
func (c *SemanticCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestKey == "" || entry.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.CreatedAt
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// Stats returns cache statistics
func (c *SemanticCache) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalHits := 0
	for _, entry := range c.entries {
		totalHits += entry.Hits
	}

	return map[string]interface{}{
		"size":       len(c.entries),
		"max_size":   c.maxSize,
		"total_hits": totalHits,
		"ttl_sec":    c.ttl.Seconds(),
	}
}

// Clear empties the cache
func (c *SemanticCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
}
