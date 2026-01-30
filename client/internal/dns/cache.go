package dns

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Cache is a simple DNS response cache
type Cache struct {
	entries map[string]*cacheEntry
	ttl     time.Duration
	maxSize int
	mu      sync.RWMutex
}

type cacheEntry struct {
	msg       *dns.Msg
	expiresAt time.Time
}

// NewCache creates a new DNS cache
func NewCache(ttl time.Duration, maxSize int) *Cache {
	c := &Cache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}

	// Start cleanup goroutine
	go c.cleanup()

	return c
}

// cacheKey generates a cache key from domain and query type
func cacheKey(domain string, qtype uint16) string {
	return domain + ":" + dns.TypeToString[qtype]
}

// Get retrieves a cached response
func (c *Cache) Get(domain string, qtype uint16) *dns.Msg {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := cacheKey(domain, qtype)
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		return nil
	}

	// Return a copy of the message
	return entry.msg.Copy()
}

// Set stores a response in the cache
func (c *Cache) Set(domain string, qtype uint16, msg *dns.Msg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Calculate TTL from response, or use default
	ttl := c.ttl
	if len(msg.Answer) > 0 {
		minTTL := uint32(3600)
		for _, rr := range msg.Answer {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
		if time.Duration(minTTL)*time.Second < ttl {
			ttl = time.Duration(minTTL) * time.Second
		}
	}

	// Don't cache very short TTLs
	if ttl < 10*time.Second {
		return
	}

	// Evict if at capacity
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	key := cacheKey(domain, qtype)
	c.entries[key] = &cacheEntry{
		msg:       msg.Copy(),
		expiresAt: time.Now().Add(ttl),
	}
}

// evictOldest removes the oldest entry (must be called with lock held)
func (c *Cache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestKey == "" || entry.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.expiresAt
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// cleanup periodically removes expired entries
func (c *Cache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.expiresAt) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}

// Clear removes all entries from the cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cacheEntry)
}

// Size returns the number of entries in the cache
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
