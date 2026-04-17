// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"sync"
	"time"

	"github.com/ostefani/subnetlens/models"
)

type mdnsCache struct {
	mu    sync.RWMutex
	names map[string]resolveResult
}

func newMDNSCache() *mdnsCache {
	return &mdnsCache{
		names: make(map[string]resolveResult),
	}
}

func (c *mdnsCache) LookupName(ip string) (resolveResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	res, ok := c.names[ip]
	if !ok {
		return resolveResult{}, false
	}
	if !res.expiresAt.IsZero() && time.Now().After(res.expiresAt) {
		return resolveResult{}, false
	}
	return res, ok
}

func (c *mdnsCache) StoreName(ip, name string, source models.HostSource) {
	c.storeName(ip, name, source)
}

func (c *mdnsCache) storeName(ip, name string, source models.HostSource) bool {
	if name == "" {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	observedAt := time.Now()
	expiresAt := observedAt.Add(cachedNameEvidenceTTL)
	if existing, exists := c.names[ip]; exists {
		if existing.name == name && existing.source == source {
			existing.observedAt = observedAt
			existing.expiresAt = expiresAt
			c.names[ip] = existing
			return true
		}
	}

	c.names[ip] = resolveResult{
		name:       name,
		source:     source,
		observedAt: observedAt,
		expiresAt:  expiresAt,
	}
	return true
}
