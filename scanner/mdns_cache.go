package scanner

import (
	"sync"

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
	return res, ok
}

func (c *mdnsCache) StoreName(ip, name string, source models.HostSource) {
	if name == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.names[ip]; !exists {
		c.names[ip] = resolveResult{name: name, source: source}
	}
}
