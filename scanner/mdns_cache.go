package scanner

import "sync"

type mdnsCache struct {
	mu    sync.RWMutex
	names map[string]string
}

func newMDNSCache() *mdnsCache {
	return &mdnsCache{
		names: make(map[string]string),
	}
}

func (c *mdnsCache) LookupName(ip string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	name, ok := c.names[ip]
	return name, ok
}

func (c *mdnsCache) StoreName(ip, name string) {
	if name == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.names[ip]; !exists {
		c.names[ip] = name
	}
}
