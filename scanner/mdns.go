package scanner

import (
	"context"
	"time"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
	mdnstransport "github.com/ostefani/subnetlens/transports/mdns"
	nbnstransport "github.com/ostefani/subnetlens/transports/nbns"
)

func resolveHostname(ctx context.Context, ip string, cache nameCache, socketLimiter contracts.SocketLimiter) resolveResult {
	if cache != nil {
		if res, ok := cache.LookupName(ip); ok && res.name != "" {
			return res
		}
	}

	start := time.Now()
	if name := mdnstransport.ResolveName(ctx, ip, socketLimiter); name != "" && name != ip {
		if cache != nil {
			cache.StoreName(ip, name, models.HostSourceMDNS)
		}
		return resolveResult{
			name:           name,
			latency:        time.Since(start),
			source:         models.HostSourceMDNS,
			provesLiveness: true,
		}
	}

	start = time.Now()
	if name := nbnstransport.ResolveName(ctx, ip, socketLimiter); name != "" {
		if cache != nil {
			cache.StoreName(ip, name, models.HostSourceNBNS)
		}
		return resolveResult{
			name:           name,
			latency:        time.Since(start),
			source:         models.HostSourceNBNS,
			provesLiveness: true,
		}
	}

	start = time.Now()
	if name := probePTR(ctx, ip, socketLimiter); name != "" && name != ip {
		if cache != nil {
			cache.StoreName(ip, name, models.HostSourcePTR)
		}
		return resolveResult{
			name:    name,
			latency: time.Since(start),
			source:  models.HostSourcePTR,
		}
	}

	return resolveResult{}
}
