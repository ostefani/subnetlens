package scanner

import (
	"context"

	mdnstransport "github.com/ostefani/subnetlens/transports/mdns"
)

func startPassiveMDNSListener(ctx context.Context) (*mdnsCache, error) {
	cache := newMDNSCache()
	err := mdnstransport.StartPassiveListener(ctx, cache)
	return cache, err
}
