// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"context"
	"time"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
	mdnstransport "github.com/ostefani/subnetlens/transports/mdns"
)

type passiveMDNSStore struct {
	ctx     context.Context
	cache   *mdnsCache
	updates chan contracts.HostObservation
}

func startPassiveMDNSListener(ctx context.Context) (passiveMDNSSession, error) {
	cache := newMDNSCache()
	updates := make(chan contracts.HostObservation, 256)
	store := &passiveMDNSStore{
		ctx:     ctx,
		cache:   cache,
		updates: updates,
	}

	err := mdnstransport.StartPassiveListener(ctx, store)
	if err != nil {
		close(updates)
		return passiveMDNSSession{cache: cache}, err
	}

	return passiveMDNSSession{
		cache:        cache,
		observations: updates,
	}, nil
}

func (s *passiveMDNSStore) StoreName(ip, name string, source models.HostSource) {
	if s == nil || s.cache == nil {
		return
	}

	if !s.cache.storeName(ip, name, source) {
		return
	}

	if s.updates == nil {
		return
	}

	sendHostObservation(s.ctx, s.updates, contracts.HostObservation{
		IP:         ip,
		Name:       name,
		Alive:      source == models.HostSourceMDNS,
		Source:     source,
		ObservedAt: time.Now(),
	})
}

func (s *passiveMDNSStore) Close() {
	if s == nil || s.updates == nil {
		return
	}
	close(s.updates)
}
