// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"context"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

type EventType int

const (
	HostDiscovered EventType = iota
	HostUpdated
)

type HostEvent struct {
	Type EventType
	Host *models.Host
}

type HostRegistry struct {
	updates chan contracts.HostObservation
}

func (r *HostRegistry) run(ctx context.Context, out chan<- HostEvent) {
	defer close(out)

	hosts := make(map[string]*models.Host)

	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-r.updates:
			if !ok {
				return
			}
			if u.IP == "" {
				continue
			}

			h, exists := hosts[u.IP]
			if !exists {
				h = models.NewHost(u.IP)
				hosts[u.IP] = h
				mergeObservation(h, u)
				if !emitHostEvent(ctx, out, HostEvent{
					Type: HostDiscovered,
					Host: h,
				}) {
					return
				}
				continue
			}

			if mergeObservation(h, u) {
				if !emitHostEvent(ctx, out, HostEvent{
					Type: HostUpdated,
					Host: h,
				}) {
					return
				}
			}
		}
	}
}

func mergeObservation(h *models.Host, u contracts.HostObservation) bool {
	if h == nil {
		return false
	}
	changed := false
	if h.SetMACIfEmpty(u.MAC) {
		changed = true
	}
	if h.SetHostnameIfEmptyOrIP(u.Name) {
		changed = true
	}
	if h.SetIdentity(u.Identity) {
		changed = true
	}
	if h.ObserveLiveness(u.Alive, u.Weak, u.Source, u.ObservedAt, u.ExpiresAt) {
		changed = true
	}
	if h.SetLatencyIfZero(u.Latency) {
		changed = true
	}
	return changed
}

func emitHostEvent(ctx context.Context, out chan<- HostEvent, event HostEvent) bool {
	select {
	case <-ctx.Done():
		return false
	case out <- event:
		return true
	}
}
