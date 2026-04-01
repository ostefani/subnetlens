package scanner

import (
	"context"
	"time"

	"github.com/ostefani/subnetlens/models"
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

type hostUpdate struct {
	ip      string
	mac     string
	name    string
	alive   bool
	latency time.Duration
	seenBy  string
}

type HostRegistry struct {
	updates chan hostUpdate
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
			if u.ip == "" {
				continue
			}

			h, exists := hosts[u.ip]
			if !exists {
				h = models.NewHost(u.ip)
				hosts[u.ip] = h
				mergeUpdate(h, u)
				if !emitHostEvent(ctx, out, HostEvent{
					Type: HostDiscovered,
					Host: h,
				}) {
					return
				}
				continue
			}

			if mergeUpdate(h, u) {
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

func mergeUpdate(h *models.Host, u hostUpdate) bool {
	if h == nil {
		return false
	}

	changed := false

	if h.SetMACIfEmpty(u.mac) {
		changed = true
	}

	if h.SetHostnameIfEmptyOrIP(u.name) {
		changed = true
	}

	if u.alive && h.SetAlive(true) {
		changed = true
	}

	if h.SetLatencyIfZero(u.latency) {
		changed = true
	}

	if h.MarkSeen(u.seenBy) {
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
