package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

func TestHostRegistryMergesLateARPWithoutReemit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := &HostRegistry{updates: make(chan contracts.HostObservation, 4)}
	out := make(chan HostEvent, 4)
	done := make(chan struct{})

	go func() {
		registry.run(ctx, out)
		close(done)
	}()

	registry.updates <- contracts.HostObservation{
		IP:      "192.168.1.10",
		Alive:   true,
		Latency: 10 * time.Millisecond,
		Source:  models.HostSourceICMP,
	}

	discovered, ok := <-out
	if !ok {
		t.Fatal("expected discovered event")
	}
	if discovered.Type != HostDiscovered {
		t.Fatalf("expected HostDiscovered, got %v", discovered.Type)
	}

	host := discovered.Host
	if host == nil {
		t.Fatal("expected emitted host")
	}
	snapshot := host.Snapshot()
	if snapshot.IP != "192.168.1.10" {
		t.Fatalf("unexpected IP %q", snapshot.IP)
	}
	if snapshot.MAC != "" {
		t.Fatalf("expected MAC to be empty before ARP update, got %q", snapshot.MAC)
	}
	if !host.IsAlive() {
		t.Fatal("expected host to be alive after probe update")
	}
	if snapshot.Latency != 10*time.Millisecond {
		t.Fatalf("unexpected latency %v", snapshot.Latency)
	}

	registry.updates <- contracts.HostObservation{
		IP:     "192.168.1.10",
		MAC:    "00:1c:b3:00:00:01",
		Alive:  true,
		Source: models.HostSourceARP,
	}

	updated, ok := <-out
	if !ok {
		t.Fatal("expected updated event")
	}
	if updated.Type != HostUpdated {
		t.Fatalf("expected HostUpdated, got %v", updated.Type)
	}
	if updated.Host != host {
		t.Fatal("expected update event to reuse the same host pointer")
	}

	close(registry.updates)
	<-done

	snapshot = host.Snapshot()
	if snapshot.MAC != "00:1c:b3:00:00:01" {
		t.Fatalf("expected late ARP to update MAC, got %q", snapshot.MAC)
	}
	if snapshot.Source != models.HostSourceMixed {
		t.Fatalf("expected merged source to be mixed, got %q", snapshot.Source)
	}

	EnrichHost(host, nil, nil)
	snapshot = host.Snapshot()
	if snapshot.Vendor != "Apple" {
		t.Fatalf("expected vendor enrichment from MAC, got %q", snapshot.Vendor)
	}

	if extra, open := <-out; open {
		t.Fatalf("unexpected extra event: %+v", extra)
	}
}

func TestHostRegistrySkipsDuplicateUpdates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := &HostRegistry{updates: make(chan contracts.HostObservation, 4)}
	out := make(chan HostEvent, 4)
	done := make(chan struct{})

	go func() {
		registry.run(ctx, out)
		close(done)
	}()

	registry.updates <- contracts.HostObservation{
		IP:     "192.168.1.20",
		MAC:    "00:1c:b3:00:00:02",
		Alive:  true,
		Source: models.HostSourceARP,
	}

	event := <-out
	if event.Type != HostDiscovered {
		t.Fatalf("expected HostDiscovered, got %v", event.Type)
	}

	registry.updates <- contracts.HostObservation{
		IP:     "192.168.1.20",
		MAC:    "00:1c:b3:00:00:02",
		Alive:  true,
		Source: models.HostSourceARP,
	}
	close(registry.updates)
	<-done

	if extra, open := <-out; open {
		t.Fatalf("unexpected duplicate update event: %+v", extra)
	}
}
