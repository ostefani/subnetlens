package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/models"
)

func TestHostRegistryMergesLateARPWithoutReemit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := &HostRegistry{updates: make(chan hostUpdate, 4)}
	out := make(chan *models.Host, 4)
	done := make(chan struct{})

	go func() {
		registry.run(ctx, out)
		close(done)
	}()

	registry.updates <- hostUpdate{
		ip:      "192.168.1.10",
		alive:   true,
		latency: 10 * time.Millisecond,
		seenBy:  "icmp",
	}

	host := <-out
	if host == nil {
		t.Fatal("expected emitted host")
	}
	if host.IP != "192.168.1.10" {
		t.Fatalf("unexpected IP %q", host.IP)
	}
	if host.MAC != "" {
		t.Fatalf("expected MAC to be empty before ARP update, got %q", host.MAC)
	}
	if !host.IsAlive() {
		t.Fatal("expected host to be alive after probe update")
	}
	if host.Latency != 10*time.Millisecond {
		t.Fatalf("unexpected latency %v", host.Latency)
	}

	registry.updates <- hostUpdate{
		ip:     "192.168.1.10",
		mac:    "00:1c:b3:00:00:01",
		alive:  true,
		seenBy: "arp",
	}
	close(registry.updates)
	<-done

	if host.MAC != "00:1c:b3:00:00:01" {
		t.Fatalf("expected late ARP to update MAC, got %q", host.MAC)
	}
	if host.Source != "mixed" {
		t.Fatalf("expected merged source to be mixed, got %q", host.Source)
	}

	EnrichHost(host, nil, nil)
	if host.Vendor != "Apple" {
		t.Fatalf("expected vendor enrichment from MAC, got %q", host.Vendor)
	}

	if extra, ok := <-out; ok {
		t.Fatalf("unexpected re-emission: %+v", extra)
	}
}
