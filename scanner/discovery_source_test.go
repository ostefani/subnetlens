package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

type stubAliveICMPProber struct{}

func (stubAliveICMPProber) Probe(context.Context, string, time.Duration) (bool, time.Duration, error) {
	return true, 10 * time.Millisecond, nil
}

func (stubAliveICMPProber) Warm(string) error { return nil }

func (stubAliveICMPProber) Close() error { return nil }

func TestProbeHostSmartPropagatesResolvedHostnameSource(t *testing.T) {
	cache := &mdnsCache{
		names: map[string]resolveResult{
			"192.168.1.20": {
				name:   "workstation",
				source: models.HostSourceNBNS,
			},
		},
	}

	updates := probeHostSmart(
		context.Background(),
		"192.168.1.20",
		models.ScanOptions{Timeout: 50 * time.Millisecond},
		cache,
		stubAliveICMPProber{},
		nil,
		nil,
	)

	var hostnameUpdate *contracts.HostObservation
	for i := range updates {
		if updates[i].Name == "workstation" {
			hostnameUpdate = &updates[i]
			break
		}
	}

	if hostnameUpdate == nil {
		t.Fatal("expected hostname update")
	}
	if hostnameUpdate.Source != models.HostSourceNBNS {
		t.Fatalf("expected hostname source nbns, got %q", hostnameUpdate.Source)
	}
}

func TestProbeHostSmartDoesNotTreatPTRNameAsLiveness(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache := &mdnsCache{
		names: map[string]resolveResult{
			"192.168.1.30": {
				name:   "stale.example.internal",
				source: models.HostSourcePTR,
			},
		},
	}

	updates := probeHostSmart(
		ctx,
		"192.168.1.30",
		models.ScanOptions{Timeout: 50 * time.Millisecond},
		cache,
		nil,
		nil,
		nil,
	)

	if len(updates) != 1 {
		t.Fatalf("expected 1 hostname-only update, got %d", len(updates))
	}

	update := updates[0]
	if update.Name != "stale.example.internal" {
		t.Fatalf("expected PTR hostname update, got %+v", update)
	}
	if update.Alive {
		t.Fatalf("expected PTR hostname update to not mark host alive, got %+v", update)
	}
	if update.Source != models.HostSourcePTR {
		t.Fatalf("expected PTR source, got %q", update.Source)
	}
}
