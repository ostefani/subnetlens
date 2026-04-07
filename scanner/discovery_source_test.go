package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/models"
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

	var hostnameUpdate *hostUpdate
	for i := range updates {
		if updates[i].name == "workstation" {
			hostnameUpdate = &updates[i]
			break
		}
	}

	if hostnameUpdate == nil {
		t.Fatal("expected hostname update")
	}
	if hostnameUpdate.seenBy != models.HostSourceNBNS {
		t.Fatalf("expected hostname source nbns, got %q", hostnameUpdate.seenBy)
	}
}
