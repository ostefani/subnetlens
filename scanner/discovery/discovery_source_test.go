// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package discovery

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

func TestProbeHostSmartPropagatesResolvedHostnameSource(t *testing.T) {
	resolve := func(context.Context, string, contracts.SocketLimiter) contracts.NameResolution {
		return contracts.NameResolution{
			Name:   "workstation",
			Source: models.HostSourceNBNS,
		}
	}

	updates := probeHostSmart(
		context.Background(),
		"192.168.1.20",
		models.ScanOptions{Timeout: 50 * time.Millisecond},
		resolve,
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

	resolve := func(context.Context, string, contracts.SocketLimiter) contracts.NameResolution {
		return contracts.NameResolution{
			Name:   "stale.example.internal",
			Source: models.HostSourcePTR,
		}
	}

	updates := probeHostSmart(
		ctx,
		"192.168.1.30",
		models.ScanOptions{Timeout: 50 * time.Millisecond},
		resolve,
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

func TestProbeHostSmartWithoutResolverReportsLivenessOnly(t *testing.T) {
	updates := probeHostSmart(
		context.Background(),
		"192.168.1.40",
		models.ScanOptions{Timeout: 50 * time.Millisecond},
		nil,
		stubAliveICMPProber{},
		nil,
		nil,
	)

	if len(updates) != 1 {
		t.Fatalf("expected 1 liveness update, got %d: %+v", len(updates), updates)
	}
	if !updates[0].Alive || updates[0].Source != models.HostSourceICMP || updates[0].Name != "" {
		t.Fatalf("expected a nameless ICMP liveness update, got %+v", updates[0])
	}
}