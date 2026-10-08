// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
	"github.com/ostefani/subnetlens/scanner/discovery"
)

type largeScanFixture struct {
	engine       *Engine
	icmpFactory  *stubICMPFactory
	mdnsListener *stubPassiveMDNSListener
	arpSweeper   *stubActiveARPSweeper
	preheater    *stubSubnetPreheater
	discoverer   *stubHostDiscoverer
}

func newLargeScanFixture(t *testing.T, allowLarge bool, onIssue func(models.ScanIssue)) *largeScanFixture {
	t.Helper()

	// Exactly one address over contracts.LargeScanThreshold, built through
	// the real expander (TargetSpec has no exported fields to fake).
	spec, err := discovery.ExpandTargets("192.168.0.0-192.168.4.0")
	if err != nil {
		t.Fatalf("expand fixture target: %v", err)
	}
	if uint64(spec.Total()) != contracts.LargeScanThreshold+1 {
		t.Fatalf("fixture must sit one past the consent threshold (%d), got %d addresses",
			contracts.LargeScanThreshold, spec.Total())
	}

	events := make(chan contracts.HostObservation)
	close(events)
	fixture := &largeScanFixture{
		icmpFactory:  &stubICMPFactory{prober: stubAliveICMPProber{}},
		mdnsListener: &stubPassiveMDNSListener{cache: &stubNameCache{}},
		arpSweeper:   &stubActiveARPSweeper{},
		preheater:    &stubSubnetPreheater{},
		discoverer:   &stubHostDiscoverer{events: events},
	}
	fixture.engine = &Engine{
		Opts: models.ScanOptions{
			Subnet:         "10.0.0.0/16",
			Timeout:        50 * time.Millisecond,
			Concurrency:    1,
			AllowLargeScan: allowLarge,
		},
		deps: engineDependencies{
			ouiLoader:           &countingOUILoader{},
			icmpFactory:         fixture.icmpFactory,
			passiveMDNSListener: fixture.mdnsListener,
			activeARPSweeper:    fixture.arpSweeper,
			targetExpander:      &stubTargetExpander{spec: spec},
			subnetPreheater:     fixture.preheater,
			hostDiscoverer:      fixture.discoverer,
			portScanner: &blockingPortScanner{
				scanStarted: make(chan struct{}),
				releaseScan: closedChan(),
			},
			hostEnricher: &countingHostEnricher{},
			osDetector:   &stubOSDetector{},
		},
	}
	if onIssue != nil {
		WithOnIssue(onIssue)(fixture.engine)
	}
	return fixture
}

func TestEngineRefusesLargeScanWithoutConsent(t *testing.T) {
	var issues []models.ScanIssue
	fixture := newLargeScanFixture(t, false, func(issue models.ScanIssue) {
		issues = append(issues, issue)
	})

	result := fixture.engine.Run(context.Background())

	if len(result.Hosts) != 0 {
		t.Fatalf("expected no hosts without large-scan consent, got %d", len(result.Hosts))
	}
	found := false
	for _, issue := range issues {
		if issue.Source == "discovery" && strings.Contains(issue.Message, "AllowLargeScan") {
			found = true
		}
		if strings.Contains(issue.Message, "--allow-large-scan") {
			t.Fatalf("expected engine issue to stay flag-agnostic, got %q", issue.Message)
		}
	}
	if !found {
		t.Fatalf("expected discovery issue naming the consent field, got %+v", issues)
	}

	// The refusal must precede any OS resource acquisition: no raw socket,
	// no listener, no sweep, no preheat, no discovery.
	for name, calls := range map[string]int{
		"icmp":      fixture.icmpFactory.Calls(),
		"mdns":      fixture.mdnsListener.Calls(),
		"arp sweep": fixture.arpSweeper.Calls(),
		"preheat":   fixture.preheater.Calls(),
		"discovery": fixture.discoverer.Calls(),
	} {
		if calls != 0 {
			t.Fatalf("expected no %s acquisition on refusal, got %d call(s)", name, calls)
		}
	}
}

func TestEngineProceedsWithLargeScanConsent(t *testing.T) {
	fixture := newLargeScanFixture(t, true, nil)

	result := fixture.engine.Run(context.Background())

	if len(result.Hosts) != 0 {
		t.Fatalf("expected no hosts from empty stub discovery, got %d", len(result.Hosts))
	}
	if calls := fixture.discoverer.Calls(); calls != 1 {
		t.Fatalf("expected discovery to run once with consent, got %d calls", calls)
	}
}