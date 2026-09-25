// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

func TestCheckTargetConsentPassesForOrdinaryTargets(t *testing.T) {
	opts := models.ScanOptions{Subnet: "192.168.1.0/24"}

	for _, target := range []string{
		"192.168.1.5",
		"192.168.1.0/24",
		"192.168.0.0-192.168.3.255", // exactly LargeScanThreshold addresses
	} {
		total, err := CheckTargetConsent(target, opts)
		if err != nil {
			t.Fatalf("expected no consent error for %q, got %v", target, err)
		}
		if total == 0 || total > contracts.LargeScanThreshold {
			t.Fatalf("expected ordinary count for %q, got %d", target, total)
		}
	}
}

func TestCheckTargetConsentCountsSlash24(t *testing.T) {
	total, err := CheckTargetConsent("192.168.1.0/24", models.ScanOptions{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if total != 254 {
		t.Fatalf("expected 254 usable addresses in a /24, got %d", total)
	}
}

func TestCheckTargetConsentRequiresFlagOverThreshold(t *testing.T) {
	total, err := CheckTargetConsent("192.168.0.0-192.168.4.0", models.ScanOptions{})
	if err == nil {
		t.Fatal("expected consent error for 1025 addresses without the flag")
	}
	if total != 1025 {
		t.Fatalf("expected count 1025 alongside the error, got %d", total)
	}
	var confirmationErr *LargeScanConfirmationError
	if !errors.As(err, &confirmationErr) {
		t.Fatalf("expected *LargeScanConfirmationError, got %T", err)
	}
	if !strings.Contains(err.Error(), "AllowLargeScan") {
		t.Fatalf("expected error to name the consent field, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "--allow-large-scan") {
		t.Fatalf("expected library error to stay flag-agnostic, got %q", err.Error())
	}

	total, err = CheckTargetConsent("192.168.0.0-192.168.4.0", models.ScanOptions{AllowLargeScan: true})
	if err != nil {
		t.Fatalf("expected consent to clear the error, got %v", err)
	}
	if total != 1025 {
		t.Fatalf("expected count 1025 with consent, got %d", total)
	}
}

func TestCheckTargetConsentSlash16NeedsFlag(t *testing.T) {
	_, err := CheckTargetConsent("10.0.0.0/16", models.ScanOptions{})
	if err == nil {
		t.Fatal("expected consent error for a /16 without the flag")
	}

	total, err := CheckTargetConsent("10.0.0.0/16", models.ScanOptions{AllowLargeScan: true})
	if err != nil {
		t.Fatalf("expected /16 to pass with consent, got %v", err)
	}
	if total != 65534 {
		t.Fatalf("expected 65534 usable addresses in a /16, got %d", total)
	}
}

func TestCheckTargetConsentFullRangeCountDoesNotOverflow(t *testing.T) {
	total, err := CheckTargetConsent("0.0.0.0-255.255.255.255", models.ScanOptions{AllowLargeScan: true})
	if err != nil {
		t.Fatalf("expected full range to expand with consent, got %v", err)
	}
	if total != 1<<32 {
		t.Fatalf("expected 2^32 addresses for the full range, got %d", total)
	}
}

func TestCheckTargetConsentKeepsSyntaxErrorsUntyped(t *testing.T) {
	_, err := CheckTargetConsent("not-a-subnet", models.ScanOptions{})
	if err == nil {
		t.Fatal("expected syntax error for an invalid target")
	}
	var confirmationErr *LargeScanConfirmationError
	if errors.As(err, &confirmationErr) {
		t.Fatalf("expected a plain syntax error, got consent error %v", err)
	}
}

func TestTargetEnumerationStreamsLargeRanges(t *testing.T) {
	for target, want := range map[string]int{
		"10.0.0.0/20": 4094,
		"10.0.0.0/16": 65534,
	} {
		spec, err := expandTargets(target)
		if err != nil {
			t.Fatalf("expected %q to expand, got %v", target, err)
		}
		if spec.total != want {
			t.Fatalf("expected %d addresses for %q, got %d", want, target, spec.total)
		}
		seen := 0
		for range spec.seq {
			seen++
		}
		if seen != want {
			t.Fatalf("expected to stream %d addresses for %q, got %d", want, target, seen)
		}
	}
}

func TestFullRangeUsableWithoutEnumerating(t *testing.T) {
	spec, err := expandTargets("0.0.0.0-255.255.255.255")
	if err != nil {
		t.Fatalf("expected full range to expand, got %v", err)
	}
	if spec.total != 1<<32 {
		t.Fatalf("expected 2^32 addresses, got %d", spec.total)
	}
	for _, ip := range []string{"0.0.0.0", "0.0.0.1", "192.168.1.1", "255.255.255.255"} {
		if !spec.contains(ip) {
			t.Fatalf("expected %q to be contained in the full range", ip)
		}
	}
	want := []string{"0.0.0.0", "0.0.0.1", "0.0.0.2"}
	var first []string
	for ip := range spec.seq {
		first = append(first, ip)
		if len(first) == len(want) {
			break
		}
	}
	for i := range want {
		if first[i] != want[i] {
			t.Fatalf("expected prefix %v, got %v", want, first)
		}
	}
}

func TestCheckTargetConsentAllocatesConstant(t *testing.T) {
	// The consent pre-flight must never materialize the candidate set:
	// counting a /16 costs the same allocations as a /24.
	small := testing.AllocsPerRun(50, func() {
		_, _ = CheckTargetConsent("192.168.1.0/24", models.ScanOptions{})
	})
	large := testing.AllocsPerRun(50, func() {
		_, _ = CheckTargetConsent("10.0.0.0/16", models.ScanOptions{AllowLargeScan: true})
	})
	if small != large {
		t.Fatalf("expected constant allocations for count checks, got /24=%v /16=%v", small, large)
	}
}

func TestTargetSequenceReusableAcrossConcurrentConsumers(t *testing.T) {
	// The engine hands the same sequence to the ARP sweeper and the subnet
	// preheater, which consume it independently and concurrently. This locks
	// in that rangeSpec captures no mutable iterator state: every invocation
	// must stream the identical addresses from scratch.
	spec, err := expandTargets("192.168.1.0/29")
	if err != nil {
		t.Fatalf("expected /29 to expand, got %v", err)
	}

	const consumers = 2
	results := make([][]string, consumers)
	var wg sync.WaitGroup
	for i := 0; i < consumers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for ip := range spec.seq {
				results[i] = append(results[i], ip)
			}
		}(i)
	}
	wg.Wait()

	if len(results[0]) != spec.total {
		t.Fatalf("expected %d addresses, got %d", spec.total, len(results[0]))
	}
	for i := 1; i < consumers; i++ {
		if !slices.Equal(results[0], results[i]) {
			t.Fatalf("expected identical streams across consumers, got %v vs %v", results[0], results[i])
		}
	}
}

func BenchmarkTargetEnumerationPerIP(b *testing.B) {
	spec, err := expandTargets("192.168.1.0/24")
	if err != nil {
		b.Fatalf("expected /24 to expand: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for range spec.seq {
		}
	}
}

func TestLargeScanWarningOnlyForLargeTargets(t *testing.T) {
	if warning := LargeScanWarning("192.168.1.0/24", 254); warning != "" {
		t.Fatalf("expected no warning for a /24, got %q", warning)
	}
	if warning := LargeScanWarning("10.0.0.0/16", 65534); !strings.Contains(warning, "65534") {
		t.Fatalf("expected warning to state the address count, got %q", warning)
	}
}

type largeScanFixture struct {
	engine       *Engine
	icmpFactory  *stubICMPFactory
	mdnsListener *stubPassiveMDNSListener
	arpSweeper   *stubActiveARPSweeper
	preheater    *stubSubnetPreheater
	discoverer   *stubHostDiscoverer
}

func newLargeScanFixture(allowLarge bool, onIssue func(models.ScanIssue)) *largeScanFixture {
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
			targetExpander: &stubTargetExpander{spec: targetSpec{
				seq:   func(func(string) bool) {},
				total: contracts.LargeScanThreshold + 1,
			}},
			subnetPreheater: fixture.preheater,
			hostDiscoverer:  fixture.discoverer,
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
	fixture := newLargeScanFixture(false, func(issue models.ScanIssue) {
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
	fixture := newLargeScanFixture(true, nil)

	result := fixture.engine.Run(context.Background())

	if len(result.Hosts) != 0 {
		t.Fatalf("expected no hosts from empty stub discovery, got %d", len(result.Hosts))
	}
	if calls := fixture.discoverer.Calls(); calls != 1 {
		t.Fatalf("expected discovery to run once with consent, got %d calls", calls)
	}
}
