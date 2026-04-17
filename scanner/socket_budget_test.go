// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package scanner

import (
	"context"
	"testing"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

func TestBuildResourcePlanWithoutSystemLimitKeepsNormalizedConcurrency(t *testing.T) {
	plan := buildResourcePlan(models.ScanOptions{}, 0, false)

	if got := plan.opts.Concurrency; got != models.DefaultConcurrency {
		t.Fatalf("expected default scan concurrency %d, got %d", models.DefaultConcurrency, got)
	}
	if got := plan.opts.DiscoveryConcurrency; got != models.DefaultConcurrency {
		t.Fatalf("expected default discovery concurrency %d, got %d", models.DefaultConcurrency, got)
	}
	if plan.socketBudget != 0 {
		t.Fatalf("expected no socket budget without a known system limit, got %d", plan.socketBudget)
	}
	if len(plan.warnings) != 0 {
		t.Fatalf("expected no warnings without a known system limit, got %v", plan.warnings)
	}
}

func TestBuildResourcePlanKeepsRequestedConcurrencyWhenDemandExceedsBudget(t *testing.T) {
	plan := buildResourcePlan(models.ScanOptions{
		Concurrency:          100,
		DiscoveryConcurrency: 50,
	}, 100, true)

	if got := plan.socketBudget; got != 36 {
		t.Fatalf("expected socket budget 36, got %d", got)
	}
	if got := plan.opts.Concurrency; got != 100 {
		t.Fatalf("expected scan concurrency to remain 100, got %d", got)
	}
	if got := plan.opts.DiscoveryConcurrency; got != 50 {
		t.Fatalf("expected discovery concurrency to remain 50, got %d", got)
	}
	if len(plan.warnings) == 0 {
		t.Fatal("expected warning when estimated socket demand exceeds the FD budget")
	}
}

func TestBuildResourcePlanWarnsWhenCombinedDemandExceedsBudget(t *testing.T) {
	plan := buildResourcePlan(models.ScanOptions{
		Concurrency:          200,
		DiscoveryConcurrency: 50,
	}, 560, true)

	if got := plan.socketBudget; got != 496 {
		t.Fatalf("expected socket budget 496, got %d", got)
	}
	if got := plan.opts.Concurrency; got != 200 {
		t.Fatalf("expected scan concurrency to remain 200, got %d", got)
	}
	if got := plan.opts.DiscoveryConcurrency; got != 50 {
		t.Fatalf("expected discovery concurrency to remain 50, got %d", got)
	}
	if len(plan.warnings) == 0 {
		t.Fatal("expected warning when combined socket demand exceeds budget")
	}
}

func TestEstimatedSocketDemandIncludesRegisteredExtensionDemand(t *testing.T) {
	additional := additionalSocketDemandForOptions(models.ScanOptions{}, []Option{
		WithDiscoveryModule(socketDemandDiscoveryModule{demand: contracts.AdditionalSocketDemand{Fixed: 2, PerDiscoverySlot: 1}}),
		WithHostScanner(socketDemandHostScanner{demand: contracts.AdditionalSocketDemand{PerScanSlot: 2}}),
	})

	if got := estimatedSocketDemandWithDemand(10, 5, additional); got != 67 {
		t.Fatalf("expected extension demand to increase estimated sockets to 67, got %d", got)
	}
}

type socketDemandDiscoveryModule struct {
	demand contracts.AdditionalSocketDemand
}

func (m socketDemandDiscoveryModule) Discover(context.Context, models.ScanOptions, contracts.DiscoveryRuntime) <-chan contracts.HostObservation {
	out := make(chan contracts.HostObservation)
	close(out)
	return out
}

func (m socketDemandDiscoveryModule) AdditionalSocketDemand(models.ScanOptions) contracts.AdditionalSocketDemand {
	return m.demand
}

type socketDemandHostScanner struct {
	demand contracts.AdditionalSocketDemand
}

func (m socketDemandHostScanner) ScanHost(context.Context, *models.Host, models.ScanOptions, contracts.Runtime) {
}

func (m socketDemandHostScanner) AdditionalSocketDemand(models.ScanOptions) contracts.AdditionalSocketDemand {
	return m.demand
}
