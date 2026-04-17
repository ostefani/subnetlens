// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package scanner

import (
	"context"
	"fmt"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

const (
	reservedFileDescriptors = 64
)

type resourcePlan struct {
	opts         models.ScanOptions
	socketBudget int
	warnings     []string
}

type socketLimiter struct {
	sem chan struct{}
}

func PrepareScanOptions(opts models.ScanOptions) (models.ScanOptions, int, []string) {
	softLimit, limitKnown := systemOpenFileLimit()
	plan := buildResourcePlan(opts, softLimit, limitKnown)
	return plan.opts, plan.socketBudget, plan.warnings
}

func PrepareScanOptionsWithOptions(opts models.ScanOptions, options ...Option) (models.ScanOptions, int, []string) {
	softLimit, limitKnown := systemOpenFileLimit()
	plan := buildResourcePlanWithDemand(opts, softLimit, limitKnown, additionalSocketDemandForOptions(opts, options))
	return plan.opts, plan.socketBudget, plan.warnings
}

func buildResourcePlan(opts models.ScanOptions, softLimit uint64, limitKnown bool) resourcePlan {
	return buildResourcePlanWithDemand(opts, softLimit, limitKnown, contracts.AdditionalSocketDemand{})
}

func buildResourcePlanWithDemand(opts models.ScanOptions, softLimit uint64, limitKnown bool, additional contracts.AdditionalSocketDemand) resourcePlan {
	planned := opts
	requestedScan := opts.ScanConcurrencyLimit()
	requestedDiscovery := opts.DiscoveryConcurrencyLimit()

	planned.Concurrency = requestedScan
	planned.DiscoveryConcurrency = requestedDiscovery
	additional = sanitizeAdditionalSocketDemand(additional)

	if !limitKnown {
		return resourcePlan{opts: planned}
	}

	budget := socketBudgetForLimit(softLimit)

	return resourcePlan{
		opts:         planned,
		socketBudget: budget,
		warnings: resourceWarnings(
			softLimit,
			budget,
			requestedScan,
			requestedDiscovery,
			additional,
		),
	}
}

func socketBudgetForLimit(softLimit uint64) int {
	if softLimit <= reservedFileDescriptors {
		return 1
	}

	budget := softLimit - reservedFileDescriptors
	maxInt := int(^uint(0) >> 1)
	if budget > uint64(maxInt) {
		return maxInt
	}
	if budget == 0 {
		return 1
	}
	return int(budget)
}

func estimatedSocketDemand(scanConcurrency, discoveryConcurrency int) int {
	return estimatedSocketDemandWithDemand(scanConcurrency, discoveryConcurrency, contracts.AdditionalSocketDemand{})
}

func estimatedSocketDemandWithDemand(scanConcurrency, discoveryConcurrency int, additional contracts.AdditionalSocketDemand) int {
	additional = sanitizeAdditionalSocketDemand(additional)
	return scanConcurrency + discoveryConcurrency*discoverySocketEstimate() +
		additional.Fixed + scanConcurrency*additional.PerScanSlot + discoveryConcurrency*additional.PerDiscoverySlot
}

func discoverySocketEstimate() int {
	return len(tcpProbePorts) + 1
}

func resourceWarnings(
	softLimit uint64,
	budget int,
	requestedScan int,
	requestedDiscovery int,
	additional contracts.AdditionalSocketDemand,
) []string {
	requestedDemand := estimatedSocketDemandWithDemand(
		requestedScan,
		requestedDiscovery,
		additional,
	)

	if requestedDemand <= budget {
		return nil
	}

	return []string{fmt.Sprintf(
		"Open-file soft limit %d leaves a shared socket budget of %d. Requested scan=%d and discovery=%d can demand about %d sockets at peak, so live socket opens will be queued at runtime to avoid EMFILE.",
		softLimit,
		budget,
		requestedScan,
		requestedDiscovery,
		requestedDemand,
	)}
}

func additionalSocketDemandForOptions(opts models.ScanOptions, options []Option) contracts.AdditionalSocketDemand {
	if len(options) == 0 {
		return contracts.AdditionalSocketDemand{}
	}

	engine := &Engine{}
	for _, option := range options {
		if option == nil {
			continue
		}
		option(engine)
	}

	return additionalSocketDemandForExtensions(opts, engine.discoveryModules, engine.hostScanners)
}

func additionalSocketDemandForExtensions(opts models.ScanOptions, discoveryModules []contracts.DiscoveryModule, hostScanners []contracts.HostScanner) contracts.AdditionalSocketDemand {
	demand := contracts.AdditionalSocketDemand{}
	for _, discoveryModule := range discoveryModules {
		demand = sumAdditionalSocketDemand(demand, additionalSocketDemandOf(opts, discoveryModule))
	}
	for _, hostScanner := range hostScanners {
		demand = sumAdditionalSocketDemand(demand, additionalSocketDemandOf(opts, hostScanner))
	}
	return demand
}

func additionalSocketDemandOf(opts models.ScanOptions, extension any) contracts.AdditionalSocketDemand {
	reporter, ok := extension.(contracts.SocketDemandReporter)
	if !ok {
		return contracts.AdditionalSocketDemand{}
	}
	return sanitizeAdditionalSocketDemand(reporter.AdditionalSocketDemand(opts))
}

func sumAdditionalSocketDemand(left, right contracts.AdditionalSocketDemand) contracts.AdditionalSocketDemand {
	return contracts.AdditionalSocketDemand{
		Fixed:            left.Fixed + right.Fixed,
		PerScanSlot:      left.PerScanSlot + right.PerScanSlot,
		PerDiscoverySlot: left.PerDiscoverySlot + right.PerDiscoverySlot,
	}
}

func sanitizeAdditionalSocketDemand(demand contracts.AdditionalSocketDemand) contracts.AdditionalSocketDemand {
	if demand.Fixed < 0 {
		demand.Fixed = 0
	}
	if demand.PerScanSlot < 0 {
		demand.PerScanSlot = 0
	}
	if demand.PerDiscoverySlot < 0 {
		demand.PerDiscoverySlot = 0
	}
	return demand
}

func newSocketLimiter(slots int) *socketLimiter {
	if slots <= 0 {
		return nil
	}
	return &socketLimiter{sem: make(chan struct{}, slots)}
}

func (l *socketLimiter) Acquire(ctx context.Context) error {
	if l == nil {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case l.sem <- struct{}{}:
		return nil
	}
}

func (l *socketLimiter) Release() {
	if l == nil {
		return
	}
	<-l.sem
}
