package scanner

import (
	"context"
	"fmt"

	"github.com/ostefani/subnetlens/models"
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

func buildResourcePlan(opts models.ScanOptions, softLimit uint64, limitKnown bool) resourcePlan {
	planned := opts
	requestedScan := opts.ScanConcurrencyLimit()
	requestedDiscovery := opts.DiscoveryConcurrencyLimit()

	planned.Concurrency = requestedScan
	planned.DiscoveryConcurrency = requestedDiscovery

	if !limitKnown {
		return resourcePlan{opts: planned}
	}

	budget := socketBudgetForLimit(softLimit)
	effectiveScan := min(requestedScan, max(1, budget))
	effectiveDiscovery := min(requestedDiscovery, max(1, budget/discoverySocketEstimate()))

	planned.Concurrency = effectiveScan
	planned.DiscoveryConcurrency = effectiveDiscovery

	return resourcePlan{
		opts:         planned,
		socketBudget: budget,
		warnings: resourceWarnings(
			softLimit,
			budget,
			requestedScan,
			requestedDiscovery,
			effectiveScan,
			effectiveDiscovery,
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
	return scanConcurrency + discoveryConcurrency*discoverySocketEstimate()
}

func discoverySocketEstimate() int {
	return len(tcpProbePorts) + 1
}

func resourceWarnings(
	softLimit uint64,
	budget int,
	requestedScan int,
	requestedDiscovery int,
	effectiveScan int,
	effectiveDiscovery int,
) []string {
	requestedDemand := estimatedSocketDemand(requestedScan, requestedDiscovery)
	clamped := requestedScan != effectiveScan || requestedDiscovery != effectiveDiscovery

	if !clamped && requestedDemand <= budget {
		return nil
	}

	if clamped {
		return []string{fmt.Sprintf(
			"Open-file soft limit %d leaves a shared socket budget of %d. Using scan concurrency %d/%d and discovery concurrency %d/%d; live socket opens are additionally queued at runtime to avoid EMFILE.",
			softLimit,
			budget,
			effectiveScan,
			requestedScan,
			effectiveDiscovery,
			requestedDiscovery,
		)}
	}

	return []string{fmt.Sprintf(
		"Open-file soft limit %d leaves a shared socket budget of %d. Requested scan=%d and discovery=%d can demand about %d sockets, so live socket opens will be queued at runtime to avoid EMFILE.",
		softLimit,
		budget,
		effectiveScan,
		effectiveDiscovery,
		requestedDemand,
	)}
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
