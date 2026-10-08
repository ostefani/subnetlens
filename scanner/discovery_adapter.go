// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"context"
	"iter"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
	"github.com/ostefani/subnetlens/scanner/discovery"
)

// Compatibility aliases: the implementations live in scanner/discovery.
type (
	targetSpec                 = discovery.TargetSpec
	LocalDiscoveryInfo         = discovery.LocalDiscoveryInfo
	LargeScanConfirmationError = discovery.LargeScanConfirmationError
)

func expandTargets(target string) (targetSpec, error) {
	return discovery.ExpandTargets(target)
}

func LocalDiscoveryInfoForTarget(target string) LocalDiscoveryInfo {
	return discovery.LocalDiscoveryInfoForTarget(target)
}

func CheckTargetConsent(target string, opts models.ScanOptions) (uint64, error) {
	return discovery.CheckTargetConsent(target, opts)
}

func LargeScanWarning(target string, total uint64) string {
	return discovery.LargeScanWarning(target, total)
}

// DiscoverHosts binds scanner-owned dependencies (name cache + resolution
// strategy) into discovery's narrower interface. Its signature matches
// hostDiscovererFunc, so existing wiring keeps working.
func DiscoverHosts(
	ctx context.Context,
	opts models.ScanOptions,
	progress func(done, total int),
	cache nameCache,
	icmpScanner icmpProber,
	arpCache *ARPCache,
	runtime contracts.DiscoveryRuntime,
) <-chan contracts.HostObservation {
	resolve := func(ctx context.Context, ip string, limiter contracts.SocketLimiter) contracts.NameResolution {
		return toNameResolution(resolveHostname(ctx, ip, cache, limiter))
	}
	// A nil interface value converts to a nil interface, so "no ICMP" survives.
	return discovery.DiscoverHosts(ctx, opts, progress, resolve, icmpScanner, arpCache, runtime)
}

func preheatSubnet(ctx context.Context, ips iter.Seq[string], total int, icmpScanner icmpProber) {
	discovery.PreheatSubnet(ctx, ips, total, icmpScanner)
}

func toNameResolution(r resolveResult) contracts.NameResolution {
	return contracts.NameResolution{
		Name:           r.name,
		Latency:        r.latency,
		Source:         r.source,
		ProvesLiveness: r.provesLiveness,
		ObservedAt:     r.observedAt,
		ExpiresAt:      r.expiresAt,
	}
}

func sendHostObservation(ctx context.Context, updates chan<- contracts.HostObservation, update contracts.HostObservation) bool {
	if update.IP == "" {
		return true
	}

	select {
	case <-ctx.Done():
		return false
	case updates <- update:
		return true
	}
}