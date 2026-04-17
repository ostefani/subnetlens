// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package scanner

import (
	"context"
	"iter"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

type ScanRuntime struct {
	socketLimiter *socketLimiter
	scanSem       chan struct{}
	issues        issueReporter
}

type discoveryTargets struct {
	seq      iter.Seq[string]
	total    int
	contains func(string) bool
}

type DiscoveryRuntime struct {
	targets       discoveryTargets
	socketLimiter *socketLimiter
	discoverySem  chan struct{}
	issues        issueReporter
}

func newScanRuntime(socketLimiter *socketLimiter, scanSem chan struct{}, issues issueReporter) *ScanRuntime {
	return &ScanRuntime{
		socketLimiter: socketLimiter,
		scanSem:       scanSem,
		issues:        issues,
	}
}

func newDiscoveryRuntime(targets targetSpec, socketLimiter *socketLimiter, discoverySem chan struct{}, issues issueReporter) *DiscoveryRuntime {
	return &DiscoveryRuntime{
		targets: discoveryTargets{
			seq:      targets.seq,
			total:    targets.total,
			contains: targets.contains,
		},
		socketLimiter: socketLimiter,
		discoverySem:  discoverySem,
		issues:        issues,
	}
}

func (r *ScanRuntime) SocketLimiter() contracts.SocketLimiter {
	return r.socketLimiter
}

func (r *ScanRuntime) AcquireScanSlot(ctx context.Context) error {
	if r == nil || r.scanSem == nil {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case r.scanSem <- struct{}{}:
		return nil
	}
}

func (r *ScanRuntime) ReleaseScanSlot() {
	if r == nil || r.scanSem == nil {
		return
	}
	<-r.scanSem
}

func (r *ScanRuntime) ReportIssue(issue models.ScanIssue) {
	if r == nil || r.issues == nil {
		return
	}
	r.issues.Report(issue)
}

func (t discoveryTargets) All() iter.Seq[string] {
	if t.seq == nil {
		return func(func(string) bool) {}
	}
	return t.seq
}

func (t discoveryTargets) Total() int {
	return t.total
}

func (t discoveryTargets) Contains(ip string) bool {
	if t.contains == nil {
		return false
	}
	return t.contains(ip)
}

func (r *DiscoveryRuntime) Targets() contracts.DiscoveryTargets {
	if r == nil {
		return discoveryTargets{}
	}
	return r.targets
}

func (r *DiscoveryRuntime) SocketLimiter() contracts.SocketLimiter {
	if r == nil {
		return nil
	}
	return r.socketLimiter
}

func (r *DiscoveryRuntime) AcquireDiscoverySlot(ctx context.Context) error {
	if r == nil || r.discoverySem == nil {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case r.discoverySem <- struct{}{}:
		return nil
	}
}

func (r *DiscoveryRuntime) ReleaseDiscoverySlot() {
	if r == nil || r.discoverySem == nil {
		return
	}
	<-r.discoverySem
}

func (r *DiscoveryRuntime) ReportIssue(issue models.ScanIssue) {
	if r == nil || r.issues == nil {
		return
	}
	r.issues.Report(issue)
}
