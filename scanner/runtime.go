// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package scanner

import (
	"context"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
	"github.com/ostefani/subnetlens/scanner/discovery"
)

type ScanRuntime struct {
	socketLimiter *socketLimiter
	scanSem       chan struct{}
	issues        issueReporter
}

type DiscoveryRuntime struct {
	targets       discovery.TargetSpec
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

func newDiscoveryRuntime(targets discovery.TargetSpec, socketLimiter *socketLimiter, discoverySem chan struct{}, issues issueReporter) *DiscoveryRuntime {
	return &DiscoveryRuntime{
		targets:       targets,
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

func (r *DiscoveryRuntime) Targets() contracts.DiscoveryTargets {
	if r == nil {
		return discovery.TargetSpec{}
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