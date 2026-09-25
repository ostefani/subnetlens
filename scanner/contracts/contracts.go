// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package contracts

import (
	"context"
	"iter"
	"time"

	"github.com/ostefani/subnetlens/models"
)

type SocketLimiter interface {
	Acquire(context.Context) error
	Release()
}

type Runtime interface {
	SocketLimiter() SocketLimiter
	AcquireScanSlot(context.Context) error
	ReleaseScanSlot()
	ReportIssue(models.ScanIssue)
}

type HostObservation struct {
	IP         string
	MAC        string
	Name       string
	Alive      bool
	Weak       bool
	Latency    time.Duration
	Source     models.HostSource
	Identity   models.HostIdentity
	ObservedAt time.Time
	ExpiresAt  time.Time
}

type DiscoveryTargets interface {
	All() iter.Seq[string]
	Total() int
	Contains(string) bool
}

// LargeScanThreshold is a UX-safety confirmation threshold: scans expanding
// past this many addresses require explicit consent via
// models.ScanOptions.AllowLargeScan. A /24 (254 usable hosts) passes
// silently; a /16 (65,534) does not.
//
// This is deliberately not an architectural maximum. Target enumeration
// streams through a lazy iterator and engine state scales with discovered
// hosts, not candidate addresses, so no resource-derived upper bound exists
// on 64-bit platforms: cost grows in wall time (roughly one worst-case
// per-IP probe batch per discovery-concurrency window), which is exactly
// what the consent flag asks the user to accept. The only hard ceiling is
// the platform int width for progress totals, enforced where ranges are
// built (a 32-bit build cannot enumerate past MaxInt32 addresses).
const LargeScanThreshold = 1024

// RequiresLargeScanConsent reports whether scanning total addresses needs
// explicit user consent that has not been given.
func RequiresLargeScanConsent(total uint64, opts models.ScanOptions) bool {
	return total > LargeScanThreshold && !opts.AllowLargeScan
}

type DiscoveryRuntime interface {
	Targets() DiscoveryTargets
	SocketLimiter() SocketLimiter
	AcquireDiscoverySlot(context.Context) error
	ReleaseDiscoverySlot()
	ReportIssue(models.ScanIssue)
}

type DiscoveryModule interface {
	Discover(context.Context, models.ScanOptions, DiscoveryRuntime) <-chan HostObservation
}

type HostScanner interface {
	ScanHost(context.Context, *models.Host, models.ScanOptions, Runtime)
}

type HostClassifier interface {
	ClassifyHost([]models.Port) (string, string)
}

type AdditionalSocketDemand struct {
	Fixed            int
	PerScanSlot      int
	PerDiscoverySlot int
}

type SocketDemandReporter interface {
	AdditionalSocketDemand(models.ScanOptions) AdditionalSocketDemand
}
