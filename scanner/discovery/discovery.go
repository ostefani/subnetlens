// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package discovery

import (
	"context"
	"fmt"
	"iter"
	"sync"

	"github.com/ostefani/subnetlens/internal/debuglog"
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
	arptransport "github.com/ostefani/subnetlens/transports/arp"
	mdnstransport "github.com/ostefani/subnetlens/transports/mdns"
)

// TargetSpec is a lazily enumerated set of IPv4 targets.
type TargetSpec struct {
	seq      iter.Seq[string]
	total    int
	contains func(string) bool
}

var _ contracts.DiscoveryTargets = TargetSpec{}

func (t TargetSpec) All() iter.Seq[string] {
	if t.seq == nil {
		return func(func(string) bool) {}
	}
	return t.seq
}

func (t TargetSpec) Total() int { return t.total }

func (t TargetSpec) Contains(ip string) bool { return t.contains != nil && t.contains(ip) }

type LocalDiscoveryInfo struct {
	Hostname    string
	Interface   string
	IP          string
	MAC         string
	InSubnet    bool
	InScanRange bool
}

func DiscoverHosts(
	ctx context.Context,
	opts models.ScanOptions,
	progress func(done, total int),
	resolve HostnameResolver,
	icmpScanner ICMPProber,
	arpCache *arptransport.Cache,
	runtime contracts.DiscoveryRuntime,
) <-chan contracts.HostObservation {
	out := make(chan contracts.HostObservation, 256)

	go func() {
		defer close(out)

		targets := runtime.Targets()
		if targets.Total() == 0 {
			return
		}
		debuglog.Printf("discovery", "sweeping %d IPs in %s", targets.Total(), opts.Subnet)

		localInfo := localDiscoveryInfoForTarget(opts.Subnet, targets.Contains)
		for _, observation := range localHostObservations(localInfo) {
			if !sendHostObservation(ctx, out, observation) {
				return
			}
		}

		go func() {
			if err := mdnstransport.TriggerServiceDiscovery(ctx); err != nil && ctx.Err() == nil {
				runtime.ReportIssue(models.ScanIssue{
					Level:   models.ScanIssueLevelWarning,
					Source:  "mdns",
					Message: fmt.Sprintf("active mDNS discovery trigger unavailable: %v", err),
				})
			}
		}()

		var waitGroup sync.WaitGroup
		done := 0
		var mu sync.Mutex
		scanDone := make(chan struct{})
		var arpWG sync.WaitGroup

		if arpCache != nil {
			arpWG.Add(1)
			go func() {
				defer arpWG.Done()
				arptransport.Watch(ctx, arpCache, targets.Contains, func(ip, mac string) bool {
					return sendHostObservation(ctx, out, contracts.HostObservation{
						IP:     ip,
						MAC:    mac,
						Alive:  true,
						Weak:   true,
						Source: models.HostSourceARP,
					})
				}, scanDone)
			}()
		}

	Loop:
		for ip := range targets.All() {
			select {
			case <-ctx.Done():
				debuglog.Printf("discovery", "context cancelled after %d IPs — draining", done)
				break Loop
			default:
			}

			if err := runtime.AcquireDiscoverySlot(ctx); err != nil {
				break Loop
			}
			waitGroup.Add(1)
			go func(ip string) {
				defer waitGroup.Done()
				defer runtime.ReleaseDiscoverySlot()

				observations := probeHostSmart(ctx, ip, opts, resolve, icmpScanner, arpCache, runtime.SocketLimiter())

				mu.Lock()
				done++
				if progress != nil {
					progress(done, targets.Total())
				}
				mu.Unlock()

				for _, observation := range observations {
					if !sendHostObservation(ctx, out, observation) {
						return
					}
				}
			}(ip)
		}

		waitGroup.Wait()

		close(scanDone)
		arpWG.Wait()

		debuglog.Printf("discovery", "sweep complete")
	}()

	return out
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
