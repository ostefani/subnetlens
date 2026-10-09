// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package discovery

import (
	"context"
	"fmt"
	"iter"
	"sync"
	"sync/atomic"

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

// DiscoverHosts sweeps the targets provided by runtime and streams host
// observations on the returned channel, which is closed when the sweep
// finishes or ctx is cancelled.
//
// progress, if non-nil, is called after every probed address. It may be
// called concurrently from multiple goroutines and values may arrive out of
// order, so it must be safe for concurrent use and must not block.
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
		total := targets.Total()
		if total == 0 {
			return
		}
		debuglog.Printf("discovery", "sweeping %d IPs in %s", total, opts.Subnet)

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

		var (
			workers sync.WaitGroup
			done    atomic.Int64 // probes completed; safe to read from any goroutine
			arpWG   sync.WaitGroup
		)
		scanDone := make(chan struct{})

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
				debuglog.Printf("discovery", "context cancelled after %d IPs — draining", done.Load())
				break Loop
			default:
			}

			if err := runtime.AcquireDiscoverySlot(ctx); err != nil {
				debuglog.Printf("discovery", "slot acquisition stopped after %d IPs: %v", done.Load(), err)
				break Loop
			}

			workers.Add(1)
			go func(ip string) {
				defer workers.Done()
				defer runtime.ReleaseDiscoverySlot()

				observations := probeHostSmart(ctx, ip, opts, resolve, icmpScanner, arpCache, runtime.SocketLimiter())

				n := done.Add(1)
				if progress != nil {
					progress(int(n), total)
				}

				for _, observation := range observations {
					if !sendHostObservation(ctx, out, observation) {
						return
					}
				}
			}(ip)
		}

		workers.Wait() // in-flight probes finish or observe ctx

		close(scanDone) // stop the ARP watcher only after the last probe
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
