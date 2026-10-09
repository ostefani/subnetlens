package discovery

import (
	"context"
	"iter"
	"sync"
	"time"

	"github.com/ostefani/subnetlens/internal/debuglog"
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
	
	arptransport "github.com/ostefani/subnetlens/transports/arp"
	tcptransport "github.com/ostefani/subnetlens/transports/tcp"
)

// ICMPProber is the liveness capability discovery needs from the scanner.
type ICMPProber interface {
	Probe(ctx context.Context, ip string, timeout time.Duration) (bool, time.Duration, error)
}

// ICMPWarmer is the capability PreheatSubnet needs.
type ICMPWarmer interface {
	Warm(ip string) error
}

// HostnameResolver resolves a name for ip (cache, mDNS, NBNS, PTR...). The
// scanner owns the strategy and the cache; discovery only consumes results.
type HostnameResolver func(ctx context.Context, ip string, limiter contracts.SocketLimiter) contracts.NameResolution

func probeHostSmart(
	ctx context.Context,
	ip string,
	opts models.ScanOptions,
	resolve HostnameResolver,
	icmpScanner ICMPProber,
	arpCache *arptransport.Cache,
	socketLimiter contracts.SocketLimiter,
) []contracts.HostObservation {
	observations := make([]contracts.HostObservation, 0, 3)
	if arpCache != nil {
		if mac, observedAt, ok := arpCache.LookupRecent(ip); ok {
			observations = append(observations, contracts.HostObservation{
				IP:         ip,
				MAC:        mac,
				Alive:      true,
				Weak:       true,
				Source:     models.HostSourceARP,
				ObservedAt: observedAt,
			})
		}
	}

	resCh := make(chan contracts.NameResolution, 1)
	go func() {
		if resolve == nil {
			resCh <- contracts.NameResolution{}
			return
		}
		resCh <- resolve(ctx, ip, socketLimiter)
	}()

	alive, latency, seenBy := livenessProbe(ctx, ip, opts, icmpScanner, socketLimiter)
	res := <-resCh

	if res.Name != "" && res.Name != ip {
		observations = append(observations, contracts.HostObservation{
			IP:         ip,
			Name:       res.Name,
			Alive:      res.ProvesLiveness,
			Weak:       !res.ProvesLiveness,
			Source:     res.Source,
			ObservedAt: res.ObservedAt,
			ExpiresAt:  res.ExpiresAt,
		})
	}

	if alive {
		observations = append(observations, contracts.HostObservation{
			IP:      ip,
			Alive:   true,
			Weak:    false,
			Latency: latency,
			Source:  seenBy,
		})
	}

	if len(observations) == 0 {
		return nil
	}

	return observations
}

func livenessProbe(
	ctx context.Context,
	ip string,
	opts models.ScanOptions,
	icmpScanner ICMPProber,
	limiter contracts.SocketLimiter,
) (bool, time.Duration, models.HostSource) {
	if icmpScanner != nil {
		for i := 0; i < 2; i++ {
			alive, latency, err := icmpScanner.Probe(ctx, ip, opts.Timeout)
			if err == nil && alive {
				return true, latency, models.HostSourceICMP
			}
		}
	}

	probe := tcptransport.ProbeOpenPort
	if opts.AllAlive {
		probe = tcptransport.ProbeAlive
	}

	alive, latency := probe(ctx, ip, opts.Timeout, limiter)
	if !alive {
		return false, 0, ""
	}

	return true, latency, models.HostSourceTCP
}

// PreheatSubnet warms ICMP state for every target before the sweep.
func PreheatSubnet(ctx context.Context, ips iter.Seq[string], total int, icmpScanner ICMPWarmer) {
	if icmpScanner == nil {
		debuglog.Printf("discovery", "preheat skipped: ICMP unavailable")
		return
	}

	const maxPreheatTargets = 4096
	if total > maxPreheatTargets {
		debuglog.Printf("discovery", "preheat skipped: %d targets exceeds %d cap", total, maxPreheatTargets)
		return
	}

	const workers = 200
	targets := make(chan string, workers)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targets {
				_ = icmpScanner.Warm(target)
			}
		}()
	}

	ips(func(target string) bool {
		select {
		case <-ctx.Done():
			return false
		case targets <- target:
			return true
		}
	})

	close(targets)
	wg.Wait()
}