// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package discovery

import (
	"context"
	"fmt"
	"iter"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ostefani/subnetlens/internal/debuglog"
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
	arptransport "github.com/ostefani/subnetlens/transports/arp"
	mdnstransport "github.com/ostefani/subnetlens/transports/mdns"
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

// TargetSpec is a lazily enumerated set of IPv4 targets. It satisfies
// contracts.DiscoveryTargets.
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

func LocalDiscoveryInfoForTarget(target string) LocalDiscoveryInfo {
	var contains func(string) bool
	targets, err := expandTargets(target)
	if err == nil {
		contains = targets.Contains
	}
	return localDiscoveryInfoForTarget(target, contains)
}

func localDiscoveryInfoForTarget(target string, contains func(string) bool) LocalDiscoveryInfo {
	info := LocalDiscoveryInfo{
		Hostname: localHostname(),
	}

	if iface, srcIP, err := arptransport.SelectInterface(target); err == nil {
		info.InSubnet = true
		populateLocalDiscoveryInfo(&info, iface, srcIP, contains)
		return info
	}

	iface, srcIP := fallbackDiscoveryInterface()
	populateLocalDiscoveryInfo(&info, iface, srcIP, contains)
	return info
}

func localHostObservations(info LocalDiscoveryInfo) []contracts.HostObservation {
	if !info.InScanRange || info.IP == "" {
		return nil
	}

	return []contracts.HostObservation{{
		IP:     info.IP,
		MAC:    info.MAC,
		Name:   info.Hostname,
		Alive:  true,
		Weak:   false,
		Source: models.HostSourceSelf,
	}}
}

func localHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hostname
}

func populateLocalDiscoveryInfo(info *LocalDiscoveryInfo, iface *net.Interface, ip net.IP, contains func(string) bool) {
	if info == nil || iface == nil || ip == nil {
		return
	}

	info.Interface = iface.Name
	info.IP = ip.String()
	info.MAC = arptransport.NormalizeMAC(iface.HardwareAddr.String())
	if contains != nil {
		info.InScanRange = contains(info.IP)
	}
}

func fallbackDiscoveryInterface() (*net.Interface, net.IP) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}

	bestScore := -1
	var bestIface *net.Interface
	var bestIP net.IP

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}

			score := 0
			if ip4.IsPrivate() {
				score += 2
			}
			if !ip4.IsLinkLocalUnicast() {
				score++
			}
			if iface.Flags&net.FlagMulticast != 0 {
				score++
			}

			if score <= bestScore {
				continue
			}

			candidate := iface
			bestIface = &candidate
			bestIP = append(net.IP(nil), ip4...)
			bestScore = score
		}
	}

	return bestIface, bestIP
}

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

// ExpandTargets resolves a CIDR, a single IPv4 address, or an "a-b" range.
func ExpandTargets(target string) (TargetSpec, error) {
	return expandTargets(target)
}

func expandTargets(target string) (TargetSpec, error) {
	if strings.Contains(target, "-") {
		return expandRangeSpec(target)
	}

	if ip := net.ParseIP(target); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return TargetSpec{}, fmt.Errorf("invalid target %q: IPv6 is not supported", target)
		}
		return rangeSpec(ipToUint32(ip4), ipToUint32(ip4), false)
	}

	return expandCIDRSpec(target)
}

func expandCIDRSpec(target string) (TargetSpec, error) {
	ip, network, err := net.ParseCIDR(target)
	if err != nil {
		return TargetSpec{}, fmt.Errorf("invalid target %q: expected CIDR, IP, or range (e.g. 192.168.0.0-192.168.0.100): %w", target, err)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return TargetSpec{}, fmt.Errorf("invalid target %q: IPv6 CIDR is not supported", target)
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return TargetSpec{}, fmt.Errorf("invalid target %q: expected IPv4 CIDR", target)
	}

	hostCount := uint64(1) << uint(bits-ones)
	start := ipToUint32(ip4.Mask(network.Mask))
	end := start + uint32(hostCount-1)
	skipNetworkBroadcast := hostCount > 2

	return rangeSpec(start, end, skipNetworkBroadcast)
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

func expandRangeSpec(target string) (TargetSpec, error) {
	parts := strings.SplitN(target, "-", 2)
	if len(parts) != 2 {
		return TargetSpec{}, fmt.Errorf("invalid range %q: expected format 192.168.0.0-192.168.0.100", target)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	endIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()

	if startIP == nil {
		return TargetSpec{}, fmt.Errorf("invalid range start IP %q", parts[0])
	}
	if endIP == nil {
		return TargetSpec{}, fmt.Errorf("invalid range end IP %q", parts[1])
	}

	start := ipToUint32(startIP)
	end := ipToUint32(endIP)
	if start > end {
		return TargetSpec{}, fmt.Errorf("range start %q is after range end %q", parts[0], parts[1])
	}

	spec, err := rangeSpec(start, end, false)
	if err != nil {
		return TargetSpec{}, err
	}
	debuglog.Printf("discovery", "range %s expanded to %d IPs", target, spec.total)
	return spec, nil
}

func rangeSpec(start, end uint32, skipEndpoints bool) (TargetSpec, error) {
	if start > end {
		return TargetSpec{}, fmt.Errorf("invalid range %d-%d", start, end)
	}

	count := uint64(end-start) + 1
	maxAddresses := uint64(math.MaxInt)
	if count > maxAddresses {
		return TargetSpec{}, fmt.Errorf("target expands to %d addresses, exceeding the %d address enumeration limit", count, maxAddresses)
	}

	total := int(count)
	if skipEndpoints && total > 2 {
		start++
		end--
		total -= 2
	}

	seq := func(yield func(string) bool) {
		for ip := start; ; ip++ {
			if !yield(uint32ToIP(ip).String()) {
				return
			}
			if ip == end {
				break
			}
		}
	}

	contains := func(ip string) bool {
		ip4 := net.ParseIP(ip).To4()
		if ip4 == nil {
			return false
		}
		val := ipToUint32(ip4)
		return val >= start && val <= end
	}

	return TargetSpec{
		seq:      seq,
		total:    total,
		contains: contains,
	}, nil
}

// LargeScanConfirmationError signals a target large enough to require
// explicit user consent. It is not a syntax error: setting AllowLargeScan
// on the scan options clears it. Frontends add their own opt-in guidance
// (e.g. the CLI names its flag); this message stays transport-agnostic.
type LargeScanConfirmationError struct {
	Target    string
	Total     uint64
	Threshold uint64
}

func (e *LargeScanConfirmationError) Error() string {
	return fmt.Sprintf("target %q expands to %d addresses (over the %d address confirmation threshold): large-scan consent required (AllowLargeScan)", e.Target, e.Total, e.Threshold)
}

// CheckTargetConsent expands target and reports its address count. When the
// count exceeds contracts.LargeScanThreshold without consent in opts, it
// returns a *LargeScanConfirmationError. Syntax errors pass through unchanged
// so callers keep their existing invalid-target behavior.
func CheckTargetConsent(target string, opts models.ScanOptions) (uint64, error) {
	spec, err := expandTargets(target)
	if err != nil {
		return 0, err
	}
	total := uint64(spec.total)
	if contracts.RequiresLargeScanConsent(total, opts) {
		return total, &LargeScanConfirmationError{Target: target, Total: total, Threshold: contracts.LargeScanThreshold}
	}
	return total, nil
}

// LargeScanWarning describes a consented-to large scan for the warnings
// channel (plain output and TUI). It returns "" for ordinary-sized targets.
func LargeScanWarning(target string, total uint64) string {
	if total <= contracts.LargeScanThreshold {
		return ""
	}
	return fmt.Sprintf("target %q expands to %d addresses: scan will take a while and generate substantial traffic", target, total)
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

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}