package scanner

import (
	"context"
	"fmt"
	"iter"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ostefani/subnetlens/models"
	arptransport "github.com/ostefani/subnetlens/transports/arp"
	mdnstransport "github.com/ostefani/subnetlens/transports/mdns"
)

type targetSpec struct {
	seq      iter.Seq[string]
	total    int
	contains func(string) bool
}

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
	cache nameCache,
	icmpScanner icmpProber,
	arpCache *ARPCache,
	socketLimiter *socketLimiter,
	issues issueReporter,
) <-chan HostEvent {
	out := make(chan HostEvent, 256)
	registry := &HostRegistry{updates: make(chan hostUpdate, 512)}

	go registry.run(ctx, out)

	go func() {
		defer close(registry.updates)

		targets, err := expandTargets(opts.Subnet)
		if err != nil {
			if issues != nil {
				issues.Report(warningIssue("discovery", "target expansion failed: %v", err))
			}
			return
		}

		debugLog("discovery", "sweeping %d IPs in %s", targets.total, opts.Subnet)

		localInfo := localDiscoveryInfoForTarget(opts.Subnet, targets.contains)
		for _, update := range localHostUpdates(localInfo) {
			if !sendHostUpdate(ctx, registry.updates, update) {
				return
			}
		}

		go func() {
			if err := mdnstransport.TriggerServiceDiscovery(ctx); err != nil && ctx.Err() == nil && issues != nil {
				issues.Report(warningIssue("mdns", "active mDNS discovery trigger unavailable: %v", err))
			}
		}()

		sem := make(chan struct{}, opts.DiscoveryConcurrencyLimit())
		var waitGroup sync.WaitGroup
		done := 0
		var mu sync.Mutex
		scanDone := make(chan struct{})
		var arpWG sync.WaitGroup

		if arpCache != nil && targets.contains != nil {
			arpWG.Add(1)
			go func() {
				defer arpWG.Done()
				arptransport.Watch(ctx, arpCache, targets.contains, func(ip, mac string) bool {
					return sendHostUpdate(ctx, registry.updates, hostUpdate{
						ip:     ip,
						mac:    mac,
						alive:  true,
						seenBy: models.HostSourceARP,
					})
				}, scanDone)
			}()
		}

	Loop:
		for ip := range targets.seq {
			select {
			case <-ctx.Done():
				debugLog("discovery", "context cancelled after %d IPs — draining", done)
				break Loop
			case sem <- struct{}{}:
			}

			waitGroup.Add(1)
			go func(ip string) {
				defer waitGroup.Done()
				defer func() { <-sem }()

				updates := probeHostSmart(ctx, ip, opts, cache, icmpScanner, arpCache, socketLimiter)

				mu.Lock()
				done++
				if progress != nil {
					progress(done, targets.total)
				}
				mu.Unlock()

				for _, update := range updates {
					if !sendHostUpdate(ctx, registry.updates, update) {
						return
					}
				}
			}(ip)
		}

		waitGroup.Wait()

		close(scanDone)
		arpWG.Wait()

		debugLog("discovery", "sweep complete")
	}()

	return out
}

func LocalDiscoveryInfoForTarget(target string) LocalDiscoveryInfo {
	var contains func(string) bool
	targets, err := expandTargets(target)
	if err == nil {
		contains = targets.contains
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

func localHostUpdates(info LocalDiscoveryInfo) []hostUpdate {
	if !info.InScanRange || info.IP == "" {
		return nil
	}

	return []hostUpdate{{
		ip:     info.IP,
		mac:    info.MAC,
		name:   info.Hostname,
		alive:  true,
		seenBy: models.HostSourceSelf,
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
	cache nameCache,
	icmpScanner icmpProber,
	arpCache *ARPCache,
	socketLimiter *socketLimiter,
) []hostUpdate {
	updates := make([]hostUpdate, 0, 3)
	if arpCache != nil {
		if mac, ok := arpCache.Lookup(ip); ok {
			updates = append(updates, hostUpdate{
				ip:     ip,
				mac:    mac,
				alive:  true,
				seenBy: models.HostSourceARP,
			})
		}
	}

	resCh := make(chan resolveResult, 1)
	go func() { resCh <- resolveHostname(ctx, ip, cache, socketLimiter) }()

	alive, latency, seenBy := livenessProbe(ctx, ip, opts, icmpScanner, socketLimiter)
	res := <-resCh

	if res.name != "" && res.name != ip {
		updates = append(updates, hostUpdate{
			ip:     ip,
			name:   res.name,
			alive:  res.provesLiveness,
			seenBy: res.source,
		})
	}

	if alive {
		updates = append(updates, hostUpdate{
			ip:      ip,
			alive:   true,
			latency: latency,
			seenBy:  seenBy,
		})
	}

	if len(updates) == 0 {
		return nil
	}

	return updates
}

func livenessProbe(
	ctx context.Context,
	ip string,
	opts models.ScanOptions,
	icmpScanner icmpProber,
	limiter *socketLimiter,
) (bool, time.Duration, models.HostSource) {
	if icmpScanner != nil {
		for i := 0; i < 2; i++ {
			alive, latency, err := icmpScanner.Probe(ctx, ip, opts.Timeout)
			if err == nil && alive {
				return true, latency, models.HostSourceICMP
			}
		}
	}

	var tcp func(context.Context, string, time.Duration, *socketLimiter) (bool, time.Duration)
	if opts.AllAlive {
		tcp = tcpProbeAlive
	} else {
		tcp = tcpProbeOpenPort
	}

	alive, latency := tcp(ctx, ip, opts.Timeout, limiter)
	if !alive {
		return false, 0, ""
	}

	return true, latency, models.HostSourceTCP
}

func expandTargets(target string) (targetSpec, error) {
	if strings.Contains(target, "-") {
		return expandRangeSpec(target)
	}

	if ip := net.ParseIP(target); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return targetSpec{}, fmt.Errorf("invalid target %q: IPv6 is not supported", target)
		}
		return rangeSpec(ipToUint32(ip4), ipToUint32(ip4), false)
	}

	return expandCIDRSpec(target)
}

func expandCIDRSpec(target string) (targetSpec, error) {
	ip, network, err := net.ParseCIDR(target)
	if err != nil {
		return targetSpec{}, fmt.Errorf("invalid target %q: expected CIDR, IP, or range (e.g. 192.168.0.0-192.168.0.100): %w", target, err)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return targetSpec{}, fmt.Errorf("invalid target %q: IPv6 CIDR is not supported", target)
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return targetSpec{}, fmt.Errorf("invalid target %q: expected IPv4 CIDR", target)
	}

	hostCount := uint64(1) << uint(bits-ones)
	start := ipToUint32(ip4.Mask(network.Mask))
	end := start + uint32(hostCount-1)
	skipNetworkBroadcast := hostCount > 2

	return rangeSpec(start, end, skipNetworkBroadcast)
}

func preheatSubnet(ctx context.Context, ips iter.Seq[string], total int, icmpScanner icmpProber) {
	if icmpScanner == nil {
		debugLog("discovery", "preheat skipped: ICMP unavailable")
		return
	}

	const maxPreheatTargets = 4096
	if total > maxPreheatTargets {
		debugLog("discovery", "preheat skipped: %d targets exceeds %d cap", total, maxPreheatTargets)
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

func expandRangeSpec(target string) (targetSpec, error) {
	parts := strings.SplitN(target, "-", 2)
	if len(parts) != 2 {
		return targetSpec{}, fmt.Errorf("invalid range %q: expected format 192.168.0.0-192.168.0.100", target)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	endIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()

	if startIP == nil {
		return targetSpec{}, fmt.Errorf("invalid range start IP %q", parts[0])
	}
	if endIP == nil {
		return targetSpec{}, fmt.Errorf("invalid range end IP %q", parts[1])
	}

	start := ipToUint32(startIP)
	end := ipToUint32(endIP)
	if start > end {
		return targetSpec{}, fmt.Errorf("range start %q is after range end %q", parts[0], parts[1])
	}

	spec, err := rangeSpec(start, end, false)
	if err != nil {
		return targetSpec{}, err
	}
	debugLog("discovery", "range %s expanded to %d IPs", target, spec.total)
	return spec, nil
}

func rangeSpec(start, end uint32, skipEndpoints bool) (targetSpec, error) {
	if start > end {
		return targetSpec{}, fmt.Errorf("invalid range %d-%d", start, end)
	}

	total := int(uint64(end-start) + 1)
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

	return targetSpec{
		seq:      seq,
		total:    total,
		contains: contains,
	}, nil
}

func sendHostUpdate(ctx context.Context, updates chan<- hostUpdate, update hostUpdate) bool {
	if update.ip == "" {
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
