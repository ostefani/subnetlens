package scanner

import (
	"context"
	"fmt"
	"iter"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ostefani/subnetlens/models"
)

type arpPending struct {
	mu    sync.Mutex
	hosts map[string]*models.Host
}

type targetSpec struct {
	seq      iter.Seq[string]
	total    int
	contains func(string) bool
}

func DiscoverHosts(
	ctx context.Context,
	opts models.ScanOptions,
	progress func(done, total int),
	cache *mdnsCache,
	icmpScanner *ICMPScanner,
	arpCache *ARPCache,
) <-chan *models.Host {
	out := make(chan *models.Host, 256)

	go func() {
		defer close(out)

		targets, err := expandTargets(opts.Subnet)
		if err != nil {
			debugLog("discovery", "expandTargets error: %v", err)
			return
		}

		debugLog("discovery", "sweeping %d IPs in %s", targets.total, opts.Subnet)

		go triggerMulticastDiscovery(ctx)

		sem := make(chan struct{}, opts.Concurrency)
		var waitGroup sync.WaitGroup
		done := 0
		var mu sync.Mutex
		var seen sync.Map
		scanDone := make(chan struct{})
		var arpWG sync.WaitGroup
		pending := newARPPending()

		emit := func(h *models.Host) {
			if h == nil || ctx.Err() != nil {
				return
			}
			if h.Hostname == "" {
				h.Hostname = h.IP
			}
			if _, loaded := seen.LoadOrStore(h.IP, struct{}{}); loaded {
				return
			}
			out <- h
		}

		if arpCache != nil && targets.contains != nil {
			arpWG.Add(1)
			go func() {
				defer arpWG.Done()
				watchARP(ctx, arpCache, targets.contains, &seen, pending, scanDone)
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

				host := probeHostSmart(ctx, ip, opts, cache, icmpScanner, arpCache)

				mu.Lock()
				done++
				if progress != nil {
					progress(done, targets.total)
				}
				mu.Unlock()

				emit(host)
			}(ip)
		}

		waitGroup.Wait()

		close(scanDone)
		arpWG.Wait()
		pendingHosts := pending.drain()

		for _, h := range pendingHosts {
			emit(h)
		}

		debugLog("discovery", "sweep complete")
	}()

	return out
}

func triggerMulticastDiscovery(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
    mcastAddr, addrError := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if addrError != nil {
		debugLog("mdns", "failed to resolve multicast address: %v", addrError)
		return
	}
    
    query := []byte{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x5f, 0x73, 0x65,
        0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x07, 0x5f,
        0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64, 0x04, 0x5f,
        0x75, 0x64, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61,
        0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01,
    }

	ifaces, _ := net.Interfaces()
    for _, iface := range ifaces {
        if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
            continue
        }

        addrs, _ := iface.Addrs()
        for _, addr := range addrs {
            ipnet, ok := addr.(*net.IPNet)
            if !ok || ipnet.IP.To4() == nil || ipnet.IP.IsLoopback() {
                continue
            }

            localAddr := &net.UDPAddr{IP: ipnet.IP.To4(), Port: 0}
            conn, err := net.DialUDP("udp4", localAddr, mcastAddr)
            if err != nil {
                continue
            }

			if ctx.Err() != nil {
				conn.Close()
				return
			}

            conn.Write(query)
            conn.Close()
            break
        }
    }
}

func probeHostSmart(
	ctx context.Context,
	ip string,
	opts models.ScanOptions,
	cache *mdnsCache,
	icmpScanner *ICMPScanner,
	arpCache *ARPCache,
) *models.Host {
	host := &models.Host{IP: ip}

	if arpCache != nil {
		if mac, ok := arpCache.Lookup(ip); ok {
			host.MAC = mac
			host.Vendor = VendorFromMAC(mac)
			host.SetAlive(true)
			host.MarkSeen("arp")
		}
	}

	resCh := make(chan resolveResult, 1)
	go func() { resCh <- resolveHostname(ctx, ip, cache) }()

	alive, latency := livenessProbe(ctx, ip, opts, icmpScanner)
	res := <-resCh

	if res.name != "" && res.name != ip {
		host.Hostname = res.name
		host.MarkSeen("mdns")
		if res.latency > 0 {
			host.SetAlive(true)
		}
	}

	if alive {
		host.SetAlive(true)
		host.Latency = latency
		host.MarkSeen("probe")
	}

	if !host.IsAlive() && host.MAC == "" && host.Hostname == "" {
		return nil
	}

	if host.Hostname == "" {
		host.Hostname = ip
	}

	host.MarkSeen("mixed")
	return host
}

func livenessProbe(ctx context.Context, ip string, opts models.ScanOptions, icmpScanner *ICMPScanner) (bool, time.Duration) {
	if icmpScanner != nil {
		for i := 0; i < 2; i++ {
			alive, latency, err := icmpScanner.Probe(ctx, ip, opts.Timeout)
			if err == nil && alive {
				return true, latency
			}
		}
	}

	var tcp func(context.Context, string, time.Duration) (bool, time.Duration)
	if opts.AllAlive {
		tcp = tcpProbeAlive
	} else {
		tcp = tcpProbeOpenPort
	}

	return tcp(ctx, ip, opts.Timeout)
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

func preheatSubnet(ctx context.Context, ips iter.Seq[string], total int, icmpScanner *ICMPScanner) {
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

func newARPPending() *arpPending {
	return &arpPending{
		hosts: make(map[string]*models.Host),
	}
}

func (p *arpPending) add(ip, mac string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.hosts[ip]; ok {
		if existing.MAC == "" && mac != "" {
			existing.MAC = mac
			existing.Vendor = VendorFromMAC(mac)
		}
		return false
	}

	h := &models.Host{IP: ip, MAC: mac, Vendor: VendorFromMAC(mac)}
	h.SetAlive(true)
	h.MarkSeen("arp")
	p.hosts[ip] = h
	return true
}

func (p *arpPending) drain() []*models.Host {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.hosts) == 0 {
		return nil
	}

	hosts := make([]*models.Host, 0, len(p.hosts))
	for _, h := range p.hosts {
		hosts = append(hosts, h)
	}
	p.hosts = make(map[string]*models.Host)
	return hosts
}

func watchARP(
	ctx context.Context,
	arpCache *ARPCache,
	contains func(string) bool,
	seen *sync.Map,
	pending *arpPending,
	scanDone <-chan struct{},
) {
	if arpCache == nil || contains == nil || pending == nil {
		return
	}

	const (
		settleInterval = 200 * time.Millisecond
		settleQuiet    = 1500 * time.Millisecond
		settleMax      = 5 * time.Second
	)

	ticker := time.NewTicker(settleInterval)
	defer ticker.Stop()

	var doneAt time.Time
	var lastNew time.Time
	done := false
	added := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-scanDone:
			if !done {
				done = true
				doneAt = time.Now()
			}
		case <-ticker.C:
		}

		table := arpCache.Refresh()
		for ip, mac := range table {
			if !contains(ip) {
				continue
			}
			if _, ok := seen.Load(ip); ok {
				continue
			}
			if pending.add(ip, mac) {
				lastNew = time.Now()
				added++
			}
		}

		if done {
			if time.Since(doneAt) >= settleMax {
				return
			}
			if !lastNew.IsZero() && time.Since(lastNew) >= settleQuiet {
				return
			}
			if lastNew.IsZero() && time.Since(doneAt) >= settleQuiet {
				return
			}
		}
	}
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}
