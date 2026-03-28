package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type arpSender interface {
	Send(targetIP net.IP) error
	Close() error
}

type arpListener interface {
	Listen(ctx context.Context, inject func(net.IP, net.HardwareAddr))
}

func startActiveARPSweep(ctx context.Context, target string, arpCache *ARPCache) {
	if !activeARPSupported() {
		return
	}

	iface, srcIP, err := selectARPInterface(target)
	if err != nil {
		debugLog("arp", "active sweep skipped: %v", err)
		return
	}

	sender, err := newARPSender(iface, srcIP)
	if err != nil {
		debugLog("arp", "active sweep init failed: %v", err)
		return
	}

	var closeOnce sync.Once
	closeSender := func() {
		closeOnce.Do(func() {
			if err := sender.Close(); err != nil {
				debugLog("arp", "active sweep close error: %v", err)
			}
		})
	}

	if listener, ok := sender.(arpListener); ok && arpCache != nil {
		go func() {
			defer closeSender()
			listener.Listen(ctx, func(ip net.IP, mac net.HardwareAddr) {
				if ip == nil || mac == nil {
					return
				}
				arpCache.Inject(ip.String(), mac.String())
			})
		}()
	}

	go func() {
		defer func() {
			if _, ok := sender.(arpListener); !ok || arpCache == nil {
				closeSender()
			}
		}()

		targets, err := expandTargets(target)
		if err != nil {
			debugLog("arp", "active sweep expand error: %v", err)
			return
		}

		sent := 0
		for ipStr := range targets.seq {
			if ctx.Err() != nil {
				return
			}
			if isLocalIP(ipStr) {
				continue
			}
			ip := net.ParseIP(ipStr).To4()
			if ip == nil {
				continue
			}
			if err := sender.Send(ip); err != nil {
				debugLog("arp", "active sweep send %s: %v", ipStr, err)
				continue
			}
			sent++

			time.Sleep(2 * time.Millisecond)
		}
	}()
}

func selectARPInterface(target string) (*net.Interface, net.IP, error) {
	targetIP, targetNet, err := parseTargetForInterface(target)
	if err != nil {
		return nil, nil, err
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

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
			if ip4 == nil {
				continue
			}
			if targetNet != nil && targetNet.Contains(ip4) {
				return &iface, ip4, nil
			}
			if targetIP != nil && ipNet.Contains(targetIP) {
				return &iface, ip4, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("no active interface found for target %q", target)
}

func parseTargetForInterface(target string) (net.IP, *net.IPNet, error) {
	if strings.Contains(target, "-") {
		parts := strings.SplitN(target, "-", 2)
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid range %q", target)
		}
		ip := net.ParseIP(strings.TrimSpace(parts[0])).To4()
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid range start %q", parts[0])
		}
		return ip, nil, nil
	}

	if ip := net.ParseIP(target); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, nil, fmt.Errorf("invalid target %q: IPv6 is not supported", target)
		}
		return ip4, nil, nil
	}

	ip, network, err := net.ParseCIDR(target)
	if err != nil {
		return nil, nil, err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, nil, fmt.Errorf("invalid target %q: IPv6 is not supported", target)
	}
	return ip4, network, nil
}
