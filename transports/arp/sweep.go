// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package arp

import (
	"context"
	"fmt"
	"iter"
	"net"
	"strings"
	"sync"
	"time"
)

type Logger func(format string, args ...any)

type sender interface {
	Send(targetIP net.IP) error
	Close() error
}

type listener interface {
	Listen(ctx context.Context, inject func(net.IP, net.HardwareAddr), logf Logger)
}

func StartActiveSweep(
	ctx context.Context,
	target string,
	targets iter.Seq[string],
	cache *Cache,
	isLocalIP func(string) bool,
	logf Logger,
) error {
	if !activeSupported() || targets == nil {
		return fmt.Errorf("active ARP sweep is not supported on this platform")
	}

	iface, srcIP, err := SelectInterface(target)
	if err != nil {
		return fmt.Errorf("active sweep skipped: %w", err)
	}

	s, err := newSender(iface, srcIP)
	if err != nil {
		return fmt.Errorf("active sweep init failed: %w", err)
	}

	var closeOnce sync.Once
	closeSender := func() {
		closeOnce.Do(func() {
			if err := s.Close(); err != nil {
				log(logf, "active sweep close error: %v", err)
			}
		})
	}

	if l, ok := s.(listener); ok && cache != nil {
		go func() {
			defer closeSender()
			l.Listen(ctx, func(ip net.IP, mac net.HardwareAddr) {
				if ip == nil || mac == nil {
					return
				}
				cache.Inject(ip.String(), mac.String())
			}, logf)
		}()
	}

	go func() {
		defer func() {
			if _, ok := s.(listener); !ok || cache == nil {
				closeSender()
			}
		}()

		for ipStr := range targets {
			if ctx.Err() != nil {
				return
			}
			if isLocalIP != nil && isLocalIP(ipStr) {
				continue
			}

			ip := net.ParseIP(ipStr).To4()
			if ip == nil {
				continue
			}
			if err := s.Send(ip); err != nil {
				log(logf, "active sweep send %s: %v", ipStr, err)
				continue
			}

			time.Sleep(2 * time.Millisecond)
		}
	}()

	return nil
}

func SelectInterface(target string) (*net.Interface, net.IP, error) {
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

func log(logf Logger, format string, args ...any) {
	if logf != nil {
		logf(format, args...)
	}
}
