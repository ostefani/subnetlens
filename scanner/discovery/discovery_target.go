package discovery

import (
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/ostefani/subnetlens/internal/debuglog"
)

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

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}