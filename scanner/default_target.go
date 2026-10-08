// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/ostefani/subnetlens/scanner/contracts"
	"github.com/ostefani/subnetlens/scanner/discovery"
)

// LocalTargetKeyword is an explicit alias for the zero-config scan target:
const LocalTargetKeyword = "local"

// outboundProbeAddr is a TEST-NET-1 address (RFC 5737): guaranteed
// unroutable, so resolving it can never leak traffic. Dialing UDP sends no
// packets at all; it only asks the kernel which local address it would use.
const outboundProbeAddr = "192.0.2.1:80"

// DefaultScanTarget reports the full CIDR of the local subnet (e.g.
// "192.168.1.0/24"). Callers behind the consent UX should prefer
// AutoScanTarget, which narrows oversized subnets to the host's /24 instead
// of forcing the user to re-run with an opt-in flag.
func DefaultScanTarget() (string, error) {
	target, _, err := AutoScanTarget(true)
	return target, err
}

// AutoScanTarget resolves the zero-config scan target. When the detected
// subnet exceeds the large-scan consent threshold and allowLarge is false,
// it narrows to the /24 containing the host so a bare `scan` just works;
// narrowedFrom reports the original subnet ("" when nothing was narrowed).
func AutoScanTarget(allowLarge bool) (target, narrowedFrom string, err error) {
	candidate, err := detectLocalCandidate()
	if err != nil {
		return "", "", err
	}
	return constrainAutoTarget(candidate, allowLarge)
}

type subnetCandidate struct {
	ifaceName string
	multicast bool
	network   *net.IPNet
}

func localSubnetCandidates() ([]subnetCandidate, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}

	var out []subnetCandidate
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
			if ip4 == nil || ip4.IsLoopback() || ip4.IsUnspecified() {
				continue
			}
			if ones, bits := ipNet.Mask.Size(); bits != 32 || ones < 0 || ones > 32 {
				continue
			}
			out = append(out, subnetCandidate{
				ifaceName: iface.Name,
				multicast: iface.Flags&net.FlagMulticast != 0,
				network:   &net.IPNet{IP: append(net.IP(nil), ip4...), Mask: append(net.IPMask(nil), ipNet.Mask...)},
			})
		}
	}
	return out, nil
}

// outboundPreferredIP returns the local address the OS would use for
// outbound traffic, or nil when that cannot be determined (offline host,
// no default route). It never sends traffic and never fails the scan:
// a nil result simply leaves selection to interface scoring.
func outboundPreferredIP() net.IP {
	conn, err := net.Dial("udp", outboundProbeAddr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return udpAddr.IP
	}
	return nil
}

func detectLocalCandidate() (subnetCandidate, error) {
	candidates, err := localSubnetCandidates()
	if err != nil {
		return subnetCandidate{}, err
	}
	return selectLocalCandidate(candidates, outboundPreferredIP())
}

// selectLocalCandidate picks the interface to scan. A private (RFC 1918)
// subnet always wins over tunnels and public addresses, because the
// zero-config target means "my local network" while the default route may
// point into a VPN tunnel. Within each tier the default-route interface
// wins, then the most specific subnet, with interface name and IP as
// deterministic final tie-breaks.
func selectLocalCandidate(candidates []subnetCandidate, preferred net.IP) (subnetCandidate, error) {
	if len(candidates) == 0 {
		return subnetCandidate{}, fmt.Errorf("no active IPv4 network interface found: connect to a network or pass an explicit target")
	}

	pool := candidates
	if private := filterPrivateSubnets(candidates); len(private) > 0 {
		pool = private
	}

	ordered := append([]subnetCandidate(nil), pool...)
	slices.SortFunc(ordered, func(a, b subnetCandidate) int {
		if scoreA, scoreB := scoreSubnetCandidate(a, preferred), scoreSubnetCandidate(b, preferred); scoreA != scoreB {
			return scoreB - scoreA // higher score first
		}
		onesA, _ := a.network.Mask.Size()
		onesB, _ := b.network.Mask.Size()
		if onesA != onesB {
			return onesB - onesA // more specific subnet first
		}
		if a.ifaceName != b.ifaceName {
			return strings.Compare(a.ifaceName, b.ifaceName)
		}
		return strings.Compare(a.network.IP.String(), b.network.IP.String())
	})

	return ordered[0], nil
}

func filterPrivateSubnets(candidates []subnetCandidate) []subnetCandidate {
	var out []subnetCandidate
	for _, c := range candidates {
		if c.network.IP.IsPrivate() {
			out = append(out, c)
		}
	}
	return out
}

func selectLocalSubnet(candidates []subnetCandidate, preferred net.IP) (string, error) {
	best, err := selectLocalCandidate(candidates, preferred)
	if err != nil {
		return "", err
	}
	return formatSubnetCIDR(best.network), nil
}

func formatSubnetCIDR(network *net.IPNet) string {
	ones, _ := network.Mask.Size()
	return fmt.Sprintf("%s/%d", network.IP.Mask(network.Mask), ones)
}

// constrainAutoTarget keeps the detected subnet when it fits the consent
// threshold (or consent was given) and otherwise narrows to the host's /24,
// which at 254 usable addresses always fits. The threshold comparison uses
// real target expansion, the same count the consent check enforces.
func constrainAutoTarget(c subnetCandidate, allowLarge bool) (target, narrowedFrom string, err error) {
	full := formatSubnetCIDR(c.network)
	if allowLarge {
		return full, "", nil
	}
	spec, err := discovery.ExpandTargets(full)
	if err != nil {
		return "", "", err
	}
	if uint64(spec.Total()) <= contracts.LargeScanThreshold {
		return full, "", nil
	}
	narrowed := &net.IPNet{IP: c.network.IP.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}
	return narrowed.String(), full, nil
}

func scoreSubnetCandidate(c subnetCandidate, preferred net.IP) int {
	ip := c.network.IP
	score := 0
	if preferred != nil && ip.Equal(preferred) {
		score += 100
	}
	if ip.IsPrivate() {
		score += 10
	}
	if ip.IsGlobalUnicast() {
		score += 2
	}
	if !ip.IsLinkLocalUnicast() {
		score += 5
	}
	if c.multicast {
		score += 1
	}
	return score
}
