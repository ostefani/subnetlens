// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"net"
	"strings"
	"testing"

	"github.com/ostefani/subnetlens/scanner/discovery"
)

func testSubnetCandidate(t *testing.T, iface, cidr string) subnetCandidate {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse test CIDR %q: %v", cidr, err)
	}
	ipNet.IP = ip // enumeration reports the host address, not the masked network
	return subnetCandidate{ifaceName: iface, multicast: true, network: ipNet}
}

func TestSelectLocalSubnetPrefersOutboundInterface(t *testing.T) {
	candidates := []subnetCandidate{
		testSubnetCandidate(t, "eth0", "10.0.0.5/8"),
		testSubnetCandidate(t, "wlan0", "192.168.1.5/24"),
	}
	got, err := selectLocalSubnet(candidates, net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatalf("selectLocalSubnet: %v", err)
	}
	if got != "10.0.0.0/8" {
		t.Fatalf("expected the default-route subnet 10.0.0.0/8, got %q", got)
	}
}

func TestSelectLocalSubnetPrefersPrivateOverPublicAndLinkLocal(t *testing.T) {
	candidates := []subnetCandidate{
		testSubnetCandidate(t, "eth0", "203.0.113.5/24"),
		testSubnetCandidate(t, "eth1", "169.254.10.5/16"),
		testSubnetCandidate(t, "wlan0", "192.168.1.5/24"),
	}
	got, err := selectLocalSubnet(candidates, nil)
	if err != nil {
		t.Fatalf("selectLocalSubnet: %v", err)
	}
	if got != "192.168.1.0/24" {
		t.Fatalf("expected private subnet 192.168.1.0/24, got %q", got)
	}
}

func TestSelectLocalSubnetFallsBackToPublicThenLinkLocal(t *testing.T) {
	public := []subnetCandidate{
		testSubnetCandidate(t, "eth0", "203.0.113.5/24"),
		testSubnetCandidate(t, "eth1", "169.254.10.5/16"),
	}
	got, err := selectLocalSubnet(public, nil)
	if err != nil {
		t.Fatalf("selectLocalSubnet: %v", err)
	}
	if got != "203.0.113.0/24" {
		t.Fatalf("expected public subnet 203.0.113.0/24, got %q", got)
	}

	linkLocal := []subnetCandidate{testSubnetCandidate(t, "eth1", "169.254.10.5/16")}
	got, err = selectLocalSubnet(linkLocal, nil)
	if err != nil {
		t.Fatalf("selectLocalSubnet: %v", err)
	}
	if got != "169.254.0.0/16" {
		t.Fatalf("expected link-local subnet 169.254.0.0/16, got %q", got)
	}
}

func TestSelectLocalSubnetMasksHostBits(t *testing.T) {
	candidates := []subnetCandidate{testSubnetCandidate(t, "wlan0", "192.168.1.5/24")}
	got, err := selectLocalSubnet(candidates, nil)
	if err != nil {
		t.Fatalf("selectLocalSubnet: %v", err)
	}
	if got != "192.168.1.0/24" {
		t.Fatalf("expected masked network 192.168.1.0/24, got %q", got)
	}
}

func TestSelectLocalSubnetTieBreakIsDeterministic(t *testing.T) {
	candidates := []subnetCandidate{
		testSubnetCandidate(t, "eth1", "10.1.0.5/24"),
		testSubnetCandidate(t, "eth0", "10.2.0.5/24"),
	}
	for i := 0; i < 2; i++ {
		got, err := selectLocalSubnet(candidates, nil)
		if err != nil {
			t.Fatalf("selectLocalSubnet: %v", err)
		}
		if got != "10.2.0.0/24" {
			t.Fatalf("expected deterministic pick 10.2.0.0/24 (eth0), got %q", got)
		}
	}
}

func TestSelectLocalSubnetPrefersPrivateOverDefaultRoutedTunnel(t *testing.T) {
	candidates := []subnetCandidate{
		testSubnetCandidate(t, "utun5", "198.18.0.1/16"),
		testSubnetCandidate(t, "en0", "192.168.0.139/24"),
	}
	got, err := selectLocalSubnet(candidates, net.ParseIP("198.18.0.1"))
	if err != nil {
		t.Fatalf("selectLocalSubnet: %v", err)
	}
	if got != "192.168.0.0/24" {
		t.Fatalf("expected home LAN 192.168.0.0/24 to win over the default-routed tunnel, got %q", got)
	}
}

func TestSelectLocalSubnetPrefersSmallerSubnetOnTie(t *testing.T) {
	candidates := []subnetCandidate{
		testSubnetCandidate(t, "docker0", "172.17.0.5/16"),
		testSubnetCandidate(t, "wlan0", "192.168.1.5/24"),
	}
	got, err := selectLocalSubnet(candidates, nil)
	if err != nil {
		t.Fatalf("selectLocalSubnet: %v", err)
	}
	if got != "192.168.1.0/24" {
		t.Fatalf("expected more specific subnet 192.168.1.0/24, got %q", got)
	}
}

func TestConstrainAutoTargetNarrowsOversizedSubnet(t *testing.T) {
	candidate := testSubnetCandidate(t, "utun5", "198.18.5.7/16")
	target, narrowedFrom, err := constrainAutoTarget(candidate, false)
	if err != nil {
		t.Fatalf("constrainAutoTarget: %v", err)
	}
	if target != "198.18.5.0/24" || narrowedFrom != "198.18.0.0/16" {
		t.Fatalf("expected host /24 198.18.5.0/24 narrowed from 198.18.0.0/16, got %q from %q", target, narrowedFrom)
	}
}

func TestConstrainAutoTargetKeepsConsentedSubnet(t *testing.T) {
	candidate := testSubnetCandidate(t, "utun5", "198.18.5.7/16")
	target, narrowedFrom, err := constrainAutoTarget(candidate, true)
	if err != nil {
		t.Fatalf("constrainAutoTarget: %v", err)
	}
	if target != "198.18.0.0/16" || narrowedFrom != "" {
		t.Fatalf("expected full consented subnet 198.18.0.0/16, got %q from %q", target, narrowedFrom)
	}
}

func TestConstrainAutoTargetKeepsSmallSubnets(t *testing.T) {
	for _, cidr := range []string{"192.168.1.5/24", "10.0.0.5/25", "10.0.0.5/22"} {
		candidate := testSubnetCandidate(t, "en0", cidr)
		target, narrowedFrom, err := constrainAutoTarget(candidate, false)
		if err != nil {
			t.Fatalf("constrainAutoTarget(%s): %v", cidr, err)
		}
		if narrowedFrom != "" {
			t.Fatalf("expected no narrowing for %s, got %q from %q", cidr, target, narrowedFrom)
		}
	}
}

func TestSelectLocalSubnetRequiresCandidates(t *testing.T) {
	if _, err := selectLocalSubnet(nil, nil); err == nil {
		t.Fatal("expected an error with no candidates")
	} else if !strings.Contains(err.Error(), "IPv4") {
		t.Fatalf("expected error to mention IPv4, got %q", err.Error())
	}
}

func TestDefaultScanTargetReturnsUsableTarget(t *testing.T) {
	target, err := DefaultScanTarget()
	if err != nil {
		// Loopback-only, IPv6-only, or offline CI runners have nothing to
		// auto-detect; the CLI surfaces this as a helpful explicit-target
		// error instead of scanning blindly.
		if !strings.Contains(err.Error(), "IPv4") && !strings.Contains(err.Error(), "interfaces") {
			t.Fatalf("expected a no-interface error, got %q", err.Error())
		}
		t.Skipf("no local subnet on this host: %v", err)
	}
	spec, err := discovery.ExpandTargets(target)
	if err != nil {
		t.Fatalf("auto-detected target %q does not expand: %v", target, err)
	}
	if spec.Total() < 1 {
		t.Fatalf("auto-detected target %q expands to no addresses", target)
	}
}
