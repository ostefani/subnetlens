package discovery

import (
	"net"
	"os"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
	arptransport "github.com/ostefani/subnetlens/transports/arp"
)

func LocalDiscoveryInfoForTarget(target string) LocalDiscoveryInfo {
	var contains func(string) bool
	targets, err := ExpandTargets(target)
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