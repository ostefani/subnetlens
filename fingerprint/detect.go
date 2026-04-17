// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package fingerprint

import (
	"strings"

	"github.com/ostefani/subnetlens/models"
)

type keywordOS struct {
	keyword string
	hostOS  string
}

type keywordDevice struct {
	keyword string
	device  string
}

type keywordOSDevice struct {
	keyword string
	hostOS  string
	device  string
}

type Detector struct{}

var tlsBannerRules = []keywordDevice{
	{"tplinkwifi", "TP-Link Router"},
	{"tp-link", "TP-Link Router"},
	{"routerlogin", "Netgear Router"},
	{"netgear", "Netgear Router"},
	{"asus", "Asus Router"},
	{"mikrotik", "MikroTik Router"},
	{"ubiquiti", "Ubiquiti Device"},
	{"unifi", "Ubiquiti Device"},
	{"cisco", "Cisco Device"},
	{"dlink", "D-Link Router"},
	{"d-link", "D-Link Router"},
	{"synology", "Synology NAS"},
	{"qnap", "QNAP NAS"},
	{"apple", "Apple Device"},
	{"microsoft", "Microsoft Device"},
	{"windows", "Microsoft Device"},
	{"openwrt", "OpenWrt Device"},
	{"proxmox", "Proxmox Host"},
	{"raspberrypi", "Raspberry Pi"},
	{"raspberry", "Raspberry Pi"},
}

var sshBannerRules = []keywordOS{
	{"windows", "Windows"},
	{"ubuntu", "Linux/Ubuntu"},
	{"debian", "Linux/Debian"},
	{"centos", "Linux/CentOS"},
	{"fedora", "Linux/Fedora"},
	{"raspbian", "Linux/Raspbian"},
	{"dropbear", "Linux/Embedded"},
	{"freebsd", "FreeBSD"},
	{"netbsd", "NetBSD"},
	{"openbsd", "OpenBSD"},
	{"openssh", "Linux/Unix"},
}

var httpHeaderRules = []keywordOSDevice{
	{"microsoft-iis", "Windows", ""},
	{"ubuntu", "Linux/Ubuntu", ""},
	{"debian", "Linux/Debian", ""},
	{"centos", "Linux/CentOS", ""},
	{"red hat", "Linux/CentOS", ""},
	{"rhel", "Linux/CentOS", ""},
	{"freebsd", "FreeBSD", ""},
	{"linux", "Linux", ""},
	{"synology", "", "Synology NAS"},
	{"mikrotik", "", "MikroTik Router"},
	{"zyxel", "", "ZyXEL Device"},
	{"airtunes", "", "Apple AirPlay"},
	{"airplay", "", "Apple AirPlay"},
}

func (Detector) ClassifyHost(ports []models.Port) (string, string) {
	return Detect(ports)
}

func Detect(ports []models.Port) (hostOS, device string) {
	portSet := map[int]bool{}
	fingerprints := map[int]models.PortFingerprint{}

	for _, p := range ports {
		if p.Protocol != "" && p.Protocol != "tcp" {
			continue
		}
		portSet[p.Number] = true
		fingerprints[p.Number] = p.Fingerprint
	}

	for _, tlsPort := range []int{443, 8443, 993, 995} {
		if summary := fingerprints[tlsPort].TLSSummary; summary != "" {
			if dev := deviceFromTLSSummary(summary); dev != "" {
				device = dev
				break
			}
		}
	}

	if portSet[22] {
		if greeting := fingerprints[22].SSHGreeting; greeting != "" {
			if o := parseSSHBanner(greeting); o != "" {
				hostOS = o
			}
		}
	}

	for _, port := range []int{80, 8080, 443, 8443} {
		if !portSet[port] {
			continue
		}

		server := fingerprints[port].HTTPServer
		if server == "" {
			continue
		}

		o, d := parseHTTPServerHeader(server)
		if hostOS == "" && o != "" {
			hostOS = o
		}
		if device == "" && d != "" {
			device = d
		}

		if hostOS != "" && device != "" {
			break
		}
	}

	if hostOS == "" {
		hostOS = "Unknown"
	}

	return hostOS, device
}

func firstMatch[R any](s string, rules []R, keyword func(R) string, value func(R) string) string {
	s = strings.ToLower(s)
	for _, r := range rules {
		if strings.Contains(s, keyword(r)) {
			return value(r)
		}
	}
	return ""
}

func deviceFromTLSSummary(summary string) string {
	return firstMatch(summary, tlsBannerRules,
		func(r keywordDevice) string { return r.keyword },
		func(r keywordDevice) string { return r.device },
	)
}

func parseSSHBanner(banner string) string {
	return firstMatch(banner, sshBannerRules,
		func(r keywordOS) string { return r.keyword },
		func(r keywordOS) string { return r.hostOS },
	)
}

func parseHTTPServerHeader(server string) (hostOS, device string) {
	for _, hr := range httpHeaderRules {
		if strings.Contains(strings.ToLower(server), hr.keyword) {
			return hr.hostOS, hr.device
		}
	}
	return "", ""
}
