package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ostefani/subnetlens/internal/textutil"
	"github.com/ostefani/subnetlens/models"
)

// --- Named rule types ---

type keywordOS struct {
	keyword string
	hostOS      string
}

type keywordDevice struct {
	keyword string
	device  string
}

type keywordOSDevice struct {
	keyword string
	hostOS      string
	device  string
}

// --- Rule tables ---

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
	// OS-bearing: the Server string directly identifies the operating system.
	{"microsoft-iis", "Windows", ""},
	{"ubuntu", "Linux/Ubuntu", ""},
	{"debian", "Linux/Debian", ""},
	{"centos", "Linux/CentOS", ""},
	{"red hat", "Linux/CentOS", ""},
	{"rhel", "Linux/CentOS", ""},
	{"freebsd", "FreeBSD", ""},
	{"linux", "Linux", ""},
	// Device-bearing: the Server string identifies the product, not the OS.
	{"synology", "", "Synology NAS"},
	{"mikrotik", "", "MikroTik Router"},
	{"zyxel", "", "ZyXEL Device"},
	{"airtunes", "", "Apple AirPlay"},
	{"airplay", "", "Apple AirPlay"},
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

// --- Main entry point ---

func DetectOS(ip string, ports []models.Port, timeout time.Duration) (hostOS, device string) {
	portSet := map[int]bool{}
	banners := map[int]string{}

	for _, p := range ports {
		portSet[p.Number] = true
		banners[p.Number] = p.Banner
	}

	// TLS CN/SAN → device identity only ---
	for _, tlsPort := range []int{443, 8443, 993, 995} {
		if banner := banners[tlsPort]; banner != "" {
			if dev := deviceFromTLSBanner(banner); dev != "" {
				debugLog("osdetect", "ip=%s device=%q (via TLS banner port=%d)", ip, dev, tlsPort)
				device = dev
				break
			}
		}
	}

	// SSH banner → OS only ---
	if portSet[22] {
		banner := banners[22]
		if banner == "" {
			debugLog("osdetect", "ip=%s port=22 no cached banner — fetching", ip)
			banner = fetchSSHBanner(ip, timeout)
		} else {
			debugLog("osdetect", "ip=%s port=22 using cached banner %q", ip, banner)
		}
		if o := parseSSHBanner(banner); o != "" {
			debugLog("osdetect", "ip=%s hostOS=%q (via SSH banner)", ip, o)
			hostOS = o
		}
	}

	// HTTP Server header → OS or device depending on match ---
	for _, p := range []int{80, 8080, 443, 8443} {
		if portSet[p] {
			debugLog("osdetect", "ip=%s port=%d probing HTTP Server header", ip, p)
			o, d := osAndDeviceFromHTTPHeader(ip, p, timeout)
			if hostOS == "" && o != "" {
				hostOS = o
			}
			if device == "" && d != "" {
				device = d
			}
		}
		if hostOS != "" && device != "" {
			break
		}
	}

	if hostOS == "" {
		hostOS = "Unknown"
	}

	debugLog("osdetect", "ip=%s hostOS=%q device=%q", ip, hostOS, device)
	return hostOS, device
}

// --- Probes implementations ---

func deviceFromTLSBanner(banner string) string {
	if !strings.HasPrefix(strings.ToLower(banner), "tls:") {
		return ""
	}
	return firstMatch(banner, tlsBannerRules,
		func(r keywordDevice) string { return r.keyword },
		func(r keywordDevice) string { return r.device },
	)
}

func fetchSSHBanner(ip string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:22", ip), timeout)
	if err != nil {
		debugLog("osdetect", "fetchSSHBanner ip=%s dial error: %v", ip, err)
		return ""
	}

	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 256)
	bytesRead, err := conn.Read(buf)
	debugLog("osdetect", "fetchSSHBanner ip=%s n=%d err=%v raw=%q", ip, bytesRead, err, string(buf[:bytesRead]))

	if bytesRead == 0 {
		return ""
	}

	return textutil.SanitizeInline(string(buf[:bytesRead]))
}

func parseSSHBanner(banner string) string {
	return firstMatch(banner, sshBannerRules,
		func(r keywordOS) string { return r.keyword },
		func(r keywordOS) string { return r.hostOS },
	)
}

func osAndDeviceFromHTTPHeader(ip string, port int, timeout time.Duration) (hostOS, device string) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSHandshakeTimeout: timeout,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	url := fmt.Sprintf("%s://%s:%d", scheme, ip, port)
	resp, err := client.Get(url)
	if err != nil {
		debugLog("osdetect", "osAndDeviceFromHTTPHeader url=%s error: %v", url, err)
		return "", ""
	}

	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	if server == "" {
		return "", ""
	}

	for _, hr := range httpHeaderRules {
		if strings.Contains(strings.ToLower(server), hr.keyword) {
			return hr.hostOS, hr.device
		}
	}
	return "", ""
}