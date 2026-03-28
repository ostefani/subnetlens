package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/ostefani/subnetlens/models"
)

func ScanPorts(ctx context.Context, host *models.Host, opts models.ScanOptions, sem chan struct{}) {
	ports := opts.Ports
	if len(ports) == 0 {
		ports = models.CommonPorts
	}

	opts.Timeout = adaptiveTimeout(opts.Timeout, host.Latency)

	// 1. Create a buffered channel large enough to hold all possible results.
	resultCh := make(chan models.Port, len(ports))
	var wg sync.WaitGroup

Loop:
	for _, port := range ports {
		select {
		case <-ctx.Done():
			break Loop // Stop scheduling new scans if canceled
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(portNum int) {
			defer wg.Done()
			defer func() { <-sem }()

			p := probePort(ctx, host.IP, portNum, opts)

			if p.State == models.PortOpen {
				// 2. Lock-free send to the buffered channel
				resultCh <- p
			}
		}(port)
	}

	// 3. Wait for all running scans to finish
	wg.Wait()

	// 4. Close the channel so we can range over it safely
	close(resultCh)

	// 5. Drain the channel into a slice. 
	results := make([]models.Port, 0, len(resultCh))
	for p := range resultCh {
		results = append(results, p)
	}

	sortPorts(results)
	host.OpenPorts = results

}

func probePort(ctx context.Context, ip string, portNum int, opts models.ScanOptions) models.Port {
	port := models.Port{
		Number:   portNum,
		Protocol: "tcp",
		State:    models.PortClosed,
	}

	addr := fmt.Sprintf("%s:%d", ip, portNum)
	dialer := net.Dialer{Timeout: opts.Timeout}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if isTimeout(err) {
			port.State = models.PortFiltered
			debugLog("portscan", "probe %s filtered (timeout)", addr)
		} else {
			debugLog("portscan", "probe %s closed: %v", addr, err)
		}
		return port
	}
	defer conn.Close()

	port.State = models.PortOpen
	port.Service = knownService(portNum)

	if opts.GrabBanners {
		if tlsPorts[portNum] {
			port.Banner = grabTLSBanner(conn, ip, addr)
		} else {
			port.Banner = grabBanner(conn, portNum, addr)
		}
	}

	return port
}

// ports where TLS banner grabbed
var tlsPorts = map[int]bool{
	443:  true, // HTTPS
	993:  true, // IMAPS
	995:  true, // POP3S
	8443: true, // HTTPS-Alt
}

var httpProbe = []byte("HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")

var clientProbes = map[int][]byte{
    80:   httpProbe,
    8080: httpProbe,
    8888: httpProbe,
    9200: httpProbe,
    6379: []byte("PING\r\n"),
    5432: {
		0x00, 0x00, 0x00, 0x22,
		0x00, 0x03, 0x00, 0x00,
		'u', 's', 'e', 'r', 0x00,
		'r', 'o', 'o', 't', 0x00,
		'd', 'a', 't', 'a', 'b', 'a', 's', 'e', 0x00,
		'p', 'o', 's', 't', 'g', 'r', 'e', 's', 0x00,
		0x00,
	},
}

func grabBanner(conn net.Conn, portNum int, addr string) string {
	// For client-speaks-first protocols, send the probe before reading.
	if probe, ok := clientProbes[portNum]; ok {
		conn.SetWriteDeadline(deadlineAfter(300))
		if _, err := conn.Write(probe); err != nil {
			debugLog("portscan", "grabBanner addr=%s port=%d probe write error: %v", addr, portNum, err)
			return ""
		}
	}

	buf := make([]byte, 512)
	conn.SetReadDeadline(deadlineAfter(500))

	n, err := conn.Read(buf)
	debugLog("portscan", "grabBanner addr=%s port=%d n=%d err=%v raw=%q", addr, portNum, n, err, string(buf[:n]))

	if n == 0 {
		return ""
	}
	return sanitize(string(buf[:n]))
}

// grabTLSBanner upgrades conn to TLS and extracts identifying metadata from
// the server certificate. It deliberately skips certificate verification
// (InsecureSkipVerify) because scanner targets are often self-signed or use
// internal CAs not trusted by the host OS.
//
// The returned banner form:
//	TLS: CN=example.com SANs=[www.example.com api.example.com] Org=Acme Corp
func grabTLSBanner(conn net.Conn, ip, addr string) string {
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         ip,
	})

	tlsConn.SetDeadline(deadlineAfter(1500))

	if err := tlsConn.Handshake(); err != nil {
		debugLog("portscan", "grabTLSBanner addr=%s handshake error: %v", addr, err)
		return ""
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		debugLog("portscan", "grabTLSBanner addr=%s no peer certificates", addr)
		return ""
	}

	cert := state.PeerCertificates[0]

	var parts []string
	if cert.Subject.CommonName != "" {
		parts = append(parts, "CN="+cert.Subject.CommonName)
	}
	if len(cert.DNSNames) > 0 {
		parts = append(parts, "SANs=["+strings.Join(cert.DNSNames, " ")+"]")
	}
	if len(cert.Subject.Organization) > 0 {
		parts = append(parts, "Org="+strings.Join(cert.Subject.Organization, ", "))
	}

	if len(parts) == 0 {
		debugLog("portscan", "grabTLSBanner addr=%s cert has no useful fields", addr)
		return ""
	}

	banner := "TLS: " + strings.Join(parts, " ")
	debugLog("portscan", "grabTLSBanner addr=%s banner=%q", addr, banner)
	return banner
}

// knownService maps well-known port numbers to service names.
func knownService(port int) string {
	services := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet",
		25: "SMTP", 53: "DNS", 80: "HTTP",
		110: "POP3", 139: "NetBIOS", 143: "IMAP",
		443: "HTTPS", 445: "SMB", 587: "SMTP/TLS",
		993: "IMAPS", 995: "POP3S", 3306: "MySQL",
		3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
		6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
		8888: "Jupyter", 9200: "Elasticsearch",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "unknown"
}

func sortPorts(ports []models.Port) {
	slices.SortFunc(ports, func(a, b models.Port) int {
		return a.Number - b.Number
	})
}