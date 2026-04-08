package tcp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ostefani/subnetlens/internal/textutil"
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

var probePorts = []int{80, 443, 22, 445, 8080}

type HostScanner struct{}

func NewHostScanner() HostScanner {
	return HostScanner{}
}

func LivenessPorts() []int {
	return append([]int(nil), probePorts...)
}

func (HostScanner) ScanHost(ctx context.Context, host *models.Host, opts models.ScanOptions, runtime contracts.Runtime) {
	snapshot := host.Snapshot()
	ports := opts.Ports
	if len(ports) == 0 {
		ports = models.CommonPorts
	}

	opts.Timeout = AdaptiveTimeout(opts.Timeout, snapshot.Latency)

	resultCh := make(chan models.Port, len(ports))
	var wg sync.WaitGroup

Loop:
	for _, port := range ports {
		if err := runtime.AcquireScanSlot(ctx); err != nil {
			break Loop
		}

		wg.Add(1)
		go func(portNum int) {
			defer wg.Done()
			defer runtime.ReleaseScanSlot()

			p := probePort(ctx, snapshot.IP, portNum, opts, runtime.SocketLimiter())
			resultCh <- p
		}(port)
	}

	wg.Wait()
	close(resultCh)

	results := make([]models.Port, 0, len(resultCh))
	for p := range resultCh {
		results = append(results, p)
	}

	host.SetProtocolPorts("tcp", results)
}

func ProbeOpenPort(ctx context.Context, ip string, timeout time.Duration, limiter contracts.SocketLimiter) (bool, time.Duration) {
	return probeLiveness(ctx, ip, timeout, func(err error) bool {
		return err == nil
	}, limiter)
}

func ProbeAlive(ctx context.Context, ip string, timeout time.Duration, limiter contracts.SocketLimiter) (bool, time.Duration) {
	return probeLiveness(ctx, ip, timeout, isRemoteTCPResponse, limiter)
}

func AdaptiveTimeout(base, latency time.Duration) time.Duration {
	if latency == 0 {
		return base
	}

	timeout := latency * 3
	if timeout < 100*time.Millisecond {
		timeout = 100 * time.Millisecond
	}
	if timeout > base {
		timeout = base
	}
	return timeout
}

func ReadHTTPServerHeader(conn net.Conn, ip, addr string, timeout time.Duration) string {
	_ = addr
	conn.SetDeadline(time.Now().Add(fingerprintTimeout(timeout)))

	req := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", ip)
	if _, err := fmt.Fprint(conn, req); err != nil {
		return ""
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodHead})
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	return textutil.SanitizeInline(resp.Header.Get("Server"))
}

func probeLiveness(
	ctx context.Context,
	ip string,
	timeout time.Duration,
	isSuccess func(error) bool,
	limiter contracts.SocketLimiter,
) (bool, time.Duration) {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	resultCh := make(chan time.Duration, len(probePorts))

	var wg sync.WaitGroup
	for _, port := range probePorts {
		wg.Add(1)
		port := port

		go func() {
			defer wg.Done()

			addr := net.JoinHostPort(ip, strconv.Itoa(port))

			if limiter != nil {
				if err := limiter.Acquire(probeCtx); err != nil {
					return
				}
				defer limiter.Release()
			}

			d := net.Dialer{}
			conn, err := d.DialContext(probeCtx, "tcp", addr)
			if conn != nil {
				conn.Close()
			}

			if isSuccess(err) {
				resultCh <- time.Since(start)
				cancel()
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	elapsed, ok := <-resultCh
	if !ok {
		return false, 0
	}
	return true, elapsed
}

func probePort(ctx context.Context, ip string, portNum int, opts models.ScanOptions, limiter contracts.SocketLimiter) models.Port {
	port := models.Port{
		Number:   portNum,
		Protocol: "tcp",
		State:    models.PortClosed,
	}

	addr := fmt.Sprintf("%s:%d", ip, portNum)
	dialer := net.Dialer{Timeout: opts.Timeout}

	if limiter != nil {
		if err := limiter.Acquire(ctx); err != nil {
			return port
		}
		defer limiter.Release()
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if isTimeout(err) {
			port.State = models.PortFiltered
		}
		return port
	}
	defer conn.Close()

	port.State = models.PortOpen
	port.Service = knownService(portNum)

	if opts.GrabBanners || needsFingerprint(portNum) {
		port.Fingerprint, port.Banner = collectPortEvidence(conn, ip, addr, portNum, opts.Timeout, opts.GrabBanners)
	}

	return port
}

func isRemoteTCPResponse(err error) bool {
	if err == nil {
		return true
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}

	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

var tlsPorts = map[int]bool{
	443:  true,
	993:  true,
	995:  true,
	8443: true,
}

var httpsFingerprintPorts = map[int]bool{
	443:  true,
	8443: true,
}

var httpFingerprintPorts = map[int]bool{
	80:   true,
	8080: true,
}

var httpProbe = []byte("HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")

var clientProbes = map[int][]byte{
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

func needsFingerprint(portNum int) bool {
	switch portNum {
	case 22, 80, 443, 8080, 8443:
		return true
	default:
		return false
	}
}

func collectPortEvidence(
	conn net.Conn,
	ip string,
	addr string,
	portNum int,
	timeout time.Duration,
	captureBanner bool,
) (models.PortFingerprint, string) {
	switch {
	case tlsPorts[portNum]:
		return grabTLSEvidence(conn, ip, addr, portNum, timeout, captureBanner)
	case httpFingerprintPorts[portNum]:
		server := ReadHTTPServerHeader(conn, ip, addr, timeout)
		return models.PortFingerprint{HTTPServer: server}, bannerFromHTTPServer(server, captureBanner)
	case portNum == 22:
		greeting := readSSHGreeting(conn, timeout)
		return models.PortFingerprint{SSHGreeting: greeting}, bannerIfEnabled(greeting, captureBanner)
	case captureBanner:
		return models.PortFingerprint{}, grabBanner(conn, portNum)
	default:
		return models.PortFingerprint{}, ""
	}
}

func grabBanner(conn net.Conn, portNum int) string {
	if probe, ok := clientProbes[portNum]; ok {
		conn.SetWriteDeadline(deadlineAfter(300)) //nolint:errcheck
		if _, err := conn.Write(probe); err != nil {
			return ""
		}
	}

	buf := make([]byte, 512)
	conn.SetReadDeadline(deadlineAfter(500)) //nolint:errcheck

	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return textutil.SanitizeInline(string(buf[:n]))
}

func readSSHGreeting(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(fingerprintTimeout(timeout))) //nolint:errcheck

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return textutil.SanitizeInline(string(buf[:n]))
}

func grabTLSEvidence(
	conn net.Conn,
	ip string,
	addr string,
	portNum int,
	timeout time.Duration,
	captureBanner bool,
) (models.PortFingerprint, string) {
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         ip,
	})

	tlsConn.SetDeadline(time.Now().Add(fingerprintTimeout(timeout))) //nolint:errcheck

	if err := tlsConn.Handshake(); err != nil {
		return models.PortFingerprint{}, ""
	}

	fingerprint := models.PortFingerprint{
		TLSSummary: tlsSummaryFromState(tlsConn.ConnectionState()),
	}

	var parts []string
	if fingerprint.TLSSummary != "" {
		parts = append(parts, fingerprint.TLSSummary)
	}
	if httpsFingerprintPorts[portNum] {
		fingerprint.HTTPServer = ReadHTTPServerHeader(tlsConn, ip, addr, timeout)
		if banner := bannerFromHTTPServer(fingerprint.HTTPServer, true); banner != "" {
			parts = append(parts, banner)
		}
	}

	if !captureBanner {
		return fingerprint, ""
	}

	return fingerprint, strings.Join(parts, " | ")
}

func tlsSummaryFromState(state tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
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
		return ""
	}

	return "TLS: " + strings.Join(parts, " ")
}

func bannerIfEnabled(value string, enabled bool) string {
	if !enabled {
		return ""
	}
	return value
}

func bannerFromHTTPServer(server string, enabled bool) string {
	if !enabled || server == "" {
		return ""
	}
	return "Server: " + server
}

func fingerprintTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return 500 * time.Millisecond
	}
	return timeout
}

func deadlineAfter(ms int) time.Time {
	return time.Now().Add(time.Duration(ms) * time.Millisecond)
}

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
