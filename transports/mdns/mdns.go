// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package mdns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ostefani/subnetlens/internal/textutil"
	"github.com/ostefani/subnetlens/models"
	"golang.org/x/net/ipv4"
)

var (
	mdnsMulticastAddr  = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	querySocketFactory = newQuerySocket
)

type socketLimiter interface {
	Acquire(context.Context) error
	Release()
}

type nameStore interface {
	StoreName(ip, name string, source models.HostSource)
}

type closeableNameStore interface {
	Close()
}

func StartPassiveListener(ctx context.Context, store nameStore) error {
	conn, err := newSocket()
	if err != nil {
		return err
	}

	pc := ipv4.NewPacketConn(conn)
	ifaces, err := net.Interfaces()
	if err != nil {
		conn.Close()
		return err
	}

	joined := 0
	var lastJoinErr error
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if err := pc.JoinGroup(&iface, &net.UDPAddr{IP: net.ParseIP("224.0.0.251")}); err != nil {
			lastJoinErr = err
			continue
		}
		joined++
	}

	if joined == 0 {
		conn.Close()
		if lastJoinErr != nil {
			return fmt.Errorf("failed to join mDNS multicast on any interface: %w", lastJoinErr)
		}
		return fmt.Errorf("no active multicast-capable interfaces available for passive mDNS")
	}

	go func() {
		if closable, ok := store.(closeableNameStore); ok {
			defer closable.Close()
		}
		defer conn.Close()
		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)) //nolint:errcheck
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			for ip, name := range parseARecords(buf[:n]) {
				store.StoreName(ip, name, models.HostSourceMDNS)
			}
		}
	}()

	return nil
}

func ResolveName(ctx context.Context, ip string, limiter socketLimiter) string {
	targetIP := net.ParseIP(ip).To4()
	if targetIP == nil {
		return ""
	}

	parts := strings.Split(targetIP.String(), ".")
	arpa := fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa", parts[3], parts[2], parts[1], parts[0])
	query := buildPTRQuery(arpa)

	timeout := cappedTimeout(ctx, 500*time.Millisecond)
	if limiter != nil {
		if err := limiter.Acquire(ctx); err != nil {
			return ""
		}
		defer limiter.Release()
	}

	conn, err := querySocketFactory(targetIP)
	if err != nil {
		return ""
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ""
	}

	// Use a one-shot multicast query so replies come back to this ephemeral
	// socket without competing with the passive listener already bound to :5353.
	// We intentionally leave the QU bit clear: because the source port is not
	// 5353, responders treat this as a simple one-shot query and reply via
	// unicast to this socket.
	if _, err := conn.WriteTo(query, mdnsMulticastAddr); err != nil {
		return ""
	}

	buf := make([]byte, 512)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return ""
		}
		if n < 12 {
			continue
		}
		if name := parseResponse(buf[:n]); name != "" {
			return name
		}
	}
}

func buildPTRQuery(domain string) []byte {
	msg := []byte{
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}

	for _, part := range strings.Split(domain, ".") {
		msg = append(msg, byte(len(part)))
		msg = append(msg, part...)
	}
	msg = append(msg, 0x00)
	msg = append(msg, 0x00, 0x0c)
	// One-shot multicast queries use a non-5353 source port and therefore get
	// direct unicast replies without needing the QU bit.
	msg = append(msg, 0x00, 0x01)

	return msg
}

func newQuerySocket(targetIP net.IP) (net.PacketConn, error) {
	iface, srcIP := selectInterfaceForTarget(targetIP)

	if srcIP != nil {
		if conn, err := net.ListenPacket("udp4", net.JoinHostPort(srcIP.String(), "0")); err == nil {
			configureQuerySocket(conn, iface)
			return conn, nil
		}
	}

	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	configureQuerySocket(conn, iface)
	return conn, nil
}

func configureQuerySocket(conn net.PacketConn, iface *net.Interface) {
	pc := ipv4.NewPacketConn(conn)
	if iface != nil {
		_ = pc.SetMulticastInterface(iface)
	}
	_ = pc.SetMulticastTTL(255)
	_ = pc.SetMulticastLoopback(false)
}

func selectInterfaceForTarget(targetIP net.IP) (*net.Interface, net.IP) {
	if targetIP == nil {
		return nil, nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagMulticast == 0 {
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
			if ipNet.Contains(targetIP) {
				return &iface, ip4
			}
		}
	}

	return nil, nil
}

func parseResponse(data []byte) string {
	offset := 12

	qdcount := int(data[4])<<8 | int(data[5])
	for i := 0; i < qdcount; i++ {
		_, newOffset, err := readDNSName(data, offset)
		if err != nil {
			return ""
		}
		offset = newOffset + 4
		if offset >= len(data) {
			return ""
		}
	}

	ancount := int(data[6])<<8 | int(data[7])
	if ancount == 0 {
		return ""
	}

	for i := 0; i < ancount; i++ {
		_, newOffset, err := readDNSName(data, offset)
		if err != nil {
			return ""
		}
		offset = newOffset

		if offset+10 > len(data) {
			return ""
		}

		qtype := int(data[offset])<<8 | int(data[offset+1])
		offset += 8
		rdlength := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+rdlength > len(data) {
			return ""
		}

		if qtype == 12 {
			name, _, err := readDNSName(data, offset)
			if err == nil {
				return normalizeName(name)
			}
		}

		offset += rdlength
	}

	return ""
}

func parseARecords(data []byte) map[string]string {
	result := make(map[string]string)
	if len(data) < 12 {
		return result
	}

	qdcount := int(data[4])<<8 | int(data[5])
	ancount := int(data[6])<<8 | int(data[7])
	nscount := int(data[8])<<8 | int(data[9])
	arcount := int(data[10])<<8 | int(data[11])

	offset := 12
	for i := 0; i < qdcount; i++ {
		_, newOffset, err := readDNSName(data, offset)
		if err != nil {
			return result
		}
		offset = newOffset + 4
	}

	for i := 0; i < ancount+nscount+arcount; i++ {
		if offset >= len(data) {
			break
		}
		name, newOffset, err := readDNSName(data, offset)
		if err != nil || newOffset+10 > len(data) {
			break
		}
		offset = newOffset

		rrType := int(data[offset])<<8 | int(data[offset+1])
		offset += 8

		rdlength := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+rdlength > len(data) {
			break
		}
		if rrType == 1 && rdlength == 4 {
			ip := net.IP(data[offset : offset+4]).String()
			hostname := normalizeName(name)

			if hostname != "" && ip != "" {
				result[ip] = hostname
			}
		}
		offset += rdlength
	}
	return result
}

func readDNSName(data []byte, offset int) (string, int, error) {
	var parts []string
	originalOffset := offset
	jumped := false
	for {
		if offset >= len(data) {
			return "", 0, fmt.Errorf("eof")
		}
		l := int(data[offset])
		if l == 0 {
			offset++
			break
		}

		if l&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", 0, fmt.Errorf("eof")
			}
			ptr := int(data[offset]&0x3F)<<8 | int(data[offset+1])
			if !jumped {
				originalOffset = offset + 2
				jumped = true
			}
			offset = ptr
			continue
		}
		offset++
		if offset+l > len(data) {
			return "", 0, fmt.Errorf("eof")
		}
		parts = append(parts, string(data[offset:offset+l]))
		offset += l
	}
	if !jumped {
		originalOffset = offset
	}
	return strings.Join(parts, "."), originalOffset, nil
}

func normalizeName(name string) string {
	name = strings.TrimSuffix(name, ".local")
	name = strings.TrimSuffix(name, ".")
	return textutil.SanitizeInline(name)
}

func cappedTimeout(ctx context.Context, max time.Duration) time.Duration {
	dl, ok := ctx.Deadline()
	if !ok {
		return max
	}
	if rem := time.Until(dl); rem < max {
		if rem <= 0 {
			return time.Millisecond
		}
		return rem
	}
	return max
}
