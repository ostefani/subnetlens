package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ostefani/subnetlens/models"
	"golang.org/x/net/ipv4"
)

// startPassiveMDNSListener opens one SO_REUSEPORT socket, joins the
// multicast group, and fills cache as devices broadcast A records.
func startPassiveMDNSListener(ctx context.Context) *mdnsCache {
	cache := newMDNSCache()

	conn, err := newMDNSSocket()
	if err != nil {
		debugLog("mdns", "passive listener unavailable: %v", err)
		return cache
	}

	pc := ipv4.NewPacketConn(conn)
	ifaces, err := net.Interfaces()

	if err != nil {
		debugLog("mdns", "failed to list interfaces: %v", err)
		return cache
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if err := pc.JoinGroup(&iface, &net.UDPAddr{IP: net.ParseIP("224.0.0.251")}); err != nil {
			debugLog("mdns", "join group failed on %s: %v", iface.Name, err)
			continue
		}
	}

	go func() {
		defer conn.Close()
		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			for ip, name := range parseARecords(buf[:n]) {
				cache.StoreName(ip, name, models.HostSourceMDNS)
			}
		}
	}()

	return cache
}

// Scans all RR sections of a raw mDNS packet and returns
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
		offset = newOffset + 4 // QTYPE + QCLASS
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
		offset += 8 // TYPE(2) + CLASS(2) + TTL(4)

		rdlength := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+rdlength > len(data) {
			break
		}
		if rrType == 1 && rdlength == 4 {
			ip := net.IP(data[offset : offset+4]).String()
			hostname := normalizeMDNSName(name)

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
			return "", 0, fmt.Errorf("EOF")
		}
		l := int(data[offset])
		if l == 0 {
			offset++
			break
		}

		if l&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", 0, fmt.Errorf("EOF")
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
			return "", 0, fmt.Errorf("EOF")
		}
		parts = append(parts, string(data[offset:offset+l]))
		offset += l
	}
	if !jumped {
		originalOffset = offset
	}
	return strings.Join(parts, "."), originalOffset, nil
}
