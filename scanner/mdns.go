package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

func resolveHostname(ctx context.Context, ip string, cache *mdnsCache) resolveResult {
	if cache != nil {
		if name, ok := cache.get(ip); ok && name != "" {
			return resolveResult{name: name}
		}
	}

	start := time.Now()
	if name := resolveMDNS(ctx, ip); name != "" && name != ip {
		if cache != nil {
			cache.set(ip, name)
		}
		return resolveResult{name: name, latency: time.Since(start)}
	}

	start = time.Now()
	if name := probeNBNS(ctx, ip); name != "" {
		if cache != nil {
			cache.set(ip, name)
		}
		return resolveResult{name: name, latency: time.Since(start)}
	}

	start = time.Now()
	if name := probePTR(ctx, ip); name != "" && name != ip {
		if cache != nil {
			cache.set(ip, name)
		}
		return resolveResult{name: name, latency: time.Since(start)}
	}

	return resolveResult{}
}

func resolveMDNS(ctx context.Context, ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}

	// Reverse IP for PTR lookup: 5.1.168.192.in-addr.arpa
	arpa := fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa", parts[3], parts[2], parts[1], parts[0])
	query := buildPTRQuery(arpa)

	timeout := cappedTimeout(ctx, 500*time.Millisecond)
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "5353"), timeout)
	if err != nil {
		debugLog("mdns", "failed to resolve PTR query: %v", err)
		return ""
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		debugLog("mdns", "failed to set deadline for PTR query: %v", err)
		return ""
	}

	if _, err := conn.Write(query); err != nil {
		debugLog("mdns", "failed to send PTR query: %v", err)
		return ""
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		debugLog("mdns", "failed to read response or invalid response size")
		return ""
	}

	return parseMDNSResponse(buf[:n])
}


func buildPTRQuery(domain string) []byte {
	msg := []byte{
		0x00, 0x00, // Transaction ID
		0x00, 0x00, // Flags
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
	}

	for _, part := range strings.Split(domain, ".") {
		msg = append(msg, byte(len(part)))
		msg = append(msg, part...)
	}
	msg = append(msg, 0x00)       // end of QNAME
	msg = append(msg, 0x00, 0x0c) // QTYPE PTR
	msg = append(msg, 0x80, 0x01) // QCLASS IN + unicast-response bit

	return msg
}

func parseMDNSResponse(data []byte) string {
	offset := 12

	qdcount := int(data[4])<<8 | int(data[5])
	for i := 0; i < qdcount; i++ {
		_, newOffset, err := readDNSName(data, offset)
		if err != nil {
			debugLog("mdns", "failed to read DNS name from response: %v", err)
			return ""
		}
		offset = newOffset + 4
		if offset >= len(data) {
			debugLog("mdns", "unexpected end of response")
			return ""
		}
	}

	ancount := int(data[6])<<8 | int(data[7])
	if ancount == 0 {
		debugLog("mdns", "no answers in mDNS response")
		return ""
	}

	for i := 0; i < ancount; i++ {
		_, newOffset, err := readDNSName(data, offset)
		if err != nil {
			debugLog("mdns", "failed to read answer DNS name: %v", err)
			return ""
		}
		offset = newOffset

		if offset+10 > len(data) {
			debugLog("mdns", "invalid response format")
			return ""
		}

		qtype := int(data[offset])<<8 | int(data[offset+1])
		offset += 8 // TYPE, CLASS, TTL
		rdlength := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+rdlength > len(data) {
			debugLog("mdns", "response data length mismatch")
			return ""
		}

		if qtype == 12 {
			name, _, err := readDNSName(data, offset)
			if err == nil {
				return normalizeMDNSName(name)
			}
		}

		offset += rdlength
	}

	debugLog("mdns", "no suitable mDNS name found in response")
	return ""
}
