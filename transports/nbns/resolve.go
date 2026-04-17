// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package nbns

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

type socketLimiter interface {
	Acquire(context.Context) error
	Release()
}

func ResolveName(ctx context.Context, ip string, limiter socketLimiter) string {
	timeout := cappedTimeout(ctx, 300*time.Millisecond)
	if limiter != nil {
		if err := limiter.Acquire(ctx); err != nil {
			return ""
		}
		defer limiter.Release()
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(ip, "137"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	if _, err := conn.Write(buildRequest()); err != nil {
		return ""
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return ""
	}

	return parseResponse(buf[:n])
}

func buildRequest() []byte {
	buf := make([]byte, 50)
	buf[0], buf[1] = 0x00, 0x01
	buf[4], buf[5] = 0x00, 0x01
	buf[12] = 0x20
	copy(buf[13:45], encode('*'))
	buf[46], buf[47] = 0x00, 0x21
	buf[48], buf[49] = 0x00, 0x01
	return buf
}

func encode(c byte) []byte {
	raw := make([]byte, 16)
	raw[0] = c
	enc := make([]byte, 32)
	for i, b := range raw {
		enc[i*2] = ((b >> 4) & 0x0F) + 0x41
		enc[i*2+1] = (b & 0x0F) + 0x41
	}
	return enc
}

func parseResponse(buf []byte) string {
	if len(buf) < 12 {
		return ""
	}

	ancount := int(binary.BigEndian.Uint16(buf[6:8]))
	if ancount == 0 {
		return ""
	}

	offset := 12
	qdcount := int(binary.BigEndian.Uint16(buf[4:6]))
	for i := 0; i < qdcount; i++ {
		for offset < len(buf) {
			l := int(buf[offset])
			if l == 0 {
				offset++
				break
			}
			if l&0xC0 == 0xC0 {
				offset += 2
				break
			}
			offset += 1 + l
		}
		offset += 4
	}

	for i := 0; i < ancount; i++ {
		if offset >= len(buf) {
			return ""
		}
		if buf[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(buf) {
				l := int(buf[offset])
				if l == 0 {
					offset++
					break
				}
				offset += 1 + l
			}
		}
		if offset+10 > len(buf) {
			return ""
		}
		offset += 8
		rdlength := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2

		if offset+rdlength > len(buf) || rdlength < 1 {
			return ""
		}
		rdata := buf[offset : offset+rdlength]
		offset += rdlength

		numNames := int(rdata[0])
		pos := 1
		for j := 0; j < numNames; j++ {
			if pos+18 > len(rdata) {
				break
			}
			nameBytes := rdata[pos : pos+15]
			suffix := rdata[pos+15]
			pos += 18

			if suffix == 0x00 {
				if name := strings.TrimRight(string(nameBytes), " \x00"); name != "" {
					return name
				}
			}
		}
	}

	return ""
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
