package scanner

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ostefani/subnetlens/models"
)

type resolveResult struct {
	name    string
	latency time.Duration
	source  models.HostSource
}

type observedConn struct {
	net.Conn
	limiter *socketLimiter
	once    sync.Once
}

type observedPacketConn struct {
	*observedConn
	packetConn net.PacketConn
}

func (c *observedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.limiter != nil {
			c.limiter.Release()
		}
	})
	return err
}

func (c *observedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.packetConn.ReadFrom(b)
}

func (c *observedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.packetConn.WriteTo(b, addr)
}

func wrapObservedConn(conn net.Conn, limiter *socketLimiter) net.Conn {
	observed := &observedConn{
		Conn:    conn,
		limiter: limiter,
	}
	packetConn, ok := conn.(net.PacketConn)
	if !ok {
		return observed
	}
	return &observedPacketConn{
		observedConn: observed,
		packetConn:   packetConn,
	}
}

func NewBoundedResolver(limiter *socketLimiter) *net.Resolver {
	if limiter == nil {
		return &net.Resolver{PreferGo: true}
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if err := limiter.Acquire(ctx); err != nil {
				return nil, err
			}

			dialer := net.Dialer{}
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				limiter.Release()
				return nil, err
			}

			return wrapObservedConn(conn, limiter), nil
		},
	}
}

// ---------------------------------------------------------------------------
// NBNS — NetBIOS node-status (Windows)
// ---------------------------------------------------------------------------

func probeNBNS(ctx context.Context, ip string, socketLimiter *socketLimiter) string {
	timeout := cappedTimeout(ctx, 300*time.Millisecond)
	if err := socketLimiter.Acquire(ctx); err != nil {
		return ""
	}
	defer socketLimiter.Release()

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(ip, "137"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	if _, err := conn.Write(buildNBNSRequest()); err != nil {
		return ""
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return ""
	}

	return parseNBNSResponse(buf[:n])
}

func buildNBNSRequest() []byte {
	// 12 header + 1 label length + 32 encoded name + 1 root + 2 type + 2 class = 50
	buf := make([]byte, 50)
	buf[0], buf[1] = 0x00, 0x01 // transaction ID
	buf[4], buf[5] = 0x00, 0x01 // QDCOUNT: 1
	buf[12] = 0x20              // label length: 32 encoded chars
	copy(buf[13:45], nbnsEncode('*'))
	// buf[45] = 0x00 — root label (zero value, already set)
	buf[46], buf[47] = 0x00, 0x21 // QTYPE: NBSTAT
	buf[48], buf[49] = 0x00, 0x01 // QCLASS: IN
	return buf
}

func nbnsEncode(c byte) []byte {
	raw := make([]byte, 16)
	raw[0] = c
	enc := make([]byte, 32)
	for i, b := range raw {
		enc[i*2] = ((b >> 4) & 0x0F) + 0x41
		enc[i*2+1] = (b & 0x0F) + 0x41
	}
	return enc
}

func parseNBNSResponse(buf []byte) string {
	if len(buf) < 12 {
		return ""
	}

	ancount := int(binary.BigEndian.Uint16(buf[6:8]))
	if ancount == 0 {
		return ""
	}

	offset := 12

	// Skip question section.
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
		offset += 4 // QTYPE + QCLASS
	}

	// Walk answer RRs.
	for i := 0; i < ancount; i++ {
		if offset >= len(buf) {
			return ""
		}
		// Skip RR owner name.
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
		// TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes
		if offset+10 > len(buf) {
			return ""
		}
		offset += 8 // skip TYPE, CLASS, TTL
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

// ---------------------------------------------------------------------------
// PTR — standard reverse DNS (enterprise / data-centre)
// ---------------------------------------------------------------------------

func probePTR(ctx context.Context, ip string, socketLimiter *socketLimiter) string {
	ctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()

	resolver := NewBoundedResolver(socketLimiter)
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
