package scanner

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

type resolveResult struct {
	name           string
	latency        time.Duration
	source         models.HostSource
	provesLiveness bool
}

type observedConn struct {
	net.Conn
	limiter contracts.SocketLimiter
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

func wrapObservedConn(conn net.Conn, limiter contracts.SocketLimiter) net.Conn {
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

func NewBoundedResolver(limiter contracts.SocketLimiter) *net.Resolver {
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

func probePTR(ctx context.Context, ip string, socketLimiter contracts.SocketLimiter) string {
	ctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()

	resolver := NewBoundedResolver(socketLimiter)
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
