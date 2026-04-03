package scanner

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

type stubAddr string

func (a stubAddr) Network() string { return "stub" }
func (a stubAddr) String() string  { return string(a) }

type stubConn struct {
	closeCount int
}

func (c *stubConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c *stubConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *stubConn) Close() error                       { c.closeCount++; return nil }
func (c *stubConn) LocalAddr() net.Addr                { return stubAddr("local") }
func (c *stubConn) RemoteAddr() net.Addr               { return stubAddr("remote") }
func (c *stubConn) SetDeadline(_ time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(_ time.Time) error { return nil }

type stubPacketConn struct {
	stubConn
}

func (c *stubPacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	return 0, stubAddr("remote"), io.EOF
}

func (c *stubPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	_ = addr
	return len(b), nil
}

func TestWrapObservedConnPreservesPacketConnForUDP(t *testing.T) {
	wrapped := wrapObservedConn(&stubPacketConn{}, newSocketLimiter(1))

	if _, ok := wrapped.(net.PacketConn); !ok {
		t.Fatal("expected wrapped UDP connection to implement net.PacketConn")
	}
}

func TestWrapObservedConnDoesNotPretendTCPIsPacketConn(t *testing.T) {
	wrapped := wrapObservedConn(&stubConn{}, newSocketLimiter(1))

	if _, ok := wrapped.(net.PacketConn); ok {
		t.Fatal("expected wrapped stream connection to not implement net.PacketConn")
	}
}

func TestObservedConnCloseReleasesLimiterOnlyOnce(t *testing.T) {
	limiter := newSocketLimiter(1)
	if err := limiter.Acquire(context.Background()); err != nil {
		t.Fatalf("acquire limiter: %v", err)
	}

	wrapped := wrapObservedConn(&stubConn{}, limiter)
	if got := len(limiter.sem); got != 1 {
		t.Fatalf("expected limiter to hold 1 slot before close, got %d", got)
	}

	if err := wrapped.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if got := len(limiter.sem); got != 0 {
		t.Fatalf("expected limiter to release after first close, got %d", got)
	}

	if err := wrapped.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if got := len(limiter.sem); got != 0 {
		t.Fatalf("expected limiter release to remain idempotent, got %d", got)
	}
}
