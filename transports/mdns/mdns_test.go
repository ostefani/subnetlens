package mdns

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBuildPTRQueryUsesNormalQClass(t *testing.T) {
	query := buildPTRQuery("1.0.0.10.in-addr.arpa")
	if len(query) < 4 {
		t.Fatalf("query too short: %d", len(query))
	}

	qclass := query[len(query)-2:]
	if got := uint16(qclass[0])<<8 | uint16(qclass[1]); got != 0x0001 {
		t.Fatalf("expected QCLASS IN without QU bit, got 0x%04x", got)
	}
}

func TestResolveNameSendsMulticastQuery(t *testing.T) {
	originalFactory := querySocketFactory
	t.Cleanup(func() {
		querySocketFactory = originalFactory
	})

	fakeConn := &stubPacketConn{
		response: buildPTRResponse("1.0.0.10.in-addr.arpa", "printer.local."),
	}
	querySocketFactory = func(targetIP net.IP) (net.PacketConn, error) {
		if got := targetIP.String(); got != "10.0.0.1" {
			t.Fatalf("expected target IP 10.0.0.1, got %s", got)
		}
		return fakeConn, nil
	}

	got := ResolveName(context.Background(), "10.0.0.1", nil)
	if got != "printer" {
		t.Fatalf("expected printer, got %q", got)
	}
	if fakeConn.deadline.IsZero() {
		t.Fatal("expected ResolveName to set a socket deadline")
	}

	dest, ok := fakeConn.writes[0].(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected UDP destination, got %T", fakeConn.writes[0])
	}
	if dest.Port != 5353 || !dest.IP.Equal(net.IPv4(224, 0, 0, 251)) {
		t.Fatalf("expected multicast destination 224.0.0.251:5353, got %s", dest.String())
	}

	qclass := fakeConn.payload[len(fakeConn.payload)-2:]
	if got := uint16(qclass[0])<<8 | uint16(qclass[1]); got != 0x0001 {
		t.Fatalf("expected multicast query QCLASS 0x0001, got 0x%04x", got)
	}
}

type stubPacketConn struct {
	payload  []byte
	writes   []net.Addr
	response []byte
	deadline time.Time
}

func (c *stubPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(c.response) == 0 {
		return 0, nil, errors.New("no response")
	}
	n := copy(p, c.response)
	c.response = nil
	return n, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5353}, nil
}

func (c *stubPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.payload = append([]byte(nil), p...)
	c.writes = append(c.writes, addr)
	return len(p), nil
}

func (c *stubPacketConn) Close() error        { return nil }
func (c *stubPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (c *stubPacketConn) SetDeadline(t time.Time) error {
	c.deadline = t
	return nil
}
func (c *stubPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubPacketConn) SetWriteDeadline(time.Time) error { return nil }

func buildPTRResponse(question, answer string) []byte {
	msg := []byte{
		0x00, 0x00,
		0x84, 0x00,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
	}

	msg = append(msg, encodeDNSName(question)...)
	msg = append(msg, 0x00, 0x0c, 0x00, 0x01)

	msg = append(msg, 0xc0, 0x0c)
	msg = append(msg, 0x00, 0x0c, 0x00, 0x01)
	msg = append(msg, 0x00, 0x00, 0x00, 0x78)

	rdata := encodeDNSName(answer)
	msg = append(msg, byte(len(rdata)>>8), byte(len(rdata)))
	msg = append(msg, rdata...)
	return msg
}

func encodeDNSName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0x00}
	}

	var out []byte
	for _, part := range strings.Split(name, ".") {
		out = append(out, byte(len(part)))
		out = append(out, part...)
	}
	out = append(out, 0x00)
	return out
}
