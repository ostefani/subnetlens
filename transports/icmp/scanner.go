package icmp

import (
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	xicmp "golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type result struct {
	latency time.Duration
}

type Scanner struct {
	conn    *xicmp.PacketConn
	pending sync.Map
	id      int
	seq     uint32
}

func NewScanner() (*Scanner, error) {
	conn, err := xicmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	s := &Scanner{
		conn: conn,
		id:   os.Getpid() & 0xffff,
	}

	go s.receiverLoop()
	return s, nil
}

func (s *Scanner) Close() error {
	return s.conn.Close()
}

func (s *Scanner) Probe(ctx context.Context, ip string, timeout time.Duration) (bool, time.Duration, error) {
	seq := uint16(atomic.AddUint32(&s.seq, 1) & 0xffff)
	dest := &net.IPAddr{IP: net.ParseIP(ip)}

	resCh := make(chan result, 1)
	s.pending.Store(seq, resCh)
	defer s.pending.Delete(seq)

	msg := xicmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &xicmp.Echo{ID: s.id, Seq: int(seq), Data: []byte("SL")},
	}
	b, _ := msg.Marshal(nil)

	start := time.Now()
	if _, err := s.conn.WriteTo(b, dest); err != nil {
		return false, 0, err
	}

	select {
	case <-resCh:
		return true, time.Since(start), nil
	case <-time.After(timeout):
		return false, 0, nil
	case <-ctx.Done():
		return false, 0, ctx.Err()
	}
}

func (s *Scanner) Warm(ip string) error {
	seq := uint16(atomic.AddUint32(&s.seq, 1) & 0xffff)
	dest := &net.IPAddr{IP: net.ParseIP(ip)}
	warmID := s.id ^ 0xffff

	msg := xicmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &xicmp.Echo{ID: warmID, Seq: int(seq)},
	}
	b, _ := msg.Marshal(nil)
	_, err := s.conn.WriteTo(b, dest)
	return err
}

func (s *Scanner) receiverLoop() {
	readBuf := make([]byte, 1500)
	for {
		n, _, err := s.conn.ReadFrom(readBuf)
		if err != nil {
			return
		}

		msg, err := xicmp.ParseMessage(1, readBuf[:n])
		if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		echo, ok := msg.Body.(*xicmp.Echo)
		if !ok || echo.ID != s.id {
			continue
		}

		if chRaw, ok := s.pending.Load(uint16(echo.Seq)); ok {
			ch := chRaw.(chan result)
			ch <- result{}
		}
	}
}
