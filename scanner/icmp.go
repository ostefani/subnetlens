package scanner

import (
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// --- Named types ---

type icmpResult struct {
	latency time.Duration
	err     error
}

type ICMPScanner struct {
	conn    *icmp.PacketConn
	pending sync.Map
	id      int
	seq     uint32
}

func NewICMPScanner() (*ICMPScanner, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	s := &ICMPScanner{
		conn: conn,
		id:   os.Getpid() & 0xffff,
	}

	go s.receiverLoop()
	return s, nil
}

func (s *ICMPScanner) Close() error {
	return s.conn.Close()
}

func (s *ICMPScanner) receiverLoop() {
	readBuf := make([]byte, 1500)
	for {
		n, _, err := s.conn.ReadFrom(readBuf)
		if err != nil {
			return // Socket closed
		}

		msg, err := icmp.ParseMessage(1, readBuf[:n])
		if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok || echo.ID != s.id {
			continue
		}

		// Find the goroutine waiting for this specific sequence number
		if chRaw, ok := s.pending.Load(uint16(echo.Seq)); ok {
			ch := chRaw.(chan icmpResult)
			ch <- icmpResult{latency: 0}
		}
	}
}

func (s *ICMPScanner) Probe(ctx context.Context, ip string, timeout time.Duration) (bool, time.Duration, error) {
	seq := uint16(atomic.AddUint32(&s.seq, 1) & 0xffff)
	dest := &net.IPAddr{IP: net.ParseIP(ip)}

	resCh := make(chan icmpResult, 1)
	s.pending.Store(seq, resCh)
	defer s.pending.Delete(seq)

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: s.id, Seq: int(seq), Data: []byte("SL")},
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

// Warm sends a minimal ICMP echo to prime neighbor/ARP caches.
// It does not track a response and will ignore any replies.
func (s *ICMPScanner) Warm(ip string) error {
	seq := uint16(atomic.AddUint32(&s.seq, 1) & 0xffff)
	dest := &net.IPAddr{IP: net.ParseIP(ip)}
	warmID := s.id ^ 0xffff

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: warmID, Seq: int(seq)},
	}
	b, _ := msg.Marshal(nil)
	_, err := s.conn.WriteTo(b, dest)
	return err
}
