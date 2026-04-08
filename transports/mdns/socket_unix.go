//go:build !windows

package mdns

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func newSocket() (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var setSockErr error
			err := c.Control(func(fd uintptr) {
				setSockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return setSockErr
		},
	}
	return lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:5353")
}
