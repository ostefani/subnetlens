//go:build !windows

package scanner

import (
	"context"
	"net"
	"syscall"
)

func newMDNSSocket() (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var setSockErr error
			err := c.Control(func(fd uintptr) {
				setSockErr = syscall.SetsockoptInt(
					int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1,
				)
			})
			if err != nil {
				return err
			}
			return setSockErr
		},
	}
	return lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:5353")
}