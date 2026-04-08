//go:build windows

package mdns

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

func newSocket() (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error

			err := c.Control(func(fd uintptr) {
				controlErr = syscall.SetsockoptInt(
					syscall.Handle(fd),
					syscall.SOL_SOCKET,
					syscall.SO_REUSEADDR,
					1,
				)
			})
			if err != nil {
				return err
			}
			return controlErr
		},
	}

	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:5353")
	if err != nil {
		return nil, fmt.Errorf("windows mDNS socket: %w", err)
	}

	return pc, nil
}
