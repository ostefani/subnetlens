//go:build windows

package scanner

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// NOTE:
// Windows mDNS passive listening is best-effort here and has NOT been tested yet.
// This file exists so the package still builds on Windows.
// Someone should verify actual receive behavior on a real Windows machine.
//
// Windows does not support SO_REUSEPORT like Unix does, so this uses SO_REUSEADDR
// as the closest practical option for a UDP listener on 5353.
func newMDNSSocket() (net.PacketConn, error) {
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