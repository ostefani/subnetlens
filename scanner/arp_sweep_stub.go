//go:build !linux && !darwin && !windows

package scanner

import (
	"fmt"
	"net"
)

func activeARPSupported() bool { return false }

func newARPSender(_ *net.Interface, _ net.IP) (arpSender, error) {
	return nil, fmt.Errorf("active ARP not supported on this platform")
}