// Copyright (c) 2026 Olha Stefanishyna. MIT License.
//go:build !linux && !darwin && !windows

package arp

import (
	"fmt"
	"net"
)

func activeSupported() bool { return false }

func newSender(_ *net.Interface, _ net.IP) (sender, error) {
	return nil, fmt.Errorf("active ARP not supported on this platform")
}
