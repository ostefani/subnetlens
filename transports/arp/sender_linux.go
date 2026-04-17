// Copyright (c) 2026 Olha Stefanishyna. MIT License.
//go:build linux

package arp

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func activeSupported() bool { return true }

type senderLinux struct {
	fd     int
	srcMAC net.HardwareAddr
	srcIP  net.IP
	sa     unix.SockaddrLinklayer
}

func newSender(iface *net.Interface, srcIP net.IP) (sender, error) {
	if iface == nil {
		return nil, fmt.Errorf("nil interface")
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("invalid hardware address for %s", iface.Name)
	}
	ip4 := srcIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("invalid source IPv4 for %s", iface.Name)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return nil, err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1); err != nil {
		unix.Close(fd)
		return nil, err
	}
	tv := unix.Timeval{Sec: 0, Usec: 200000}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	var sa unix.SockaddrLinklayer
	sa.Ifindex = iface.Index
	sa.Protocol = htons(unix.ETH_P_ARP)
	sa.Halen = 6
	copy(sa.Addr[:], broadcastMAC())

	return &senderLinux{
		fd:     fd,
		srcMAC: iface.HardwareAddr,
		srcIP:  ip4,
		sa:     sa,
	}, nil
}

func (s *senderLinux) Send(targetIP net.IP) error {
	ip4 := targetIP.To4()
	if ip4 == nil {
		return fmt.Errorf("invalid target ip")
	}
	frame := buildRequest(s.srcMAC, s.srcIP, ip4)
	return unix.Sendto(s.fd, frame, 0, &s.sa)
}

func (s *senderLinux) Close() error {
	return unix.Close(s.fd)
}

func (s *senderLinux) Listen(ctx context.Context, inject func(net.IP, net.HardwareAddr), logf Logger) {
	buf := make([]byte, 2048)
	for {
		if ctx.Err() != nil {
			return
		}
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR || err == unix.ETIMEDOUT {
				continue
			}
			log(logf, "active sweep recv error: %v", err)
			continue
		}
		ip, mac, ok := parseReply(buf[:n])
		if !ok {
			continue
		}
		inject(ip, mac)
	}
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}
