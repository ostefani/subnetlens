package mdns

import (
	"context"
	"fmt"
	"net"
)

func TriggerServiceDiscovery(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	mcastAddr, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if err != nil {
		return err
	}

	query := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x09, 0x5f, 0x73, 0x65,
		0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x07, 0x5f,
		0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64, 0x04, 0x5f,
		0x75, 0x64, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61,
		0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01,
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	eligible := 0
	sent := 0
	var lastErr error
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil || ipnet.IP.IsLoopback() {
				continue
			}
			eligible++

			localAddr := &net.UDPAddr{IP: ipnet.IP.To4(), Port: 0}
			conn, err := net.DialUDP("udp4", localAddr, mcastAddr)
			if err != nil {
				lastErr = err
				continue
			}

			if ctx.Err() != nil {
				conn.Close()
				return ctx.Err()
			}

			if _, err := conn.Write(query); err != nil {
				lastErr = err
				conn.Close()
				continue
			}
			conn.Close()
			sent++
			break
		}
	}

	if sent > 0 {
		return nil
	}
	if eligible == 0 {
		return fmt.Errorf("no active multicast-capable interfaces available for active mDNS discovery")
	}
	if lastErr != nil {
		return fmt.Errorf("failed to send active mDNS discovery trigger: %w", lastErr)
	}
	return fmt.Errorf("active mDNS discovery trigger was not sent")
}
