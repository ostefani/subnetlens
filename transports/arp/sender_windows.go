// Copyright (c) 2026 Olha Stefanishyna. MIT License.
//go:build windows

package arp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func activeSupported() bool { return true }

type senderWindows struct {
	device string
	tx     *pcap.Handle
	srcMAC net.HardwareAddr
	srcIP  net.IP
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

	device, err := findWindowsPCAPDevice(iface, ip4)
	if err != nil {
		return nil, err
	}

	tx, err := pcap.OpenLive(device, 65536, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open pcap device %q: %w", device, err)
	}

	return &senderWindows{
		device: device,
		tx:     tx,
		srcMAC: append(net.HardwareAddr(nil), iface.HardwareAddr...),
		srcIP:  append(net.IP(nil), ip4...),
	}, nil
}

func (s *senderWindows) Send(targetIP net.IP) error {
	ip4 := targetIP.To4()
	if ip4 == nil {
		return fmt.Errorf("invalid target ip")
	}

	data, err := buildRequestPacket(s.srcMAC, s.srcIP, ip4)
	if err != nil {
		return err
	}

	return s.tx.WritePacketData(data)
}

func (s *senderWindows) Close() error {
	if s.tx == nil {
		return nil
	}

	s.tx.Close()
	return nil
}

func (s *senderWindows) Listen(ctx context.Context, inject func(net.IP, net.HardwareAddr), logf Logger) {
	if inject == nil {
		return
	}

	rx, err := pcap.OpenLive(s.device, 65536, false, 100*time.Millisecond)
	if err != nil {
		log(logf, "windows passive listener unavailable: %v", err)
		return
	}
	defer rx.Close()

	if err := rx.SetBPFFilter("arp"); err != nil {
		log(logf, "windows passive listener filter failed: %v", err)
		return
	}

	for {
		if ctx.Err() != nil {
			return
		}

		data, _, err := rx.ReadPacketData()
		if err != nil {
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			log(logf, "windows passive listener read error: %v", err)
			return
		}

		packet := gopacket.NewPacket(data, rx.LinkType(), gopacket.Default)
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}

		arpPkt, ok := arpLayer.(*layers.ARP)
		if !ok || arpPkt == nil {
			continue
		}
		if arpPkt.Operation != layers.ARPReply {
			continue
		}
		if len(arpPkt.SourceProtAddress) != 4 || len(arpPkt.SourceHwAddress) != 6 {
			continue
		}

		ip := net.IP(append([]byte(nil), arpPkt.SourceProtAddress...)).To4()
		mac := net.HardwareAddr(append([]byte(nil), arpPkt.SourceHwAddress...))
		if ip == nil || mac == nil {
			continue
		}

		inject(ip, mac)
	}
}

func findWindowsPCAPDevice(iface *net.Interface, srcIP net.IP) (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("enumerate pcap devices: %w", err)
	}

	var fallback string

	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if addr.IP == nil {
				continue
			}
			if ip4 := addr.IP.To4(); ip4 != nil && ip4.Equal(srcIP) {
				return dev.Name, nil
			}
		}

		if fallback == "" {
			if dev.Name == iface.Name || strings.EqualFold(dev.Description, iface.Name) {
				fallback = dev.Name
			}
		}
	}

	if fallback != "" {
		return fallback, nil
	}

	return "", fmt.Errorf("no pcap device found for interface %s (%s)", iface.Name, srcIP)
}

func buildRequestPacket(srcMAC net.HardwareAddr, srcIP, targetIP net.IP) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(targetIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
