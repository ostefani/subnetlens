package arp

import (
	"encoding/binary"
	"net"
)

func buildRequest(srcMAC net.HardwareAddr, srcIP, targetIP net.IP) []byte {
	frame := make([]byte, 42)
	copy(frame[0:6], broadcastMAC())
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)

	binary.BigEndian.PutUint16(frame[14:16], 0x0001)
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	frame[18] = 6
	frame[19] = 4
	binary.BigEndian.PutUint16(frame[20:22], 0x0001)
	copy(frame[22:28], srcMAC)
	copy(frame[28:32], srcIP.To4())
	copy(frame[38:42], targetIP.To4())
	return frame
}

func broadcastMAC() []byte {
	return []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

func parseReply(frame []byte) (net.IP, net.HardwareAddr, bool) {
	if len(frame) < 42 {
		return nil, nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0806 {
		return nil, nil, false
	}
	if binary.BigEndian.Uint16(frame[14:16]) != 0x0001 {
		return nil, nil, false
	}
	if binary.BigEndian.Uint16(frame[16:18]) != 0x0800 {
		return nil, nil, false
	}
	if frame[18] != 6 || frame[19] != 4 {
		return nil, nil, false
	}
	if binary.BigEndian.Uint16(frame[20:22]) != 0x0002 {
		return nil, nil, false
	}
	mac := net.HardwareAddr(frame[22:28])
	ip := net.IP(frame[28:32])
	return ip, mac, true
}
