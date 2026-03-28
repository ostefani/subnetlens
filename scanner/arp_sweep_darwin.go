//go:build darwin

package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

func activeARPSupported() bool { return true }

type arpSenderDarwin struct {
	fd     int
	srcMAC net.HardwareAddr
	srcIP  net.IP
}

type bpfIfreq struct {
	Name [unix.IFNAMSIZ]byte
	// BIOCSETIF expects a full Darwin struct ifreq. Only ifr_name matters for
	// this ioctl, but the kernel still copies sizeof(struct ifreq) bytes.
	Pad [16]byte
}

func newARPSender(iface *net.Interface, srcIP net.IP) (arpSender, error) {
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

	fd, err := openBPF()
	if err != nil {
		return nil, err
	}

	var ifr bpfIfreq
	copy(ifr.Name[:], iface.Name)
	if err := ioctlSetPointer(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr)); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("BIOCSETIF %s: %w", iface.Name, err)
	}

	if err := unix.IoctlSetPointerInt(fd, unix.BIOCSHDRCMPLT, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("BIOCSHDRCMPLT: %w", err)
	}

	if err := unix.IoctlSetPointerInt(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("BIOCIMMEDIATE: %w", err)
	}

	_ = unix.SetNonblock(fd, true)

	return &arpSenderDarwin{
		fd:     fd,
		srcMAC: iface.HardwareAddr,
		srcIP:  ip4,
	}, nil
}

func (s *arpSenderDarwin) Send(targetIP net.IP) error {
	ip4 := targetIP.To4()
	if ip4 == nil {
		return fmt.Errorf("invalid target ip")
	}
	frame := buildARPRequest(s.srcMAC, s.srcIP, ip4)
	_, err := unix.Write(s.fd, frame)
	return err
}

func (s *arpSenderDarwin) Close() error {
	return unix.Close(s.fd)
}

func (s *arpSenderDarwin) Listen(ctx context.Context, inject func(net.IP, net.HardwareAddr)) {
	bufLen := getBPFBufferLength(s.fd)
	if bufLen < 256 {
		bufLen = 4096
	}
	buf := make([]byte, bufLen)

	for {
		if ctx.Err() != nil {
			return
		}
		n, err := unix.Read(s.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			debugLog("arp", "active sweep recv error: %v", err)
			continue
		}
		if n <= 0 {
			continue
		}

		parseBPFFrames(buf[:n], func(frame []byte) {
			kind, _, ip, mac := classifyARPFrame(frame)
			if kind == "arp-reply" {
				inject(ip, mac)
			}
		})
	}
}

func openBPF() (int, error) {
	for i := 0; i < 255; i++ {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := unix.Open(path, unix.O_RDWR, 0)
		if err == nil {
			return fd, nil
		}
		if err == unix.EBUSY {
			continue
		}
		return -1, err
	}
	return -1, fmt.Errorf("no available BPF devices")
}

func ioctlSetPointer(fd int, req uintptr, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

func getBPFBufferLength(fd int) int {
	v, err := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if err != nil {
		return 0
	}
	return v
}

func parseBPFFrames(buf []byte, handle func([]byte)) int {
	// Darwin BPF timeval is two 32-bit integers (8 bytes), rather than the 16-byte unix.Timeval.
	tvSize := 8
	offset := 0
	frames := 0
	for {
		if offset+tvSize+10 > len(buf) {
			return frames
		}
		caplen := int(binary.LittleEndian.Uint32(buf[offset+tvSize:]))
		hdrlen := int(binary.LittleEndian.Uint16(buf[offset+tvSize+8:]))
		if hdrlen <= 0 {
			return frames
		}
		dataStart := offset + hdrlen
		dataEnd := dataStart + caplen
		if dataEnd > len(buf) {
			return frames
		}
		handle(buf[dataStart:dataEnd])
		frames++
		offset += bpfWordAlign(hdrlen + caplen)
		if offset >= len(buf) {
			return frames
		}
	}
}

func bpfWordAlign(x int) int {
	return (x + 3) &^ 3
}

func classifyARPFrame(frame []byte) (kind, summary string, ip net.IP, mac net.HardwareAddr) {
	if len(frame) < 14 {
		return "short", fmt.Sprintf("len=%d", len(frame)), nil, nil
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType != 0x0806 {
		return "non-arp", fmt.Sprintf("len=%d ethertype=0x%04x", len(frame), etherType), nil, nil
	}

	if len(frame) < 42 {
		return "short", fmt.Sprintf("len=%d ethertype=0x0806", len(frame)), nil, nil
	}

	if binary.BigEndian.Uint16(frame[14:16]) != 0x0001 || binary.BigEndian.Uint16(frame[16:18]) != 0x0800 {
		return "arp-other", fmt.Sprintf("len=%d htype=0x%04x ptype=0x%04x", len(frame), binary.BigEndian.Uint16(frame[14:16]), binary.BigEndian.Uint16(frame[16:18])), nil, nil
	}
	if frame[18] != 6 || frame[19] != 4 {
		return "arp-other", fmt.Sprintf("len=%d hlen=%d plen=%d", len(frame), frame[18], frame[19]), nil, nil
	}

	opcode := binary.BigEndian.Uint16(frame[20:22])
	senderIP := net.IPv4(frame[28], frame[29], frame[30], frame[31])
	targetIP := net.IPv4(frame[38], frame[39], frame[40], frame[41])
	senderMAC := net.HardwareAddr(append([]byte(nil), frame[22:28]...))

	summary = fmt.Sprintf("len=%d opcode=%d sender_ip=%s sender_mac=%s target_ip=%s", len(frame), opcode, senderIP, senderMAC, targetIP)
	switch opcode {
	case 0x0001:
		return "arp-request", summary, nil, nil
	case 0x0002:
		return "arp-reply", summary, senderIP, senderMAC
	default:
		return "arp-other", summary, nil, nil
	}
}
