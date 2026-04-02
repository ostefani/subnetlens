package models

import (
	"sync"
	"time"

	"github.com/ostefani/subnetlens/internal/textutil"
)

type Port struct {
	Number   int
	Protocol string
	State    PortState
	Service  string
	Banner   string
}

type PortState string

const (
	PortOpen     PortState = "open"
	PortClosed   PortState = "closed"
	PortFiltered PortState = "filtered"
)

type Host struct {
	mu sync.RWMutex

	ip        string
	Hostname  string
	MAC       string
	Vendor    string
	Latency   time.Duration
	OpenPorts []Port
	OS        string
	Device    string

	SeenAt    time.Time
	UpdatedAt time.Time
	Source    string // "arp", "mdns", "icmp", "tcp", "mixed"

	alive bool
}

type HostSnapshot struct {
	IP        string
	Hostname  string
	MAC       string
	Vendor    string
	Latency   time.Duration
	OpenPorts []Port
	OS        string
	Device    string
	SeenAt    time.Time
	UpdatedAt time.Time
	Source    string
	Alive     bool
}

func NewHost(ip string) *Host {
	return &Host{
		ip:       ip,
		Hostname: ip,
	}
}

func (h *Host) IP() string {
	if h == nil {
		return ""
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.ip
}

func (h *Host) Snapshot() HostSnapshot {
	if h == nil {
		return HostSnapshot{}
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	snapshot := HostSnapshot{
		IP:        h.ip,
		Hostname:  h.Hostname,
		MAC:       h.MAC,
		Vendor:    h.Vendor,
		Latency:   h.Latency,
		OS:        h.OS,
		Device:    h.Device,
		SeenAt:    h.SeenAt,
		UpdatedAt: h.UpdatedAt,
		Source:    h.Source,
		Alive:     h.alive,
	}
	if len(h.OpenPorts) > 0 {
		snapshot.OpenPorts = append([]Port(nil), h.OpenPorts...)
	}

	return snapshot
}

func (h *Host) MarkSeen(source string) bool {
	if h == nil || source == "" {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	return h.markSeenLocked(source)
}

func (h *Host) markSeenLocked(source string) bool {
	now := time.Now()
	changed := false
	if h.SeenAt.IsZero() {
		h.SeenAt = now
		changed = true
	}
	h.UpdatedAt = now
	if h.Source == "" {
		h.Source = source
		changed = true
	} else if h.Source != source && h.Source != "mixed" {
		h.Source = "mixed"
		changed = true
	}

	return changed
}

func (h *Host) IsAlive() bool {
	if h == nil {
		return false
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.alive
}

func (h *Host) SetAlive(v bool) bool {
	if h == nil {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.alive == v {
		return false
	}
	h.alive = v
	return true
}

func (h *Host) SetMAC(mac string) bool {
	if h == nil || mac == "" {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.MAC == mac {
		return false
	}
	h.MAC = mac
	return true
}

func (h *Host) SetMACIfEmpty(mac string) bool {
	if h == nil || mac == "" {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.MAC != "" {
		return false
	}
	h.MAC = mac
	return true
}

func (h *Host) SetHostname(name string) bool {
	name = textutil.SanitizeInline(name)
	if h == nil || name == "" {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.Hostname == name {
		return false
	}
	h.Hostname = name
	return true
}

func (h *Host) SetHostnameIfEmptyOrIP(name string) bool {
	name = textutil.SanitizeInline(name)
	if h == nil || name == "" {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.Hostname != "" && h.Hostname != h.ip {
		return false
	}
	if h.Hostname == name {
		return false
	}
	h.Hostname = name
	return true
}

func (h *Host) SetVendor(vendor string) bool {
	vendor = textutil.SanitizeInline(vendor)
	if h == nil || vendor == "" {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.Vendor == vendor {
		return false
	}
	h.Vendor = vendor
	return true
}

func (h *Host) SetVendorIfEmpty(vendor string) bool {
	vendor = textutil.SanitizeInline(vendor)
	if h == nil || vendor == "" {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.Vendor != "" {
		return false
	}
	h.Vendor = vendor
	return true
}

func (h *Host) SetDevice(device string) bool {
	device = textutil.SanitizeInline(device)
	if h == nil || device == "" {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.Device == device {
		return false
	}
	h.Device = device
	return true
}

func (h *Host) SetDeviceIfEmpty(device string) bool {
	device = textutil.SanitizeInline(device)
	if h == nil || device == "" {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.Device != "" {
		return false
	}
	h.Device = device
	return true
}

func (h *Host) SetOS(hostOS string) bool {
	hostOS = textutil.SanitizeInline(hostOS)
	if h == nil || hostOS == "" {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.OS == hostOS {
		return false
	}
	h.OS = hostOS
	return true
}

func (h *Host) SetLatency(latency time.Duration) bool {
	if h == nil || latency <= 0 {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.Latency == latency {
		return false
	}
	h.Latency = latency
	return true
}

func (h *Host) SetLatencyIfZero(latency time.Duration) bool {
	if h == nil || latency <= 0 {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.Latency != 0 {
		return false
	}
	h.Latency = latency
	return true
}

func (h *Host) SetOpenPorts(ports []Port) bool {
	if h == nil {
		return false
	}

	copied := append([]Port(nil), ports...)

	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.OpenPorts) == len(copied) {
		same := true
		for i := range copied {
			if h.OpenPorts[i] != copied[i] {
				same = false
				break
			}
		}
		if same {
			return false
		}
	}

	h.OpenPorts = copied
	return true
}

func (h *Host) AddPort(port Port) bool {
	if h == nil {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	for _, existing := range h.OpenPorts {
		if existing.Number == port.Number && existing.Protocol == port.Protocol {
			return false
		}
	}
	h.OpenPorts = append(h.OpenPorts, port)
	return true
}

type ScanResult struct {
	Subnet     string
	StartedAt  time.Time
	FinishedAt time.Time
	Hosts      []*Host
}

func (r *ScanResult) Duration() time.Duration {
	return r.FinishedAt.Sub(r.StartedAt)
}

func (r *ScanResult) AliveHosts() []*Host {
	var alive []*Host
	for _, h := range r.Hosts {
		if h.IsAlive() {
			alive = append(alive, h)
		}
	}
	return alive
}

type ScanOptions struct {
	Subnet      string
	Ports       []int
	Timeout     time.Duration // per-connection timeout
	Concurrency int           // parallel goroutines
	GrabBanners bool
	AllAlive    bool
}

var CommonPorts = []int{
	// ── Standard services ─────────────────────────────────────────────────
	21, 22, 23, 25, 53, 80, 110, 139, 143,
	443, 445, 587, 993, 995,

	// ── Databases ─────────────────────────────────────────────────────────
	3306, 5432, 6379, 9200,

	// ── Remote access / desktop ───────────────────────────────────────────
	3389, 5900,

	// ── HTTP alternates ───────────────────────────────────────────────────
	8080, 8443, 8888,

	// ── Apple / iOS / macOS ───────────────────────────────────────────────
	// 548   — AFP (Apple Filing Protocol); macOS File Sharing
	// 5000  — AirPlay receiver (macOS 12+)
	// 7000  — AirPlay video mirroring (macOS + Apple TV)
	// 62078 — lockdownd; present on every iPhone/iPad; primary iOS signal
	548, 5000, 7000, 62078,
	// ── Android / Samsung ─────────────────────────────────────────────────
	// 5555  — ADB (Android Debug Bridge); only open if USB debugging enabled
	// 7676  — Samsung AllShare / Media sharing
	// 8200  — Samsung Smart Switch
	// 9100  — Samsung printer services (Galaxy phones with print plugins)
	// 49152 — UPnP / DLNA media server (common on Samsung devices)
	// 1900  — SSDP/UPnP discovery (Samsung SmartThings, DLNA)
	5555, 7676, 8200, 49152,
}
