package models

import "time"

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
	Source    string // "arp", "mdns", "icmp", "tcp", "mixed"

	alive bool
}

func (h *Host) MarkSeen(source string) {
	now := time.Now()
	if h.SeenAt.IsZero() {
		h.SeenAt = now
	}
	h.UpdatedAt = now
	if h.Source == "" {
		h.Source = source
	} else if h.Source != source && h.Source != "mixed" {
		h.Source = "mixed"
	}
}

func (h *Host) IsAlive() bool   { return h.alive }
func (h *Host) SetAlive(v bool) { h.alive = v }

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
	AllAlive bool
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