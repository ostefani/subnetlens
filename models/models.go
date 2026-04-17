// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package models

import (
	"slices"
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

	// Fingerprint stores low-noise scan-time evidence that classifiers can
	// parse without needing to open new network connections.
	Fingerprint PortFingerprint
}

type PortFingerprint struct {
	SSHGreeting string
	HTTPServer  string
	TLSSummary  string
}

type PortState string

const (
	PortOpen     PortState = "open"
	PortClosed   PortState = "closed"
	PortFiltered PortState = "filtered"
)

type HostSource string

const (
	HostSourceARP   HostSource = "arp"
	HostSourceMDNS  HostSource = "mdns"
	HostSourceNBNS  HostSource = "nbns"
	HostSourcePTR   HostSource = "ptr"
	HostSourceICMP  HostSource = "icmp"
	HostSourceTCP   HostSource = "tcp"
	HostSourceUDP   HostSource = "udp"
	HostSourceSelf  HostSource = "self"
	HostSourceMixed HostSource = "mixed"
)

type IdentityConfidence string

const (
	IdentityConfidenceLow  IdentityConfidence = "low"
	IdentityConfidenceHigh IdentityConfidence = "high"
)

type IdentitySource string

const (
	IdentitySourceUnknown  IdentitySource = ""
	IdentitySourceIP       IdentitySource = "ip"
	IdentitySourceMAC      IdentitySource = "mac"
	IdentitySourceProvided IdentitySource = "provided"
)

type HostIdentity struct {
	HostID             string
	IdentityConfidence IdentityConfidence
	IdentitySource     IdentitySource
	IdentityAliases    []string
	IdentityAnchorKeys []string
}

type ScanIssueLevel string

const (
	ScanIssueLevelWarning ScanIssueLevel = "warning"
)

type ScanIssue struct {
	At      time.Time
	Level   ScanIssueLevel
	Source  string
	Message string
}

func (i ScanIssue) String() string {
	switch {
	case i.Source != "" && i.Level != "":
		return string(i.Level) + " [" + i.Source + "]: " + i.Message
	case i.Source != "":
		return "[" + i.Source + "]: " + i.Message
	case i.Level != "":
		return string(i.Level) + ": " + i.Message
	default:
		return i.Message
	}
}

type Host struct {
	mu sync.RWMutex

	ip            string
	Hostname      string
	MAC           string
	RandomizedMAC bool
	Vendor        string
	Latency       time.Duration
	Ports         []Port
	OS            string
	Device        string

	SeenAt    time.Time
	UpdatedAt time.Time
	Source    HostSource

	alive bool
	weak  bool

	livenessBySource map[HostSource]livenessObservation

	identity         HostIdentity
	identityOverride HostIdentity
}

type livenessObservation struct {
	alive     bool
	weak      bool
	expiresAt time.Time
}

type HostSnapshot struct {
	IP            string
	Hostname      string
	MAC           string
	RandomizedMAC bool
	Vendor        string
	Latency       time.Duration
	Ports         []Port
	OS            string
	Device        string
	SeenAt        time.Time
	UpdatedAt     time.Time
	Source        HostSource
	Alive         bool
	Weak          bool

	HostID             string
	IdentityConfidence IdentityConfidence
	IdentitySource     IdentitySource
	IdentityAliases    []string
	IdentityAnchorKeys []string
}

func NewHost(ip string) *Host {
	return &Host{
		ip:       ip,
		Hostname: ip,
		identity: deriveIdentityMetadata(ip, ip, "", false),
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

	alive, weak := h.currentLivenessLocked(time.Now())

	snapshot := HostSnapshot{
		IP:                 h.ip,
		Hostname:           h.Hostname,
		MAC:                h.MAC,
		RandomizedMAC:      h.RandomizedMAC,
		Vendor:             h.Vendor,
		Latency:            h.Latency,
		OS:                 h.OS,
		Device:             h.Device,
		SeenAt:             h.SeenAt,
		UpdatedAt:          h.UpdatedAt,
		Source:             h.Source,
		Alive:              alive,
		Weak:               weak,
		HostID:             h.identity.HostID,
		IdentityConfidence: h.identity.IdentityConfidence,
		IdentitySource:     h.identity.IdentitySource,
	}
	if len(h.Ports) > 0 {
		snapshot.Ports = append([]Port(nil), h.Ports...)
	}
	if len(h.identity.IdentityAliases) > 0 {
		snapshot.IdentityAliases = append([]string(nil), h.identity.IdentityAliases...)
	}
	if len(h.identity.IdentityAnchorKeys) > 0 {
		snapshot.IdentityAnchorKeys = append([]string(nil), h.identity.IdentityAnchorKeys...)
	}

	return snapshot
}

func (s HostSnapshot) OpenPorts() []Port {
	return filterOpenPorts(s.Ports)
}

func (s *HostSnapshot) applyIdentityMetadata() {
	if s == nil {
		return
	}

	derived := deriveIdentityMetadata(s.IP, s.Hostname, s.MAC, s.RandomizedMAC)
	if s.HostID == "" {
		s.HostID = derived.HostID
	}
	if s.IdentityConfidence == "" {
		s.IdentityConfidence = derived.IdentityConfidence
	}
	if s.IdentitySource == "" {
		s.IdentitySource = derived.IdentitySource
	}
	s.IdentityAliases = mergeIdentityValues(s.IdentityAliases, derived.IdentityAliases...)
	s.IdentityAnchorKeys = mergeIdentityValues(s.IdentityAnchorKeys, derived.IdentityAnchorKeys...)
}

func deriveIdentity(ip, mac string, randomizedMAC bool) (string, IdentityConfidence, IdentitySource) {
	if mac != "" && !randomizedMAC {
		return "mac:" + mac, IdentityConfidenceHigh, IdentitySourceMAC
	}
	if ip != "" {
		return "ip:" + ip, IdentityConfidenceLow, IdentitySourceIP
	}
	return "", IdentityConfidenceLow, IdentitySourceUnknown
}

func deriveIdentityMetadata(ip, hostname, mac string, randomizedMAC bool) HostIdentity {
	hostID, confidence, source := deriveIdentity(ip, mac, randomizedMAC)
	snapshot := HostSnapshot{
		IP:            ip,
		Hostname:      hostname,
		MAC:           mac,
		RandomizedMAC: randomizedMAC,
	}
	return HostIdentity{
		HostID:             hostID,
		IdentityConfidence: confidence,
		IdentitySource:     source,
		IdentityAliases:    deriveIdentityAliases(snapshot),
		IdentityAnchorKeys: deriveIdentityAnchorKeys(snapshot),
	}
}

func deriveIdentityAliases(snapshot HostSnapshot) []string {
	var aliases []string
	aliases = appendIdentityValue(aliases, "ip", snapshot.IP)
	if !snapshot.RandomizedMAC {
		aliases = appendIdentityValue(aliases, "mac", snapshot.MAC)
	}
	if snapshot.Hostname != "" && snapshot.Hostname != snapshot.IP {
		aliases = appendIdentityValue(aliases, "name", snapshot.Hostname)
	}
	return aliases
}

func deriveIdentityAnchorKeys(snapshot HostSnapshot) []string {
	var keys []string
	keys = appendIdentityValue(keys, "ip", snapshot.IP)
	if !snapshot.RandomizedMAC {
		keys = appendIdentityValue(keys, "mac", snapshot.MAC)
	}
	if !snapshot.RandomizedMAC && snapshot.IP != "" && snapshot.MAC != "" {
		keys = appendIdentityValue(keys, "pair", snapshot.MAC+"@"+snapshot.IP)
	}
	return keys
}

func appendIdentityValue(values []string, prefix, value string) []string {
	if value == "" {
		return values
	}

	entry := prefix + ":" + value
	if slices.Contains(values, entry) {
		return values
	}
	return append(values, entry)
}

func mergeIdentityValues(values []string, extras ...string) []string {
	merged := append([]string(nil), values...)
	for _, extra := range extras {
		if extra == "" || slices.Contains(merged, extra) {
			continue
		}
		merged = append(merged, extra)
	}
	return merged
}

func (h *Host) SetIdentity(identity HostIdentity) bool {
	if h == nil {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	normalized := normalizeHostIdentity(identity)
	if hostIdentityEqual(h.identityOverride, normalized) {
		return false
	}

	h.identityOverride = normalized
	h.rebuildIdentityLocked()
	return true
}

func (h *Host) rebuildIdentityLocked() {
	identity := deriveIdentityMetadata(h.ip, h.Hostname, h.MAC, h.RandomizedMAC)
	override := h.identityOverride

	if override.HostID != "" {
		identity.HostID = override.HostID
		if override.IdentityConfidence != "" {
			identity.IdentityConfidence = override.IdentityConfidence
		} else {
			identity.IdentityConfidence = IdentityConfidenceLow
		}
		// A custom HostID came from a producer rather than OSS derivation.
		// Keep that signal stable; more granular provenance can be added
		// separately later without weakening the provided/not-provided split.
		identity.IdentitySource = IdentitySourceProvided
	}
	if override.IdentitySource != "" && override.HostID == "" {
		identity.IdentitySource = override.IdentitySource
	}
	if override.IdentityConfidence != "" && override.HostID == "" {
		identity.IdentityConfidence = override.IdentityConfidence
	}

	identity.IdentityAliases = mergeIdentityValues(identity.IdentityAliases, override.IdentityAliases...)
	identity.IdentityAnchorKeys = mergeIdentityValues(identity.IdentityAnchorKeys, override.IdentityAnchorKeys...)
	h.identity = identity
}

func normalizeHostIdentity(identity HostIdentity) HostIdentity {
	return HostIdentity{
		HostID:             identity.HostID,
		IdentityConfidence: identity.IdentityConfidence,
		IdentitySource:     identity.IdentitySource,
		IdentityAliases:    mergeIdentityValues(nil, identity.IdentityAliases...),
		IdentityAnchorKeys: mergeIdentityValues(nil, identity.IdentityAnchorKeys...),
	}
}

func hostIdentityEqual(a, b HostIdentity) bool {
	return a.HostID == b.HostID &&
		a.IdentityConfidence == b.IdentityConfidence &&
		a.IdentitySource == b.IdentitySource &&
		slices.Equal(a.IdentityAliases, b.IdentityAliases) &&
		slices.Equal(a.IdentityAnchorKeys, b.IdentityAnchorKeys)
}

func (h *Host) MarkSeen(source HostSource) bool {
	if h == nil || source == "" {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	return h.markSeenLocked(source)
}

func (h *Host) markSeenLocked(source HostSource) bool {
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
	} else if h.Source != source && h.Source != HostSourceMixed {
		h.Source = HostSourceMixed
		changed = true
	}

	return changed
}

// MergeLiveness applies an observation's liveness, weakness, and source under a
// single lock so late weak signals cannot race with stronger confirmations.
func (h *Host) MergeLiveness(alive, weak bool, source HostSource) bool {
	return h.ObserveLiveness(alive, weak, source, time.Time{}, time.Time{})
}

func (h *Host) ObserveLiveness(alive, weak bool, source HostSource, observedAt, expiresAt time.Time) bool {
	if h == nil {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if observedAt.IsZero() {
		observedAt = time.Now()
	}

	changed := false
	h.pruneExpiredLivenessLocked(observedAt)
	if alive {
		if h.livenessBySource == nil {
			h.livenessBySource = make(map[HostSource]livenessObservation)
		}
		h.livenessBySource[source] = livenessObservation{
			alive:     true,
			weak:      weak,
			expiresAt: expiresAt,
		}
	}

	if source != "" && h.markSeenLocked(source) {
		changed = true
	}
	if h.reconcileLivenessLocked(observedAt) {
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

	alive, _ := h.currentLivenessLocked(time.Now())
	return alive
}

func (h *Host) SetAlive(v bool) bool {
	if h == nil {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	changed := len(h.livenessBySource) > 0
	h.clearObservedLivenessLocked()
	if h.alive == v && (!v || !h.weak) {
		return changed
	}
	h.alive = v
	if v {
		h.weak = false
	}
	return true
}

func (h *Host) IsWeak() bool {
	if h == nil {
		return false
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	_, weak := h.currentLivenessLocked(time.Now())
	return weak
}

func (h *Host) currentLivenessLocked(now time.Time) (bool, bool) {
	if len(h.livenessBySource) == 0 {
		return h.alive, h.weak
	}

	alive := false
	weak := false
	for _, observation := range h.livenessBySource {
		if !observation.expiresAt.IsZero() && now.After(observation.expiresAt) {
			continue
		}
		if !observation.alive {
			continue
		}
		if !observation.weak {
			alive = true
			weak = false
			break
		}
		alive = true
		weak = true
	}

	return alive, weak
}

func (h *Host) reconcileLivenessLocked(now time.Time) bool {
	alive, weak := h.currentLivenessLocked(now)
	changed := h.alive != alive || h.weak != weak
	h.alive = alive
	h.weak = weak
	return changed
}

func (h *Host) SetWeak(v bool) bool {
	if h == nil {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	changed := len(h.livenessBySource) > 0
	h.clearObservedLivenessLocked()
	if h.weak == v {
		return changed
	}
	h.weak = v
	return true
}

func (h *Host) clearObservedLivenessLocked() {
	if len(h.livenessBySource) == 0 {
		h.livenessBySource = nil
		return
	}
	clear(h.livenessBySource)
	h.livenessBySource = nil
}

func (h *Host) pruneExpiredLivenessLocked(now time.Time) {
	if len(h.livenessBySource) == 0 {
		return
	}
	for source, observation := range h.livenessBySource {
		if observation.expiresAt.IsZero() || !now.After(observation.expiresAt) {
			continue
		}
		delete(h.livenessBySource, source)
	}
	if len(h.livenessBySource) == 0 {
		h.livenessBySource = nil
	}
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
	h.rebuildIdentityLocked()
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
	h.rebuildIdentityLocked()
	return true
}

func (h *Host) SetRandomizedMAC(v bool) bool {
	if h == nil {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.RandomizedMAC == v {
		return false
	}
	h.RandomizedMAC = v
	h.rebuildIdentityLocked()
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
	h.rebuildIdentityLocked()
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
	h.rebuildIdentityLocked()
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

func (h *Host) SetPorts(ports []Port) bool {
	if h == nil {
		return false
	}

	copied := append([]Port(nil), ports...)
	sortPorts(copied)

	h.mu.Lock()
	defer h.mu.Unlock()

	if portsEqual(h.Ports, copied) {
		return false
	}

	h.Ports = copied
	return true
}

func (h *Host) SetOpenPorts(ports []Port) bool {
	return h.SetPorts(filterOpenPorts(ports))
}

// SetProtocolPorts replaces the host's ports for one protocol while preserving
// any ports discovered for other protocols.
func (h *Host) SetProtocolPorts(protocol string, ports []Port) bool {
	return h.setProtocolPorts(protocol, ports, false)
}

// SetProtocolPortsAndMarkAlive replaces the host's ports for one protocol while
// preserving ports discovered for other protocols. When any replacement port is
// open, the host is atomically promoted to alive and strong.
func (h *Host) SetProtocolPortsAndMarkAlive(protocol string, ports []Port) bool {
	return h.setProtocolPorts(protocol, ports, true)
}

func (h *Host) setProtocolPorts(protocol string, ports []Port, markAliveOnOpen bool) bool {
	if h == nil || protocol == "" {
		return false
	}

	replacement := append([]Port(nil), ports...)
	hasOpen := false
	for i := range replacement {
		replacement[i].Protocol = protocol
		if replacement[i].State == PortOpen {
			hasOpen = true
		}
	}
	sortPorts(replacement)

	h.mu.Lock()
	defer h.mu.Unlock()

	merged := make([]Port, 0, len(h.Ports)+len(replacement))
	for _, existing := range h.Ports {
		if existing.Protocol == protocol {
			continue
		}
		merged = append(merged, existing)
	}
	merged = append(merged, replacement...)
	sortPorts(merged)

	if portsEqual(h.Ports, merged) {
		currentAlive, currentWeak := h.currentLivenessLocked(time.Now())
		if !(markAliveOnOpen && hasOpen && (!currentAlive || currentWeak || len(h.livenessBySource) > 0)) {
			return false
		}
	}

	h.Ports = merged
	if markAliveOnOpen && hasOpen {
		h.clearObservedLivenessLocked()
		h.alive = true
		h.weak = false
	}
	return true
}

func (h *Host) AddPort(port Port) bool {
	if h == nil {
		return false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	merged, changed := upsertPort(h.Ports, port)
	if !changed {
		return false
	}

	h.Ports = merged
	return true
}

func filterOpenPorts(ports []Port) []Port {
	if len(ports) == 0 {
		return nil
	}

	openPorts := make([]Port, 0, len(ports))
	for _, port := range ports {
		if port.State == PortOpen {
			openPorts = append(openPorts, port)
		}
	}
	if len(openPorts) == 0 {
		return nil
	}
	return openPorts
}

func portsEqual(a, b []Port) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sortPorts(ports []Port) {
	slices.SortFunc(ports, func(a, b Port) int {
		if a.Number != b.Number {
			if a.Number < b.Number {
				return -1
			}
			return 1
		}
		switch {
		case a.Protocol < b.Protocol:
			return -1
		case a.Protocol > b.Protocol:
			return 1
		default:
			return 0
		}
	})
}

func upsertPort(ports []Port, port Port) ([]Port, bool) {
	merged := append([]Port(nil), ports...)
	for i, existing := range merged {
		if existing.Number != port.Number || existing.Protocol != port.Protocol {
			continue
		}
		if existing == port {
			return ports, false
		}
		merged[i] = port
		sortPorts(merged)
		return merged, true
	}

	merged = append(merged, port)
	sortPorts(merged)
	return merged, true
}

type ScanResult struct {
	Subnet     string
	StartedAt  time.Time
	FinishedAt time.Time
	Hosts      []*Host
	Issues     []ScanIssue
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
	Subnet               string
	Ports                []int
	Timeout              time.Duration // per-connection timeout
	Concurrency          int           // max concurrent port/banner probes
	DiscoveryConcurrency int           // max concurrent host discovery probes; 0 falls back to Concurrency
	GrabBanners          bool
	AllAlive             bool
}

const DefaultConcurrency = 100

func (o ScanOptions) ScanConcurrencyLimit() int {
	return normalizedConcurrency(o.Concurrency, DefaultConcurrency)
}

func (o ScanOptions) DiscoveryConcurrencyLimit() int {
	return normalizedConcurrency(o.DiscoveryConcurrency, o.ScanConcurrencyLimit())
}

func normalizedConcurrency(value, fallback int) int {
	if value > 0 {
		return value
	}
	if fallback > 0 {
		return fallback
	}
	return 1
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
