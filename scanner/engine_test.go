package scanner

import (
	"context"
	"errors"
	"iter"
	"sync"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/models"
)

type countingOUILoader struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (m *countingOUILoader) LoadOUICSV() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.err
}

func (m *countingOUILoader) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type stubICMPFactory struct {
	mu      sync.Mutex
	calls   int
	prober  icmpProber
	factory error
}

func (m *stubICMPFactory) NewICMPScanner() (icmpProber, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.prober, m.factory
}

func (m *stubICMPFactory) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type stubNameCache struct {
	mu      sync.Mutex
	names   map[string]resolveResult
	lookups int
	stores  int
}

func (m *stubNameCache) LookupName(ip string) (resolveResult, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lookups++
	res, ok := m.names[ip]
	return res, ok
}

func (m *stubNameCache) StoreName(ip, name string, source models.HostSource) {
	if name == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.stores++
	if m.names == nil {
		m.names = make(map[string]resolveResult)
	}
	m.names[ip] = resolveResult{name: name, source: source}
}

type stubPassiveMDNSListener struct {
	mu    sync.Mutex
	calls int
	cache nameCache
}

func (m *stubPassiveMDNSListener) Start(context.Context) nameCache {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.cache
}

func (m *stubPassiveMDNSListener) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type stubActiveARPSweeper struct {
	mu         sync.Mutex
	calls      int
	lastTarget string
}

func (m *stubActiveARPSweeper) Start(_ context.Context, target string, _ *ARPCache) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.lastTarget = target
}

func (m *stubActiveARPSweeper) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *stubActiveARPSweeper) LastTarget() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastTarget
}

type stubTargetExpander struct {
	mu     sync.Mutex
	calls  int
	target string
	spec   targetSpec
	err    error
}

func (m *stubTargetExpander) Expand(target string) (targetSpec, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.target = target
	return m.spec, m.err
}

func (m *stubTargetExpander) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type stubSubnetPreheater struct {
	mu             sync.Mutex
	calls          int
	lastTotal      int
	lastICMPWasNil bool
}

func (m *stubSubnetPreheater) Preheat(_ context.Context, _ iter.Seq[string], total int, icmp icmpProber) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.lastTotal = total
	m.lastICMPWasNil = icmp == nil
}

func (m *stubSubnetPreheater) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type stubHostDiscoverer struct {
	mu     sync.Mutex
	calls  int
	events <-chan HostEvent
}

func (m *stubHostDiscoverer) Discover(
	_ context.Context,
	_ models.ScanOptions,
	_ func(done, total int),
	_ nameCache,
	_ icmpProber,
	_ *ARPCache,
	_ *socketLimiter,
) <-chan HostEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.events
}

func (m *stubHostDiscoverer) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type blockingPortScanner struct {
	mu          sync.Mutex
	calls       int
	scanStarted chan struct{}
	releaseScan <-chan struct{}
	startOnce   sync.Once
}

func (m *blockingPortScanner) Scan(
	ctx context.Context,
	host *models.Host,
	_ models.ScanOptions,
	_ chan struct{},
	_ *socketLimiter,
) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()

	m.startOnce.Do(func() { close(m.scanStarted) })

	select {
	case <-ctx.Done():
		return
	case <-m.releaseScan:
	}

	host.SetOpenPorts([]models.Port{{
		Number:   22,
		Protocol: "tcp",
		State:    models.PortOpen,
		Service:  "SSH",
	}})
}

func (m *blockingPortScanner) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type countingHostEnricher struct {
	mu    sync.Mutex
	calls int
}

func (m *countingHostEnricher) Enrich(*models.Host, nameCache, *ARPCache) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
}

func (m *countingHostEnricher) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type stubOSDetector struct {
	mu     sync.Mutex
	calls  int
	hostOS string
	device string
}

func (m *stubOSDetector) Detect([]models.Port) (string, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.hostOS, m.device
}

func (m *stubOSDetector) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func TestEngineCoordinatesHostUpdatesWithScanCompletion(t *testing.T) {
	events := make(chan HostEvent, 4)
	scanStarted := make(chan struct{})
	releaseScan := make(chan struct{})
	callbacks := make(chan models.HostSnapshot, 4)

	ouiLoader := &countingOUILoader{}
	icmpFactory := &stubICMPFactory{factory: errors.New("icmp unavailable in test")}
	mdnsListener := &stubPassiveMDNSListener{cache: &stubNameCache{}}
	arpSweeper := &stubActiveARPSweeper{}
	targetExpander := &stubTargetExpander{
		spec: targetSpec{
			seq: func(func(string) bool) {},
		},
	}
	preheater := &stubSubnetPreheater{}
	discoverer := &stubHostDiscoverer{events: events}
	portScanner := &blockingPortScanner{
		scanStarted: scanStarted,
		releaseScan: releaseScan,
	}
	enricher := &countingHostEnricher{}
	osDetector := &stubOSDetector{
		hostOS: "Linux",
		device: "Router",
	}

	host := models.NewHost("192.168.1.10")
	engine := &Engine{
		Opts: models.ScanOptions{
			Subnet:      "192.168.1.0/24",
			Timeout:     50 * time.Millisecond,
			Concurrency: 1,
		},
		OnHost: func(h *models.Host) {
			callbacks <- h.Snapshot()
		},
		deps: engineDependencies{
			ouiLoader:           ouiLoader,
			icmpFactory:         icmpFactory,
			passiveMDNSListener: mdnsListener,
			activeARPSweeper:    arpSweeper,
			targetExpander:      targetExpander,
			subnetPreheater:     preheater,
			hostDiscoverer:      discoverer,
			portScanner:         portScanner,
			hostEnricher:        enricher,
			osDetector:          osDetector,
		},
	}

	resultCh := make(chan *models.ScanResult, 1)
	go func() {
		resultCh <- engine.Run(context.Background())
	}()

	events <- HostEvent{Type: HostDiscovered, Host: host}

	select {
	case <-scanStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for port scan to start")
	}

	if !host.SetMACIfEmpty("00:1c:b3:00:00:01") {
		t.Fatal("expected MAC update before ready callback")
	}
	events <- HostEvent{Type: HostUpdated, Host: host}

	select {
	case snapshot := <-callbacks:
		t.Fatalf("unexpected callback before scan completed: %+v", snapshot)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseScan)

	var first models.HostSnapshot
	select {
	case first = <-callbacks:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ready host callback")
	}

	if first.IP != "192.168.1.10" {
		t.Fatalf("expected host IP 192.168.1.10, got %q", first.IP)
	}
	if first.MAC != "00:1c:b3:00:00:01" {
		t.Fatalf("expected MAC to survive the buffered update, got %q", first.MAC)
	}
	if first.OS != "Linux" {
		t.Fatalf("expected detected OS Linux, got %q", first.OS)
	}
	if first.Device != "Router" {
		t.Fatalf("expected detected device Router, got %q", first.Device)
	}
	if len(first.OpenPorts) != 1 || first.OpenPorts[0].Number != 22 {
		t.Fatalf("expected port scan results to be published after readiness, got %+v", first.OpenPorts)
	}

	if !host.SetHostname("lab-router") {
		t.Fatal("expected post-ready hostname update to succeed")
	}
	events <- HostEvent{Type: HostUpdated, Host: host}

	var second models.HostSnapshot
	select {
	case second = <-callbacks:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for post-ready update callback")
	}

	if second.Hostname != "lab-router" {
		t.Fatalf("expected post-ready callback to include latest hostname, got %q", second.Hostname)
	}

	close(events)

	var result *models.ScanResult
	select {
	case result = <-resultCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for engine shutdown")
	}

	if len(result.Hosts) != 1 {
		t.Fatalf("expected one host in result, got %d", len(result.Hosts))
	}
	if result.Hosts[0] != host {
		t.Fatal("expected engine to keep the discovered host pointer in the final result")
	}

	if got := ouiLoader.Calls(); got != 1 {
		t.Fatalf("expected OUI loader to be called once, got %d", got)
	}
	if got := icmpFactory.Calls(); got != 1 {
		t.Fatalf("expected ICMP factory to be called once, got %d", got)
	}
	if got := mdnsListener.Calls(); got != 1 {
		t.Fatalf("expected passive mDNS listener to be started once, got %d", got)
	}
	if got := arpSweeper.Calls(); got != 1 {
		t.Fatalf("expected active ARP sweep to be started once, got %d", got)
	}
	if got := arpSweeper.LastTarget(); got != "192.168.1.0/24" {
		t.Fatalf("expected ARP sweep target to be preserved, got %q", got)
	}
	if got := targetExpander.Calls(); got != 1 {
		t.Fatalf("expected target expander to be called once, got %d", got)
	}
	if got := preheater.Calls(); got != 1 {
		t.Fatalf("expected subnet preheater to be called once, got %d", got)
	}
	if !preheater.lastICMPWasNil {
		t.Fatal("expected subnet preheater to receive nil ICMP prober when factory fails")
	}
	if got := discoverer.Calls(); got != 1 {
		t.Fatalf("expected host discoverer to be called once, got %d", got)
	}
	if got := portScanner.Calls(); got != 1 {
		t.Fatalf("expected port scanner to be called once, got %d", got)
	}
	if got := osDetector.Calls(); got != 1 {
		t.Fatalf("expected OS detector to be called once, got %d", got)
	}
}

func TestEngineSkipsPreheatingWhenTargetExpansionFails(t *testing.T) {
	events := make(chan HostEvent)
	close(events)

	releaseScan := make(chan struct{})
	close(releaseScan)

	preheater := &stubSubnetPreheater{}
	discoverer := &stubHostDiscoverer{events: events}

	engine := &Engine{
		Opts: models.ScanOptions{
			Subnet:      "bad-subnet",
			Timeout:     50 * time.Millisecond,
			Concurrency: 1,
		},
		deps: engineDependencies{
			ouiLoader:           &countingOUILoader{},
			icmpFactory:         &stubICMPFactory{factory: errors.New("icmp unavailable in test")},
			passiveMDNSListener: &stubPassiveMDNSListener{cache: &stubNameCache{}},
			activeARPSweeper:    &stubActiveARPSweeper{},
			targetExpander:      &stubTargetExpander{err: errors.New("bad subnet")},
			subnetPreheater:     preheater,
			hostDiscoverer:      discoverer,
			portScanner: &blockingPortScanner{
				scanStarted: make(chan struct{}),
				releaseScan: releaseScan,
			},
			hostEnricher: &countingHostEnricher{},
			osDetector:   &stubOSDetector{},
		},
	}

	result := engine.Run(context.Background())

	if got := preheater.Calls(); got != 0 {
		t.Fatalf("expected preheater to be skipped when target expansion fails, got %d call(s)", got)
	}
	if got := discoverer.Calls(); got != 1 {
		t.Fatalf("expected host discoverer to still be called once, got %d", got)
	}
	if len(result.Hosts) != 0 {
		t.Fatalf("expected no hosts when discoverer emits nothing, got %d", len(result.Hosts))
	}
}
