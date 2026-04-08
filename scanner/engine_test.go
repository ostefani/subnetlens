package scanner

import (
	"context"
	"errors"
	"iter"
	"sync"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
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
	mu     sync.Mutex
	calls  int
	cache  nameCache
	events <-chan contracts.HostObservation
	err    error
}

func (m *stubPassiveMDNSListener) Start(ctx context.Context) (passiveMDNSSession, error) {
	m.mu.Lock()
	m.calls++
	cache := m.cache
	events := m.events
	err := m.err
	m.mu.Unlock()

	session := passiveMDNSSession{cache: cache}
	if events == nil {
		return session, err
	}

	out := make(chan contracts.HostObservation, 16)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case observation, ok := <-events:
				if !ok {
					return
				}
				if !sendHostObservation(ctx, out, observation) {
					return
				}
			}
		}
	}()

	session.observations = out
	return session, err
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

func (m *stubActiveARPSweeper) Start(_ context.Context, target string, _ *ARPCache, _ issueReporter) {
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
	events <-chan contracts.HostObservation
}

func (m *stubHostDiscoverer) Discover(
	_ context.Context,
	_ models.ScanOptions,
	_ func(done, total int),
	_ nameCache,
	_ icmpProber,
	_ *ARPCache,
	_ contracts.DiscoveryRuntime,
) <-chan contracts.HostObservation {
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
	_ contracts.Runtime,
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

	host.SetProtocolPorts("tcp", []models.Port{{
		Number:  22,
		State:   models.PortOpen,
		Service: "SSH",
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

func (m *countingHostEnricher) Enrich(*models.Host, *ARPCache) {
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

type registeredHostScanner struct {
	mu             sync.Mutex
	calls          int
	socketBudgetOK bool
}

func (m *registeredHostScanner) ScanHost(ctx context.Context, host *models.Host, _ models.ScanOptions, runtime contracts.Runtime) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()

	if err := runtime.AcquireScanSlot(ctx); err == nil {
		runtime.ReleaseScanSlot()
	}

	if limiter := runtime.SocketLimiter(); limiter != nil {
		if err := limiter.Acquire(ctx); err == nil {
			m.mu.Lock()
			m.socketBudgetOK = true
			m.mu.Unlock()
			limiter.Release()
		}
	}

	host.SetProtocolPorts("udp", []models.Port{{
		Number:  161,
		State:   models.PortOpen,
		Service: "SNMP",
	}})
}

func (m *registeredHostScanner) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *registeredHostScanner) SocketBudgetOK() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.socketBudgetOK
}

type protocolHostScanner struct {
	mu       sync.Mutex
	calls    int
	protocol string
	ports    []models.Port
}

func (m *protocolHostScanner) ScanHost(_ context.Context, host *models.Host, _ models.ScanOptions, _ contracts.Runtime) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()

	host.SetProtocolPorts(m.protocol, m.ports)
}

func (m *protocolHostScanner) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type registeredDiscoveryModule struct {
	mu           sync.Mutex
	calls        int
	targetTotal  int
	socketBudget bool
}

func (m *registeredDiscoveryModule) Discover(ctx context.Context, _ models.ScanOptions, runtime contracts.DiscoveryRuntime) <-chan contracts.HostObservation {
	m.mu.Lock()
	m.calls++
	targets := runtime.Targets()
	m.targetTotal = targets.Total()
	m.mu.Unlock()

	if err := runtime.AcquireDiscoverySlot(ctx); err == nil {
		runtime.ReleaseDiscoverySlot()
	}

	if limiter := runtime.SocketLimiter(); limiter != nil {
		if err := limiter.Acquire(ctx); err == nil {
			m.mu.Lock()
			m.socketBudget = true
			m.mu.Unlock()
			limiter.Release()
		}
	}

	out := make(chan contracts.HostObservation, 1)
	out <- contracts.HostObservation{
		IP:     "192.168.1.77",
		Name:   "udp-probe",
		Alive:  true,
		Source: models.HostSourceUDP,
	}
	close(out)
	return out
}

func (m *registeredDiscoveryModule) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *registeredDiscoveryModule) TargetTotal() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.targetTotal
}

func (m *registeredDiscoveryModule) SocketBudgetOK() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.socketBudget
}

type registeredHostClassifier struct {
	mu     sync.Mutex
	calls  int
	hostOS string
	device string
}

func (m *registeredHostClassifier) ClassifyHost([]models.Port) (string, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.hostOS, m.device
}

func (m *registeredHostClassifier) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func TestEngineReportsNonFatalIssues(t *testing.T) {
	var mu sync.Mutex
	var got []models.ScanIssue
	engine := &Engine{
		Opts: models.ScanOptions{
			Subnet:      "bad-subnet",
			Timeout:     50 * time.Millisecond,
			Concurrency: 1,
		},
		OnIssue: func(issue models.ScanIssue) {
			mu.Lock()
			got = append(got, issue)
			mu.Unlock()
		},
		deps: engineDependencies{
			ouiLoader:           &countingOUILoader{err: errors.New("missing oui data")},
			icmpFactory:         &stubICMPFactory{factory: errors.New("raw socket denied")},
			passiveMDNSListener: &stubPassiveMDNSListener{cache: &stubNameCache{}, err: errors.New("bind failed")},
			activeARPSweeper:    &stubActiveARPSweeper{},
			targetExpander:      &stubTargetExpander{err: errors.New("bad subnet")},
			subnetPreheater:     preheaterNoop{},
			hostDiscoverer:      hostDiscovererFunc(DiscoverHosts),
			portScanner: &blockingPortScanner{
				scanStarted: make(chan struct{}),
				releaseScan: closedChan(),
			},
			hostEnricher: &countingHostEnricher{},
			osDetector:   &stubOSDetector{},
		},
	}

	result := engine.Run(context.Background())

	mu.Lock()
	defer mu.Unlock()

	if len(got) != 4 {
		t.Fatalf("expected 4 non-fatal issues, got %d: %+v", len(got), got)
	}
	if len(result.Issues) != len(got) {
		t.Fatalf("expected result issues to mirror callback count, got %d vs %d", len(result.Issues), len(got))
	}

	wantSources := []string{"oui", "icmp", "mdns", "discovery"}
	for i, source := range wantSources {
		if got[i].Source != source {
			t.Fatalf("expected issue %d source %q, got %q", i, source, got[i].Source)
		}
		if got[i].Level != models.ScanIssueLevelWarning {
			t.Fatalf("expected issue %d level warning, got %q", i, got[i].Level)
		}
		if got[i].At.IsZero() {
			t.Fatalf("expected issue %d timestamp to be set", i)
		}
	}
}

func TestEngineCoordinatesHostUpdatesWithScanCompletion(t *testing.T) {
	events := make(chan contracts.HostObservation, 4)
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

	events <- contracts.HostObservation{
		IP:      "192.168.1.10",
		Alive:   true,
		Latency: 10 * time.Millisecond,
		Source:  models.HostSourceICMP,
	}

	select {
	case <-scanStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for port scan to start")
	}

	events <- contracts.HostObservation{
		IP:     "192.168.1.10",
		MAC:    "00:1c:b3:00:00:01",
		Alive:  true,
		Source: models.HostSourceARP,
	}

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

	events <- contracts.HostObservation{
		IP:     "192.168.1.10",
		Name:   "lab-router",
		Source: models.HostSourceNBNS,
	}

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
	if got := result.Hosts[0].Snapshot().IP; got != "192.168.1.10" {
		t.Fatalf("expected final result to contain the discovered IP, got %q", got)
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

func TestEngineMergesPassiveMDNSObservationsBeforeHostReady(t *testing.T) {
	events := make(chan contracts.HostObservation, 1)
	mdnsEvents := make(chan contracts.HostObservation, 1)
	scanStarted := make(chan struct{})
	releaseScan := make(chan struct{})
	callbacks := make(chan models.HostSnapshot, 2)

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
			ouiLoader:   &countingOUILoader{},
			icmpFactory: &stubICMPFactory{factory: errors.New("icmp unavailable in test")},
			passiveMDNSListener: &stubPassiveMDNSListener{
				cache:  &stubNameCache{},
				events: mdnsEvents,
			},
			activeARPSweeper: &stubActiveARPSweeper{},
			targetExpander: &stubTargetExpander{
				spec: targetSpec{
					seq: func(yield func(string) bool) {
						yield("192.168.1.10")
					},
					total: 1,
					contains: func(ip string) bool {
						return ip == "192.168.1.10"
					},
				},
			},
			subnetPreheater: preheaterNoop{},
			hostDiscoverer:  &stubHostDiscoverer{events: events},
			portScanner: &blockingPortScanner{
				scanStarted: scanStarted,
				releaseScan: releaseScan,
			},
			hostEnricher: &countingHostEnricher{},
			osDetector:   &stubOSDetector{},
		},
	}

	resultCh := make(chan *models.ScanResult, 1)
	go func() {
		resultCh <- engine.Run(context.Background())
	}()

	events <- contracts.HostObservation{
		IP:     "192.168.1.10",
		Alive:  true,
		Source: models.HostSourceICMP,
	}

	select {
	case <-scanStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for port scan to start")
	}

	mdnsEvents <- contracts.HostObservation{
		IP:     "192.168.1.10",
		Name:   "lab-router",
		Alive:  true,
		Source: models.HostSourceMDNS,
	}

	select {
	case snapshot := <-callbacks:
		t.Fatalf("unexpected callback before scan completed: %+v", snapshot)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseScan)
	close(events)
	close(mdnsEvents)

	var snapshot models.HostSnapshot
	select {
	case snapshot = <-callbacks:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ready host callback")
	}

	if snapshot.Hostname != "lab-router" {
		t.Fatalf("expected passive mDNS hostname to be merged before readiness, got %q", snapshot.Hostname)
	}
	if snapshot.Source != models.HostSourceMixed {
		t.Fatalf("expected merged source to include mDNS, got %q", snapshot.Source)
	}

	var result *models.ScanResult
	select {
	case result = <-resultCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for engine shutdown")
	}

	if len(result.Hosts) != 1 {
		t.Fatalf("expected one host in result, got %d", len(result.Hosts))
	}
	if got := result.Hosts[0].Snapshot().Hostname; got != "lab-router" {
		t.Fatalf("expected final host snapshot to retain passive mDNS hostname, got %q", got)
	}
}

func TestEngineFiltersPassiveMDNSObservationsOutsideTargets(t *testing.T) {
	events := make(chan contracts.HostObservation)
	mdnsEvents := make(chan contracts.HostObservation, 1)
	portScanner := &blockingPortScanner{
		scanStarted: make(chan struct{}),
		releaseScan: closedChan(),
	}

	engine := &Engine{
		Opts: models.ScanOptions{
			Subnet:      "192.168.1.0/24",
			Timeout:     50 * time.Millisecond,
			Concurrency: 1,
		},
		deps: engineDependencies{
			ouiLoader:   &countingOUILoader{},
			icmpFactory: &stubICMPFactory{factory: errors.New("icmp unavailable in test")},
			passiveMDNSListener: &stubPassiveMDNSListener{
				cache:  &stubNameCache{},
				events: mdnsEvents,
			},
			activeARPSweeper: &stubActiveARPSweeper{},
			targetExpander: &stubTargetExpander{
				spec: targetSpec{
					seq: func(yield func(string) bool) {
						yield("192.168.1.10")
					},
					total: 1,
					contains: func(ip string) bool {
						return ip == "192.168.1.10"
					},
				},
			},
			subnetPreheater: preheaterNoop{},
			hostDiscoverer:  &stubHostDiscoverer{events: events},
			portScanner:     portScanner,
			hostEnricher:    &countingHostEnricher{},
			osDetector:      &stubOSDetector{},
		},
	}

	resultCh := make(chan *models.ScanResult, 1)
	go func() {
		resultCh <- engine.Run(context.Background())
	}()

	mdnsEvents <- contracts.HostObservation{
		IP:     "192.168.1.88",
		Name:   "outside-target",
		Alive:  true,
		Source: models.HostSourceMDNS,
	}

	close(mdnsEvents)
	close(events)

	var result *models.ScanResult
	select {
	case result = <-resultCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for engine shutdown")
	}

	if got := len(result.Hosts); got != 0 {
		t.Fatalf("expected passive mDNS result outside targets to be ignored, got %d host(s)", got)
	}
	if got := portScanner.Calls(); got != 0 {
		t.Fatalf("expected no host scans for out-of-target passive mDNS results, got %d", got)
	}
}

func TestEngineSkipsPreheatingWhenTargetExpansionFails(t *testing.T) {
	events := make(chan contracts.HostObservation)
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

func TestEngineUsesRegisteredHostScannerAndClassifier(t *testing.T) {
	events := make(chan contracts.HostObservation, 1)
	events <- contracts.HostObservation{
		IP:     "192.168.1.44",
		Alive:  true,
		Source: models.HostSourceICMP,
	}
	close(events)

	discoverer := &stubHostDiscoverer{events: events}
	fallbackPortScanner := &blockingPortScanner{
		scanStarted: make(chan struct{}),
		releaseScan: closedChan(),
	}
	fallbackClassifier := &stubOSDetector{
		hostOS: "fallback-os",
		device: "fallback-device",
	}
	registeredScanner := &registeredHostScanner{}
	registeredClassifier := &registeredHostClassifier{
		hostOS: "NetworkOS",
		device: "Managed Device",
	}

	engine := &Engine{
		Opts: models.ScanOptions{
			Subnet:      "192.168.1.0/24",
			Timeout:     50 * time.Millisecond,
			Concurrency: 2,
		},
		SocketBudget: 2,
		deps: engineDependencies{
			ouiLoader:           &countingOUILoader{},
			icmpFactory:         &stubICMPFactory{factory: errors.New("icmp unavailable in test")},
			passiveMDNSListener: &stubPassiveMDNSListener{cache: &stubNameCache{}},
			activeARPSweeper:    &stubActiveARPSweeper{},
			targetExpander: &stubTargetExpander{
				spec: targetSpec{
					seq: func(func(string) bool) {},
				},
			},
			subnetPreheater: preheaterNoop{},
			hostDiscoverer:  discoverer,
			portScanner:     fallbackPortScanner,
			hostEnricher:    &countingHostEnricher{},
			osDetector:      fallbackClassifier,
		},
	}
	engine.RegisterHostScanner(registeredScanner)
	engine.RegisterHostClassifier(registeredClassifier)

	result := engine.Run(context.Background())

	if got := registeredScanner.Calls(); got != 1 {
		t.Fatalf("expected registered host scanner to run once, got %d", got)
	}
	if !registeredScanner.SocketBudgetOK() {
		t.Fatal("expected registered host scanner to receive a working socket limiter")
	}
	if got := registeredClassifier.Calls(); got != 1 {
		t.Fatalf("expected registered host classifier to run once, got %d", got)
	}
	if got := fallbackPortScanner.Calls(); got != 0 {
		t.Fatalf("expected fallback port scanner to be skipped, got %d call(s)", got)
	}
	if got := fallbackClassifier.Calls(); got != 0 {
		t.Fatalf("expected fallback classifier to be skipped, got %d call(s)", got)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("expected one host in result, got %d", len(result.Hosts))
	}

	snapshot := result.Hosts[0].Snapshot()
	if snapshot.OS != "NetworkOS" {
		t.Fatalf("expected registered classifier OS, got %q", snapshot.OS)
	}
	if snapshot.Device != "Managed Device" {
		t.Fatalf("expected registered classifier device, got %q", snapshot.Device)
	}
	if len(snapshot.OpenPorts) != 1 || snapshot.OpenPorts[0].Protocol != "udp" {
		t.Fatalf("expected registered scanner ports to be published, got %+v", snapshot.OpenPorts)
	}
}

func TestEngineMergesPortsAcrossProtocolScopedHostScanners(t *testing.T) {
	events := make(chan contracts.HostObservation, 1)
	events <- contracts.HostObservation{
		IP:     "192.168.1.55",
		Alive:  true,
		Source: models.HostSourceICMP,
	}
	close(events)

	discoverer := &stubHostDiscoverer{events: events}
	fallbackPortScanner := &blockingPortScanner{
		scanStarted: make(chan struct{}),
		releaseScan: closedChan(),
	}
	udpScanner := &protocolHostScanner{
		protocol: "udp",
		ports: []models.Port{{
			Number:  161,
			State:   models.PortOpen,
			Service: "SNMP",
		}},
	}
	tcpScanner := &protocolHostScanner{
		protocol: "tcp",
		ports: []models.Port{{
			Number:  22,
			State:   models.PortOpen,
			Service: "SSH",
		}},
	}

	engine := &Engine{
		Opts: models.ScanOptions{
			Subnet:      "192.168.1.0/24",
			Timeout:     50 * time.Millisecond,
			Concurrency: 2,
		},
		deps: engineDependencies{
			ouiLoader:           &countingOUILoader{},
			icmpFactory:         &stubICMPFactory{factory: errors.New("icmp unavailable in test")},
			passiveMDNSListener: &stubPassiveMDNSListener{cache: &stubNameCache{}},
			activeARPSweeper:    &stubActiveARPSweeper{},
			targetExpander: &stubTargetExpander{
				spec: targetSpec{
					seq: func(func(string) bool) {},
				},
			},
			subnetPreheater: preheaterNoop{},
			hostDiscoverer:  discoverer,
			portScanner:     fallbackPortScanner,
			hostEnricher:    &countingHostEnricher{},
			osDetector:      &stubOSDetector{},
		},
	}
	engine.RegisterHostScanner(udpScanner)
	engine.RegisterHostScanner(tcpScanner)

	result := engine.Run(context.Background())

	if got := udpScanner.Calls(); got != 1 {
		t.Fatalf("expected UDP scanner to run once, got %d", got)
	}
	if got := tcpScanner.Calls(); got != 1 {
		t.Fatalf("expected TCP scanner to run once, got %d", got)
	}
	if got := fallbackPortScanner.Calls(); got != 0 {
		t.Fatalf("expected fallback port scanner to be skipped, got %d call(s)", got)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("expected one host in result, got %d", len(result.Hosts))
	}

	snapshot := result.Hosts[0].Snapshot()
	if len(snapshot.OpenPorts) != 2 {
		t.Fatalf("expected both protocol scanners to contribute ports, got %+v", snapshot.OpenPorts)
	}
	if snapshot.OpenPorts[0].Number != 22 || snapshot.OpenPorts[0].Protocol != "tcp" {
		t.Fatalf("expected sorted TCP port first, got %+v", snapshot.OpenPorts[0])
	}
	if snapshot.OpenPorts[1].Number != 161 || snapshot.OpenPorts[1].Protocol != "udp" {
		t.Fatalf("expected UDP port to be preserved, got %+v", snapshot.OpenPorts[1])
	}
}

func TestEngineUsesRegisteredDiscoveryModules(t *testing.T) {
	events := make(chan contracts.HostObservation)
	close(events)

	discoverer := &stubHostDiscoverer{events: events}
	discoveryModule := &registeredDiscoveryModule{}
	registeredScanner := &registeredHostScanner{}
	registeredClassifier := &registeredHostClassifier{
		hostOS: "NetworkOS",
		device: "Managed Device",
	}

	engine := &Engine{
		Opts: models.ScanOptions{
			Subnet:      "192.168.1.0/24",
			Timeout:     50 * time.Millisecond,
			Concurrency: 2,
		},
		SocketBudget: 2,
		deps: engineDependencies{
			ouiLoader:           &countingOUILoader{},
			icmpFactory:         &stubICMPFactory{factory: errors.New("icmp unavailable in test")},
			passiveMDNSListener: &stubPassiveMDNSListener{cache: &stubNameCache{}},
			activeARPSweeper:    &stubActiveARPSweeper{},
			targetExpander: &stubTargetExpander{
				spec: targetSpec{
					seq: func(yield func(string) bool) {
						yield("192.168.1.77")
					},
					total: 1,
				},
			},
			subnetPreheater: preheaterNoop{},
			hostDiscoverer:  discoverer,
			portScanner: &blockingPortScanner{
				scanStarted: make(chan struct{}),
				releaseScan: closedChan(),
			},
			hostEnricher: &countingHostEnricher{},
			osDetector:   &stubOSDetector{},
		},
	}
	engine.RegisterDiscoveryModule(discoveryModule)
	engine.RegisterHostScanner(registeredScanner)
	engine.RegisterHostClassifier(registeredClassifier)

	result := engine.Run(context.Background())

	if got := discoverer.Calls(); got != 1 {
		t.Fatalf("expected built-in discoverer to still be invoked once, got %d", got)
	}
	if got := discoveryModule.Calls(); got != 1 {
		t.Fatalf("expected registered discovery module to run once, got %d", got)
	}
	if got := discoveryModule.TargetTotal(); got != 1 {
		t.Fatalf("expected registered discovery module to receive expanded target set, got %d", got)
	}
	if !discoveryModule.SocketBudgetOK() {
		t.Fatal("expected registered discovery module to receive a working socket limiter")
	}
	if got := registeredScanner.Calls(); got != 1 {
		t.Fatalf("expected registered host scanner to run once for discovered host, got %d", got)
	}
	if got := registeredClassifier.Calls(); got != 1 {
		t.Fatalf("expected registered host classifier to run once for discovered host, got %d", got)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("expected one host discovered by registered module, got %d", len(result.Hosts))
	}

	snapshot := result.Hosts[0].Snapshot()
	if snapshot.IP != "192.168.1.77" {
		t.Fatalf("expected registered discovery module host IP, got %q", snapshot.IP)
	}
	if snapshot.Source != models.HostSourceUDP {
		t.Fatalf("expected registered discovery source udp, got %q", snapshot.Source)
	}
}

type preheaterNoop struct{}

func (preheaterNoop) Preheat(context.Context, iter.Seq[string], int, icmpProber) {}

func closedChan() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
