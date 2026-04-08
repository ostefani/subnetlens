package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/ostefani/subnetlens/fingerprint"
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
	icmptransport "github.com/ostefani/subnetlens/transports/icmp"
	tcptransport "github.com/ostefani/subnetlens/transports/tcp"
)

type Engine struct {
	Opts            models.ScanOptions
	SocketBudget    int
	OnHost          func(h *models.Host)  // called when a host is ready or later updated
	OnProgress      func(done, total int) // called after each ping probe in discovery
	OnIssue         func(issue models.ScanIssue)
	deps            engineDependencies
	hostScanners    []contracts.HostScanner
	hostClassifiers []contracts.HostClassifier
}

// NewEngine constructs a production-ready engine with the default scanner
// collaborators wired in.
func NewEngine(opts models.ScanOptions, socketBudget int, options ...Option) *Engine {
	engine := &Engine{
		Opts:         opts,
		SocketBudget: socketBudget,
		deps: engineDependencies{
			ouiLoader: ouiLoaderFunc(LoadOUICSV),
			icmpFactory: icmpFactoryFunc(func() (icmpProber, error) {
				s, err := icmptransport.NewScanner()
				if err != nil {
					return nil, err
				}
				return s, nil
			}),
			passiveMDNSListener: passiveMDNSListenerFunc(func(ctx context.Context) (nameCache, error) {
				return startPassiveMDNSListener(ctx)
			}),
			activeARPSweeper: activeARPSweeperFunc(startActiveARPSweepWithIssues),
			targetExpander:   targetExpanderFunc(expandTargets),
			subnetPreheater:  subnetPreheaterFunc(preheatSubnet),
			hostDiscoverer:   hostDiscovererFunc(DiscoverHosts),
			portScanner:      portScannerFunc(ScanPorts),
			hostEnricher:     hostEnricherFunc(EnrichHost),
			osDetector:       osDetectorFunc(DetectOS),
		},
	}

	engine.RegisterHostScanner(tcptransport.NewHostScanner())
	engine.RegisterHostClassifier(fingerprint.Detector{})
	for _, option := range options {
		option(engine)
	}
	return engine
}

func (e *Engine) Run(ctx context.Context) *models.ScanResult {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	deps := e.deps

	socketLimiter := newSocketLimiter(e.SocketBudget)

	result := &models.ScanResult{
		Subnet:    e.Opts.Subnet,
		StartedAt: time.Now(),
	}
	issues := newIssueRecorder(result, e.OnIssue)

	if err := deps.ouiLoader.LoadOUICSV(); err != nil {
		issues.Report(warningIssue("oui", "OUI vendor data unavailable: %v", err))
	}

	icmpScanner, err := deps.icmpFactory.NewICMPScanner()
	if err != nil {
		icmpScanner = nil
		issues.Report(warningIssue("icmp", "ICMP probing unavailable: %v", err))
	} else {
		defer icmpScanner.Close()
	}

	cache, err := deps.passiveMDNSListener.Start(runCtx)
	if err != nil {
		issues.Report(warningIssue("mdns", "passive mDNS listener unavailable: %v", err))
	}
	arpCache := &ARPCache{}
	arpCache.SetErrorHandler(func(err error) {
		issues.Report(warningIssue("arp", "ARP table unavailable: %v", err))
	})

	deps.activeARPSweeper.Start(runCtx, e.Opts.Subnet, arpCache, issues)

	targets, err := deps.targetExpander.Expand(e.Opts.Subnet)
	if err != nil {
		debugLog("engine", "expandTargets error: %v", err)
	} else {
		debugLog("engine", "expandTargets")
		deps.subnetPreheater.Preheat(runCtx, targets.seq, targets.total, icmpScanner)
	}

	eventCh := deps.hostDiscoverer.Discover(runCtx, e.Opts, e.OnProgress, cache, icmpScanner, arpCache, socketLimiter, issues)

	globalSem := make(chan struct{}, e.Opts.ScanConcurrencyLimit())
	runtime := newScanRuntime(socketLimiter, globalSem, issues)
	var scanWG sync.WaitGroup
	hostsByIP := make(map[string]*models.Host)
	hostReady := make(map[string]chan struct{})

	for event := range eventCh {
		if event.Host == nil {
			continue
		}

		ip := event.Host.Snapshot().IP

		switch event.Type {
		case HostDiscovered:
			if _, exists := hostsByIP[ip]; exists {
				continue
			}

			hostsByIP[ip] = event.Host
			result.Hosts = append(result.Hosts, event.Host)

			ready := make(chan struct{})
			hostReady[ip] = ready

			scanWG.Add(1)
			go func(scannedHost *models.Host, ready chan struct{}) {
				defer scanWG.Done()
				defer close(ready)

				e.runHostScanners(runCtx, scannedHost, runtime, deps)
				deps.hostEnricher.Enrich(scannedHost, cache, arpCache)

				e.classifyHost(scannedHost, deps)

				if e.OnHost != nil {
					e.OnHost(scannedHost)
				}
			}(event.Host, ready)

		case HostUpdated:
			if _, exists := hostsByIP[ip]; !exists {
				continue
			}

			deps.hostEnricher.Enrich(event.Host, cache, arpCache)

			ready, ok := hostReady[ip]
			if !ok {
				continue
			}

			select {
			case <-ready:
				if e.OnHost != nil {
					e.OnHost(event.Host)
				}
			default:
			}
		}
	}

	scanWG.Wait()
	result.FinishedAt = time.Now()

	return result
}

func (e *Engine) runHostScanners(
	ctx context.Context,
	host *models.Host,
	runtime *ScanRuntime,
	deps engineDependencies,
) {
	if len(e.hostScanners) == 0 {
		deps.portScanner.Scan(ctx, host, e.Opts, runtime)
		return
	}

	for _, hostScanner := range e.hostScanners {
		hostScanner.ScanHost(ctx, host, e.Opts, runtime)
	}
}

func (e *Engine) classifyHost(host *models.Host, deps engineDependencies) {
	if len(e.hostClassifiers) == 0 {
		snapshot := host.Snapshot()
		detectedOS, detectedDevice := deps.osDetector.Detect(snapshot.OpenPorts)
		host.SetOS(detectedOS)
		host.SetDeviceIfEmpty(detectedDevice)
		return
	}

	snapshot := host.Snapshot()
	hostOS := ""
	device := ""
	for _, classifier := range e.hostClassifiers {
		detectedOS, detectedDevice := classifier.ClassifyHost(snapshot.OpenPorts)
		if detectedOS != "" {
			hostOS = detectedOS
		}
		if detectedDevice != "" {
			device = detectedDevice
		}
	}

	if hostOS != "" {
		host.SetOS(hostOS)
	}
	if device != "" {
		host.SetDeviceIfEmpty(device)
	}
}
