package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/ostefani/subnetlens/models"
)

type Engine struct {
	Opts         models.ScanOptions
	SocketBudget int
	OnHost       func(h *models.Host)  // called when a host is ready or later updated
	OnProgress   func(done, total int) // called after each ping probe in discovery
	deps         engineDependencies
}

// NewEngine constructs a production-ready engine with the default scanner
// collaborators wired in.
func NewEngine(opts models.ScanOptions, socketBudget int) *Engine {
	return &Engine{
		Opts:         opts,
		SocketBudget: socketBudget,
		deps: engineDependencies{
			ouiLoader: ouiLoaderFunc(LoadOUICSV),
			icmpFactory: icmpFactoryFunc(func() (icmpProber, error) {
				s, err := NewICMPScanner()
				if err != nil {
					return nil, err
				}
				return s, nil
			}),
			passiveMDNSListener: passiveMDNSListenerFunc(func(ctx context.Context) nameCache {
				return startPassiveMDNSListener(ctx)
			}),
			activeARPSweeper: activeARPSweeperFunc(startActiveARPSweep),
			targetExpander:   targetExpanderFunc(expandTargets),
			subnetPreheater:  subnetPreheaterFunc(preheatSubnet),
			hostDiscoverer:   hostDiscovererFunc(DiscoverHosts),
			portScanner:      portScannerFunc(ScanPorts),
			hostEnricher:     hostEnricherFunc(EnrichHost),
			osDetector:       osDetectorFunc(DetectOS),
		},
	}
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

	if err := deps.ouiLoader.LoadOUICSV(); err != nil {
		debugLog("engine", "expandTargets error: %v", err)
	}

	icmpScanner, err := deps.icmpFactory.NewICMPScanner()
	if err != nil {
		icmpScanner = nil
	} else {
		defer icmpScanner.Close()
	}

	cache := deps.passiveMDNSListener.Start(runCtx)
	arpCache := &ARPCache{}

	deps.activeARPSweeper.Start(runCtx, e.Opts.Subnet, arpCache)

	targets, err := deps.targetExpander.Expand(e.Opts.Subnet)
	if err != nil {
		debugLog("engine", "expandTargets error: %v", err)
	} else {
		debugLog("engine", "expandTargets")
		deps.subnetPreheater.Preheat(runCtx, targets.seq, targets.total, icmpScanner)
	}

	eventCh := deps.hostDiscoverer.Discover(runCtx, e.Opts, e.OnProgress, cache, icmpScanner, arpCache, socketLimiter)

	globalSem := make(chan struct{}, e.Opts.ScanConcurrencyLimit())
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

				deps.portScanner.Scan(runCtx, scannedHost, e.Opts, globalSem, socketLimiter)
				deps.hostEnricher.Enrich(scannedHost, cache, arpCache)

				snapshot := scannedHost.Snapshot()
				detectedOS, detectedDevice := deps.osDetector.Detect(snapshot.IP, snapshot.OpenPorts, e.Opts.Timeout)
				scannedHost.SetOS(detectedOS)
				scannedHost.SetDeviceIfEmpty(detectedDevice)

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
