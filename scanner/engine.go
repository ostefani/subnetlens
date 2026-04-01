package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/ostefani/subnetlens/models"
)

type Engine struct {
	Opts       models.ScanOptions
	OnHost     func(h *models.Host)  // called when a host is ready or later updated
	OnProgress func(done, total int) // called after each ping probe in discovery
}

func (e *Engine) Run(ctx context.Context) *models.ScanResult {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	result := &models.ScanResult{
		Subnet:    e.Opts.Subnet,
		StartedAt: time.Now(),
	}

	if err := LoadOUICSV(); err != nil {
		debugLog("engine", "expandTargets error: %v", err)
	}

	icmpScanner, err := NewICMPScanner()
	if err == nil {
		defer icmpScanner.Close()
	}

	cache := startPassiveMDNSListener(runCtx)
	arpCache := &ARPCache{}

	startActiveARPSweep(runCtx, e.Opts.Subnet, arpCache)

	targets, err := expandTargets(e.Opts.Subnet)
	if err != nil {
		debugLog("engine", "expandTargets error: %v", err)
	} else {
		debugLog("engine", "expandTargets")
		preheatSubnet(runCtx, targets.seq, targets.total, icmpScanner)
	}

	eventCh := DiscoverHosts(runCtx, e.Opts, e.OnProgress, cache, icmpScanner, arpCache)

	globalSem := make(chan struct{}, e.Opts.Concurrency)
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

				ScanPorts(runCtx, scannedHost, e.Opts, globalSem)
				EnrichHost(scannedHost, cache, arpCache)

				snapshot := scannedHost.Snapshot()
				detectedOS, detectedDevice := DetectOS(snapshot.IP, snapshot.OpenPorts, e.Opts.Timeout)
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

			EnrichHost(event.Host, cache, arpCache)

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
