package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ostefani/subnetlens/models"
)

type Engine struct {
	Opts       models.ScanOptions
	OnHost     func(h *models.Host)  // called each time a host completes all stages
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

	hostCh := DiscoverHosts(runCtx, e.Opts, e.OnProgress, cache, icmpScanner, arpCache)

	globalSem := make(chan struct{}, e.Opts.Concurrency)
	var scanWG sync.WaitGroup
	var hostsMu sync.Mutex

	for host := range hostCh {
		scanWG.Add(1)
		go func(scannedHost *models.Host) {
			defer scanWG.Done()

			// 1. Port scanning acts as a natural time buffer
			ScanPorts(runCtx, scannedHost, e.Opts, globalSem)

			if scannedHost.MAC == "" {
				if mac, ok := arpCache.Lookup(scannedHost.IP); ok {
					scannedHost.MAC = mac
				}
			}

			if scannedHost.MAC != "" && scannedHost.Vendor == "" {
				if isMACRandomized(scannedHost.MAC) {
					scannedHost.Vendor = "Randomized MAC — vendor unknown"
					scannedHost.Device = "Randomized MAC — device undetectable"
				} else {
					scannedHost.Vendor = VendorFromMAC(scannedHost.MAC)
				}
			}

			if scannedHost.Hostname == scannedHost.IP || scannedHost.Hostname == "" {
				if name, ok := cache.get(scannedHost.IP); ok {
					scannedHost.Hostname = name
				}
			}

			detectedOS, detectedDevice := DetectOS(scannedHost.IP, scannedHost.OpenPorts, e.Opts.Timeout)
			scannedHost.OS = detectedOS
			if scannedHost.Device == "" {
				scannedHost.Device = detectedDevice
			}

			hostsMu.Lock()
			result.Hosts = append(result.Hosts, scannedHost)
			hostsMu.Unlock()

			if e.OnHost != nil {
				e.OnHost(scannedHost)
			}
		}(host)
	}

	scanWG.Wait()
	result.FinishedAt = time.Now()

	return result
}

func DefaultOptions(subnet string) models.ScanOptions {
	return models.ScanOptions{
		Subnet:      subnet,
		Ports:       models.CommonPorts,
		Timeout:     500 * time.Millisecond,
		Concurrency: 100,
		GrabBanners: true,
	}
}

func isMACRandomized(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	// Parse the first byte from the MAC string (e.g. "da" from "da:4b:3f:...")
	var firstByte byte
	_, err := fmt.Sscanf(mac[:2], "%02x", &firstByte)
	if err != nil {
		return false
	}
	return firstByte&0x02 != 0
}
