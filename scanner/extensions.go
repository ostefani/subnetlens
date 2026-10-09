// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

type Option func(*Engine)

func WithDiscoveryModule(discoveryModule contracts.DiscoveryModule) Option {
	return func(e *Engine) {
		e.RegisterDiscoveryModule(discoveryModule)
	}
}

func WithHostScanner(hostScanner contracts.HostScanner) Option {
	return func(e *Engine) {
		e.RegisterHostScanner(hostScanner)
	}
}

func WithHostClassifier(hostClassifier contracts.HostClassifier) Option {
	return func(e *Engine) {
		e.RegisterHostClassifier(hostClassifier)
	}
}

func WithOnHost(onHost func(*models.Host)) Option {
	return func(e *Engine) {
		if e == nil {
			return
		}
		e.onHost = onHost
	}
}

func WithARPCache(cache *ARPCache) Option {
	return func(e *Engine) {
		if e == nil {
			return
		}
		e.arpCache = cache
	}
}

// WithOnProgress registers a callback that reports host-discovery progress.
//
// The callback is never called concurrently, done never decreases, and calls
// are throttled to roughly 20 per second. A final call with the last values
// is made before Run returns. It is not called at all when the target is
// invalid or lacks large-scan consent. A slow callback delays later progress
// updates only; it never slows the scan.
func WithOnProgress(onProgress func(done, total int)) Option {
	return func(e *Engine) {
		if e == nil {
			return
		}
		e.onProgress = onProgress
	}
}

func WithOnIssue(onIssue func(models.ScanIssue)) Option {
	return func(e *Engine) {
		if e == nil {
			return
		}
		e.onIssue = onIssue
	}
}

func (e *Engine) RegisterDiscoveryModule(discoveryModule contracts.DiscoveryModule) {
	if e == nil || discoveryModule == nil {
		return
	}
	e.discoveryModules = append(e.discoveryModules, discoveryModule)
}

func (e *Engine) RegisterHostScanner(hostScanner contracts.HostScanner) {
	if e == nil || hostScanner == nil {
		return
	}
	e.hostScanners = append(e.hostScanners, hostScanner)
}

func (e *Engine) RegisterHostClassifier(hostClassifier contracts.HostClassifier) {
	if e == nil || hostClassifier == nil {
		return
	}
	e.hostClassifiers = append(e.hostClassifiers, hostClassifier)
}
