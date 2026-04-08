package scanner

import "github.com/ostefani/subnetlens/scanner/contracts"

type Option func(*Engine)

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
