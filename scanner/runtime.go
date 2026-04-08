package scanner

import (
	"context"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

type ScanRuntime struct {
	socketLimiter *socketLimiter
	scanSem       chan struct{}
	issues        issueReporter
}

func newScanRuntime(socketLimiter *socketLimiter, scanSem chan struct{}, issues issueReporter) *ScanRuntime {
	return &ScanRuntime{
		socketLimiter: socketLimiter,
		scanSem:       scanSem,
		issues:        issues,
	}
}

func (r *ScanRuntime) SocketLimiter() contracts.SocketLimiter {
	return r.socketLimiter
}

func (r *ScanRuntime) AcquireScanSlot(ctx context.Context) error {
	if r == nil || r.scanSem == nil {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case r.scanSem <- struct{}{}:
		return nil
	}
}

func (r *ScanRuntime) ReleaseScanSlot() {
	if r == nil || r.scanSem == nil {
		return
	}
	<-r.scanSem
}

func (r *ScanRuntime) ReportIssue(issue models.ScanIssue) {
	if r == nil || r.issues == nil {
		return
	}
	r.issues.Report(issue)
}
