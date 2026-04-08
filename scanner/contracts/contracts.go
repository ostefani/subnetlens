package contracts

import (
	"context"
	"iter"
	"time"

	"github.com/ostefani/subnetlens/models"
)

type SocketLimiter interface {
	Acquire(context.Context) error
	Release()
}

type Runtime interface {
	SocketLimiter() SocketLimiter
	AcquireScanSlot(context.Context) error
	ReleaseScanSlot()
	ReportIssue(models.ScanIssue)
}

type HostObservation struct {
	IP      string
	MAC     string
	Name    string
	Alive   bool
	Latency time.Duration
	Source  models.HostSource
}

type DiscoveryTargets interface {
	All() iter.Seq[string]
	Total() int
	Contains(string) bool
}

type DiscoveryRuntime interface {
	Targets() DiscoveryTargets
	SocketLimiter() SocketLimiter
	AcquireDiscoverySlot(context.Context) error
	ReleaseDiscoverySlot()
	ReportIssue(models.ScanIssue)
}

type DiscoveryModule interface {
	Discover(context.Context, models.ScanOptions, DiscoveryRuntime) <-chan HostObservation
}

type HostScanner interface {
	ScanHost(context.Context, *models.Host, models.ScanOptions, Runtime)
}

type HostClassifier interface {
	ClassifyHost([]models.Port) (string, string)
}
