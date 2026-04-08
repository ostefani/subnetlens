package contracts

import (
	"context"

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

type HostScanner interface {
	ScanHost(context.Context, *models.Host, models.ScanOptions, Runtime)
}

type HostClassifier interface {
	ClassifyHost([]models.Port) (string, string)
}
