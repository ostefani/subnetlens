package scanner

import (
	"context"
	"net"
	"time"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
	tcptransport "github.com/ostefani/subnetlens/transports/tcp"
)

func ScanPorts(ctx context.Context, host *models.Host, opts models.ScanOptions, runtime contracts.Runtime) {
	tcptransport.NewHostScanner().ScanHost(ctx, host, opts, runtime)
}

func readHTTPServerHeader(conn net.Conn, ip, addr string, timeout time.Duration) string {
	return tcptransport.ReadHTTPServerHeader(conn, ip, addr, timeout)
}
