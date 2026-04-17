// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package scanner

import (
	"context"
	"time"

	"github.com/ostefani/subnetlens/scanner/contracts"
	tcptransport "github.com/ostefani/subnetlens/transports/tcp"
)

var tcpProbePorts = tcptransport.LivenessPorts()

func tcpProbeOpenPort(ctx context.Context, ip string, timeout time.Duration, socketLimiter contracts.SocketLimiter) (bool, time.Duration) {
	return tcptransport.ProbeOpenPort(ctx, ip, timeout, socketLimiter)
}

func tcpProbeAlive(ctx context.Context, ip string, timeout time.Duration, socketLimiter contracts.SocketLimiter) (bool, time.Duration) {
	return tcptransport.ProbeAlive(ctx, ip, timeout, socketLimiter)
}

func adaptiveTimeout(base, latency time.Duration) time.Duration {
	return tcptransport.AdaptiveTimeout(base, latency)
}
