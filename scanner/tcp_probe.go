package scanner

import (
	"context"
	"time"

	tcptransport "github.com/ostefani/subnetlens/transports/tcp"
)

var tcpProbePorts = tcptransport.LivenessPorts()

func tcpProbeOpenPort(ctx context.Context, ip string, timeout time.Duration, socketLimiter *socketLimiter) (bool, time.Duration) {
	return tcptransport.ProbeOpenPort(ctx, ip, timeout, socketLimiter)
}

func tcpProbeAlive(ctx context.Context, ip string, timeout time.Duration, socketLimiter *socketLimiter) (bool, time.Duration) {
	return tcptransport.ProbeAlive(ctx, ip, timeout, socketLimiter)
}

func adaptiveTimeout(base, latency time.Duration) time.Duration {
	return tcptransport.AdaptiveTimeout(base, latency)
}
