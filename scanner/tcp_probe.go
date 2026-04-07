package scanner

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

var tcpProbePorts = []int{80, 443, 22, 445, 8080}

// tcpProbe checks if ip is reachable by racing concurrent TCP connections
// against a small set of well-known ports.
func tcpProbe(
	ctx context.Context,
	ip string,
	timeout time.Duration,
	isSuccess func(error) bool,
	socketLimiter *socketLimiter,
) (bool, time.Duration) {
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	resultCh := make(chan time.Duration, len(tcpProbePorts))

	var wg sync.WaitGroup
	for _, port := range tcpProbePorts {
		wg.Add(1)
		port := port

		go func() {
			defer wg.Done()

			addr := net.JoinHostPort(ip, strconv.Itoa(port))

			if err := socketLimiter.Acquire(probeCtx); err != nil {
				return
			}
			defer socketLimiter.Release()

			d := net.Dialer{}
			conn, err := d.DialContext(probeCtx, "tcp", addr)
			if conn != nil {
				conn.Close()
			}

			if isSuccess(err) {
				resultCh <- time.Since(start)
				cancel()
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	elapsed, ok := <-resultCh
	if !ok {
		return false, 0
	}
	return true, elapsed
}

func tcpProbeOpenPort(ctx context.Context, ip string, timeout time.Duration, socketLimiter *socketLimiter) (bool, time.Duration) {
	return tcpProbe(ctx, ip, timeout, func(err error) bool {
		return err == nil
	}, socketLimiter)
}

func tcpProbeAlive(ctx context.Context, ip string, timeout time.Duration, socketLimiter *socketLimiter) (bool, time.Duration) {
	return tcpProbe(ctx, ip, timeout, isRemoteTCPResponse, socketLimiter)
}

func isRemoteTCPResponse(err error) bool {
	if err == nil {
		return true
	}

	// Internal probe cancellation/timeouts are local control flow, not
	// evidence that the target host responded.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}

	// Count only errors that require a remote TCP/IP stack to answer.
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
}

// adaptiveTimeout computes a per-host port-scan timeout that is proportional
// to the observed round-trip latency from the discovery phase.
func adaptiveTimeout(base, latency time.Duration) time.Duration {
	if latency == 0 {
		return base
	}

	timeout := latency * 3
	if timeout < 100*time.Millisecond {
		timeout = 100 * time.Millisecond
	}
	if timeout > base {
		timeout = base
	}
	return timeout
}
