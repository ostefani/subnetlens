// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package discovery

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

type slowProber struct{}

func (slowProber) Probe(ctx context.Context, ip string, timeout time.Duration) (bool, time.Duration, error) {
	time.Sleep(2 * time.Millisecond)
	return true, time.Millisecond, nil
}

// cancelingRuntime cancels the sweep on the Nth slot acquisition.
type cancelingRuntime struct {
	targets     contracts.DiscoveryTargets
	cancel      context.CancelFunc
	cancelAfter int32
	calls       atomic.Int32
}

func (r *cancelingRuntime) Targets() contracts.DiscoveryTargets { return r.targets }
func (r *cancelingRuntime) ReportIssue(models.ScanIssue)         {}
func (r *cancelingRuntime) ReleaseDiscoverySlot()                {}
func (r *cancelingRuntime) SocketLimiter() contracts.SocketLimiter { return nil }
func (r *cancelingRuntime) AcquireDiscoverySlot(ctx context.Context) error {
	if r.calls.Add(1) == r.cancelAfter {
		r.cancel()
	}
	return nil
}

func TestDiscoverHostsCancelMidSweepHasNoRace(t *testing.T) {
	const target = "10.255.255.0/24"

	spec, err := ExpandTargets(target)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rt := &cancelingRuntime{targets: spec, cancel: cancel, cancelAfter: 20}
	opts := models.ScanOptions{Subnet: target, Timeout: 50 * time.Millisecond}

	for range DiscoverHosts(ctx, opts, nil, nil, slowProber{}, nil, rt) {
	}
}