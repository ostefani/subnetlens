package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/scanner/contracts"
)

func TestMergeHostObservationStreamsClosesOnContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	stream := make(chan contracts.HostObservation)
	merged := mergeHostObservationStreams(ctx, stream)

	cancel()

	select {
	case _, ok := <-merged:
		if ok {
			t.Fatal("expected merged observation stream to close after cancellation")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for merged observation stream to close after cancellation")
	}
}

func TestMergePassiveMDNSObservationsClosesOnContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	discovery := make(chan contracts.HostObservation)
	passive := make(chan contracts.HostObservation)
	stopped := make(chan struct{})
	merged := mergePassiveMDNSObservations(
		ctx,
		discovery,
		passive,
		func(string) bool { return true },
		func() { close(stopped) },
	)

	cancel()

	select {
	case _, ok := <-merged:
		if ok {
			t.Fatal("expected passive merge stream to close after cancellation")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for passive merge stream to close after cancellation")
	}

	select {
	case <-stopped:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected passive discovery stop callback after cancellation")
	}
}
