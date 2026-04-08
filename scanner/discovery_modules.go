package scanner

import (
	"context"
	"sync"

	"github.com/ostefani/subnetlens/scanner/contracts"
)

func mergeHostObservationStreams(ctx context.Context, streams ...<-chan contracts.HostObservation) <-chan contracts.HostObservation {
	out := make(chan contracts.HostObservation, 256)

	var wg sync.WaitGroup
	for _, stream := range streams {
		if stream == nil {
			continue
		}

		wg.Add(1)
		go func(stream <-chan contracts.HostObservation) {
			defer wg.Done()
			for observation := range stream {
				if !sendHostObservation(ctx, out, observation) {
					return
				}
			}
		}(stream)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}
