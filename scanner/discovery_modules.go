// Copyright (c) 2026 Olha Stefanishyna. MIT License.

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
			for {
				select {
				case <-ctx.Done():
					return
				case observation, ok := <-stream:
					if !ok {
						return
					}
					if !sendHostObservation(ctx, out, observation) {
						return
					}
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

func mergePassiveMDNSObservations(
	ctx context.Context,
	discovery <-chan contracts.HostObservation,
	passive <-chan contracts.HostObservation,
	contains func(string) bool,
	stopPassive context.CancelFunc,
) <-chan contracts.HostObservation {
	if passive == nil {
		return discovery
	}

	out := make(chan contracts.HostObservation, 256)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if stopPassive != nil {
				stopPassive()
			}
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case observation, ok := <-discovery:
				if !ok {
					return
				}
				if !sendHostObservation(ctx, out, observation) {
					return
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case observation, ok := <-passive:
				if !ok {
					return
				}
				if contains == nil || !contains(observation.IP) {
					continue
				}
				if !sendHostObservation(ctx, out, observation) {
					return
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}
