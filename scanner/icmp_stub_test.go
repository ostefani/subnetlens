// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"context"
	"time"
)

type stubAliveICMPProber struct{}

func (stubAliveICMPProber) Probe(context.Context, string, time.Duration) (bool, time.Duration, error) {
	return true, 10 * time.Millisecond, nil
}

func (stubAliveICMPProber) Warm(string) error { return nil }

func (stubAliveICMPProber) Close() error { return nil }

var _ icmpProber = stubAliveICMPProber{}