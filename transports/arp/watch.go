// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package arp

import (
	"context"
	"time"
)

func Watch(
	ctx context.Context,
	cache *Cache,
	contains func(string) bool,
	emit func(ip, mac string) bool,
	scanDone <-chan struct{},
) {
	if cache == nil || contains == nil || emit == nil {
		return
	}

	const (
		settleInterval = 200 * time.Millisecond
		settleQuiet    = 1500 * time.Millisecond
		settleMax      = 5 * time.Second
	)

	ticker := time.NewTicker(settleInterval)
	defer ticker.Stop()

	sent := make(map[string]string)
	var deadline <-chan time.Time
	var quietTimer *time.Timer
	defer func() {
		if quietTimer != nil {
			quietTimer.Stop()
		}
	}()

	for {
		var quietC <-chan time.Time
		if quietTimer != nil {
			quietC = quietTimer.C
		}

		select {
		case <-ctx.Done():
			return
		case <-scanDone:
			scanDone = nil
			deadline = time.After(settleMax)
			quietTimer = time.NewTimer(settleQuiet)
		case <-deadline:
			return
		case <-quietC:
			return
		case <-ticker.C:
		}

		newSeen := false
		table := cache.Refresh()
		for ip, mac := range table {
			if !contains(ip) || mac == "" || sent[ip] == mac {
				continue
			}
			if !emit(ip, mac) {
				return
			}
			sent[ip] = mac
			newSeen = true
		}

		if newSeen && quietTimer != nil {
			quietTimer.Reset(settleQuiet)
		}
	}
}
