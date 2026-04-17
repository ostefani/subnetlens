// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package arp

import (
	"errors"
	"testing"
	"time"
)

func TestCacheRefreshPreservesOverlayWithoutKeepingStaleRows(t *testing.T) {
	currentTable := Table{
		"192.168.1.10": "aa:aa:aa:aa:aa:aa",
	}
	cache := &Cache{
		readTable: func() (Table, error) {
			return currentTable, nil
		},
	}

	cache.Inject("192.168.1.50", "bb-bb-bb-bb-bb-bb")

	refreshed := cache.Refresh()
	if got := refreshed["192.168.1.10"]; got != "aa:aa:aa:aa:aa:aa" {
		t.Fatalf("expected OS ARP row to be present, got %q", got)
	}
	if got := refreshed["192.168.1.50"]; got != "bb:bb:bb:bb:bb:bb" {
		t.Fatalf("expected injected overlay row to persist, got %q", got)
	}

	currentTable = Table{
		"192.168.1.20": "cc:cc:cc:cc:cc:cc",
	}

	refreshed = cache.Refresh()
	if _, ok := refreshed["192.168.1.10"]; ok {
		t.Fatal("expected stale OS ARP row to be removed after successful refresh")
	}
	if got := refreshed["192.168.1.20"]; got != "cc:cc:cc:cc:cc:cc" {
		t.Fatalf("expected latest OS ARP row to be present, got %q", got)
	}
	if got := refreshed["192.168.1.50"]; got != "bb:bb:bb:bb:bb:bb" {
		t.Fatalf("expected overlay row to survive refresh, got %q", got)
	}
}

func TestCacheRefreshKeepsLastGoodTableOnReadError(t *testing.T) {
	readErr := error(nil)
	cache := &Cache{
		readTable: func() (Table, error) {
			if readErr != nil {
				return nil, readErr
			}
			return Table{
				"192.168.1.10": "aa:aa:aa:aa:aa:aa",
			}, nil
		},
	}

	cache.Refresh()

	readErr = errors.New("boom")

	refreshed := cache.Refresh()
	if got := refreshed["192.168.1.10"]; got != "aa:aa:aa:aa:aa:aa" {
		t.Fatalf("expected last good ARP row to be preserved on error, got %q", got)
	}
}

func TestCacheRefreshDoesNotRejuvenateUnchangedARPEntries(t *testing.T) {
	cache := &Cache{
		readTable: func() (Table, error) {
			return Table{
				"192.168.1.10": "aa:aa:aa:aa:aa:aa",
			}, nil
		},
	}

	cache.Refresh()
	cache.mu.Lock()
	cache.observedAt["192.168.1.10"] = time.Now().Add(-entryFreshnessTTL - time.Second)
	cache.mu.Unlock()

	refreshed := cache.Refresh()
	if _, ok := refreshed["192.168.1.10"]; ok {
		t.Fatal("expected unchanged stale ARP entry to stay expired after refresh")
	}
}

func TestCacheLookupPrunesExpiredOverlayEntries(t *testing.T) {
	cache := &Cache{}
	cache.Inject("192.168.1.50", "bb-bb-bb-bb-bb-bb")

	cache.mu.Lock()
	cache.overlayObserved["192.168.1.50"] = time.Now().Add(-entryFreshnessTTL - time.Second)
	cache.overlay["192.168.1.50"] = "bb:bb:bb:bb:bb:bb"
	cache.table = Table{"192.168.1.50": "bb:bb:bb:bb:bb:bb"}
	cache.observedAt = map[string]time.Time{
		"192.168.1.50": cache.overlayObserved["192.168.1.50"],
	}
	cache.mu.Unlock()

	if _, _, ok := cache.LookupRecent("192.168.1.50"); ok {
		t.Fatal("expected expired overlay entry not to resolve")
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	if cache.overlay != nil {
		if _, ok := cache.overlay["192.168.1.50"]; ok {
			t.Fatal("expected expired overlay entry to be pruned")
		}
	}
	if cache.overlayObserved != nil {
		if _, ok := cache.overlayObserved["192.168.1.50"]; ok {
			t.Fatal("expected expired overlay timestamp to be pruned")
		}
	}
	if cache.table != nil {
		if _, ok := cache.table["192.168.1.50"]; ok {
			t.Fatal("expected expired overlay row to be removed from active table")
		}
	}
	if cache.observedAt != nil {
		if _, ok := cache.observedAt["192.168.1.50"]; ok {
			t.Fatal("expected expired overlay observation metadata to be pruned")
		}
	}
}
