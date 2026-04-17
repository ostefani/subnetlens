// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package arp

import (
	"errors"
	"testing"
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
