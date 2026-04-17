package arp

import (
	"errors"
	"testing"
)

func TestCacheRefreshPreservesOverlayWithoutKeepingStaleRows(t *testing.T) {
	originalReadARPTable := readARPTable
	defer func() { readARPTable = originalReadARPTable }()

	readARPTable = func() (Table, error) {
		return Table{
			"192.168.1.10": "aa:aa:aa:aa:aa:aa",
		}, nil
	}

	cache := &Cache{}
	cache.Inject("192.168.1.50", "bb-bb-bb-bb-bb-bb")

	refreshed := cache.Refresh()
	if got := refreshed["192.168.1.10"]; got != "aa:aa:aa:aa:aa:aa" {
		t.Fatalf("expected OS ARP row to be present, got %q", got)
	}
	if got := refreshed["192.168.1.50"]; got != "bb:bb:bb:bb:bb:bb" {
		t.Fatalf("expected injected overlay row to persist, got %q", got)
	}

	readARPTable = func() (Table, error) {
		return Table{
			"192.168.1.20": "cc:cc:cc:cc:cc:cc",
		}, nil
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
	originalReadARPTable := readARPTable
	defer func() { readARPTable = originalReadARPTable }()

	readARPTable = func() (Table, error) {
		return Table{
			"192.168.1.10": "aa:aa:aa:aa:aa:aa",
		}, nil
	}

	cache := &Cache{}
	cache.Refresh()

	readARPTable = func() (Table, error) {
		return nil, errors.New("boom")
	}

	refreshed := cache.Refresh()
	if got := refreshed["192.168.1.10"]; got != "aa:aa:aa:aa:aa:aa" {
		t.Fatalf("expected last good ARP row to be preserved on error, got %q", got)
	}
}
