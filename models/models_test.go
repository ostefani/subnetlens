package models

import "testing"

func TestHostStringSettersSanitizeInlineTerminalText(t *testing.T) {
	host := NewHost("192.168.1.20")

	if !host.SetHostname(" printer\x1b[31m\nlab\t01 ") {
		t.Fatal("expected hostname update to succeed")
	}
	if !host.SetVendor(" Vendor\r\nCorp\x07 ") {
		t.Fatal("expected vendor update to succeed")
	}
	if !host.SetDevice(" NAS\tRack\nA ") {
		t.Fatal("expected device update to succeed")
	}
	if !host.SetOS(" Linux\x1b[0m ") {
		t.Fatal("expected OS update to succeed")
	}

	snapshot := host.Snapshot()
	if got := snapshot.Hostname; got != "printer lab 01" {
		t.Fatalf("expected sanitized hostname, got %q", got)
	}
	if got := snapshot.Vendor; got != "Vendor Corp" {
		t.Fatalf("expected sanitized vendor, got %q", got)
	}
	if got := snapshot.Device; got != "NAS Rack A" {
		t.Fatalf("expected sanitized device, got %q", got)
	}
	if got := snapshot.OS; got != "Linux" {
		t.Fatalf("expected sanitized OS, got %q", got)
	}
}

func TestSetHostnameRejectsTextThatSanitizesEmpty(t *testing.T) {
	host := NewHost("192.168.1.20")

	if host.SetHostname("\x1b\x07\r\n\t") {
		t.Fatal("expected control-only hostname to be rejected")
	}
	if got := host.Snapshot().Hostname; got != "192.168.1.20" {
		t.Fatalf("expected default hostname to remain unchanged, got %q", got)
	}
}

func TestScanOptionsScanConcurrencyLimitDefaults(t *testing.T) {
	opts := ScanOptions{}

	if got := opts.ScanConcurrencyLimit(); got != DefaultConcurrency {
		t.Fatalf("expected default scan concurrency %d, got %d", DefaultConcurrency, got)
	}
}

func TestScanOptionsDiscoveryConcurrencyFallsBackToScanConcurrency(t *testing.T) {
	opts := ScanOptions{Concurrency: 32}

	if got := opts.DiscoveryConcurrencyLimit(); got != 32 {
		t.Fatalf("expected discovery concurrency to fall back to scan concurrency 32, got %d", got)
	}
}

func TestScanOptionsDiscoveryConcurrencyUsesExplicitValue(t *testing.T) {
	opts := ScanOptions{
		Concurrency:          32,
		DiscoveryConcurrency: 256,
	}

	if got := opts.DiscoveryConcurrencyLimit(); got != 256 {
		t.Fatalf("expected explicit discovery concurrency 256, got %d", got)
	}
}
