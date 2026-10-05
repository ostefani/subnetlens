// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"strings"
	"testing"

	"github.com/ostefani/subnetlens/models"
)

func TestParseHostFilterEmptyMatchesAll(t *testing.T) {
	for _, expr := range []string{"", "   "} {
		filter, err := ParseHostFilter(expr)
		if err != nil {
			t.Fatalf("ParseHostFilter(%q): %v", expr, err)
		}
		if filter != nil {
			t.Fatalf("expected empty expression to yield a nil filter, got %+v", filter)
		}
		if filter.Matches(models.HostSnapshot{IP: "192.168.1.1"}) != true {
			t.Fatal("expected a nil filter to match every host")
		}
	}
}

func TestParseHostFilterRejectsBadInput(t *testing.T) {
	tests := []struct {
		expr    string
		wantErr string
	}{
		{"bogus:x", `unknown key "bogus"`},
		{"port:", "empty value"},
		{"os:", "empty value"},
		{"port:abc", "port needs a number"},
		{"port:0", "port needs a number"},
		{"port:70000", "port needs a number"},
		{"weak:maybe", "weak needs true/false"},
		{"alive:2", "alive needs true/false"},
		{"port:22,", "empty condition"},
		{"", ""}, // control: valid empty is tested elsewhere
	}
	for _, tt := range tests {
		if tt.expr == "" {
			continue
		}
		_, err := ParseHostFilter(tt.expr)
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Fatalf("ParseHostFilter(%q): expected error containing %q, got %v", tt.expr, tt.wantErr, err)
		}
	}
}

func filterTestSnapshot() models.HostSnapshot {
	return models.HostSnapshot{
		IP:       "192.168.1.10",
		Hostname: "printer.local",
		MAC:      "aa:bb:cc:dd:ee:ff",
		Vendor:   "TP-Link Systems Inc",
		OS:       "Linux",
		Device:   "Print Server",
		Source:   models.HostSourceARP,
		Alive:    true,
		Weak:     false,
		Ports: []models.Port{
			{Number: 22, Protocol: "tcp", State: models.PortOpen, Service: "SSH"},
			{Number: 80, Protocol: "tcp", State: models.PortOpen, Service: "HTTP"},
			{Number: 443, Protocol: "tcp", State: models.PortClosed, Service: "HTTPS"},
		},
	}
}

func TestHostFilterMatches(t *testing.T) {
	snapshot := filterTestSnapshot()
	tests := []struct {
		expr string
		want bool
	}{
		{"port:22", true},
		{"port:80", true},
		{"port:443", false}, // closed ports do not match
		{"port:22,port:23", true},
		{"port:23,port:24", false},
		{"service:ssh", true},
		{"service:HTTP", true},
		{"service:dns", false},
		{"os:linux", true},
		{"os:windows", false},
		{"vendor:tp-link", true},
		{"device:print", true},
		{"host:printer", true},
		{"hostname:printer.local", true},
		{"mac:aa:bb", true},
		{"ip:.1.10", true},
		{"weak:false", true},
		{"weak:true", false},
		{"alive:true", true},
		{"alive:1", true},
		{"source:arp", true},
		{"source:tcp", false},
		{"printer", true}, // bare term searches several fields
		{"tp-link", true}, // bare term hits vendor
		{"nosuchost", false},
		{"os:linux,port:22", true},    // AND across keys
		{"os:linux,port:23", false},   // AND across keys
		{"os:linux,os:windows", true}, // OR within a repeated key
	}
	for _, tt := range tests {
		filter, err := ParseHostFilter(tt.expr)
		if err != nil {
			t.Fatalf("ParseHostFilter(%q): %v", tt.expr, err)
		}
		if got := filter.Matches(snapshot); got != tt.want {
			t.Fatalf("filter %q: Matches = %v, want %v", tt.expr, got, tt.want)
		}
	}
}

func TestHostFilterMatchesUnicodeCaseInsensitively(t *testing.T) {
	filter, err := ParseHostFilter("vendor:müller")
	if err != nil {
		t.Fatalf("ParseHostFilter: %v", err)
	}
	match := models.HostSnapshot{Vendor: "Müller GmbH"}
	if !filter.Matches(match) {
		t.Fatal("expected vendor:müller to match Müller GmbH")
	}
	miss := models.HostSnapshot{Vendor: "Miller Inc"}
	if filter.Matches(miss) {
		t.Fatal("expected vendor:müller to reject Miller Inc")
	}
}

func BenchmarkHostFilterMatches(b *testing.B) {
	filter, err := ParseHostFilter("vendor:tp-link,port:22,os:linux")
	if err != nil {
		b.Fatalf("ParseHostFilter: %v", err)
	}
	snapshot := filterTestSnapshot()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !filter.Matches(snapshot) {
			b.Fatal("expected the fixture to match")
		}
	}
}

func TestHostFilterHelpersAreNilSafe(t *testing.T) {
	var filter *HostFilter
	snapshots := []models.HostSnapshot{filterTestSnapshot()}
	if got := filter.FilterSnapshots(snapshots); len(got) != 1 {
		t.Fatalf("expected nil filter to keep all snapshots, got %d", len(got))
	}
	host := models.NewHost("192.168.1.10")
	if got := filter.FilterHosts([]*models.Host{host, nil}); len(got) != 2 {
		t.Fatalf("expected nil filter to keep all hosts untouched, got %d", len(got))
	}
	if filter.Expression() != "" {
		t.Fatalf("expected empty expression for nil filter, got %q", filter.Expression())
	}
}
