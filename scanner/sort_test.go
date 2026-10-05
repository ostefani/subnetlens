// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"strconv"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/models"
)

func TestNormalizeSortOrder(t *testing.T) {
	tests := []struct {
		raw     string
		want    string
		wantErr string
	}{
		{"", SortDiscovery, ""},
		{"  ", SortDiscovery, ""},
		{"ip", SortIP, ""},
		{" IP ", SortIP, ""},
		{"LATENCY", SortLatency, ""},
		{"vendor", SortVendor, ""},
		{"hostname", SortHostname, ""},
		{"discovery", SortDiscovery, ""},
		{"bogus", "", "invalid --sort"},
		{"ip,hostname", "", "invalid --sort"},
	}
	for _, tt := range tests {
		got, err := NormalizeSortOrder(tt.raw)
		if tt.wantErr != "" {
			if err == nil {
				t.Fatalf("NormalizeSortOrder(%q): expected error, got %q", tt.raw, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeSortOrder(%q): %v", tt.raw, err)
		}
		if got != tt.want {
			t.Fatalf("NormalizeSortOrder(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestNextSortOrderCyclesThroughAllOrders(t *testing.T) {
	seen := make(map[string]bool)
	next := SortDiscovery
	for i := 0; i < len(SortOrders); i++ {
		next = NextSortOrder(next)
		seen[next] = true
	}
	if next != SortDiscovery {
		t.Fatalf("expected the cycle to return to discovery, ended at %q", next)
	}
	for _, order := range SortOrders {
		if !seen[order] {
			t.Fatalf("expected cycle to visit %q", order)
		}
	}
	if got := NextSortOrder("bogus"); got != SortIP {
		t.Fatalf("expected unknown order to restart the cycle at ip, got %q", got)
	}
}

func snapshotIPs(t *testing.T, snapshots []models.HostSnapshot) []string {
	t.Helper()
	ips := make([]string, 0, len(snapshots))
	for _, snapshot := range snapshots {
		ips = append(ips, snapshot.IP)
	}
	return ips
}

func TestSortSnapshotsByIPNumerically(t *testing.T) {
	snapshots := []models.HostSnapshot{
		{IP: "192.168.1.10"},
		{IP: "not-an-ip"},
		{IP: "192.168.1.2"},
		{IP: "10.0.0.1"},
	}
	SortSnapshots(snapshots, SortIP)
	want := []string{"10.0.0.1", "192.168.1.2", "192.168.1.10", "not-an-ip"}
	for i := range want {
		if snapshots[i].IP != want[i] {
			t.Fatalf("position %d: got %q, want %q (full: %v)", i, snapshots[i].IP, want[i], snapshotIPs(t, snapshots))
		}
	}
}

func TestSortSnapshotsByLatencyUnknownLast(t *testing.T) {
	snapshots := []models.HostSnapshot{
		{IP: "192.168.1.3"},
		{IP: "192.168.1.1", Latency: 5 * time.Millisecond},
		{IP: "192.168.1.2", Latency: time.Millisecond},
	}
	SortSnapshots(snapshots, SortLatency)
	want := []string{"192.168.1.2", "192.168.1.1", "192.168.1.3"}
	for i := range want {
		if snapshots[i].IP != want[i] {
			t.Fatalf("position %d: got %q, want %q", i, snapshots[i].IP, want[i])
		}
	}
}

func TestSortSnapshotsByVendorEmptyLastWithIPTiebreak(t *testing.T) {
	snapshots := []models.HostSnapshot{
		{IP: "192.168.1.9", Vendor: "cisco"},
		{IP: "192.168.1.1"},
		{IP: "192.168.1.2", Vendor: "Apple"},
		{IP: "192.168.1.3", Vendor: "cisco"},
	}
	SortSnapshots(snapshots, SortVendor)
	want := []string{"192.168.1.2", "192.168.1.3", "192.168.1.9", "192.168.1.1"}
	for i := range want {
		if snapshots[i].IP != want[i] {
			t.Fatalf("position %d: got %q, want %q", i, snapshots[i].IP, want[i])
		}
	}
}

func TestSortSnapshotsDiscoveryKeepsArrivalOrder(t *testing.T) {
	snapshots := []models.HostSnapshot{
		{IP: "192.168.1.30"},
		{IP: "192.168.1.1"},
	}
	SortSnapshots(snapshots, SortDiscovery)
	if snapshots[0].IP != "192.168.1.30" || snapshots[1].IP != "192.168.1.1" {
		t.Fatalf("expected arrival order to be preserved, got %v", snapshotIPs(t, snapshots))
	}
}

func BenchmarkSortSnapshotsByIP(b *testing.B) {
	base := make([]models.HostSnapshot, 1024)
	for i := range base {
		// Deterministic shuffle of the last octet: unsorted but stable.
		base[i] = models.HostSnapshot{IP: "10.0.0." + strconv.Itoa((i*37)%256)}
	}
	work := make([]models.HostSnapshot, len(base))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(work, base)
		SortSnapshots(work, SortIP)
	}
}

func TestSortHostsSortsBySnapshotAndToleratesNil(t *testing.T) {
	hosts := []*models.Host{
		models.NewHost("192.168.1.10"),
		nil,
		models.NewHost("192.168.1.2"),
	}
	SortHosts(hosts, SortIP)
	if hosts[0] == nil || hosts[0].IP() != "192.168.1.2" {
		t.Fatalf("expected .2 first, got %v", hosts[0])
	}
	if hosts[1] == nil || hosts[1].IP() != "192.168.1.10" {
		t.Fatalf("expected .10 second, got %v", hosts[1])
	}
	if hosts[2] != nil {
		t.Fatalf("expected nil last, got %v", hosts[2])
	}
}
