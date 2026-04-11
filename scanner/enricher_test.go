package scanner

import (
	"testing"

	"github.com/ostefani/subnetlens/models"
)

func TestEnrichHostDoesNotApplyHostnameFromCache(t *testing.T) {
	host := models.NewHost("192.168.1.10")

	EnrichHost(host, nil)

	if got := host.Snapshot().Hostname; got != "192.168.1.10" {
		t.Fatalf("expected enricher to leave hostname unchanged, got %q", got)
	}
}

func TestEnrichHostMarksRandomizedMACInSnapshot(t *testing.T) {
	host := models.NewHost("192.168.1.10")
	host.SetMAC("9a:11:22:33:44:55")

	EnrichHost(host, nil)

	snapshot := host.Snapshot()
	if !snapshot.RandomizedMAC {
		t.Fatalf("expected randomized MAC flag, got %+v", snapshot)
	}
	if snapshot.Vendor == "" || snapshot.Device == "" {
		t.Fatalf("expected randomized MAC placeholders, got %+v", snapshot)
	}
}
