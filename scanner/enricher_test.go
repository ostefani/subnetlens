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
