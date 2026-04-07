package scanner

import (
	"testing"

	"github.com/ostefani/subnetlens/models"
)

func TestLocalHostUpdatesIncludesSelfWhenInScanRange(t *testing.T) {
	info := LocalDiscoveryInfo{
		Hostname:    "workstation",
		IP:          "192.168.1.20",
		MAC:         "aa:bb:cc:dd:ee:ff",
		InScanRange: true,
	}

	updates := localHostUpdates(info)
	if len(updates) != 1 {
		t.Fatalf("expected 1 local host update, got %d", len(updates))
	}

	update := updates[0]
	if update.ip != info.IP {
		t.Fatalf("expected IP %q, got %q", info.IP, update.ip)
	}
	if update.mac != info.MAC {
		t.Fatalf("expected MAC %q, got %q", info.MAC, update.mac)
	}
	if update.name != info.Hostname {
		t.Fatalf("expected hostname %q, got %q", info.Hostname, update.name)
	}
	if !update.alive {
		t.Fatal("expected local host update to be alive")
	}
	if update.seenBy != models.HostSourceSelf {
		t.Fatalf("expected seenBy to be self, got %q", update.seenBy)
	}
}

func TestLocalHostUpdatesSkipsSelfOutsideScanRange(t *testing.T) {
	info := LocalDiscoveryInfo{
		Hostname:    "workstation",
		IP:          "192.168.1.20",
		MAC:         "aa:bb:cc:dd:ee:ff",
		InScanRange: false,
	}

	updates := localHostUpdates(info)
	if len(updates) != 0 {
		t.Fatalf("expected no local host updates, got %d", len(updates))
	}
}
