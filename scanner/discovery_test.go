package scanner

import (
	"testing"

	"github.com/ostefani/subnetlens/models"
)

func TestLocalHostObservationsIncludeSelfWhenInScanRange(t *testing.T) {
	info := LocalDiscoveryInfo{
		Hostname:    "workstation",
		IP:          "192.168.1.20",
		MAC:         "aa:bb:cc:dd:ee:ff",
		InScanRange: true,
	}

	observations := localHostObservations(info)
	if len(observations) != 1 {
		t.Fatalf("expected 1 local host observation, got %d", len(observations))
	}

	observation := observations[0]
	if observation.IP != info.IP {
		t.Fatalf("expected IP %q, got %q", info.IP, observation.IP)
	}
	if observation.MAC != info.MAC {
		t.Fatalf("expected MAC %q, got %q", info.MAC, observation.MAC)
	}
	if observation.Name != info.Hostname {
		t.Fatalf("expected hostname %q, got %q", info.Hostname, observation.Name)
	}
	if !observation.Alive {
		t.Fatal("expected local host observation to be alive")
	}
	if observation.Source != models.HostSourceSelf {
		t.Fatalf("expected source to be self, got %q", observation.Source)
	}
}

func TestLocalHostObservationsSkipSelfOutsideScanRange(t *testing.T) {
	info := LocalDiscoveryInfo{
		Hostname:    "workstation",
		IP:          "192.168.1.20",
		MAC:         "aa:bb:cc:dd:ee:ff",
		InScanRange: false,
	}

	observations := localHostObservations(info)
	if len(observations) != 0 {
		t.Fatalf("expected no local host observations, got %d", len(observations))
	}
}
