// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package fingerprint

import (
	"testing"

	"github.com/ostefani/subnetlens/models"
)

func TestDetectIgnoresNonTCPPorts(t *testing.T) {
	ports := []models.Port{
		{
			Number:   443,
			Protocol: "tcp",
			State:    models.PortOpen,
			Fingerprint: models.PortFingerprint{
				TLSSummary: "routerlogin.netgear.local",
			},
		},
		{
			Number:   443,
			Protocol: "udp",
			State:    models.PortOpen,
		},
	}

	hostOS, device := Detect(ports)

	if hostOS != "Unknown" {
		t.Fatalf("expected host OS to remain Unknown without TCP OS evidence, got %q", hostOS)
	}
	if device != "Netgear Router" {
		t.Fatalf("expected TCP TLS evidence to survive UDP coexistence, got %q", device)
	}
}
