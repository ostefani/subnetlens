package scanner

import (
	"testing"

	"github.com/ostefani/subnetlens/models"
)

func TestDetectOSUsesStoredFingerprints(t *testing.T) {
	ports := []models.Port{
		{
			Number: 22,
			Fingerprint: models.PortFingerprint{
				SSHGreeting: "SSH-2.0-OpenSSH_9.6 Ubuntu-3ubuntu13",
			},
		},
		{
			Number: 443,
			Fingerprint: models.PortFingerprint{
				TLSSummary: "TLS: CN=routerlogin.net SANs=[routerlogin.net]",
				HTTPServer: "Microsoft-IIS/10.0",
			},
		},
	}

	hostOS, device := DetectOS(ports)

	if hostOS != "Linux/Ubuntu" {
		t.Fatalf("expected host OS Linux/Ubuntu, got %q", hostOS)
	}
	if device != "Netgear Router" {
		t.Fatalf("expected device Netgear Router, got %q", device)
	}
}

func TestDetectOSParsesHTTPServerFingerprints(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		wantHostOS string
		wantDevice string
	}{
		{
			name:       "os from server header",
			server:     "Microsoft-IIS/10.0",
			wantHostOS: "Windows",
		},
		{
			name:       "device from server header",
			server:     "Synology DSM",
			wantHostOS: "Unknown",
			wantDevice: "Synology NAS",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hostOS, device := DetectOS([]models.Port{{
				Number: 80,
				Fingerprint: models.PortFingerprint{
					HTTPServer: tc.server,
				},
			}})

			if hostOS != tc.wantHostOS {
				t.Fatalf("expected host OS %q, got %q", tc.wantHostOS, hostOS)
			}
			if device != tc.wantDevice {
				t.Fatalf("expected device %q, got %q", tc.wantDevice, device)
			}
		})
	}
}
