package scanner

import (
	"github.com/ostefani/subnetlens/fingerprint"
	"github.com/ostefani/subnetlens/models"
)

func DetectOS(ports []models.Port) (hostOS, device string) {
	return fingerprint.Detect(ports)
}
