// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"time"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

const (
	weakEvidenceTTL       = 45 * time.Second
	cachedNameEvidenceTTL = 90 * time.Second
)

func stampObservationFreshness(observation contracts.HostObservation) contracts.HostObservation {
	if observation.ObservedAt.IsZero() {
		observation.ObservedAt = time.Now()
	}
	if observation.ExpiresAt.IsZero() {
		if ttl := observationTTL(observation); ttl > 0 {
			observation.ExpiresAt = observation.ObservedAt.Add(ttl)
		}
	}
	return observation
}

func observationTTL(observation contracts.HostObservation) time.Duration {
	switch observation.Source {
	case models.HostSourceARP:
		return weakEvidenceTTL
	case models.HostSourceMDNS, models.HostSourceNBNS:
		return cachedNameEvidenceTTL
	case models.HostSourcePTR:
		if observation.Alive {
			return cachedNameEvidenceTTL
		}
	}
	if observation.Weak {
		return weakEvidenceTTL
	}
	return 0
}
