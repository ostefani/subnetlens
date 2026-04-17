// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"fmt"

	"github.com/ostefani/subnetlens/models"
)

func EnrichHost(h *models.Host, arp *ARPCache) {
	if h == nil {
		return
	}

	_ = arp
	snapshot := h.Snapshot()

	if snapshot.MAC != "" {
		randomizedMAC := isMACRandomized(snapshot.MAC)
		h.SetRandomizedMAC(randomizedMAC)
		if !randomizedMAC && snapshot.Vendor == "" {
			h.SetVendorIfEmpty(VendorFromMAC(snapshot.MAC))
		}
	}
}

func isMACRandomized(mac string) bool {
	if len(mac) < 2 {
		return false
	}

	var firstByte byte
	_, err := fmt.Sscanf(mac[:2], "%02x", &firstByte)
	if err != nil {
		return false
	}

	return firstByte&0x02 != 0
}
