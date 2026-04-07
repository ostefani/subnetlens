package scanner

import (
	"fmt"

	"github.com/ostefani/subnetlens/models"
)

func EnrichHost(h *models.Host, cache nameCache, arp *ARPCache) {
	if h == nil {
		return
	}

	_ = arp
	snapshot := h.Snapshot()

	if snapshot.MAC != "" {
		if isMACRandomized(snapshot.MAC) {
			h.SetVendor("Randomized MAC — vendor unknown")
			h.SetDevice("Randomized MAC — device undetectable")
		} else if snapshot.Vendor == "" {
			h.SetVendorIfEmpty(VendorFromMAC(snapshot.MAC))
		}
	}

	if cache != nil && (snapshot.Hostname == "" || snapshot.Hostname == snapshot.IP) {
		if res, ok := cache.LookupName(snapshot.IP); ok {
			h.SetHostnameIfEmptyOrIP(res.name)
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
