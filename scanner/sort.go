// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ostefani/subnetlens/models"
)

// Host listing orders shared by the CLI flags and the TUI sort cycle.
const (
	SortDiscovery = "discovery"
	SortIP        = "ip"
	SortLatency   = "latency"
	SortVendor    = "vendor"
	SortHostname  = "hostname"
)

// SortOrders lists every valid sort order. The slice order doubles as the
// TUI sort-cycle sequence.
var SortOrders = []string{SortDiscovery, SortIP, SortLatency, SortVendor, SortHostname}

// NormalizeSortOrder validates a raw --sort value. Empty input means
// discovery (arrival) order, which preserves the historical streaming order.
func NormalizeSortOrder(raw string) (string, error) {
	cleaned := strings.ToLower(strings.TrimSpace(raw))
	if cleaned == "" {
		return SortDiscovery, nil
	}
	for _, order := range SortOrders {
		if cleaned == order {
			return cleaned, nil
		}
	}
	return "", fmt.Errorf("invalid --sort %q: want one of %s", raw, strings.Join(SortOrders, ", "))
}

// DefaultSortOrder resolves a sort order without failing: "" and unknown
// values fall back to discovery order. The CLI validates strictly via
// NormalizeSortOrder; this is for frontends holding already-validated input.
func DefaultSortOrder(raw string) string {
	if order, err := NormalizeSortOrder(raw); err == nil {
		return order
	}
	return SortDiscovery
}

// NextSortOrder advances the TUI sort cycle.
func NextSortOrder(current string) string {
	resolved := DefaultSortOrder(current)
	for i, order := range SortOrders {
		if order == resolved {
			return SortOrders[(i+1)%len(SortOrders)]
		}
	}
	return SortDiscovery
}

// SortSnapshots sorts snapshots in place (stable). Discovery order is a
// no-op that preserves arrival order. Non-IP orders break ties by numeric
// IP so listings are deterministic.
func SortSnapshots(snapshots []models.HostSnapshot, order string) {
	resolved := DefaultSortOrder(order)
	if resolved == SortDiscovery || len(snapshots) < 2 {
		return
	}
	keys := make([]hostSortKey, len(snapshots))
	for i := range snapshots {
		keys[i] = makeHostSortKey(snapshots[i])
	}
	applyPermutation(snapshots, sortedPermutation(keys, nil, resolved))
}

// SortHosts sorts host pointers by their snapshots (each host is snapshotted
// once). Nil entries sort last. Discovery order is a no-op.
func SortHosts(hosts []*models.Host, order string) {
	resolved := DefaultSortOrder(order)
	if resolved == SortDiscovery || len(hosts) < 2 {
		return
	}
	keys := make([]hostSortKey, len(hosts))
	skip := make([]bool, len(hosts))
	for i, host := range hosts {
		if host == nil {
			skip[i] = true
			continue
		}
		keys[i] = makeHostSortKey(host.Snapshot())
	}
	applyPermutation(hosts, sortedPermutation(keys, skip, resolved))
}

// hostSortKey is the precomputed comparison state for one host. IP parsing
// and case folding happen once per sort — not once per comparison — so the
// O(N log N) comparator itself allocates nothing.
type hostSortKey struct {
	addr     netip.Addr
	hasAddr  bool
	rawIP    string
	latency  time.Duration
	vendor   string
	hostname string
}

func makeHostSortKey(snapshot models.HostSnapshot) hostSortKey {
	key := hostSortKey{
		rawIP:    snapshot.IP,
		latency:  snapshot.Latency,
		vendor:   strings.ToLower(snapshot.Vendor),
		hostname: strings.ToLower(snapshot.Hostname),
	}
	if addr, err := netip.ParseAddr(snapshot.IP); err == nil {
		key.addr, key.hasAddr = addr, true
	}
	return key
}

// sortedPermutation returns the identity permutation sorted by keys under
// order (stable, so equal keys keep arrival order). Positions flagged in
// skip sort last; a nil skip slice disables the check.
func sortedPermutation(keys []hostSortKey, skip []bool, order string) []int {
	perm := make([]int, len(keys))
	for i := range perm {
		perm[i] = i
	}
	slices.SortStableFunc(perm, func(a, b int) int {
		if skip != nil {
			switch {
			case skip[a] && skip[b]:
				return 0
			case skip[a]:
				return 1
			case skip[b]:
				return -1
			}
		}
		return compareSortKeys(keys[a], keys[b], order)
	})
	return perm
}

func applyPermutation[T any](items []T, perm []int) {
	sorted := make([]T, len(items))
	for i, idx := range perm {
		sorted[i] = items[idx]
	}
	copy(items, sorted)
}

func compareSortKeys(a, b hostSortKey, order string) int {
	switch order {
	case SortLatency:
		if c := compareLatency(a.latency, b.latency); c != 0 {
			return c
		}
	case SortVendor:
		if c := compareKeyText(a.vendor, b.vendor); c != 0 {
			return c
		}
	case SortHostname:
		if c := compareKeyText(a.hostname, b.hostname); c != 0 {
			return c
		}
	}
	return compareKeyIP(a, b)
}

// compareKeyIP orders IPv4 numerically (.2 before .10). Unparseable values
// sort last, ordered lexically among themselves.
func compareKeyIP(a, b hostSortKey) int {
	switch {
	case a.hasAddr && b.hasAddr:
		return a.addr.Compare(b.addr)
	case a.hasAddr:
		return -1
	case b.hasAddr:
		return 1
	default:
		return strings.Compare(a.rawIP, b.rawIP)
	}
}

// compareLatency orders round-trip times ascending; zero (unknown) sorts last.
func compareLatency(a, b time.Duration) int {
	switch {
	case a == b:
		return 0
	case a == 0:
		return 1
	case b == 0:
		return -1
	case a < b:
		return -1
	default:
		return 1
	}
}

// compareKeyText orders pre-lowered text; empty sorts last.
func compareKeyText(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	default:
		return strings.Compare(a, b)
	}
}
