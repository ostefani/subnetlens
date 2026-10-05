// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package tui

import (
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner"
)

func (m Model) visibleHosts() []*models.Host {
	if m.visibleCache != nil || len(m.hosts) == 0 {
		return m.visibleCache
	}
	return m.computeVisibleHosts()
}

// refreshListing rebuilds the visible set after a sort/filter keypress. The
// offset is clamped because filtering can shrink the list under the cursor.
func (m *Model) refreshListing() {
	m.rebuildVisibleHosts()
	m.clampTableOffset()
	m.invalidateTableCache()
}

// computeVisibleHosts drops the local machine, applies the --filter
// expression plus the weak/no-open-ports toggles, then sorts. It always
// returns a fresh slice so sorting never reorders the arrival-ordered
// m.hosts backing store. Order refreshes when hosts arrive and on every
// sort/filter keypress — not on every in-place host update.
func (m Model) computeVisibleHosts() []*models.Host {
	visible := filterVisibleHosts(m.hosts, m.local)
	filtered := make([]*models.Host, 0, len(visible))
	for _, host := range visible {
		if host == nil {
			continue
		}
		snapshot := host.Snapshot()
		if m.hideWeak && snapshot.Weak {
			continue
		}
		if m.hideNoOpenPorts && len(snapshot.OpenPorts()) == 0 {
			continue
		}
		if m.filter != nil && !m.filter.Matches(snapshot) {
			continue
		}
		filtered = append(filtered, host)
	}
	scanner.SortHosts(filtered, m.sortOrder)
	return filtered
}

func (m *Model) applyHostBatch(hosts []*models.Host) {
	visibleDirty := false
	tableDirty := false

	for _, host := range hosts {
		if host == nil || host.IP() == "" {
			continue
		}

		tableDirty = true
		if m.upsertHostNoRefresh(host) {
			visibleDirty = true
		}
	}

	if visibleDirty {
		m.rebuildVisibleHosts()
		m.clampTableOffset()
	}
	if tableDirty {
		m.invalidateTableCache()
	}
}

func (m *Model) scrollTable(delta int) {
	if delta == 0 {
		return
	}
	m.setTableOffset(m.tableOffset + delta)
}

func (m *Model) setTableOffset(offset int) {
	previous := m.tableOffset
	m.tableOffset = offset
	m.clampTableOffset()
	if m.tableOffset != previous {
		m.invalidateTableCache()
	}
}

func (m *Model) clampTableOffset() {
	if m.tableOffset < 0 {
		m.tableOffset = 0
		return
	}
	maxOffset := m.maxTableOffset()
	if m.tableOffset > maxOffset {
		m.tableOffset = maxOffset
	}
}

func (m Model) maxTableOffset() int {
	visibleHosts := m.visibleHosts()
	viewport := m.hostTableViewport(visibleHosts)
	if viewport.rows == 0 {
		return 0
	}
	maxOffset := len(visibleHosts) - viewport.rows
	if maxOffset < 0 {
		return 0
	}
	return maxOffset
}

func (m Model) tablePageStep() int {
	viewport := m.hostTableViewport(m.visibleHosts())
	if viewport.rows <= 1 {
		return 1
	}
	return viewport.rows - 1
}

func (m *Model) upsertHostNoRefresh(host *models.Host) bool {
	if host == nil {
		return false
	}

	ip := host.IP()
	if ip == "" {
		return false
	}

	if idx, exists := m.hostIndex[ip]; exists {
		// Keep the streamed order stable while refreshing the pointer in case
		// the final result slice carries the authoritative host instance.
		if m.hosts[idx] == host {
			return false
		}
		m.hosts[idx] = host
		return true
	}

	m.hostIndex[ip] = len(m.hosts)
	m.hosts = append(m.hosts, host)
	return true
}

func (m *Model) mergeHosts(hosts []*models.Host) {
	m.applyHostBatch(hosts)
}

func filterVisibleHosts(hosts []*models.Host, local scanner.LocalDiscoveryInfo) []*models.Host {
	if !local.InScanRange || local.IP == "" {
		return hosts
	}

	visible := make([]*models.Host, 0, len(hosts))
	for _, host := range hosts {
		if host == nil || host.IP() == local.IP {
			continue
		}
		visible = append(visible, host)
	}
	return visible
}

func (m *Model) rebuildVisibleHosts() {
	m.visibleCache = m.computeVisibleHosts()
}
