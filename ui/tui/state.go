package tui

import (
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner"
)

func (m Model) visibleHosts() []*models.Host {
	if m.visibleCache != nil || len(m.hosts) == 0 {
		return m.visibleCache
	}
	return filterVisibleHosts(m.hosts, m.local)
}

func (m *Model) upsertHost(host *models.Host) {
	if !m.upsertHostNoRefresh(host) {
		return
	}
	m.rebuildVisibleHosts()
	m.invalidateTableCache()
	m.clampTableOffset()
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
	changed := false
	for _, host := range hosts {
		if m.upsertHostNoRefresh(host) {
			changed = true
		}
	}
	if !changed {
		return
	}
	m.rebuildVisibleHosts()
	m.invalidateTableCache()
	m.clampTableOffset()
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
	m.visibleCache = filterVisibleHosts(m.hosts, m.local)
}