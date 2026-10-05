// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package tui

import (
	tea "github.com/charmbracelet/bubbletea"
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
// cursor and offset are clamped because filtering can shrink the list under
// them.
func (m *Model) refreshListing() {
	m.rebuildVisibleHosts()
	m.clampSelected()
	m.clampTableOffset()
	m.ensureSelectedVisible()
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
		m.clampSelected()
		m.clampTableOffset()
		m.ensureSelectedVisible()
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

// --- Selection ---

func (m *Model) clampSelected() {
	if m.selected < 0 {
		m.selected = 0
		return
	}
	if maxSelected := len(m.visibleHosts()) - 1; m.selected > maxSelected {
		m.selected = max(0, maxSelected)
	}
}

func (m *Model) moveSelection(delta int) {
	if delta == 0 || len(m.visibleHosts()) == 0 {
		return
	}
	previous := m.selected
	m.selected += delta
	m.clampSelected()
	m.ensureSelectedVisible()
	if m.selected != previous {
		m.invalidateTableCache()
	}
}

func (m *Model) moveSelectionTo(index int) {
	if len(m.visibleHosts()) == 0 {
		return
	}
	previous := m.selected
	m.selected = index
	m.clampSelected()
	m.ensureSelectedVisible()
	if m.selected != previous {
		m.invalidateTableCache()
	}
}

// ensureSelectedVisible scrolls the table just enough to keep the cursor in
// view after selection moves, listing rebuilds, or window resizes.
func (m *Model) ensureSelectedVisible() {
	visibleHosts := m.visibleHosts()
	if len(visibleHosts) == 0 {
		return
	}
	m.clampSelected()
	viewport := m.hostTableViewport(visibleHosts)
	if viewport.rows == 0 {
		return
	}
	switch {
	case m.selected < viewport.start:
		m.setTableOffset(m.selected)
	case m.selected >= viewport.end:
		m.setTableOffset(m.selected - viewport.rows + 1)
	}
}

// --- Detail view ---

func (m *Model) openDetail() {
	visibleHosts := m.visibleHosts()
	if len(visibleHosts) == 0 {
		return
	}
	m.clampSelected()
	if visibleHosts[m.selected] == nil {
		return
	}
	m.detailOpen = true
	m.detailIP = visibleHosts[m.selected].IP()
	m.detailOffset = 0
}

func (m *Model) closeDetail() {
	m.detailOpen = false
	m.detailOffset = 0
	visibleHosts := m.visibleHosts()
	for i, host := range visibleHosts {
		if host != nil && host.IP() == m.detailIP {
			m.selected = i
			break
		}
	}
	m.clampSelected()
	m.ensureSelectedVisible()
	m.invalidateTableCache()
}

// detailHost resolves the open detail view against the live listing. The host
// pointer is looked up on every call so the detail view reflects in-place
// updates; index/total drive the "host i/n" position hint.
func (m Model) detailHost() (host *models.Host, index, total int) {
	visibleHosts := m.visibleHosts()
	for i, candidate := range visibleHosts {
		if candidate != nil && candidate.IP() == m.detailIP {
			return candidate, i, len(visibleHosts)
		}
	}
	return nil, 0, len(visibleHosts)
}

func (m *Model) detailNext(delta int) {
	_, index, total := m.detailHost()
	if total == 0 {
		return
	}
	next := clamp(index+delta, 0, total-1)
	if host := m.visibleHosts()[next]; host != nil {
		m.detailIP = host.IP()
	}
	m.detailOffset = 0
}

func (m *Model) scrollDetail(delta int) {
	if delta == 0 {
		return
	}
	m.detailOffset = clamp(m.detailOffset+delta, 0, m.maxDetailOffset())
}

func (m Model) maxDetailOffset() int {
	host, _, _ := m.detailHost()
	if host == nil {
		return 0
	}
	rows := m.detailRows(m.viewLayout())
	maxOffset := len(m.detailLines(host)) - rows
	return max(0, maxOffset)
}

func (m Model) detailPageStep() int {
	rows := m.detailRows(m.viewLayout())
	if rows <= 1 {
		return 1
	}
	return rows - 1
}

func (m Model) updateDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.closeDetail()
	case "n":
		m.detailNext(1)
	case "p":
		m.detailNext(-1)
	case "up", "k":
		m.scrollDetail(-1)
	case "down", "j":
		m.scrollDetail(1)
	case "pgup", "b":
		m.scrollDetail(-m.detailPageStep())
	case "pgdown", " ":
		m.scrollDetail(m.detailPageStep())
	case "home", "g":
		m.detailOffset = 0
	case "end", "G":
		m.detailOffset = m.maxDetailOffset()
	}
	return m, nil
}
