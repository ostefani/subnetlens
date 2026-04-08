package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/charmbracelet/x/ansi"
	"github.com/ostefani/subnetlens/internal/textutil"
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner"
)

type tableViewport struct {
	width int
	rows  int
	start int
	end   int
}

type tableRenderCache struct {
	width    int
	start    int
	end      int
	total    int
	rendered string
	dirty    bool
}

type viewLayout struct {
	header        string
	headerHeight  int
	summary       string
	summaryHeight int
}

// --- Top-level View ---

func (m Model) View() string {
	if m.err != nil {
		return m.renderLayout(fmt.Sprintf("\nError: %v\n", m.err))
	}

	layout := m.viewLayout()
	visibleHosts := m.visibleHosts()
	sections := []string{layout.header}

	if len(visibleHosts) > 0 {
		viewport := m.hostTableViewportWithLayout(visibleHosts, layout)
		if viewport.rows > 0 {
			sections = append(sections, m.renderHostTableSection(visibleHosts, viewport))
		} else {
			sections = append(sections, noteStyle.Render("Terminal is too small to render the host table. Expand the viewport to continue."))
		}
	} else if m.done > 0 {
		sections = append(sections, dimStyle.Render("Searching for hosts..."))
	}

	if layout.summary != "" {
		sections = append(sections, layout.summary)
	}

	return m.renderLayout(joinSections(sections...))
}

// --- Layout helpers ---

func (m Model) viewLayout() viewLayout {
	header := m.renderHeader()
	summary := m.renderSummary()

	return viewLayout{
		header:        header,
		headerHeight:  m.contentHeight(header),
		summary:       summary,
		summaryHeight: m.contentHeight(summary),
	}
}

func (m Model) renderLayout(content string) string {
	width := m.windowWidth
	if width < 1 {
		width = 1
	}
	return layoutStyle.
		MaxWidth(width).
		Render(content)
}

func (m Model) contentWidth() int {
	return max(m.windowWidth-layoutStyle.GetHorizontalFrameSize(), 1)
}

func (m Model) contentHeight(content string) int {
	if content == "" {
		return 0
	}
	return lipgloss.Height(
		lipgloss.NewStyle().
			MaxWidth(m.contentWidth()).
			Render(content),
	)
}

// --- Viewport calculation ---

func (m Model) hostTableViewport(hosts []*models.Host) tableViewport {
	return m.hostTableViewportWithLayout(hosts, m.viewLayout())
}

func (m Model) hostTableViewportWithLayout(hosts []*models.Host, layout viewLayout) tableViewport {
	empty := tableViewport{width: m.contentWidth()}

	if len(hosts) == 0 {
		return empty
	}

	availableHeight := m.windowHeight - layout.headerHeight - 1
	if availableHeight < 0 {
		availableHeight = 0
	}

	availableHeight--
	if layout.summary != "" {
		availableHeight -= layout.summaryHeight + 1
	}

	rows := availableHeight - hostTableFrameLines
	if rows < 1 || availableHeight < hostTableMinHeight {
		return empty
	}

	maxStart := max(0, len(hosts)-rows)
	start := clamp(m.tableOffset, 0, maxStart)
	end := min(start+rows, len(hosts))

	return tableViewport{width: m.contentWidth(), rows: rows, start: start, end: end}
}

func (m *Model) invalidateTableCache() {
	if m.tableCache == nil {
		m.tableCache = &tableRenderCache{dirty: true}
		return
	}
	m.tableCache.dirty = true
}

// --- Section renderers ---

func (m Model) renderHeader() string {
	return joinSections(
		titleStyle.Render("✧ SUBNETLENS ✧"),
		renderProgress(m.done, m.total),
		renderWarnings(m.warnings),
		renderLocalMachine(m.local),
	)
}

func (m Model) renderSummary() string {
	if !m.finished || m.result == nil {
		return ""
	}

	summaryHeader := summaryHeaderStyle.Render(fmt.Sprintf(
		"Scan complete. Found %d host(s) in %s",
		m.summaryAliveHosts(),
		m.result.Duration().Round(0),
	))
	exitHint := dimStyle.Render("Press 'q' or 'ctrl+c' to exit.")

	return lipgloss.JoinVertical(
		lipgloss.Left,
		summaryHeader,
		exitHint,
	)
}

func (m Model) renderHostTableSection(visibleHosts []*models.Host, viewport tableViewport) string {
	cache := m.tableCache
	if cache == nil {
		cache = &tableRenderCache{dirty: true}
	}

	if cache.dirty ||
		cache.width != viewport.width ||
		cache.start != viewport.start ||
		cache.end != viewport.end ||
		cache.total != len(visibleHosts) {
		pageHosts := visibleHosts[viewport.start:viewport.end]
		tableBlock := renderHostTable(pageHosts, viewport.width)
		footnote := renderRandomizedMACFootnote(pageHosts)
		status := renderHostTableStatus(len(visibleHosts), viewport.start, viewport.end)

		cache.width = viewport.width
		cache.start = viewport.start
		cache.end = viewport.end
		cache.total = len(visibleHosts)
		cache.rendered = joinLines(tableBlock, footnote, status)
		cache.dirty = false
	}

	return cache.rendered
}

// --- Primitive renderers ---

func renderProgress(done, total int) string {
	total = max(total, 1)

	pct := done * 100 / total
	return lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.NewStyle().PaddingLeft(1).Render(renderProgressBar(done, total)),
		progressMetaStyle.Render(fmt.Sprintf("Scanning Hosts: (%d/%d)  %3d%%", done, total, pct)),
	)
}

func renderProgressBar(done, total int) string {
	filled := clamp(done*progressBarWidth/total, 0, progressBarWidth)

	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		barFill.Render(strings.Repeat("█", filled)),
		barEmpty.Render(strings.Repeat("░", progressBarWidth-filled)),
	)
}

func renderLocalMachine(info scanner.LocalDiscoveryInfo) string {
	if info.Hostname == "" && info.Interface == "" {
		return ""
	}

	name := info.Hostname
	if name == "" {
		name = "Local machine"
	}
	name = textutil.SanitizeInline(name)
	ifaceName := textutil.SanitizeInline(info.Interface)

	lines := []string{
		localMachineHeaderStyle.Render("Local Machine:"),
		localMachineContentStyle.Render("Hostname: " + name),
	}
	if ifaceName != "" {
		lines = append(lines, localMachineContentStyle.Render("Interface: "+ifaceName))
	}

	body := noteStyle.Render("Scanning from a different subnet; local IP/MAC details are hidden.")
	if info.InSubnet {
		ip := info.IP
		if ip == "" {
			ip = "—"
		}

		mac := info.MAC
		if mac == "" {
			mac = "—"
		}

		body = localMachineContentStyle.Render(fmt.Sprintf("IP: %s   MAC: %s", ip, mac))
		if !info.InScanRange {
			lines = append(lines, dimStyle.Render("Discovery interface is active, but its IP is outside the requested scan range."))
		}
	}

	lines = append(lines, body)
	return localMachineStyle.Render(joinLines(lines...))
}

func renderWarnings(warnings []string) string {
	if len(warnings) == 0 {
		return ""
	}

	lines := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		warning = strings.TrimSpace(warning)
		if warning == "" {
			continue
		}
		lines = append(lines, noteStyle.Render("Warning: "+warning))
	}

	return joinLines(lines...)
}

func renderHostTable(hosts []*models.Host, width int) string {
	headers := []string{"IP ADDRESS", "HOSTNAME", "MAC", "VENDOR", "OS", "DEVICE", "OPEN PORTS"}

	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(tableBorderStyle).
		Headers(headers...).
		StyleFunc(hostTableStyle).
		Wrap(false)

	if width > 0 {
		t.Width(width)
	}

	for _, host := range hosts {
		if host == nil {
			continue
		}
		t.Row(hostTableRow(host.Snapshot())...)
	}

	return t.String()
}

func renderHostTableStatus(total, start, end int) string {
	if total == 0 || end == 0 {
		return ""
	}

	if start == 0 && end == total {
		return tableStatusStyle.Render(fmt.Sprintf("Hosts visible: %d", total))
	}

	return tableStatusStyle.Render(fmt.Sprintf(
		"Showing hosts %d-%d of %d. Use ↑/↓, PgUp/PgDn, Home/End to scroll.",
		start+1,
		end,
		total,
	))
}

func renderRandomizedMACFootnote(hosts []*models.Host) string {
	for _, host := range hosts {
		if host == nil {
			continue
		}
		snapshot := host.Snapshot()
		if snapshot.Vendor == randomizedMACVendorValue || snapshot.Device == randomizedMACDeviceValue {
			return footnoteStyle.Render("* For Randomized MAC vendor and device are undetectable.")
		}
	}
	return ""
}

// --- Table cell helpers ---

func hostTableStyle(row, col int) lipgloss.Style {
	var base lipgloss.Style
	switch {
	case row == table.HeaderRow:
		return tableHeaderStyle
	case col == 0:
		base = tableHostStyle
	case col == 3:
		base = tableVendorStyle
	case col == 4:
		base = tableOSStyle
	case col == 5:
		base = tableDeviceStyle
	default:
		base = tableCellStyle
	}

	switch col {
	case 0:
		return base.Width(ipColumnWidth)
	case 1:
		return base.Width(hostnameColumnWidth)
	case 2:
		return base.Width(macColumnWidth)
	case 3:
		return base.Width(vendorColumnWidth)
	case 4:
		return base.Width(osColumnWidth)
	case 5:
		return base.Width(deviceColumnWidth)
	default:
		return base
	}
}

func hostTableRow(snapshot models.HostSnapshot) []string {
	return []string{
		truncateCell(snapshot.IP, ipColumnWidth-2),
		truncateCell(snapshot.Hostname, hostnameColumnWidth-2),
		orDefault(snapshot.MAC, "—"),
		truncateCell(displayVendor(snapshot.Vendor), vendorColumnWidth-2),
		hostOSLabel(snapshot.OS),
		truncateCell(displayDevice(snapshot.Device), deviceColumnWidth-2),
		formatPorts(snapshot.OpenPorts),
	}
}

func displayVendor(vendor string) string {
	switch vendor {
	case randomizedMACVendorValue:
		return randomizedMACLabel
	default:
		return orDefault(vendor, "—")
	}
}

func displayDevice(device string) string {
	switch device {
	case randomizedMACDeviceValue:
		return randomizedMACLabel
	default:
		return orDefault(device, "—")
	}
}

func hostOSLabel(hostOS string) string {
	if hostOS == "" || hostOS == "Unknown" {
		return "?"
	}
	return hostOS
}

func formatPorts(ports []models.Port) string {
	if len(ports) == 0 {
		return "—"
	}
	pStrings := make([]string, 0, len(ports))
	for _, p := range ports {
		label := fmt.Sprintf("%d/%s", p.Number, p.Protocol)
		if p.Service != "" {
			label += " " + p.Service
		}
		pStrings = append(pStrings, label)
	}
	return portStyle.Render(strings.Join(pStrings, ", "))
}

func truncateCell(value string, width int) string {
	if width <= 0 {
		return ""
	}
	return ansi.Truncate(value, width, "…")
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// --- String layout helpers ---

func joinSections(sections ...string) string {
	filtered := make([]string, 0, len(sections))
	for _, s := range sections {
		if strings.TrimSpace(s) != "" {
			filtered = append(filtered, s)
		}
	}
	return lipgloss.JoinVertical(lipgloss.Left, filtered...)
}

func joinLines(lines ...string) string {
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.Join(filtered, "\n")
}

// --- Generic math helpers ---

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (m Model) summaryAliveHosts() int {
	if m.aliveCountOK || m.result == nil {
		return m.aliveHosts
	}

	return countAliveHosts(m.result.Hosts)
}

func countAliveHosts(hosts []*models.Host) int {
	aliveHosts := 0
	for _, host := range hosts {
		if host != nil && host.IsAlive() {
			aliveHosts++
		}
	}

	return aliveHosts
}
