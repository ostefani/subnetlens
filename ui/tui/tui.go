package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/charmbracelet/x/ansi"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner"
)

// --- Styles ---

var (
	layoutStyle = lipgloss.NewStyle().
			MarginLeft(2)

	progressStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#d9fbff"))

	localMachineStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#d9fbff")).
				MarginTop(1).MarginBottom(1).Padding(1, 3).
				Background(lipgloss.Color("#0c161b"))

	localMachineSectionStyle = lipgloss.NewStyle().
					Bold(true).
					Foreground(lipgloss.Color("#59bfc4")).
					Background(lipgloss.Color("#0c161b"))

	localMachineHostStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#A8FF78")).
				Bold(true).
				Background(lipgloss.Color("#0c161b"))

	localMachineHeaderStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#0c161b")).
				MarginTop(1)

	localMachineSpacerStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#0c161b"))

	localMachineBadgeStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#555555")).
				Background(lipgloss.Color("#d9e0e6")).
				Padding(0, 1)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#40e6ef")).
			MarginBottom(1).
			MarginTop(1)

	summaryHeaderStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#080808")).
				Bold(true).MarginTop(1)

	sectionStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#59bfc4"))

	hostStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#4ec60d")).
			Bold(true)

	portStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFD700"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7e7e7e")).PaddingLeft(2)

	noteStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#f67b33")).MarginTop(0).MarginLeft(2)

	vendorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CC99FF"))

	barFill = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#40e6ef"))

	barEmpty = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#333333"))

	progressMetaStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6d7478")).
				Padding(0, 1)

	tableBorderStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("240"))

	tableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#59bfc4")).
				Padding(0, 1)

	tableHostStyle = hostStyle.
			Padding(0, 1)

	tableVendorStyle = vendorStyle.
				Padding(0, 1)

	tableOSStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7e7e7e")).Padding(0, 1)

	tableDeviceStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#f67b33")).
				Padding(0, 1)

	tableCellStyle = lipgloss.NewStyle().
			Padding(0, 1)
)

const progressBarWidth = 40
const hostBatchSize = 16

const (
	defaultWindowWidth  = 120
	defaultWindowHeight = 32
	hostTableMinHeight  = 5
	hostTableFrameLines = 4
	ipColumnWidth       = 15
	hostnameColumnWidth = 15
	vendorColumnWidth   = 22
	deviceColumnWidth   = 18
	osColumnWidth       = 5
	macColumnWidth      = 20
)

const (
	randomizedMACVendorValue = "Randomized MAC — vendor unknown"
	randomizedMACDeviceValue = "Randomized MAC — device undetectable"
	randomizedMACLabel       = "Randomized MAC*"
)

// --- Messages ---

type hostsFoundMsg struct{ hosts []*models.Host }
type progressMsg struct{ done, total int }
type scanDoneMsg struct {
	result     *models.ScanResult
	finalDone  int
	finalTotal int
}

// --- Model ---

type Model struct {
	opts         models.ScanOptions
	local        scanner.LocalDiscoveryInfo
	hostCh       chan *models.Host
	progCh       chan [2]int
	hosts        []*models.Host
	visibleCache []*models.Host
	tableCache   *tableRenderCache
	hostIndex    map[string]int
	done         int
	total        int
	finished     bool
	aliveHosts   int
	result       *models.ScanResult
	err          error
	windowWidth  int
	windowHeight int
	tableOffset  int
}

func New(opts models.ScanOptions) Model {
	return Model{
		opts:         opts,
		local:        scanner.LocalDiscoveryInfoForTarget(opts.Subnet),
		hostCh:       make(chan *models.Host, 32),
		progCh:       make(chan [2]int, 32),
		tableCache:   &tableRenderCache{dirty: true},
		hostIndex:    make(map[string]int),
		windowWidth:  defaultWindowWidth,
		windowHeight: defaultWindowHeight,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		runScanCmd(m.opts, m.hostCh, m.progCh),
		waitForHostCmd(m.hostCh),
		waitForProgressCmd(m.progCh),
	)
}

// --- Update ---

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			m.scrollTable(-1)
		case "down", "j":
			m.scrollTable(1)
		case "pgup", "b":
			m.scrollTable(-m.tablePageStep())
		case "pgdown", " ":
			m.scrollTable(m.tablePageStep())
		case "home", "g":
			m.setTableOffset(0)
		case "end", "G":
			m.setTableOffset(m.maxTableOffset())
		}
		return m, nil

	case tea.WindowSizeMsg:
		m.windowWidth = msg.Width
		m.windowHeight = msg.Height
		m.clampTableOffset()
		m.invalidateTableCache()
		return m, nil

	case hostsFoundMsg:
		for _, host := range msg.hosts {
			m.upsertHost(host)
		}
		return m, waitForHostCmd(m.hostCh)

	case progressMsg:
		if m.finished {
			return m, nil
		}
		m.done = msg.done
		m.total = msg.total
		return m, waitForProgressCmd(m.progCh)

	case scanDoneMsg:
		m.finished = true
		m.result = msg.result
		m.aliveHosts = len(msg.result.AliveHosts())
		m.mergeHosts(msg.result.Hosts)
		m.clampTableOffset()
		switch {
		case msg.finalTotal > 0:
			m.total = msg.finalTotal
			m.done = msg.finalTotal
		case m.total > 0:
			m.done = m.total
		default:
			m.done = msg.finalDone
		}
		return m, nil
	}

	return m, nil
}

// --- View ---

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

func (m Model) renderHeader() string {
	return joinSections(
		titleStyle.Render("✧ SUBNETLENS ✧"),
		renderProgress(m.done, m.total),
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

func (m Model) summaryAliveHosts() int {
	if m.aliveHosts > 0 || m.result == nil {
		return m.aliveHosts
	}

	aliveHosts := 0
	for _, host := range m.result.Hosts {
		if host != nil && host.IsAlive() {
			aliveHosts++
		}
	}

	return aliveHosts
}

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

func (m *Model) rebuildVisibleHosts() {
	m.visibleCache = filterVisibleHosts(m.hosts, m.local)
}

func (m Model) contentWidth() int {
	width := m.windowWidth - layoutStyle.GetHorizontalFrameSize()
	if width < 1 {
		return 1
	}
	return width
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

func (m Model) hostTableViewport(hosts []*models.Host) tableViewport {
	return m.hostTableViewportWithLayout(hosts, m.viewLayout())
}

func (m Model) hostTableViewportWithLayout(hosts []*models.Host, layout viewLayout) tableViewport {
	if len(hosts) == 0 {
		return tableViewport{width: m.contentWidth()}
	}

	availableHeight := m.windowHeight - layout.headerHeight - 1
	if availableHeight < 0 {
		availableHeight = 0
	}

	// The table is rendered as its own section, followed by a one-line status.
	availableHeight--
	if layout.summary != "" {
		availableHeight -= layout.summaryHeight + 1
	}

	if availableHeight < hostTableMinHeight {
		return tableViewport{width: m.contentWidth()}
	}

	rows := availableHeight - hostTableFrameLines
	if rows < 1 {
		return tableViewport{width: m.contentWidth()}
	}

	maxStart := len(hosts) - rows
	if maxStart < 0 {
		maxStart = 0
	}

	start := m.tableOffset
	if start < 0 {
		start = 0
	}
	if start > maxStart {
		start = maxStart
	}

	end := start + rows
	if end > len(hosts) {
		end = len(hosts)
	}

	return tableViewport{
		width: m.contentWidth(),
		rows:  rows,
		start: start,
		end:   end,
	}
}

func (m *Model) invalidateTableCache() {
	if m.tableCache == nil {
		m.tableCache = &tableRenderCache{dirty: true}
		return
	}
	m.tableCache.dirty = true
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

func renderLocalMachine(info scanner.LocalDiscoveryInfo) string {
	if info.Hostname == "" && info.Interface == "" {
		return ""
	}

	name := info.Hostname
	if name == "" {
		name = "Local machine"
	}

	var lines []string
	lines = append(lines, localMachineSectionStyle.Render("Local Machine"))

	header := localMachineHostStyle.Render(name)
	if info.Interface != "" {
		header = lipgloss.JoinHorizontal(
			lipgloss.Top,
			header,
			localMachineSpacerStyle.Render("  "),
			localMachineBadgeStyle.Render("("+info.Interface+")"),
		)
	}
	lines = append(lines, localMachineHeaderStyle.Render(header))

	if info.InSubnet {
		ip := info.IP

		if ip == "" {
			ip = "—"
		}

		mac := info.MAC
		if mac == "" {
			mac = "—"
		}

		lines = append(lines, fmt.Sprintf("IP: %s   MAC: %s", ip, mac))
		if !info.InScanRange {
			lines = append(lines, dimStyle.Render("Discovery interface is active, but its IP is outside the requested scan range."))
		}

		return localMachineStyle.Render(strings.Join(lines, "\n"))
	}

	lines = append(lines, noteStyle.Render("Scanning from a different subnet; local IP/MAC details are hidden."))
	return localMachineStyle.Render(strings.Join(lines, "\n"))
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

func hostTableStyle(row, col int) lipgloss.Style {
	style := tableCellStyle

	switch {
	case row == table.HeaderRow:
		style = tableHeaderStyle
	case col == 0:
		style = tableHostStyle
	case col == 3:
		style = tableVendorStyle
	case col == 4:
		style = tableOSStyle
	case col == 5:
		style = tableDeviceStyle
	}

	switch col {
	case 0:
		return style.Width(ipColumnWidth)
	case 1:
		return style.Width(hostnameColumnWidth)
	case 2:
		return style.Width(macColumnWidth)
	case 3:
		return style.Width(vendorColumnWidth)
	case 4:
		return style.Width(osColumnWidth)
	case 5:
		return style.Width(deviceColumnWidth)
	default:
		return style
	}
}

func renderHostTableStatus(total, start, end int) string {
	if total == 0 || end == 0 {
		return ""
	}

	if start == 0 && end == total {
		return dimStyle.Render(fmt.Sprintf("Hosts visible: %d", total))
	}

	return dimStyle.Render(fmt.Sprintf(
		"Showing hosts %d-%d of %d. Use ↑/↓, PgUp/PgDn, Home/End to scroll.",
		start+1,
		end,
		total,
	))
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

func renderRandomizedMACFootnote(hosts []*models.Host) string {
	for _, host := range hosts {
		if host == nil {
			continue
		}
		snapshot := host.Snapshot()
		if snapshot.Vendor == randomizedMACVendorValue || snapshot.Device == randomizedMACDeviceValue {
			return noteStyle.Render("* For Randomized MAC vendor and device are undetectable.")
		}
	}
	return ""
}

func truncateCell(value string, width int) string {
	if width <= 0 {
		return ""
	}
	return ansi.Truncate(value, width, "…")
}

func formatPorts(ports []models.Port) string {
	if len(ports) == 0 {
		return "—"
	}
	var pStrings []string
	for _, p := range ports {
		pStrings = append(pStrings, fmt.Sprintf("%d/%s", p.Number, p.Service))
	}
	return portStyle.Render(strings.Join(pStrings, ", "))
}

func renderProgress(done, total int) string {
	if total <= 0 {
		total = 1
	}

	pct := done * 100 / total
	content := lipgloss.JoinVertical(lipgloss.Left,
		sectionStyle.Render("Scanning Hosts"),
		renderProgressBar(done, total),
		progressMetaStyle.Render(fmt.Sprintf("%3d%%  (%d/%d)", pct, done, total)),
	)

	return progressStyle.Render(content)
}

func renderProgressBar(done, total int) string {
	filled := done * progressBarWidth / total
	if filled < 0 {
		filled = 0
	}
	if filled > progressBarWidth {
		filled = progressBarWidth
	}

	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		barFill.Render(strings.Repeat("█", filled)),
		barEmpty.Render(strings.Repeat("░", progressBarWidth-filled)),
	)
}

func hostOSLabel(hostOS string) string {
	if hostOS == "" || hostOS == "Unknown" {
		return "?"
	}
	return hostOS
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// Run starts the TUI program.
func Run(opts models.ScanOptions) error {
	m := New(opts)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
