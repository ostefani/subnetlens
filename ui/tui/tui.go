package tui

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

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
			Padding(1, 3).
			Foreground(lipgloss.Color("#d9fbff"))

	localMachineStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#d9fbff")).
				Padding(1, 3).
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

	sectionStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#59bfc4"))

	hostStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8bf850")).
			Bold(true)

	portStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFD700"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7e7e7e"))

	noteStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#f67b33"))

	vendorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CC99FF"))

	barFill = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#40e6ef"))

	barEmpty = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#333333"))

	progressMetaStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6d7478"))

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

	tableOSStyle = dimStyle.
			Padding(0, 1)

	tableDeviceStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#f67b33")).
				Padding(0, 1)

	tableCellStyle = lipgloss.NewStyle().
			Padding(0, 1)
)

const progressBarWidth = 40

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

type hostFoundMsg struct{ host *models.Host }
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
	hostIndex    map[string]int
	done         int
	total        int
	finished     bool
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
		hostIndex:    make(map[string]int),
		windowWidth:  defaultWindowWidth,
		windowHeight: defaultWindowHeight,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		runScanCmd(m.opts, m.hostCh, m.progCh),
		waitForHost(m.hostCh),
		waitForProgress(m.progCh),
	)
}

// --- Async commands ---

func runScanCmd(opts models.ScanOptions, hostCh chan *models.Host, progCh chan [2]int) tea.Cmd {
	return func() tea.Msg {
		defer close(hostCh)
		defer close(progCh)

		ctx := context.Background()
		var finalDone atomic.Int64
		var finalTotal atomic.Int64
		eng := &scanner.Engine{
			Opts: opts,
			OnHost: func(h *models.Host) {
				hostCh <- h

			},
			OnProgress: func(done, total int) {
				finalDone.Store(int64(done))
				finalTotal.Store(int64(total))

				select {
				case progCh <- [2]int{done, total}:
				default:
				}
			},
		}
		result := eng.Run(ctx)
		return scanDoneMsg{
			result:     result,
			finalDone:  int(finalDone.Load()),
			finalTotal: int(finalTotal.Load()),
		}
	}
}

func waitForHost(hostCh chan *models.Host) tea.Cmd {
	return func() tea.Msg {
		h, ok := <-hostCh
		if !ok {
			return nil
		}
		return hostFoundMsg{host: h}
	}
}

// waitForProgress blocks until the next progress tick arrives.
func waitForProgress(progCh chan [2]int) tea.Cmd {
	return func() tea.Msg {
		v, ok := <-progCh
		if !ok {
			return nil
		}
		return progressMsg{done: v[0], total: v[1]}
	}
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
			m.tableOffset = 0
		case "end", "G":
			m.tableOffset = m.maxTableOffset()
		}
		return m, nil

	case tea.WindowSizeMsg:
		m.windowWidth = msg.Width
		m.windowHeight = msg.Height
		m.clampTableOffset()
		return m, nil

	case hostFoundMsg:
		m.upsertHost(msg.host)
		return m, waitForHost(m.hostCh)

	case progressMsg:
		if m.finished {
			return m, nil
		}
		m.done = msg.done
		m.total = msg.total
		return m, waitForProgress(m.progCh)

	case scanDoneMsg:
		m.finished = true
		m.result = msg.result
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

	visibleHosts := m.visibleHosts()
	sections := []string{m.renderHeader()}

	if len(visibleHosts) > 0 {
		viewport := m.hostTableViewport(visibleHosts)
		if viewport.rows > 0 {
			pageHosts := visibleHosts[viewport.start:viewport.end]
			tableBlock := renderHostTable(pageHosts, viewport.width)
			footnote := renderRandomizedMACFootnote(pageHosts)
			status := renderHostTableStatus(len(visibleHosts), viewport.start, viewport.end)
			sections = append(sections, joinLines(tableBlock, footnote, status))
		} else {
			sections = append(sections, noteStyle.Render("Terminal is too small to render the host table. Expand the viewport to continue."))
		}
	} else if m.done > 0 {
		sections = append(sections, dimStyle.Render("  Searching for hosts..."))
	}

	if summary := m.renderSummary(); summary != "" {
		sections = append(sections, summary)
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

	return strings.Join([]string{
		fmt.Sprintf("  Scan complete. Found %d host(s) in %s",
			len(m.result.AliveHosts()),
			m.result.Duration().Round(0)),
		dimStyle.Render("  Press 'q' or 'ctrl+c' to exit."),
	}, "\n")
}

func (m Model) visibleHosts() []*models.Host {
	return filterVisibleHosts(m.hosts, m.local)
}

func (m *Model) upsertHost(host *models.Host) {
	if host == nil {
		return
	}

	ip := host.Snapshot().IP
	if ip == "" {
		return
	}

	if idx, exists := m.hostIndex[ip]; exists {
		// Keep the streamed order stable while refreshing the pointer in case
		// the final result slice carries the authoritative host instance.
		m.hosts[idx] = host
		return
	}

	m.hostIndex[ip] = len(m.hosts)
	m.hosts = append(m.hosts, host)
	m.clampTableOffset()
}

func (m *Model) mergeHosts(hosts []*models.Host) {
	for _, host := range hosts {
		m.upsertHost(host)
	}
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
	m.tableOffset += delta
	m.clampTableOffset()
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
	viewport := m.hostTableViewport(m.visibleHosts())
	if viewport.rows == 0 {
		return 0
	}
	maxOffset := len(m.visibleHosts()) - viewport.rows
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

func (m Model) hostTableViewport(hosts []*models.Host) tableViewport {
	if len(hosts) == 0 {
		return tableViewport{width: m.contentWidth()}
	}

	availableHeight := m.windowHeight - m.contentHeight(m.renderHeader()) - 1
	if availableHeight < 0 {
		availableHeight = 0
	}

	// The table is rendered as its own section, followed by a one-line status.
	availableHeight--
	if summary := m.renderSummary(); summary != "" {
		availableHeight -= m.contentHeight(summary) + 1
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

func joinSections(sections ...string) string {
	filtered := make([]string, 0, len(sections))
	for _, section := range sections {
		if section == "" {
			continue
		}
		filtered = append(filtered, section)
	}
	return strings.Join(filtered, "\n\n")
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
		if host == nil || host.Snapshot().IP == local.IP {
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
		return dimStyle.Render(fmt.Sprintf("  Hosts visible: %d", total))
	}

	return dimStyle.Render(fmt.Sprintf(
		"  Showing hosts %d-%d of %d. Use ↑/↓, PgUp/PgDn, Home/End to scroll.",
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
			return noteStyle.Render("  * For Randomized MAC vendor and device are undetectable.")
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
