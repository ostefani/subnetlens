package tui

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"

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
	opts      models.ScanOptions
	local     scanner.LocalDiscoveryInfo
	hostCh    chan *models.Host
	progCh    chan [2]int
	hosts     []*models.Host
	hostIndex map[string]int
	done      int
	total     int
	finished  bool
	result    *models.ScanResult
	err       error
}

func New(opts models.ScanOptions) Model {
	return Model{
		opts:      opts,
		local:     scanner.LocalDiscoveryInfoForTarget(opts.Subnet),
		hostCh:    make(chan *models.Host, 32),
		progCh:    make(chan [2]int, 32),
		hostIndex: make(map[string]int),
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
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case hostFoundMsg:
		if !m.finished {
			ip := msg.host.Snapshot().IP
			if _, exists := m.hostIndex[ip]; !exists {
				m.hostIndex[ip] = len(m.hosts)
				m.hosts = append(m.hosts, msg.host)
			}
		}
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
		m.hosts = msg.result.Hosts
		m.hostIndex = make(map[string]int, len(m.hosts))
		for i, host := range m.hosts {
			m.hostIndex[host.Snapshot().IP] = i
		}
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
		return layoutStyle.Render(fmt.Sprintf("\nError: %v\n", m.err))
	}

	var sb strings.Builder

	sb.WriteString(titleStyle.Render("✧ SUBNETLENS ✧"))
	sb.WriteString("\n")
	sb.WriteString(renderProgress(m.done, m.total))
	sb.WriteString("\n\n")

	if localBlock := renderLocalMachine(m.local); localBlock != "" {
		sb.WriteString(localBlock)
		sb.WriteString("\n\n")
	}

	visibleHosts := filterVisibleHosts(m.hosts, m.local)
	if len(visibleHosts) > 0 {
		sb.WriteString(renderHostTable(visibleHosts))
	} else if m.done > 0 {
		sb.WriteString(dimStyle.Render("  Searching for hosts..."))
	}

	if m.finished {
		sb.WriteString(fmt.Sprintf("\n  Scan complete. Found %d host(s) in %s\n",
			len(m.result.AliveHosts()),
			m.result.Duration().Round(0)))
		sb.WriteString(dimStyle.Render("  Press 'q' or 'ctrl+c' to exit"))
	}

	return layoutStyle.Render(sb.String())
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

func renderHostTable(hosts []*models.Host) string {
	headers := []string{"IP ADDRESS", "HOSTNAME", "MAC", "VENDOR", "OS", "DEVICE", "OPEN PORTS"}

	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(tableBorderStyle).
		Headers(headers...).
		StyleFunc(hostTableStyle)

	for _, host := range hosts {
		if host == nil {
			continue
		}
		t.Row(hostTableRow(host.Snapshot())...)
	}

	return t.String()
}

func hostTableStyle(row, col int) lipgloss.Style {
	switch {
	case row == 0:
		return tableHeaderStyle
	case col == 0:
		return tableHostStyle
	case col == 3:
		return tableVendorStyle
	case col == 4:
		return tableOSStyle
	case col == 5:
		return tableDeviceStyle
	default:
		return tableCellStyle
	}
}

func hostTableRow(snapshot models.HostSnapshot) []string {
	return []string{
		snapshot.IP,
		snapshot.Hostname,
		orDefault(snapshot.MAC, "—"),
		orDefault(snapshot.Vendor, "—"),
		hostOSLabel(snapshot.OS),
		orDefault(snapshot.Device, "—"),
		formatPorts(snapshot.OpenPorts),
	}
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
