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
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7DF9FF")).
			MarginBottom(1)

	hostStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A8FF78")).
			Bold(true)

	portStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFD700"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#555555"))

	vendorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CC99FF"))

	barFill  = lipgloss.NewStyle().Foreground(lipgloss.Color("#7DF9FF"))
	barEmpty = lipgloss.NewStyle().Foreground(lipgloss.Color("#333333"))
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
	opts      models.ScanOptions
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
		return fmt.Sprintf("\n  Error: %v\n\n", m.err)
	}

	var sb strings.Builder

	sb.WriteString(titleStyle.Render("⬡ SubnetLens Scanner"))
	sb.WriteString("\n")
	sb.WriteString(renderProgress(m.done, m.total))
	sb.WriteString("\n\n")

	if len(m.hosts) > 0 {
		headers := []string{"IP ADDRESS", "HOSTNAME", "MAC", "VENDOR", "OS", "DEVICE", "OPEN PORTS"}

		t := table.New().
			Border(lipgloss.NormalBorder()).
			BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("240"))).
			Headers(headers...).
			StyleFunc(func(row, col int) lipgloss.Style {
				switch {
				case row == 0:
					return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#59bfc4")).Padding(0, 1)
				case col == 0:
					return hostStyle.Copy().Padding(0, 1)
				case col == 3:
					return vendorStyle.Copy().Padding(0, 1)
				case col == 4:
					return dimStyle.Copy().Padding(0, 1)
				case col == 5:
					return lipgloss.NewStyle().Foreground(lipgloss.Color("#f67b33")).Padding(0, 1)
				default:
					return lipgloss.NewStyle().Padding(0, 1)
				}
			})

		for _, h := range m.hosts {
			snapshot := h.Snapshot()
			os := snapshot.OS
			if os == "" || os == "Unknown" {
				os = "?"
			}
			mac := snapshot.MAC
			if mac == "" {
				mac = "—"
			}
			vendor := snapshot.Vendor
			if vendor == "" {
				vendor = "—"
			}
			device := snapshot.Device
			if device == "" {
				device = "—"
			}
			t.Row(snapshot.IP, snapshot.Hostname, mac, vendor, os, device, formatPorts(snapshot.OpenPorts))
		}

		sb.WriteString(t.String())
	} else if m.done > 0 {
		sb.WriteString(dimStyle.Render("  Searching for hosts..."))
	}

	if m.finished {
		sb.WriteString(fmt.Sprintf("\n  Scan complete. Found %d host(s) in %s\n",
			len(m.result.AliveHosts()),
			m.result.Duration().Round(0)))
		sb.WriteString(dimStyle.Render("  Press 'q' or 'ctrl+c' to exit"))
	}

	return sb.String()
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
	width := 40
	if total == 0 {
		total = 1
	}
	filled := done * width / total
	bar := barFill.Render(strings.Repeat("█", filled)) +
		barEmpty.Render(strings.Repeat("░", width-filled))
	pct := done * 100 / total
	return fmt.Sprintf("Scanning hosts  %s  %3d%%  (%d/%d)", bar, pct, done, total)
}

// Run starts the TUI program.
func Run(opts models.ScanOptions) error {
	m := New(opts)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
