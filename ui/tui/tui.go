package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner"
)

const (
	randomizedMACVendorValue = "Randomized MAC — vendor unknown"
	randomizedMACDeviceValue = "Randomized MAC — device undetectable"
	randomizedMACLabel       = "Randomized MAC*"

	hostBatchSize = 16
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

// Run starts the TUI program.
func Run(opts models.ScanOptions) error {
	m := New(opts)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}