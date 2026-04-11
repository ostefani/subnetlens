package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner"
)

const (
	randomizedMACLabel = "Randomized MAC*"

	hostBatchSize = 16
)

// --- Messages ---

type hostsFoundMsg struct{ hosts []*models.Host }
type progressMsg struct{ done, total int }
type issueMsg struct{ issue models.ScanIssue }
type scanDoneMsg struct {
	result     *models.ScanResult
	finalDone  int
	finalTotal int
}

// --- Model ---

type Model struct {
	opts         models.ScanOptions
	socketBudget int
	warnings     []string
	local        scanner.LocalDiscoveryInfo
	hostCh       chan *models.Host
	progCh       chan [2]int
	issueCh      chan models.ScanIssue
	hosts        []*models.Host
	visibleCache []*models.Host
	tableCache   *tableRenderCache
	hostIndex    map[string]int
	done         int
	total        int
	finished     bool
	aliveHosts   int
	aliveCountOK bool
	result       *models.ScanResult
	err          error
	windowWidth  int
	windowHeight int
	tableOffset  int
}

func New(opts models.ScanOptions, socketBudget int, warnings []string) Model {
	return Model{
		opts:         opts,
		socketBudget: socketBudget,
		warnings:     warnings,
		local:        scanner.LocalDiscoveryInfoForTarget(opts.Subnet),
		hostCh:       make(chan *models.Host, 32),
		progCh:       make(chan [2]int, 32),
		issueCh:      make(chan models.ScanIssue, 16),
		tableCache:   &tableRenderCache{dirty: true},
		hostIndex:    make(map[string]int),
		windowWidth:  defaultWindowWidth,
		windowHeight: defaultWindowHeight,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		runScanCmd(m.opts, m.socketBudget, m.hostCh, m.progCh, m.issueCh),
		waitForHostCmd(m.hostCh),
		waitForProgressCmd(m.progCh),
		waitForIssueCmd(m.issueCh),
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
		m.applyHostBatch(msg.hosts)
		return m, waitForHostCmd(m.hostCh)

	case progressMsg:
		if m.finished {
			return m, nil
		}
		m.done = msg.done
		m.total = msg.total
		return m, waitForProgressCmd(m.progCh)

	case issueMsg:
		m.warnings = append(m.warnings, msg.issue.String())
		return m, waitForIssueCmd(m.issueCh)

	case scanDoneMsg:
		m.finished = true
		m.result = msg.result
		m.aliveHosts = countAliveHosts(msg.result.Hosts)
		m.aliveCountOK = true
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
func Run(opts models.ScanOptions, socketBudget int, warnings []string) error {
	m := New(opts, socketBudget, warnings)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
