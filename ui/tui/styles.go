package tui

import "github.com/charmbracelet/lipgloss"

// ── Palette ───────────────────────────────────────────────────────────────────

const (
	colorCyan      = lipgloss.Color("#22c1ca")
	colorCyanLight = lipgloss.Color("#40e6ef")
	colorCyanMuted = lipgloss.Color("#59bfc4")
	colorIce       = lipgloss.Color("#d9fbff")
	colorGreen     = lipgloss.Color("#4ec60d")
	colorAmber     = lipgloss.Color("#f67b33")
	colorGold      = lipgloss.Color("#FFD700")
	colorPurple    = lipgloss.Color("#CC99FF")
	colorDim       = lipgloss.Color("#7e7e7e")
	colorDimDark   = lipgloss.Color("#6d7478")
	colorGutter    = lipgloss.Color("#333333")
	colorBorder    = lipgloss.Color("240")
	colorNavy      = lipgloss.Color("#0c161b")
	colorFg        = lipgloss.Color("#e0e0e0")
)

// ── Layout ────────────────────────────────────────────────────────────────────

var layoutStyle = lipgloss.NewStyle().MarginLeft(2)

// ── Chrome: title, summary, status ───────────────────────────────────────────

var (
	titleStyle         = lipgloss.NewStyle().Bold(true).Foreground(colorCyan).MarginTop(1).MarginBottom(1)
	summaryHeaderStyle = lipgloss.NewStyle().Bold(true).Foreground(colorFg).MarginTop(1)
	dimStyle           = lipgloss.NewStyle().Foreground(colorDim)
	noteStyle          = lipgloss.NewStyle().Foreground(colorAmber)
	tableStatusStyle   = dimStyle.PaddingLeft(2)
	footnoteStyle      = noteStyle.PaddingLeft(2)
)

// ── Progress bar ──────────────────────────────────────────────────────────────

var (
	sectionStyle      = lipgloss.NewStyle().Bold(true).Foreground(colorCyanMuted)
	progressStyle     = lipgloss.NewStyle().Foreground(colorIce)
	progressMetaStyle = lipgloss.NewStyle().Foreground(colorDimDark).Padding(0, 1)
	barFill           = lipgloss.NewStyle().Foreground(colorCyanLight)
	barEmpty          = lipgloss.NewStyle().Foreground(colorGutter)
)

// ── Local machine box ─────────────────────────────────────────────────────────

var (
	localMachineStyle = lipgloss.NewStyle().
				Foreground(colorIce).Background(colorNavy).
				MarginTop(1).MarginBottom(1).
				Padding(1, 3)

	localMachineHeaderStyle = lipgloss.NewStyle().
				Foreground(colorCyanMuted).Background(colorNavy).
				Bold(true).MarginBottom(1)

	localMachineContentStyle = lipgloss.NewStyle().
					Foreground(colorIce).Background(colorNavy)
)

// ── Host table ────────────────────────────────────────────────────────────────

var (
	hostStyle   = lipgloss.NewStyle().Bold(true).Foreground(colorGreen)
	vendorStyle = lipgloss.NewStyle().Foreground(colorPurple)
	portStyle   = lipgloss.NewStyle().Foreground(colorGold)

	tableBorderStyle = lipgloss.NewStyle().Foreground(colorBorder)
	tableHeaderStyle = lipgloss.NewStyle().Bold(true).Foreground(colorCyanMuted).Padding(0, 1)
	tableCellStyle   = lipgloss.NewStyle().Padding(0, 1)
	tableHostStyle   = hostStyle.Padding(0, 1)
	tableVendorStyle = vendorStyle.Padding(0, 1)
	tableOSStyle     = lipgloss.NewStyle().Foreground(colorDim).Padding(0, 1)
	tableDeviceStyle = lipgloss.NewStyle().Foreground(colorAmber).Padding(0, 1)
)

// ── Sizing ────────────────────────────────────────────────────────────────────

const (
	progressBarWidth = 40

	defaultWindowWidth  = 120
	defaultWindowHeight = 32

	hostTableMinHeight  = 5
	hostTableFrameLines = 4

	ipColumnWidth       = 15
	hostnameColumnWidth = 15
	macColumnWidth      = 20
	vendorColumnWidth   = 22
	deviceColumnWidth   = 18
	osColumnWidth       = 5
)