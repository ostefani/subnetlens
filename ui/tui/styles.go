package tui

import "github.com/charmbracelet/lipgloss"

// --- Palette ---

const (
	// Cyan family — title → fill → muted (bright to muted)
	colorCyan      = lipgloss.Color("#22c1ca") // title
	colorCyanLight = lipgloss.Color("#40e6ef") // progress bar fill
	colorCyanMuted = lipgloss.Color("#59bfc4") // section headers, borders
 
	// Neutral
	colorFg     = lipgloss.Color("#92a9ac") // primary text (ice white)
	colorDim    = lipgloss.Color("#6d7478") // secondary / metadata text
	colorGutter = lipgloss.Color("#2e2e2e") // progress bar empty track
	colorBorder = lipgloss.Color("#4a4a4a") // table borders
 
	// Accents — one role each
	colorGreen  = lipgloss.Color("#4ec60d") // IP address (alive host)
	colorPurple = lipgloss.Color("#CC99FF") // vendor
	colorGold   = lipgloss.Color("#FFD700") // open ports
	colorOrange = lipgloss.Color("#f67b33") // device type
	colorWarn   = lipgloss.Color("#ff6b6b") // warnings, notes, errors
)

// --- Layout ---

var layoutStyle = lipgloss.NewStyle().MarginLeft(2)

// --- Chrome: title, summary, status ---
var (
	titleStyle         = lipgloss.NewStyle().Bold(true).Foreground(colorCyan).MarginTop(1).MarginBottom(1)
	summaryHeaderStyle = lipgloss.NewStyle().Bold(true).Foreground(colorFg).MarginTop(1)
	dimStyle           = lipgloss.NewStyle().Foreground(colorDim)
	noteStyle          = lipgloss.NewStyle().Foreground(colorWarn)
	tableStatusStyle   = dimStyle.PaddingLeft(2)
	footnoteStyle      = noteStyle.PaddingLeft(2)
)

// --- Progress bar ---

var (
	progressMetaStyle = lipgloss.NewStyle().Foreground(colorDim).PaddingLeft(1)
	barFill           = lipgloss.NewStyle().Foreground(colorCyanLight)
	barEmpty          = lipgloss.NewStyle().Foreground(colorGutter)
)

// --- Local machine box ---

var (
	localMachineStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorCyanMuted).
				Padding(0, 2).
				MarginTop(1).MarginBottom(1)
 
	localMachineHeaderStyle = lipgloss.NewStyle().
				Foreground(colorCyanMuted).
				Bold(true).MarginBottom(1)
 
	localMachineContentStyle = lipgloss.NewStyle().
					Foreground(colorFg)
)

// --- Host table ---

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
	tableDeviceStyle = lipgloss.NewStyle().Foreground(colorOrange).Padding(0, 1)
)

// --- Sizing ---

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