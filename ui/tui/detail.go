// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package tui

import (
	"fmt"
	"strings"

	"github.com/ostefani/subnetlens/internal/textutil"
	"github.com/ostefani/subnetlens/models"
)

// --- Detail rows ---

// detailRows reports how many body lines fit between the header, the detail
// title/hint frame, and the summary footer.
func (m Model) detailRows(layout viewLayout) int {
	availableHeight := m.windowHeight - layout.headerHeight - 1
	if availableHeight < 0 {
		availableHeight = 0
	}

	availableHeight--
	if layout.summary != "" {
		availableHeight -= layout.summaryHeight + 1
	}

	if availableHeight < detailMinHeight {
		return 0
	}
	return max(0, availableHeight-detailFrameLines)
}

// detailLines renders every detail body line for one host at full width: no
// truncation, so values the table shortens stay complete here. Callers window
// the result with detailRows for display and scrolling.
func (m Model) detailLines(host *models.Host) []string {
	if host == nil {
		return nil
	}
	snapshot := host.Snapshot()

	lines := []string{
		"IP: " + snapshot.IP,
		"Hostname: " + orDefault(snapshot.Hostname, "—"),
		"MAC: " + orDefault(snapshot.MAC, "—"),
		"Vendor: " + orDefault(displayVendor(snapshot), "—"),
		"OS: " + orDefault(snapshot.OS, "—"),
		"Device: " + orDefault(displayDevice(snapshot), "—"),
	}
	if snapshot.Latency > 0 {
		lines = append(lines, "Latency: "+snapshot.Latency.String())
	}

	lines = append(lines, "Liveness:")
	liveness := host.LivenessBySource()
	if len(liveness) == 0 {
		lines = append(lines, "  —")
	}
	for _, observation := range liveness {
		strength := "strong"
		if observation.Weak {
			strength = "weak"
		}
		lines = append(lines, fmt.Sprintf("  %s: %s", observation.Source, strength))
	}

	open := snapshot.OpenPorts()
	lines = append(lines, fmt.Sprintf("Open ports (%d):", len(open)))
	for _, port := range open {
		lines = append(lines, m.detailPortLines(port)...)
	}
	if summary := detailHiddenPortsSummary(snapshot.Ports); summary != "" {
		lines = append(lines, summary)
	}

	width := m.contentWidth()
	wrapped := make([]string, 0, len(lines))
	for _, line := range lines {
		wrapped = append(wrapped, wrapText(line, width)...)
	}
	return wrapped
}

func (m Model) detailPortLines(port models.Port) []string {
	header := fmt.Sprintf("  %d/%s", port.Number, port.Protocol)
	if service := textutil.SanitizeInline(port.Service); service != "" {
		header += " " + service
	}
	lines := []string{header}
	if banner := textutil.SanitizeInline(port.Banner); banner != "" {
		lines = append(lines, "    Banner: "+banner)
	}
	if greeting := textutil.SanitizeInline(port.Fingerprint.SSHGreeting); greeting != "" {
		lines = append(lines, "    SSH greeting: "+greeting)
	}
	if server := textutil.SanitizeInline(port.Fingerprint.HTTPServer); server != "" {
		lines = append(lines, "    HTTP server: "+server)
	}
	if summary := textutil.SanitizeInline(port.Fingerprint.TLSSummary); summary != "" {
		lines = append(lines, "    "+summary)
	}
	return lines
}

func detailHiddenPortsSummary(ports []models.Port) string {
	var closed, filtered int
	for _, port := range ports {
		switch port.State {
		case models.PortClosed:
			closed++
		case models.PortFiltered:
			filtered++
		}
	}
	var parts []string
	if closed > 0 {
		parts = append(parts, fmt.Sprintf("+%d closed", closed))
	}
	if filtered > 0 {
		parts = append(parts, fmt.Sprintf("+%d filtered", filtered))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ") + " not shown"
}

// --- Detail section ---

func (m Model) renderDetailSection(host *models.Host, index, total int, layout viewLayout) string {
	lines := m.detailLines(host)
	rows := m.detailRows(layout)

	title := detailTitleStyle.Render("Host " + host.IP())
	if rows == 0 {
		hint := m.renderDetailHint(index, total, 0, 0, len(lines))
		return joinLines(title, noteStyle.Render("Terminal is too small to render the host detail. Expand the viewport to continue."), hint)
	}

	offset := clamp(m.detailOffset, 0, max(0, len(lines)-rows))
	end := min(offset+rows, len(lines))
	body := detailBodyStyle.Render(strings.Join(lines[offset:end], "\n"))
	hint := m.renderDetailHint(index, total, offset, end, len(lines))
	return joinLines(title, body, hint)
}

func (m Model) renderDetailHint(index, total, start, end, lineCount int) string {
	first, last := 0, 0
	if lineCount > 0 && end > start {
		first, last = start+1, end
	}
	return tableStatusStyle.Render(fmt.Sprintf(
		"host %d/%d · lines %d-%d of %d · n/p next/prev host · j/k scroll · esc back",
		index+1, total, first, last, lineCount,
	))
}

// --- Text wrapping ---

// wrapText folds s into chunks of at most width runes, preferring word
// boundaries and hard-breaking words that exceed the width. Non-positive
// widths yield the input unchanged so narrow terminals still show content.
func wrapText(s string, width int) []string {
	if width <= 0 {
		return []string{s}
	}
	runes := []rune(s)
	if len(runes) <= width {
		return []string{s}
	}

	var chunks []string
	for _, word := range strings.Fields(s) {
		for len([]rune(word)) > width {
			wordRunes := []rune(word)
			chunks = append(chunks, string(wordRunes[:width]))
			word = string(wordRunes[width:])
		}
		if len(chunks) == 0 {
			chunks = append(chunks, word)
			continue
		}
		last := len(chunks) - 1
		if len([]rune(chunks[last]))+1+len([]rune(word)) <= width {
			chunks[last] += " " + word
		} else {
			chunks = append(chunks, word)
		}
	}
	if len(chunks) == 0 {
		return []string{s}
	}
	return chunks
}
