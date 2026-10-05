// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/ostefani/subnetlens/models"
)

func pressSpecial(t *testing.T, m Model, typ tea.KeyType) Model {
	t.Helper()
	updated, _ := m.Update(tea.KeyMsg{Type: typ})
	model, ok := updated.(Model)
	if !ok {
		t.Fatalf("expected Update to return a Model, got %T", updated)
	}
	return model
}

func openDetailTestModel(t *testing.T, hosts ...*models.Host) Model {
	t.Helper()
	m := Model{hostIndex: make(map[string]int)}
	m.applyHostBatch(hosts)
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	m = updated.(Model)
	return pressSpecial(t, m, tea.KeyEnter)
}

func detailTestHost() *models.Host {
	host := models.NewHost("192.168.1.44")
	host.SetHostname("very-long-printer-hostname-floor-3-office-east-wing.local")
	host.SetMAC("aa:bb:cc:dd:ee:ff")
	host.SetVendor("Very Long Vendor Name Incorporated GmbH")
	host.SetOS("Windows 11 Pro 23H2")
	host.SetDevice("Network Laser Printer XYZ-5000")
	host.SetLatency(3 * time.Millisecond)
	host.ObserveLiveness(true, true, models.HostSourceARP, time.Time{}, time.Time{})
	host.ObserveLiveness(true, false, models.HostSourceTCP, time.Time{}, time.Time{})
	host.SetPorts([]models.Port{
		{Number: 22, Protocol: "tcp", State: models.PortOpen, Service: "SSH", Banner: "SSH-2.0-OpenSSH_9.6p1 Debian-3ubuntu2",
			Fingerprint: models.PortFingerprint{SSHGreeting: "SSH-2.0-OpenSSH_9.6p1 Debian-3ubuntu2"}},
		{Number: 443, Protocol: "tcp", State: models.PortOpen, Service: "HTTPS",
			Fingerprint: models.PortFingerprint{TLSSummary: "TLS: CN=printer.local SANs=[printer.local]"}},
		{Number: 2323, Protocol: "tcp", State: models.PortClosed},
		{Number: 8080, Protocol: "tcp", State: models.PortFiltered},
	})
	return host
}

func TestEnterOpensDetailWithFullUntruncatedValues(t *testing.T) {
	host := detailTestHost()

	m := Model{hostIndex: make(map[string]int)}
	m.applyHostBatch([]*models.Host{host})
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	m = updated.(Model)

	tableView := ansi.Strip(m.View())
	if !strings.Contains(tableView, "…") {
		t.Fatalf("expected the table to truncate long values, got:\n%s", tableView)
	}
	if strings.Contains(tableView, "very-long-printer-hostname-floor-3-office-east-wing.local") {
		t.Fatalf("expected the full hostname to be truncated in the table, got:\n%s", tableView)
	}

	m = pressSpecial(t, m, tea.KeyEnter)
	if !m.detailOpen {
		t.Fatal("expected Enter to open the detail view")
	}

	view := ansi.Strip(m.View())
	for _, want := range []string{
		"very-long-printer-hostname-floor-3-office-east-wing.local",
		"aa:bb:cc:dd:ee:ff",
		"Very Long Vendor Name Incorporated GmbH",
		"Windows 11 Pro 23H2",
		"Network Laser Printer XYZ-5000",
		"SSH-2.0-OpenSSH_9.6p1 Debian-3ubuntu2",
		"TLS: CN=printer.local SANs=[printer.local]",
		"arp: weak",
		"tcp: strong",
		"Open ports (2)",
		"22/tcp",
		"443/tcp",
		"+1 closed, +1 filtered not shown",
		"esc back",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("expected detail view to contain %q, got:\n%s", want, view)
		}
	}
	for _, unwanted := range []string{"2323/tcp", "8080/tcp"} {
		if strings.Contains(view, unwanted) {
			t.Fatalf("expected non-open port %q to stay out of the per-port rows, got:\n%s", unwanted, view)
		}
	}
}

func TestEscReturnsToTableAtDetailHost(t *testing.T) {
	first := models.NewHost("192.168.1.10")
	second := models.NewHost("192.168.1.20")

	m := Model{hostIndex: make(map[string]int)}
	m.applyHostBatch([]*models.Host{first, second})
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	m = updated.(Model)

	m = pressKey(t, m, 'j')
	m = pressSpecial(t, m, tea.KeyEnter)
	if !m.detailOpen || m.detailIP != "192.168.1.20" {
		t.Fatalf("expected detail for the selected host, got open=%v ip=%q", m.detailOpen, m.detailIP)
	}

	m = pressSpecial(t, m, tea.KeyEsc)
	if m.detailOpen {
		t.Fatal("expected Esc to close the detail view")
	}
	if m.selected != 1 {
		t.Fatalf("expected cursor to return to the detail host, got selected=%d", m.selected)
	}
	if view := ansi.Strip(m.View()); !strings.Contains(view, "IP ADDRESS") {
		t.Fatalf("expected the table to render again after Esc, got:\n%s", view)
	}
}

func TestEnterWithNoHostsKeepsTableView(t *testing.T) {
	m := Model{hostIndex: make(map[string]int)}
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	m = updated.(Model)

	m = pressSpecial(t, m, tea.KeyEnter)
	if m.detailOpen {
		t.Fatal("expected Enter with no hosts to stay in the table view")
	}
}

func TestSelectionMovesAndViewportFollows(t *testing.T) {
	m := Model{hostIndex: make(map[string]int)}
	m.applyHostBatch(makeHosts(20))
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 18})
	m = updated.(Model)

	rows := m.hostTableViewport(m.visibleHosts()).rows
	if rows <= 1 || rows >= 20 {
		t.Fatalf("expected a scrolled viewport for this test, got rows=%d", rows)
	}

	for i := 0; i < rows+2; i++ {
		m = pressKey(t, m, 'j')
	}
	if m.selected != rows+2 {
		t.Fatalf("expected selected=%d, got %d", rows+2, m.selected)
	}
	if want := rows + 2 - rows + 1; m.tableOffset != want {
		t.Fatalf("expected viewport to follow the cursor to offset %d, got %d", want, m.tableOffset)
	}

	m = pressKey(t, m, 'G')
	if m.selected != 19 {
		t.Fatalf("expected end to select the last host, got %d", m.selected)
	}
	viewport := m.hostTableViewport(m.visibleHosts())
	if m.selected < viewport.start || m.selected >= viewport.end {
		t.Fatalf("expected the last host to be visible, viewport=%+v", viewport)
	}

	m = pressKey(t, m, 'g')
	if m.selected != 0 || m.tableOffset != 0 {
		t.Fatalf("expected home to return to the top, got selected=%d offset=%d", m.selected, m.tableOffset)
	}

	m = pressKey(t, m, 'k')
	if m.selected != 0 {
		t.Fatalf("expected selection to clamp at the top, got %d", m.selected)
	}
}

func TestDetailNextPrevHost(t *testing.T) {
	m := Model{hostIndex: make(map[string]int)}
	m.applyHostBatch([]*models.Host{models.NewHost("192.168.1.10"), models.NewHost("192.168.1.20")})
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	m = updated.(Model)
	m = pressSpecial(t, m, tea.KeyEnter)

	m = pressKey(t, m, 'n')
	if m.detailIP != "192.168.1.20" {
		t.Fatalf("expected n to move to the next host, got %q", m.detailIP)
	}
	m = pressKey(t, m, 'n')
	if m.detailIP != "192.168.1.20" {
		t.Fatalf("expected n to clamp at the last host, got %q", m.detailIP)
	}
	m = pressKey(t, m, 'p')
	if m.detailIP != "192.168.1.10" {
		t.Fatalf("expected p to move to the previous host, got %q", m.detailIP)
	}
	if view := ansi.Strip(m.View()); !strings.Contains(view, "host 1/2") {
		t.Fatalf("expected detail hint to show the host position, got:\n%s", view)
	}
}

func TestDetailScrollClampsToContent(t *testing.T) {
	ports := make([]models.Port, 0, 30)
	for i := 0; i < 30; i++ {
		ports = append(ports, models.Port{Number: 1000 + i, Protocol: "tcp", State: models.PortOpen, Service: "svc"})
	}
	host := models.NewHost("192.168.1.44")
	host.SetPorts(ports)

	m := Model{hostIndex: make(map[string]int)}
	m.applyHostBatch([]*models.Host{host})
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 24})
	m = updated.(Model)
	m = pressSpecial(t, m, tea.KeyEnter)

	if maxOffset := m.maxDetailOffset(); maxOffset <= 0 {
		t.Fatalf("expected scrollable detail content for this test, got maxOffset=%d", maxOffset)
	}
	m = pressKey(t, m, 'G')
	if m.detailOffset != m.maxDetailOffset() {
		t.Fatalf("expected end to scroll to max offset %d, got %d", m.maxDetailOffset(), m.detailOffset)
	}
	if view := ansi.Strip(m.View()); !strings.Contains(view, "of ") || !strings.Contains(view, "lines ") {
		t.Fatalf("expected the detail hint to show scroll position, got:\n%s", view)
	}
	m = pressKey(t, m, 'g')
	if m.detailOffset != 0 {
		t.Fatalf("expected home to scroll back to the top, got %d", m.detailOffset)
	}
}

func TestDetailReflectsLiveHostUpdates(t *testing.T) {
	host := models.NewHost("192.168.1.44")
	m := openDetailTestModel(t, host)

	host.SetVendor("Updated Vendor Name")
	if view := ansi.Strip(m.View()); !strings.Contains(view, "Updated Vendor Name") {
		t.Fatalf("expected the open detail view to reflect live updates, got:\n%s", view)
	}
}

func TestDetailSanitizesUntrustedBannerText(t *testing.T) {
	host := models.NewHost("192.168.1.44")
	host.SetPorts([]models.Port{
		{Number: 22, Protocol: "tcp", State: models.PortOpen, Service: "SSH", Banner: "greeting\x1b[31m\nnext"},
	})
	m := openDetailTestModel(t, host)

	view := m.View()
	if strings.Contains(view, "\x1b[31m") {
		t.Fatalf("expected banner escape sequences to be stripped, got:\n%q", ansi.Strip(view))
	}
	if stripped := ansi.Strip(view); !strings.Contains(stripped, "greeting next") {
		t.Fatalf("expected sanitized banner text in the detail view, got:\n%s", stripped)
	}
}

func TestWrapTextWrapsWordsAndBreaksSpacelessNames(t *testing.T) {
	chunks := wrapText("aaa bbb ccc", 7)
	if got, want := strings.Join(chunks, "|"), "aaa bbb|ccc"; got != want {
		t.Fatalf("expected word wrap %q, got %q", want, got)
	}

	name := "very-long-printer-hostname-floor-3.local"
	chunks = wrapText(name, 10)
	if got := strings.Join(chunks, ""); got != name {
		t.Fatalf("expected hard-broken chunks to rejoin to %q, got %q", name, got)
	}
	for _, chunk := range chunks {
		if len([]rune(chunk)) > 10 {
			t.Fatalf("expected chunks of at most 10 runes, got %q", chunk)
		}
	}
	if len(chunks) < 2 {
		t.Fatalf("expected the spaceless name to wrap, got %q", chunks)
	}
}
