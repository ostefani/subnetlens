// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package tui

import (
	"strconv"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner"
	"github.com/ostefani/subnetlens/scanner/discovery"
)

func TestHostTableViewportClampsOffsetToVisibleRows(t *testing.T) {
	hosts := makeHosts(12)
	m := Model{
		windowWidth:  120,
		windowHeight: 18,
		tableOffset:  99,
	}

	viewport := m.hostTableViewport(hosts)

	if viewport.rows == 0 {
		t.Fatal("expected viewport rows to be available")
	}
	if viewport.end != len(hosts) {
		t.Fatalf("expected viewport to end at the final host, got %d", viewport.end)
	}

	wantStart := len(hosts) - viewport.rows
	if wantStart < 0 {
		wantStart = 0
	}
	if viewport.start != wantStart {
		t.Fatalf("expected clamped start %d, got %d", wantStart, viewport.start)
	}
}

func TestHostTableViewportReservesSpaceForSummary(t *testing.T) {
	hosts := makeHosts(20)
	base := Model{
		windowWidth:  120,
		windowHeight: 24,
	}

	withoutSummary := base.hostTableViewport(hosts)

	base.finished = true
	base.result = &models.ScanResult{
		StartedAt:  time.Unix(0, 0),
		FinishedAt: time.Unix(5, 0),
		Hosts:      hosts,
	}
	withSummary := base.hostTableViewport(hosts)

	if withoutSummary.rows == 0 || withSummary.rows == 0 {
		t.Fatal("expected both viewports to have rows")
	}
	if withSummary.rows >= withoutSummary.rows {
		t.Fatalf("expected summary footer to reduce table rows, got %d >= %d", withSummary.rows, withoutSummary.rows)
	}

	layout := base.viewLayout()
	wantDelta := layout.summaryHeight + 1
	if got := withoutSummary.rows - withSummary.rows; got != wantDelta {
		t.Fatalf("expected summary to consume %d row(s), got %d", wantDelta, got)
	}
}

func TestRenderSummaryUsesStyledLayout(t *testing.T) {
	hosts := makeHosts(2)
	hosts[0].SetAlive(true)

	m := Model{
		finished: true,
		result: &models.ScanResult{
			StartedAt:  time.Unix(0, 0),
			FinishedAt: time.Unix(5, 0),
			Hosts:      hosts,
		},
	}

	summary := m.renderSummary()
	rawLines := strings.Split(summary, "\n")
	lines := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		if strings.TrimSpace(ansi.Strip(line)) == "" {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) != 2 {
		t.Fatalf("expected summary to have 2 non-empty lines, got %d", len(lines))
	}
	if stripped := strings.TrimSpace(ansi.Strip(lines[0])); !strings.HasPrefix(stripped, "Scan complete. Found 1 host(s) in 5s") {
		t.Fatalf("expected styled summary headline, got %q", stripped)
	}
	if stripped := strings.TrimSpace(ansi.Strip(lines[1])); stripped != "Press 'q' or 'ctrl+c' to exit." {
		t.Fatalf("expected summary footer text to remain unchanged, got %q", stripped)
	}
}

func TestFormatPortsIncludesProtocol(t *testing.T) {
	snapshot := models.HostSnapshot{
		Ports: []models.Port{
			{Number: 53, Protocol: "udp", State: models.PortOpen, Service: "DNS"},
			{Number: 443, Protocol: "tcp", State: models.PortOpen, Service: "HTTPS"},
			{Number: 161, Protocol: "udp", State: models.PortClosed},
		},
	}
	formatted := ansi.Strip(formatPorts(snapshot.OpenPorts()))

	if !strings.Contains(formatted, "53/udp DNS") {
		t.Fatalf("expected UDP port label to include protocol, got %q", formatted)
	}
	if !strings.Contains(formatted, "443/tcp HTTPS") {
		t.Fatalf("expected TCP port label to include protocol, got %q", formatted)
	}
	if strings.Contains(formatted, "161/udp") {
		t.Fatalf("expected non-open ports to stay out of the open-port formatter, got %q", formatted)
	}
}

func TestMergeHostsPreservesStreamOrderAndAddsMissingFinalHosts(t *testing.T) {
	streamedA := models.NewHost("192.168.1.10")
	streamedB := models.NewHost("192.168.1.20")
	finalA := models.NewHost("192.168.1.10")
	finalC := models.NewHost("192.168.1.30")

	m := Model{
		hostIndex: make(map[string]int),
	}
	m.applyHostBatch([]*models.Host{streamedA})
	m.applyHostBatch([]*models.Host{streamedB})

	m.mergeHosts([]*models.Host{finalA, finalC})

	if len(m.hosts) != 3 {
		t.Fatalf("expected 3 hosts after merge, got %d", len(m.hosts))
	}
	if got := m.hosts[0].Snapshot().IP; got != "192.168.1.10" {
		t.Fatalf("expected first host to stay in streamed order, got %s", got)
	}
	if got := m.hosts[1].Snapshot().IP; got != "192.168.1.20" {
		t.Fatalf("expected second host to stay in streamed order, got %s", got)
	}
	if got := m.hosts[2].Snapshot().IP; got != "192.168.1.30" {
		t.Fatalf("expected missing final host to be appended, got %s", got)
	}
	if m.hosts[0] != finalA {
		t.Fatal("expected merge to refresh the existing pointer for matching IPs")
	}
}

func TestVisibleHostsFiltersLocalHost(t *testing.T) {
	m := Model{
		local: discovery.LocalDiscoveryInfo{
			InScanRange: true,
			IP:          "192.168.1.10",
		},
		hostIndex: make(map[string]int),
	}

	m.applyHostBatch([]*models.Host{models.NewHost("192.168.1.10")})
	remote := models.NewHost("192.168.1.20")
	m.applyHostBatch([]*models.Host{remote})

	visibleHosts := m.visibleHosts()
	if len(visibleHosts) != 1 {
		t.Fatalf("expected only the remote host to be visible, got %d hosts", len(visibleHosts))
	}
	if visibleHosts[0] != remote {
		t.Fatal("expected visible hosts to retain the remote host pointer")
	}
}

func TestVisibleHostsRefreshesPointerReplacement(t *testing.T) {
	m := Model{
		hostIndex: make(map[string]int),
	}

	original := models.NewHost("192.168.1.20")
	updated := models.NewHost("192.168.1.20")

	m.applyHostBatch([]*models.Host{original})
	m.applyHostBatch([]*models.Host{updated})

	visibleHosts := m.visibleHosts()
	if len(visibleHosts) != 1 {
		t.Fatalf("expected one visible host, got %d", len(visibleHosts))
	}
	if visibleHosts[0] != updated {
		t.Fatal("expected the visible host cache to refresh the stored pointer")
	}
}

func TestRenderHostTableSectionReusesMatchingCache(t *testing.T) {
	visibleHosts := makeHosts(2)
	m := Model{
		tableCache: &tableRenderCache{
			width:    120,
			start:    0,
			end:      2,
			total:    2,
			rendered: "cached table section",
		},
	}

	got := m.renderHostTableSection(visibleHosts, tableViewport{
		width: 120,
		start: 0,
		end:   2,
	})

	if got != "cached table section" {
		t.Fatalf("expected cached table section, got %q", got)
	}
	if m.tableCache.dirty {
		t.Fatal("expected cache to remain clean when the viewport signature matches")
	}
}

func TestRenderHostTableSectionRebuildsAfterHostUpdate(t *testing.T) {
	m := Model{
		tableCache: &tableRenderCache{
			width:    120,
			start:    0,
			end:      1,
			total:    1,
			rendered: "stale table section",
		},
		hostIndex: make(map[string]int),
	}

	m.applyHostBatch([]*models.Host{models.NewHost("192.168.1.20")})

	rendered := m.renderHostTableSection(m.visibleHosts(), tableViewport{
		width: 120,
		start: 0,
		end:   1,
	})

	if rendered == "stale table section" {
		t.Fatal("expected table section cache to be invalidated after a host update")
	}
	if m.tableCache.dirty {
		t.Fatal("expected the rebuilt table section cache to be marked clean")
	}
}

func TestRenderHostTableSectionRebuildsWhenViewportChanges(t *testing.T) {
	visibleHosts := makeHosts(2)
	m := Model{
		tableCache: &tableRenderCache{
			width:    120,
			start:    0,
			end:      2,
			total:    2,
			rendered: "cached table section",
		},
	}

	rendered := m.renderHostTableSection(visibleHosts, tableViewport{
		width: 80,
		start: 0,
		end:   2,
	})

	if rendered == "cached table section" {
		t.Fatal("expected viewport changes to rebuild the cached table section")
	}
}

func TestWaitForHostReturnsBufferedBatch(t *testing.T) {
	hostCh := make(chan *models.Host, 4)
	hostA := models.NewHost("192.168.1.10")
	hostB := models.NewHost("192.168.1.11")
	hostC := models.NewHost("192.168.1.12")

	hostCh <- hostA
	hostCh <- hostB
	hostCh <- hostC

	msg := waitForHostCmd(hostCh)()
	batchMsg, ok := msg.(hostsFoundMsg)
	if !ok {
		t.Fatalf("expected hostsFoundMsg, got %T", msg)
	}
	if len(batchMsg.hosts) != 3 {
		t.Fatalf("expected 3 hosts in batch, got %d", len(batchMsg.hosts))
	}
	if batchMsg.hosts[0] != hostA || batchMsg.hosts[1] != hostB || batchMsg.hosts[2] != hostC {
		t.Fatal("expected batch to preserve channel order")
	}
	if got := len(hostCh); got != 0 {
		t.Fatalf("expected channel to be drained, got %d buffered hosts remaining", got)
	}
}

func TestWaitForHostRespectsBatchLimit(t *testing.T) {
	hostCh := make(chan *models.Host, hostBatchSize+4)

	for i := 0; i < hostBatchSize+4; i++ {
		hostCh <- models.NewHost("192.168.1." + strconv.Itoa(i+1))
	}

	msg := waitForHostCmd(hostCh)()
	batchMsg, ok := msg.(hostsFoundMsg)
	if !ok {
		t.Fatalf("expected hostsFoundMsg, got %T", msg)
	}
	if len(batchMsg.hosts) != hostBatchSize {
		t.Fatalf("expected batch size %d, got %d", hostBatchSize, len(batchMsg.hosts))
	}
	if got := len(hostCh); got != 4 {
		t.Fatalf("expected 4 buffered hosts to remain for the next command, got %d", got)
	}
}

func TestWaitForHostReturnsNilWhenClosed(t *testing.T) {
	hostCh := make(chan *models.Host)
	close(hostCh)

	if msg := waitForHostCmd(hostCh)(); msg != nil {
		t.Fatalf("expected nil when channel is closed, got %T", msg)
	}
}

func TestRenderRandomizedMACFootnote(t *testing.T) {
	host := models.NewHost("192.168.1.44")
	host.SetRandomizedMAC(true)

	footnote := renderRandomizedMACFootnote([]*models.Host{host})
	if footnote == "" {
		t.Fatal("expected randomized MAC footnote to be rendered")
	}
	if got, want := footnote, footnoteStyle.Render("* For Randomized MAC vendor and device are undetectable."); got != want {
		t.Fatalf("expected footnote %q, got %q", want, got)
	}
	if got := displayVendor(host.Snapshot()); got != randomizedMACLabel {
		t.Fatalf("expected vendor label %q, got %q", randomizedMACLabel, got)
	}
	if got := displayDevice(host.Snapshot()); got != randomizedMACLabel {
		t.Fatalf("expected device label %q, got %q", randomizedMACLabel, got)
	}
}

func TestRenderLocalMachineUsesLabeledLines(t *testing.T) {
	info := discovery.LocalDiscoveryInfo{
		Hostname:    "workstation",
		Interface:   "en0",
		IP:          "192.168.1.20",
		MAC:         "aa:bb:cc:dd:ee:ff",
		InSubnet:    true,
		InScanRange: true,
	}

	rendered := renderLocalMachine(info)
	rawLines := strings.Split(ansi.Strip(rendered), "\n")
	lines := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) != 7 {
		t.Fatalf("expected local machine box to render 7 non-empty lines, got %d: %#v", len(lines), lines)
	}
	if !strings.HasPrefix(lines[0], "╭") || !strings.HasSuffix(lines[0], "╮") {
		t.Fatalf("expected top border line, got %q", lines[0])
	}
	if !strings.HasPrefix(lines[len(lines)-1], "╰") || !strings.HasSuffix(lines[len(lines)-1], "╯") {
		t.Fatalf("expected bottom border line, got %q", lines[len(lines)-1])
	}

	contentLines := make([]string, 0, len(lines)-2)
	for _, line := range lines[1 : len(lines)-1] {
		contentLines = append(contentLines, strings.TrimSpace(strings.Trim(line, "│")))
	}

	want := []string{
		"Local Machine:",
		"",
		"Hostname: workstation",
		"Interface: en0",
		"IP: 192.168.1.20   MAC: aa:bb:cc:dd:ee:ff",
	}
	if len(contentLines) != len(want) {
		t.Fatalf("expected %d boxed content lines, got %d: %#v", len(want), len(contentLines), contentLines)
	}
	for i := range want {
		if contentLines[i] != want[i] {
			t.Fatalf("expected line %d to be %q, got %q", i, want[i], contentLines[i])
		}
	}
}

func TestRenderLocalMachineSanitizesInlineValues(t *testing.T) {
	info := discovery.LocalDiscoveryInfo{
		Hostname:  "workstation\x1b[31m\nlab",
		Interface: "en0\tmain",
	}

	rendered := ansi.Strip(renderLocalMachine(info))
	if strings.Contains(rendered, "\x1b") {
		t.Fatal("expected escape sequences to be removed from local machine block")
	}
	if !strings.Contains(rendered, "Hostname: workstation lab") {
		t.Fatalf("expected sanitized hostname in local machine block, got %q", rendered)
	}
	if !strings.Contains(rendered, "Interface: en0 main") {
		t.Fatalf("expected sanitized interface in local machine block, got %q", rendered)
	}
}

func TestRenderHostTableStatusUsesIndentedStatusStyle(t *testing.T) {
	if got, want := renderHostTableStatus(3, 0, 3), tableStatusStyle.Render("Hosts visible: 3"); got != want {
		t.Fatalf("expected status %q, got %q", want, got)
	}
}

func makeHosts(count int) []*models.Host {
	hosts := make([]*models.Host, 0, count)
	for i := 1; i <= count; i++ {
		hosts = append(hosts, models.NewHost("192.168.1."+strconv.Itoa(i)))
	}
	return hosts
}

func pressKey(t *testing.T, m Model, key rune) Model {
	t.Helper()
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{key}})
	model, ok := updated.(Model)
	if !ok {
		t.Fatalf("expected Update to return a Model, got %T", updated)
	}
	return model
}

func visibleIPs(hosts []*models.Host) []string {
	ips := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if host == nil {
			continue
		}
		ips = append(ips, host.IP())
	}
	return ips
}

func TestSortKeyCyclesOrderAndReordersHosts(t *testing.T) {
	m := Model{hostIndex: make(map[string]int)}
	m.applyHostBatch([]*models.Host{
		models.NewHost("192.168.1.30"),
		models.NewHost("192.168.1.2"),
	})

	if got := visibleIPs(m.visibleHosts()); len(got) != 2 || got[0] != "192.168.1.30" {
		t.Fatalf("expected arrival order first, got %v", got)
	}

	m = pressKey(t, m, 's')
	if m.sortOrder != scanner.SortIP {
		t.Fatalf("expected sort order ip after one press, got %q", m.sortOrder)
	}
	if got := visibleIPs(m.visibleHosts()); len(got) != 2 || got[0] != "192.168.1.2" {
		t.Fatalf("expected numeric IP order, got %v", got)
	}

	for range len(scanner.SortOrders) - 1 {
		m = pressKey(t, m, 's')
	}
	if m.sortOrder != scanner.SortDiscovery {
		t.Fatalf("expected the cycle to return to discovery, got %q", m.sortOrder)
	}
	if got := visibleIPs(m.visibleHosts()); len(got) != 2 || got[0] != "192.168.1.30" {
		t.Fatalf("expected arrival order restored, got %v", got)
	}
	// The backing store keeps arrival order throughout: sorting must never
	// mutate it.
	if m.hosts[0].IP() != "192.168.1.30" {
		t.Fatalf("expected m.hosts to keep arrival order, got %v", visibleIPs(m.hosts))
	}
}

func TestWeakToggleHidesWeakHosts(t *testing.T) {
	strong := models.NewHost("192.168.1.10")
	strong.ObserveLiveness(true, false, models.HostSourceTCP, time.Time{}, time.Time{})
	weak := models.NewHost("192.168.1.11")
	weak.ObserveLiveness(true, true, models.HostSourceARP, time.Time{}, time.Time{})

	m := Model{hostIndex: make(map[string]int)}
	m.applyHostBatch([]*models.Host{strong, weak})
	if got := len(m.visibleHosts()); got != 2 {
		t.Fatalf("expected both hosts visible before the toggle, got %d", got)
	}

	m = pressKey(t, m, 'w')
	visible := m.visibleHosts()
	if len(visible) != 1 || visible[0].IP() != "192.168.1.10" {
		t.Fatalf("expected only the strong host visible, got %v", visibleIPs(visible))
	}

	m = pressKey(t, m, 'w')
	if got := len(m.visibleHosts()); got != 2 {
		t.Fatalf("expected the toggle to restore both hosts, got %d", got)
	}
}

func TestNoOpenPortsToggleHidesPortlessHosts(t *testing.T) {
	withPort := models.NewHost("192.168.1.10")
	withPort.SetProtocolPortsAndMarkAlive("tcp", []models.Port{
		{Number: 22, Protocol: "tcp", State: models.PortOpen, Service: "SSH"},
	})
	portless := models.NewHost("192.168.1.11")

	m := Model{hostIndex: make(map[string]int)}
	m.applyHostBatch([]*models.Host{withPort, portless})

	m = pressKey(t, m, 'o')
	visible := m.visibleHosts()
	if len(visible) != 1 || visible[0].IP() != "192.168.1.10" {
		t.Fatalf("expected only the host with open ports, got %v", visibleIPs(visible))
	}
}

func TestNewSeedsSortAndFilterFromOptions(t *testing.T) {
	// TEST-NET-2 is never a local interface, so no local-machine filtering
	// can interfere with the listing assertions.
	m := New(models.ScanOptions{
		Subnet: "198.51.100.0/24",
		Sort:   "ip",
		Filter: "port:22",
	}, 64, nil)
	if m.sortOrder != scanner.SortIP {
		t.Fatalf("expected sort order ip, got %q", m.sortOrder)
	}
	if m.filter == nil || m.filterExpr != "port:22" {
		t.Fatalf("expected the port:22 filter to be seeded, got expr %q", m.filterExpr)
	}

	withPort := models.NewHost("198.51.100.30")
	withPort.SetProtocolPortsAndMarkAlive("tcp", []models.Port{
		{Number: 22, Protocol: "tcp", State: models.PortOpen, Service: "SSH"},
	})
	other := models.NewHost("198.51.100.2")
	other.SetProtocolPortsAndMarkAlive("tcp", []models.Port{
		{Number: 80, Protocol: "tcp", State: models.PortOpen, Service: "HTTP"},
	})
	m.applyHostBatch([]*models.Host{withPort, other})
	if got := visibleIPs(m.visibleHosts()); len(got) != 1 || got[0] != "198.51.100.30" {
		t.Fatalf("expected only the filtered host visible, got %v", got)
	}

	m = pressKey(t, m, 'c')
	if m.filter != nil || m.filterExpr != "" || m.hideWeak || m.hideNoOpenPorts {
		t.Fatal("expected c to clear the filter expression and all toggles")
	}
	if m.sortOrder != scanner.SortIP {
		t.Fatalf("expected c to keep the sort order, got %q", m.sortOrder)
	}
	if got := visibleIPs(m.visibleHosts()); len(got) != 2 {
		t.Fatalf("expected both hosts visible after clear, got %v", got)
	}
}

func TestRenderListingStatusSummarizesState(t *testing.T) {
	m := Model{
		hosts:           makeHosts(3),
		sortOrder:       scanner.SortIP,
		hideWeak:        true,
		filterExpr:      "port:22",
		hostIndex:       make(map[string]int),
		tableCache:      &tableRenderCache{dirty: true},
		windowWidth:     120,
		windowHeight:    32,
		hideNoOpenPorts: false,
	}
	status := ansi.Strip(m.renderListingStatus(1))
	for _, want := range []string{"sort: ip", "hide: weak", "filter: port:22", "1/3 shown", "s sort"} {
		if !strings.Contains(status, want) {
			t.Fatalf("expected status to contain %q, got %q", want, status)
		}
	}

	plain := Model{hosts: makeHosts(2)}
	status = ansi.Strip(plain.renderListingStatus(2))
	if !strings.Contains(status, "sort: discovery") {
		t.Fatalf("expected default sort in status, got %q", status)
	}
	if strings.Contains(status, "shown") {
		t.Fatalf("expected no fraction when nothing is filtered, got %q", status)
	}
}

func TestViewShowsSortedFilteredListing(t *testing.T) {
	cisco := models.NewHost("198.51.100.30")
	cisco.SetVendor("cisco")
	cisco.ObserveLiveness(true, false, models.HostSourceTCP, time.Time{}, time.Time{})
	cisco.SetProtocolPortsAndMarkAlive("tcp", []models.Port{
		{Number: 22, Protocol: "tcp", State: models.PortOpen, Service: "SSH"},
	})
	apple := models.NewHost("198.51.100.2")
	apple.SetVendor("Apple")
	apple.ObserveLiveness(true, false, models.HostSourceTCP, time.Time{}, time.Time{})
	apple.SetProtocolPortsAndMarkAlive("tcp", []models.Port{
		{Number: 80, Protocol: "tcp", State: models.PortOpen, Service: "HTTP"},
	})
	weak := models.NewHost("198.51.100.10")
	weak.ObserveLiveness(true, true, models.HostSourceARP, time.Time{}, time.Time{})

	m := Model{hostIndex: make(map[string]int)}
	m.applyHostBatch([]*models.Host{cisco, apple, weak})
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	m = updated.(Model)

	m = pressKey(t, m, 's') // discovery -> ip
	m = pressKey(t, m, 'w') // hide weak
	view := ansi.Strip(m.View())
	t.Logf("rendered view:\n%s", view)

	pos2 := strings.Index(view, "198.51.100.2")
	pos30 := strings.Index(view, "198.51.100.30")
	if pos2 < 0 || pos30 < 0 || pos2 > pos30 {
		t.Fatalf("expected .2 before .30 in the rendered table, got:\n%s", view)
	}
	if strings.Contains(view, "198.51.100.10") {
		t.Fatalf("expected the weak host to be hidden from the rendered table, got:\n%s", view)
	}
	for _, want := range []string{"sort: ip", "hide: weak", "2/3 shown", "s sort"} {
		if !strings.Contains(view, want) {
			t.Fatalf("expected rendered view to contain %q, got:\n%s", want, view)
		}
	}
}

func TestModelResultIsNilUntilScanCompletes(t *testing.T) {
	m := New(models.ScanOptions{Subnet: "192.168.1.0/24"}, 64, nil)
	if m.result != nil {
		t.Fatal("expected no result before the scan completes")
	}

	updated, _ := m.Update(scanDoneMsg{
		result:     &models.ScanResult{Subnet: "192.168.1.0/24"},
		finalTotal: 1,
	})
	if got := updated.(Model).result; got == nil {
		t.Fatal("expected the finished result to be retained for export")
	}
}
