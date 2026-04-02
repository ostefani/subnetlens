package tui

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner"
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
}

func TestPrimaryBlockPaddingMatchesDesign(t *testing.T) {
	if got := progressStyle.GetPaddingLeft(); got != 0 {
		t.Fatalf("expected progress block left padding 0, got %d", got)
	}
	if got := progressStyle.GetPaddingRight(); got != 0 {
		t.Fatalf("expected progress block right padding 0, got %d", got)
	}
	if got := localMachineStyle.GetPaddingLeft(); got != 3 {
		t.Fatalf("expected local machine block left padding 3 to preserve the box shape, got %d", got)
	}
	if got := localMachineStyle.GetPaddingRight(); got != 3 {
		t.Fatalf("expected local machine block right padding 3 to preserve the box shape, got %d", got)
	}
	if got := localMachineStyle.GetPaddingTop(); got != 1 {
		t.Fatalf("expected local machine block top padding 1, got %d", got)
	}
	if got := localMachineStyle.GetPaddingBottom(); got != 1 {
		t.Fatalf("expected local machine block bottom padding 1, got %d", got)
	}
	if got := dimStyle.GetPaddingLeft(); got != 0 {
		t.Fatalf("expected shared dim style to avoid layout padding, got %d", got)
	}
	if got := noteStyle.GetMarginLeft(); got != 0 {
		t.Fatalf("expected shared note style to avoid layout margin, got %d", got)
	}
	if got := tableStatusStyle.GetPaddingLeft(); got != 2 {
		t.Fatalf("expected table status style left padding 2, got %d", got)
	}
	if got := footnoteStyle.GetPaddingLeft(); got != 2 {
		t.Fatalf("expected footnote style left padding 2, got %d", got)
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

func TestMergeHostsPreservesStreamOrderAndAddsMissingFinalHosts(t *testing.T) {
	streamedA := models.NewHost("192.168.1.10")
	streamedB := models.NewHost("192.168.1.20")
	finalA := models.NewHost("192.168.1.10")
	finalC := models.NewHost("192.168.1.30")

	m := Model{
		hostIndex: make(map[string]int),
	}
	m.upsertHost(streamedA)
	m.upsertHost(streamedB)

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
		local: scanner.LocalDiscoveryInfo{
			InScanRange: true,
			IP:          "192.168.1.10",
		},
		hostIndex: make(map[string]int),
	}

	m.upsertHost(models.NewHost("192.168.1.10"))
	remote := models.NewHost("192.168.1.20")
	m.upsertHost(remote)

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

	m.upsertHost(original)
	m.upsertHost(updated)

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

	m.upsertHost(models.NewHost("192.168.1.20"))

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
	host.SetVendor(randomizedMACVendorValue)
	host.SetDevice(randomizedMACDeviceValue)

	footnote := renderRandomizedMACFootnote([]*models.Host{host})
	if footnote == "" {
		t.Fatal("expected randomized MAC footnote to be rendered")
	}
	if got, want := footnote, footnoteStyle.Render("* For Randomized MAC vendor and device are undetectable."); got != want {
		t.Fatalf("expected footnote %q, got %q", want, got)
	}
	if got := displayVendor(host.Snapshot().Vendor); got != randomizedMACLabel {
		t.Fatalf("expected vendor label %q, got %q", randomizedMACLabel, got)
	}
	if got := displayDevice(host.Snapshot().Device); got != randomizedMACLabel {
		t.Fatalf("expected device label %q, got %q", randomizedMACLabel, got)
	}
}

func TestRenderLocalMachineUsesLabeledLines(t *testing.T) {
	info := scanner.LocalDiscoveryInfo{
		Hostname:    "workstation",
		Interface:   "en0",
		IP:          "192.168.1.20",
		MAC:         "aa:bb:cc:dd:ee:ff",
		InSubnet:    true,
		InScanRange: true,
	}

	rendered := renderLocalMachine(info)
	rawLines := strings.Split(rendered, "\n")
	lines := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		stripped := strings.TrimSpace(ansi.Strip(line))
		if stripped == "" {
			continue
		}
		lines = append(lines, stripped)
	}

	want := []string{
		"Local Machine:",
		"Hostname: workstation",
		"Interface: en0",
		"IP: 192.168.1.20   MAC: aa:bb:cc:dd:ee:ff",
	}
	if len(lines) != len(want) {
		t.Fatalf("expected %d non-empty lines, got %d: %#v", len(want), len(lines), lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("expected line %d to be %q, got %q", i, want[i], lines[i])
		}
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