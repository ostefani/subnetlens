package tui

import (
	"strconv"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/models"
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

func TestWaitForHostReturnsBufferedBatch(t *testing.T) {
	hostCh := make(chan *models.Host, 4)
	hostA := models.NewHost("192.168.1.10")
	hostB := models.NewHost("192.168.1.11")
	hostC := models.NewHost("192.168.1.12")

	hostCh <- hostA
	hostCh <- hostB
	hostCh <- hostC

	msg := waitForHost(hostCh)()
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

	msg := waitForHost(hostCh)()
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

	if msg := waitForHost(hostCh)(); msg != nil {
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
	if got, want := footnote, noteStyle.Render("  * For Randomized MAC vendor and device are undetectable."); got != want {
		t.Fatalf("expected footnote %q, got %q", want, got)
	}
	if got := displayVendor(host.Snapshot().Vendor); got != randomizedMACLabel {
		t.Fatalf("expected vendor label %q, got %q", randomizedMACLabel, got)
	}
	if got := displayDevice(host.Snapshot().Device); got != randomizedMACLabel {
		t.Fatalf("expected device label %q, got %q", randomizedMACLabel, got)
	}
}

func makeHosts(count int) []*models.Host {
	hosts := make([]*models.Host, 0, count)
	for i := 1; i <= count; i++ {
		hosts = append(hosts, models.NewHost("192.168.1."+strconv.Itoa(i)))
	}
	return hosts
}
