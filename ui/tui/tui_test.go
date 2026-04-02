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
