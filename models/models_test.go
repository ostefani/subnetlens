package models

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestHostStringSettersSanitizeInlineTerminalText(t *testing.T) {
	host := NewHost("192.168.1.20")

	if !host.SetHostname(" printer\x1b[31m\nlab\t01 ") {
		t.Fatal("expected hostname update to succeed")
	}
	if !host.SetVendor(" Vendor\r\nCorp\x07 ") {
		t.Fatal("expected vendor update to succeed")
	}
	if !host.SetDevice(" NAS\tRack\nA ") {
		t.Fatal("expected device update to succeed")
	}
	if !host.SetOS(" Linux\x1b[0m ") {
		t.Fatal("expected OS update to succeed")
	}

	snapshot := host.Snapshot()
	if got := snapshot.Hostname; got != "printer lab 01" {
		t.Fatalf("expected sanitized hostname, got %q", got)
	}
	if got := snapshot.Vendor; got != "Vendor Corp" {
		t.Fatalf("expected sanitized vendor, got %q", got)
	}
	if got := snapshot.Device; got != "NAS Rack A" {
		t.Fatalf("expected sanitized device, got %q", got)
	}
	if got := snapshot.OS; got != "Linux" {
		t.Fatalf("expected sanitized OS, got %q", got)
	}
}

func TestSetHostnameRejectsTextThatSanitizesEmpty(t *testing.T) {
	host := NewHost("192.168.1.20")

	if host.SetHostname("\x1b\x07\r\n\t") {
		t.Fatal("expected control-only hostname to be rejected")
	}
	if got := host.Snapshot().Hostname; got != "192.168.1.20" {
		t.Fatalf("expected default hostname to remain unchanged, got %q", got)
	}
}

func TestSetRandomizedMACUpdatesSnapshot(t *testing.T) {
	host := NewHost("192.168.1.20")

	if !host.SetRandomizedMAC(true) {
		t.Fatal("expected randomized MAC flag update to succeed")
	}
	if !host.Snapshot().RandomizedMAC {
		t.Fatalf("expected randomized MAC flag in snapshot, got %+v", host.Snapshot())
	}
	if host.SetRandomizedMAC(true) {
		t.Fatal("expected no-op randomized MAC update to report unchanged")
	}
}

func TestScanOptionsScanConcurrencyLimitDefaults(t *testing.T) {
	opts := ScanOptions{}

	if got := opts.ScanConcurrencyLimit(); got != DefaultConcurrency {
		t.Fatalf("expected default scan concurrency %d, got %d", DefaultConcurrency, got)
	}
}

func TestScanOptionsDiscoveryConcurrencyFallsBackToScanConcurrency(t *testing.T) {
	opts := ScanOptions{Concurrency: 32}

	if got := opts.DiscoveryConcurrencyLimit(); got != 32 {
		t.Fatalf("expected discovery concurrency to fall back to scan concurrency 32, got %d", got)
	}
}

func TestScanOptionsDiscoveryConcurrencyUsesExplicitValue(t *testing.T) {
	opts := ScanOptions{
		Concurrency:          32,
		DiscoveryConcurrency: 256,
	}

	if got := opts.DiscoveryConcurrencyLimit(); got != 256 {
		t.Fatalf("expected explicit discovery concurrency 256, got %d", got)
	}
}

func TestHostConcurrentMutationAndSnapshot(t *testing.T) {
	host := NewHost("192.168.1.20")
	sourcePorts := []Port{
		{Number: 22, Protocol: "tcp", State: PortOpen, Service: "SSH"},
		{Number: 443, Protocol: "tcp", State: PortOpen, Service: "HTTPS"},
	}

	start := make(chan struct{})
	errCh := make(chan error, 32)
	var wg sync.WaitGroup

	writer := func() {
		defer wg.Done()
		<-start
		for i := 0; i < 200; i++ {
			host.SetHostname("workstation")
			host.SetMAC("00:1c:b3:00:00:01")
			host.SetRandomizedMAC(true)
			host.SetVendor("Apple")
			host.SetDevice("Laptop")
			host.SetOS("Linux")
			host.SetLatency(12 * time.Millisecond)
			host.SetAlive(true)
			host.MarkSeen(HostSourceICMP)
			host.SetOpenPorts(sourcePorts)
		}
	}

	reader := func() {
		defer wg.Done()
		<-start
		for i := 0; i < 200; i++ {
			snapshot := host.Snapshot()
			if snapshot.IP != "192.168.1.20" {
				errCh <- fmt.Errorf("unexpected snapshot IP %q", snapshot.IP)
				return
			}
			openPorts := snapshot.OpenPorts()
			if len(openPorts) > 0 {
				openPorts[0].Number = 9999
			}
		}
	}

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go writer()
		wg.Add(1)
		go reader()
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	sourcePorts[0].Number = 9999

	snapshot := host.Snapshot()
	if snapshot.Hostname != "workstation" {
		t.Fatalf("expected stable hostname, got %q", snapshot.Hostname)
	}
	if snapshot.MAC != "00:1c:b3:00:00:01" {
		t.Fatalf("expected stable MAC, got %q", snapshot.MAC)
	}
	if !snapshot.RandomizedMAC {
		t.Fatal("expected randomized MAC flag to remain true")
	}
	if snapshot.Vendor != "Apple" {
		t.Fatalf("expected stable vendor, got %q", snapshot.Vendor)
	}
	if snapshot.Device != "Laptop" {
		t.Fatalf("expected stable device, got %q", snapshot.Device)
	}
	if snapshot.OS != "Linux" {
		t.Fatalf("expected stable OS, got %q", snapshot.OS)
	}
	if snapshot.Latency != 12*time.Millisecond {
		t.Fatalf("expected stable latency, got %v", snapshot.Latency)
	}
	if !snapshot.Alive {
		t.Fatal("expected host to remain alive")
	}
	if snapshot.Source != HostSourceICMP {
		t.Fatalf("expected stable source, got %q", snapshot.Source)
	}
	if snapshot.SeenAt.IsZero() || snapshot.UpdatedAt.IsZero() {
		t.Fatal("expected seen/updated timestamps to be recorded")
	}
	openPorts := snapshot.OpenPorts()
	if len(openPorts) != 2 {
		t.Fatalf("expected 2 open ports, got %d", len(openPorts))
	}
	if len(snapshot.Ports) != 2 {
		t.Fatalf("expected 2 total ports, got %d", len(snapshot.Ports))
	}
	if openPorts[0].Number != 22 {
		t.Fatalf("expected snapshot open ports to be copied defensively, got %d", openPorts[0].Number)
	}
	if snapshot.Ports[0].Number != 22 {
		t.Fatalf("expected snapshot total ports to be copied defensively, got %d", snapshot.Ports[0].Number)
	}

	openPorts[0].Number = 1
	if got := host.Snapshot().OpenPorts()[0].Number; got != 22 {
		t.Fatalf("expected open port snapshot mutation to leave host ports unchanged, got %d", got)
	}
	snapshot.Ports[0].Number = 1
	if got := host.Snapshot().Ports[0].Number; got != 22 {
		t.Fatalf("expected total snapshot mutation to leave host ports unchanged, got %d", got)
	}
}

func TestSetProtocolPortsReplacesOnlyMatchingProtocol(t *testing.T) {
	host := NewHost("192.168.1.20")
	host.SetPorts([]Port{
		{Number: 53, Protocol: "udp", State: PortOpen, Service: "DNS"},
		{Number: 123, Protocol: "udp", State: PortClosed},
		{Number: 22, Protocol: "tcp", State: PortOpen, Service: "SSH"},
		{Number: 161, Protocol: "udp", State: PortOpen, Service: "SNMP"},
	})

	if !host.SetProtocolPorts("tcp", []Port{{
		Number: 80,
		State:  PortFiltered,
	}}) {
		t.Fatal("expected TCP protocol ports to be replaced")
	}

	snapshot := host.Snapshot()
	if len(snapshot.Ports) != 4 {
		t.Fatalf("expected 4 total ports after protocol-scoped replacement, got %d", len(snapshot.Ports))
	}
	openPorts := snapshot.OpenPorts()
	if len(openPorts) != 2 {
		t.Fatalf("expected 2 open ports after protocol-scoped replacement, got %d", len(openPorts))
	}

	if snapshot.Ports[0].Number != 53 || snapshot.Ports[0].Protocol != "udp" || snapshot.Ports[0].State != PortOpen {
		t.Fatalf("expected first total port to preserve UDP DNS, got %+v", snapshot.Ports[0])
	}
	if snapshot.Ports[1].Number != 80 || snapshot.Ports[1].Protocol != "tcp" || snapshot.Ports[1].State != PortFiltered {
		t.Fatalf("expected TCP replacement to normalize protocol and keep filtered state, got %+v", snapshot.Ports[1])
	}
	if snapshot.Ports[2].Number != 123 || snapshot.Ports[2].Protocol != "udp" || snapshot.Ports[2].State != PortClosed {
		t.Fatalf("expected closed UDP port to remain in total ports, got %+v", snapshot.Ports[2])
	}
	if snapshot.Ports[3].Number != 161 || snapshot.Ports[3].Protocol != "udp" || snapshot.Ports[3].State != PortOpen {
		t.Fatalf("expected second open UDP port to remain untouched, got %+v", snapshot.Ports[3])
	}
	if openPorts[0].Number != 53 || openPorts[0].Protocol != "udp" {
		t.Fatalf("expected first open port to preserve UDP DNS, got %+v", openPorts[0])
	}
	if openPorts[1].Number != 161 || openPorts[1].Protocol != "udp" {
		t.Fatalf("expected second open port to remain untouched, got %+v", openPorts[1])
	}
}

func TestAddPortUpsertsExistingPort(t *testing.T) {
	host := NewHost("192.168.1.20")

	if !host.AddPort(Port{
		Number:   161,
		Protocol: "udp",
		State:    PortOpen,
		Service:  "unknown",
	}) {
		t.Fatal("expected first port insert to succeed")
	}

	if !host.AddPort(Port{
		Number:   161,
		Protocol: "udp",
		State:    PortOpen,
		Service:  "SNMP",
		Banner:   "public",
	}) {
		t.Fatal("expected matching port to be updated with richer evidence")
	}

	if host.AddPort(Port{
		Number:   161,
		Protocol: "udp",
		State:    PortOpen,
		Service:  "SNMP",
		Banner:   "public",
	}) {
		t.Fatal("expected identical port update to be ignored")
	}

	snapshot := host.Snapshot()
	openPorts := snapshot.OpenPorts()
	if len(openPorts) != 1 {
		t.Fatalf("expected one merged port, got %d", len(openPorts))
	}
	if len(snapshot.Ports) != 1 {
		t.Fatalf("expected one merged total port, got %d", len(snapshot.Ports))
	}
	if openPorts[0].Service != "SNMP" || openPorts[0].Banner != "public" {
		t.Fatalf("expected updated port evidence to win, got %+v", openPorts[0])
	}
	if snapshot.Ports[0].Service != "SNMP" || snapshot.Ports[0].Banner != "public" {
		t.Fatalf("expected updated total port evidence to win, got %+v", snapshot.Ports[0])
	}
}

func TestSetPortsDerivesOpenPorts(t *testing.T) {
	host := NewHost("192.168.1.20")

	if !host.SetPorts([]Port{
		{Number: 53, Protocol: "udp", State: PortOpen, Service: "DNS"},
		{Number: 80, Protocol: "tcp", State: PortClosed},
		{Number: 123, Protocol: "udp", State: PortFiltered},
	}) {
		t.Fatal("expected total port replacement to succeed")
	}

	snapshot := host.Snapshot()
	if len(snapshot.Ports) != 3 {
		t.Fatalf("expected 3 total ports, got %d", len(snapshot.Ports))
	}
	openPorts := snapshot.OpenPorts()
	if len(openPorts) != 1 {
		t.Fatalf("expected 1 derived open port, got %d", len(openPorts))
	}
	if openPorts[0].Number != 53 || openPorts[0].Protocol != "udp" {
		t.Fatalf("expected DNS to remain in derived open ports, got %+v", openPorts[0])
	}
}
