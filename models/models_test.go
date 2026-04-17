// Copyright (c) 2026 Olha Stefanishyna. MIT License.

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

func TestZeroValueSnapshotIdentityMetadataIsSafe(t *testing.T) {
	var snapshot HostSnapshot
	snapshot.applyIdentityMetadata()

	if snapshot.HostID != "" {
		t.Fatalf("expected empty host id, got %q", snapshot.HostID)
	}
	if snapshot.IdentitySource != IdentitySourceUnknown {
		t.Fatalf("expected unknown identity source, got %q", snapshot.IdentitySource)
	}
	if len(snapshot.IdentityAliases) != 0 {
		t.Fatalf("expected no identity aliases, got %+v", snapshot.IdentityAliases)
	}
	if len(snapshot.IdentityAnchorKeys) != 0 {
		t.Fatalf("expected no identity anchor keys, got %+v", snapshot.IdentityAnchorKeys)
	}
}

func TestSnapshotIdentityUsesStableMACWhenAvailable(t *testing.T) {
	host := NewHost("192.168.1.20")
	host.SetHostname("workstation")
	host.SetMAC("00:1c:b3:00:00:01")

	snapshot := host.Snapshot()
	if snapshot.HostID != "mac:00:1c:b3:00:00:01" {
		t.Fatalf("expected MAC-based host id, got %q", snapshot.HostID)
	}
	if snapshot.IdentityConfidence != IdentityConfidenceHigh {
		t.Fatalf("expected high identity confidence, got %q", snapshot.IdentityConfidence)
	}
	if snapshot.IdentitySource != IdentitySourceMAC {
		t.Fatalf("expected MAC identity source, got %q", snapshot.IdentitySource)
	}
	if len(snapshot.IdentityAliases) != 3 {
		t.Fatalf("expected ip/mac/name aliases, got %+v", snapshot.IdentityAliases)
	}
	if snapshot.IdentityAliases[0] != "ip:192.168.1.20" ||
		snapshot.IdentityAliases[1] != "mac:00:1c:b3:00:00:01" ||
		snapshot.IdentityAliases[2] != "name:workstation" {
		t.Fatalf("unexpected identity aliases: %+v", snapshot.IdentityAliases)
	}
	if len(snapshot.IdentityAnchorKeys) != 3 {
		t.Fatalf("expected ip/mac/pair anchor keys, got %+v", snapshot.IdentityAnchorKeys)
	}
	if snapshot.IdentityAnchorKeys[2] != "pair:00:1c:b3:00:00:01@192.168.1.20" {
		t.Fatalf("unexpected pair anchor key: %+v", snapshot.IdentityAnchorKeys)
	}
}

func TestSnapshotIdentityFallsBackToIPWhenMACIsRandomized(t *testing.T) {
	host := NewHost("192.168.1.20")
	host.SetHostname("phone")
	host.SetMAC("02:11:22:33:44:55")
	host.SetRandomizedMAC(true)

	snapshot := host.Snapshot()
	if snapshot.HostID != "ip:192.168.1.20" {
		t.Fatalf("expected IP-based host id for randomized MAC, got %q", snapshot.HostID)
	}
	if snapshot.IdentityConfidence != IdentityConfidenceLow {
		t.Fatalf("expected low identity confidence, got %q", snapshot.IdentityConfidence)
	}
	if snapshot.IdentitySource != IdentitySourceIP {
		t.Fatalf("expected IP identity source, got %q", snapshot.IdentitySource)
	}
	if len(snapshot.IdentityAliases) != 2 {
		t.Fatalf("expected ip/name aliases only, got %+v", snapshot.IdentityAliases)
	}
	if snapshot.IdentityAliases[0] != "ip:192.168.1.20" || snapshot.IdentityAliases[1] != "name:phone" {
		t.Fatalf("unexpected identity aliases: %+v", snapshot.IdentityAliases)
	}
	if len(snapshot.IdentityAnchorKeys) != 1 {
		t.Fatalf("expected ip anchor key only, got %+v", snapshot.IdentityAnchorKeys)
	}
	if snapshot.IdentityAnchorKeys[0] != "ip:192.168.1.20" {
		t.Fatalf("unexpected identity anchor keys: %+v", snapshot.IdentityAnchorKeys)
	}
}

func TestSnapshotIdentityPrefersProducerProvidedIdentity(t *testing.T) {
	host := NewHost("192.168.1.20")
	host.SetHostname("printer")
	host.SetMAC("00:1c:b3:00:00:01")
	host.SetIdentity(HostIdentity{
		HostID:             "asset:printer-01",
		IdentityConfidence: IdentityConfidenceHigh,
		IdentityAliases:    []string{"asset:printer-01"},
		IdentityAnchorKeys: []string{"site:lab-a"},
	})

	snapshot := host.Snapshot()
	if snapshot.HostID != "asset:printer-01" {
		t.Fatalf("expected producer-provided host id, got %q", snapshot.HostID)
	}
	if snapshot.IdentityConfidence != IdentityConfidenceHigh {
		t.Fatalf("expected producer-provided confidence, got %q", snapshot.IdentityConfidence)
	}
	if snapshot.IdentitySource != IdentitySourceProvided {
		t.Fatalf("expected provided identity source, got %q", snapshot.IdentitySource)
	}
	if len(snapshot.IdentityAliases) != 4 {
		t.Fatalf("expected provided alias plus derived aliases, got %+v", snapshot.IdentityAliases)
	}
	if snapshot.IdentityAliases[0] != "ip:192.168.1.20" ||
		snapshot.IdentityAliases[1] != "mac:00:1c:b3:00:00:01" ||
		snapshot.IdentityAliases[2] != "name:printer" ||
		snapshot.IdentityAliases[3] != "asset:printer-01" {
		t.Fatalf("unexpected identity aliases: %+v", snapshot.IdentityAliases)
	}
	if len(snapshot.IdentityAnchorKeys) != 4 {
		t.Fatalf("expected provided anchor plus derived anchors, got %+v", snapshot.IdentityAnchorKeys)
	}
	if snapshot.IdentityAnchorKeys[3] != "site:lab-a" {
		t.Fatalf("unexpected identity anchor keys: %+v", snapshot.IdentityAnchorKeys)
	}
}

func TestSnapshotIdentityKeepsProvidedSourceWhenHostIDIsCustom(t *testing.T) {
	host := NewHost("192.168.1.20")
	host.SetMAC("00:1c:b3:00:00:01")
	host.SetIdentity(HostIdentity{
		HostID:             "asset:printer-01",
		IdentityConfidence: IdentityConfidenceHigh,
		IdentitySource:     IdentitySourceMAC,
	})

	snapshot := host.Snapshot()
	if snapshot.IdentitySource != IdentitySourceProvided {
		t.Fatalf("expected custom host id to keep provided identity source, got %q", snapshot.IdentitySource)
	}
}

func TestApplyIdentityMetadataDoesNotOverwriteExistingHostID(t *testing.T) {
	snapshot := HostSnapshot{
		IP:                 "192.168.1.20",
		MAC:                "00:1c:b3:00:00:01",
		HostID:             "asset:printer-01",
		IdentityConfidence: IdentityConfidenceHigh,
		IdentitySource:     IdentitySourceProvided,
	}

	snapshot.applyIdentityMetadata()

	if snapshot.HostID != "asset:printer-01" {
		t.Fatalf("expected existing host id to be preserved, got %q", snapshot.HostID)
	}
	if snapshot.IdentitySource != IdentitySourceProvided {
		t.Fatalf("expected existing identity source to be preserved, got %q", snapshot.IdentitySource)
	}
	if len(snapshot.IdentityAliases) != 2 {
		t.Fatalf("expected derived aliases to be added without overriding identity, got %+v", snapshot.IdentityAliases)
	}
	if len(snapshot.IdentityAnchorKeys) != 3 {
		t.Fatalf("expected derived anchors to be added without overriding identity, got %+v", snapshot.IdentityAnchorKeys)
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

func TestSetProtocolPortsAndMarkAlivePromotesHostOnOpenPort(t *testing.T) {
	host := NewHost("192.168.1.20")
	host.SetWeak(true)

	if !host.SetProtocolPortsAndMarkAlive("tcp", []Port{{
		Number: 443,
		State:  PortOpen,
	}}) {
		t.Fatal("expected protocol update to change host")
	}

	snapshot := host.Snapshot()
	if !snapshot.Alive {
		t.Fatal("expected open protocol port to mark host alive")
	}
	if snapshot.Weak {
		t.Fatal("expected open protocol port to clear weak state")
	}
	if len(snapshot.OpenPorts()) != 1 || snapshot.OpenPorts()[0].Number != 443 {
		t.Fatalf("expected open TCP port to be stored, got %+v", snapshot.OpenPorts())
	}
}

func TestMergeLivenessDoesNotLetWeakObservationDowngradeStrongHost(t *testing.T) {
	host := NewHost("192.168.1.20")

	if !host.MergeLiveness(true, true, HostSourceARP) {
		t.Fatal("expected weak observation to update host")
	}
	if !host.Snapshot().Weak {
		t.Fatal("expected initial ARP-only observation to mark host weak")
	}

	if !host.MergeLiveness(true, false, HostSourceICMP) {
		t.Fatal("expected strong observation to update host")
	}
	snapshot := host.Snapshot()
	if !snapshot.Alive {
		t.Fatal("expected strong observation to mark host alive")
	}
	if snapshot.Weak {
		t.Fatal("expected strong observation to clear weak state")
	}

	host.MergeLiveness(true, true, HostSourceARP)
	if host.Snapshot().Weak {
		t.Fatal("expected later weak observation not to downgrade strong host")
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
