// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ostefani/subnetlens/export"
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner"
)

func TestRunScanRefusesLargeTargetWithoutFlag(t *testing.T) {
	if flagAllowLargeScan {
		t.Skip("flagAllowLargeScan is set; refusal path not exercised")
	}

	err := runScan(nil, []string{"10.0.0.0/16"})
	if err == nil {
		t.Fatal("expected large scan without --allow-large-scan to fail")
	}
	if !strings.Contains(err.Error(), "--allow-large-scan") {
		t.Fatalf("expected error to name the opt-in flag, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "65534") {
		t.Fatalf("expected error to state the address count, got %q", err.Error())
	}
}

func TestVersionFlagReportsBuildMetadata(t *testing.T) {
	SetVersionInfo("v9.9.9", "deadbee", "2026-09-16")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--version"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)
	defer rootCmd.SetErr(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("expected --version to succeed, got %v", err)
	}

	out := buf.String()
	for _, want := range []string{"v9.9.9", "deadbee", "2026-09-16"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected --version output to contain %q, got %q", want, out)
		}
	}
}

func TestResolveExport(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0o644); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}
	tests := []struct {
		name     string
		output   string
		format   string
		want     export.Format
		wantDir  string
		disabled bool
		wantErr  string
	}{
		{"disabled", "", "", "", "", true, ""},
		{"stdout needs format", "-", "json", export.FormatJSON, "", false, ""},
		{"stdout without format", "-", "", "", "", false, "--format is required with --output"},
		{"format only uses default dir", "", "json", export.FormatJSON, filepath.Join(dir, ".subnetlens"), false, ""},
		{"format only rejects bad format", "", "yaml", "", "", false, "invalid --format"},
		{"output dir auto-names", dir, "json", export.FormatJSON, dir, false, ""},
		{"output dir keeps trailing separator working", dir + string(os.PathSeparator), "csv", export.FormatCSV, dir, false, ""},
		{"output without format", dir, "", "", "", false, "--format is required with --output"},
		{"output bad format", dir, "yaml", "", "", false, "invalid --format"},
		{"output missing dir", filepath.Join(dir, "nope"), "json", "", "", false, "cannot use directory"},
		{"output file rejected", blocker, "json", "", "", false, "is not a directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, got, err := resolveExport(tt.output, tt.format)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveExport: %v", err)
			}
			if tt.disabled {
				if got != "" || gotPath != "" {
					t.Fatalf("expected export to be disabled, got path %q format %q", gotPath, got)
				}
				return
			}
			if got != tt.want {
				t.Fatalf("expected format %q, got %q", tt.want, got)
			}
			if tt.wantDir == "" {
				if gotPath != tt.output {
					t.Fatalf("expected path %q, got %q", tt.output, gotPath)
				}
				return
			}
			if parent := filepath.Dir(gotPath); parent != tt.wantDir {
				t.Fatalf("expected a path under %q, got %q", tt.wantDir, gotPath)
			}
			base := filepath.Base(gotPath)
			if !strings.HasPrefix(base, "scan-") || !strings.HasSuffix(base, "."+string(tt.want)) {
				t.Fatalf("expected an auto-named %q report, got %q", tt.want, gotPath)
			}
		})
	}
}

func TestResolveExportAccumulatesDefaultExports(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	first, format, err := resolveExport("", "json")
	if err != nil {
		t.Fatalf("resolveExport: %v", err)
	}
	if err := writeExport(first, testExportResult(), format); err != nil {
		t.Fatalf("write first export: %v", err)
	}
	second, _, err := resolveExport("", "json")
	if err != nil {
		t.Fatalf("resolveExport rerun: %v", err)
	}
	if second == first {
		t.Fatalf("expected a rerun to pick a fresh path, got %q twice", first)
	}
	if err := writeExport(second, testExportResult(), format); err != nil {
		t.Fatalf("write second export: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(home, ".subnetlens"))
	if err != nil {
		t.Fatalf("read export dir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected two accumulated exports, got %d", len(entries))
	}
}

func testExportResult() *models.ScanResult {
	host := models.NewHost("192.168.1.5")
	host.ObserveLiveness(true, false, models.HostSourceARP, time.Time{}, time.Time{})
	host.SetHostname("printer.local")
	host.SetProtocolPortsAndMarkAlive("tcp", []models.Port{
		{Number: 80, Protocol: "tcp", State: models.PortOpen, Service: "HTTP"},
	})
	start := time.Date(2026, time.September, 27, 10, 0, 0, 0, time.UTC)
	return &models.ScanResult{
		Subnet:     "192.168.1.0/24",
		StartedAt:  start,
		FinishedAt: start.Add(time.Second),
		Hosts:      []*models.Host{host},
	}
}

func TestWriteExportToFile(t *testing.T) {
	dir := t.TempDir()

	jsonPath := filepath.Join(dir, "out.json")
	if err := writeExport(jsonPath, testExportResult(), export.FormatJSON); err != nil {
		t.Fatalf("writeExport JSON: %v", err)
	}
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON export: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("JSON export does not parse: %v", err)
	}
	if decoded["version"] != float64(export.ExportVersion) {
		t.Fatalf("expected version %d, got %v", export.ExportVersion, decoded["version"])
	}

	csvPath := filepath.Join(dir, "out.csv")
	if err := writeExport(csvPath, testExportResult(), export.FormatCSV); err != nil {
		t.Fatalf("writeExport CSV: %v", err)
	}
	csvRaw, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatalf("read CSV export: %v", err)
	}
	header, _, _ := strings.Cut(string(csvRaw), "\n")
	if header != "ip,hostname,mac,vendor,os,device,source,alive,port,protocol,state,service,banner" {
		t.Fatalf("unexpected CSV header %q", header)
	}
	if !strings.Contains(string(csvRaw), "printer.local") {
		t.Fatalf("expected CSV to contain the host, got %q", csvRaw)
	}
}

func TestFormatPlainHostKeepsClassicShape(t *testing.T) {
	snapshot := models.HostSnapshot{
		IP: "192.168.0.1", Hostname: "192.168.0.1",
		Vendor: "TP-Link Systems Inc", Device: "TP-Link Router",
		Ports: []models.Port{
			{Number: 53, Protocol: "tcp", State: models.PortOpen, Service: "DNS"},
		},
	}
	want := []string{
		"",
		"[+] 192.168.0.1         192.168.0.1",
		"    OS: ?                     Device: TP-Link Router             Vendor: TP-Link Systems Inc",
		"    53     tcp   DNS        ",
	}
	got := formatPlainHost(snapshot)
	if len(got) != len(want) {
		t.Fatalf("expected %d lines, got %d: %q", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d mismatch:\n got: %q\nwant: %q", i, got[i], want[i])
		}
	}
}

func TestFormatPlainHostTruncatesLongFields(t *testing.T) {
	snapshot := models.HostSnapshot{
		IP:       "192.168.1.5",
		Hostname: strings.Repeat("h", 80),
		OS:       strings.Repeat("o", 30),
		Device:   strings.Repeat("d", 40),
		Vendor:   strings.Repeat("v", 60),
		Ports: []models.Port{
			{Number: 443, Protocol: "tcp", State: models.PortOpen, Service: strings.Repeat("s", 20), Banner: strings.Repeat("b", 100)},
		},
	}
	want := []string{
		"",
		"[+] 192.168.1.5         " + strings.Repeat("h", 47) + "…",
		"    OS: " + strings.Repeat("o", 19) + "…" + "  Device: " + strings.Repeat("d", 24) + "…" + "  Vendor: " + strings.Repeat("v", 26) + "…",
		"    443    tcp   " + strings.Repeat("s", 9) + "…" + " " + strings.Repeat("b", 63) + "…",
	}
	got := formatPlainHost(snapshot)
	if len(got) != len(want) {
		t.Fatalf("expected %d lines, got %d: %q", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d mismatch:\n got: %q\nwant: %q", i, got[i], want[i])
		}
		if utf8.RuneCountInString(got[i]) > 100 {
			t.Fatalf("line %d exceeds 100 cells: %q", i, got[i])
		}
	}
}

func TestKeepRunningOnClosedStdout(t *testing.T) {
	tests := []struct {
		output string
		want   bool
	}{
		{"", false},
		{"-", false},
		{"out.json", true},
		{"/tmp/out.csv", true},
	}
	for _, tt := range tests {
		if got := keepRunningOnClosedStdout(tt.output); got != tt.want {
			t.Fatalf("keepRunningOnClosedStdout(%q) = %v, want %v", tt.output, got, tt.want)
		}
	}
}

func TestExportScanResult(t *testing.T) {
	if err := exportScanResult("", nil, ""); err != nil {
		t.Fatalf("expected disabled export to succeed, got %v", err)
	}

	skipped := filepath.Join(t.TempDir(), "skipped.json")
	if err := exportScanResult(skipped, nil, export.FormatJSON); err != nil {
		t.Fatalf("expected nil result to skip cleanly, got %v", err)
	}
	if _, err := os.Stat(skipped); !os.IsNotExist(err) {
		t.Fatalf("expected no file for a nil result, stat err: %v", err)
	}

	written := filepath.Join(t.TempDir(), "out.json")
	if err := exportScanResult(written, testExportResult(), export.FormatJSON); err != nil {
		t.Fatalf("exportScanResult: %v", err)
	}
	if _, err := os.Stat(written); err != nil {
		t.Fatalf("expected the export file to exist: %v", err)
	}
}

func stubAutoScanTarget(t *testing.T, subnet, narrowedFrom string, err error) {
	t.Helper()
	prevTarget := autoScanTarget
	prevFlag := flagAllowLargeScan
	autoScanTarget = func(bool) (string, string, error) { return subnet, narrowedFrom, err }
	flagAllowLargeScan = false
	t.Cleanup(func() {
		autoScanTarget = prevTarget
		flagAllowLargeScan = prevFlag
	})
}

func TestScanCmdAcceptsZeroOrOneArg(t *testing.T) {
	if err := scanCmd.Args(scanCmd, nil); err != nil {
		t.Fatalf("expected bare scan to be accepted, got %v", err)
	}
	if err := scanCmd.Args(scanCmd, []string{"192.168.1.0/24"}); err != nil {
		t.Fatalf("expected one arg to be accepted, got %v", err)
	}
	if err := scanCmd.Args(scanCmd, []string{"a", "b"}); err == nil {
		t.Fatal("expected two args to be rejected")
	}
}

func TestRunScanAutoTargetRefusedWhenLarge(t *testing.T) {
	stubAutoScanTarget(t, "10.0.0.0/16", "", nil)

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("expected auto-detected large scan without --allow-large-scan to fail")
	}
	for _, want := range []string{"auto-detected", "10.0.0.0/16", "65534", "--allow-large-scan"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to contain %q, got %q", want, err.Error())
		}
	}
}

func TestRunScanNoTargetResolutionError(t *testing.T) {
	stubAutoScanTarget(t, "", "", errors.New("no active IPv4 network interface found"))

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("expected resolution failure to fail the scan")
	}
	if !strings.Contains(err.Error(), "could not determine the local subnet") {
		t.Fatalf("expected a helpful resolution error, got %q", err.Error())
	}
}

func TestRunScanLocalKeywordUsesResolver(t *testing.T) {
	stubAutoScanTarget(t, "", "", errors.New("no active IPv4 network interface found"))

	err := runScan(nil, []string{"local"})
	if err == nil {
		t.Fatal("expected scan local to use the resolver and fail here")
	}
	if !strings.Contains(err.Error(), "could not determine the local subnet") {
		t.Fatalf("expected a helpful resolution error, got %q", err.Error())
	}
}

func TestResolveScanTargetPassesExplicitTargetThrough(t *testing.T) {
	stubAutoScanTarget(t, "", "", errors.New("resolver must not be called"))

	resolved, err := resolveScanTarget([]string{"192.168.1.0/24"}, false)
	if err != nil {
		t.Fatalf("explicit target must not consult the resolver: %v", err)
	}
	if resolved.auto || resolved.subnet != "192.168.1.0/24" || resolved.narrowedFrom != "" {
		t.Fatalf("expected plain passthrough of 192.168.1.0/24, got %+v", resolved)
	}
}

func TestRunScanRejectsInvalidSortBeforeScanning(t *testing.T) {
	prev := flagSort
	flagSort = "bogus"
	t.Cleanup(func() { flagSort = prev })

	err := runScan(nil, []string{"192.168.1.0/24"})
	if err == nil || !strings.Contains(err.Error(), "invalid --sort") {
		t.Fatalf("expected an invalid --sort error before any scan, got %v", err)
	}
}

func TestRunScanRejectsInvalidFilterBeforeScanning(t *testing.T) {
	prev := flagFilter
	flagFilter = "bogus:x"
	t.Cleanup(func() { flagFilter = prev })

	err := runScan(nil, []string{"192.168.1.0/24"})
	if err == nil || !strings.Contains(err.Error(), "invalid --filter") {
		t.Fatalf("expected an invalid --filter error before any scan, got %v", err)
	}
}

func TestFinalPlainSnapshotsSkipsLocalMachineAndAppliesFilter(t *testing.T) {
	local := models.NewHost("192.168.1.5")
	remote := models.NewHost("192.168.1.10")
	remote.SetProtocolPortsAndMarkAlive("tcp", []models.Port{
		{Number: 22, Protocol: "tcp", State: models.PortOpen, Service: "SSH"},
	})
	other := models.NewHost("192.168.1.11")
	other.SetProtocolPortsAndMarkAlive("tcp", []models.Port{
		{Number: 80, Protocol: "tcp", State: models.PortOpen, Service: "HTTP"},
	})
	result := &models.ScanResult{
		Subnet: "192.168.1.0/24",
		Hosts:  []*models.Host{local, remote, other, nil},
	}
	info := scanner.LocalDiscoveryInfo{InScanRange: true, IP: "192.168.1.5"}

	filter, err := scanner.ParseHostFilter("port:22")
	if err != nil {
		t.Fatalf("parse filter: %v", err)
	}
	got := finalPlainSnapshots(result, info, filter)
	if len(got) != 1 || got[0].IP != "192.168.1.10" {
		t.Fatalf("expected only the port-22 remote host, got %v", got)
	}

	unfiltered := finalPlainSnapshots(result, info, nil)
	if len(unfiltered) != 2 {
		t.Fatalf("expected local machine (only) skipped without a filter, got %d snapshots", len(unfiltered))
	}
}

func TestResolveScanTargetReportsNarrowing(t *testing.T) {
	stubAutoScanTarget(t, "198.18.0.0/24", "198.18.0.0/16", nil)

	resolved, err := resolveScanTarget(nil, false)
	if err != nil {
		t.Fatalf("resolveScanTarget: %v", err)
	}
	if !resolved.auto || resolved.subnet != "198.18.0.0/24" || resolved.narrowedFrom != "198.18.0.0/16" {
		t.Fatalf("expected narrowed auto target, got %+v", resolved)
	}
}
