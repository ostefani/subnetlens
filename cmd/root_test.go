// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ostefani/subnetlens/export"
	"github.com/ostefani/subnetlens/models"
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

func TestResolveExportFormat(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name     string
		output   string
		format   string
		want     export.Format
		disabled bool
		wantErr  string
	}{
		{"disabled", "", "", "", true, ""},
		{"json inferred", filepath.Join(dir, "o.json"), "", export.FormatJSON, false, ""},
		{"csv inferred", filepath.Join(dir, "o.csv"), "", export.FormatCSV, false, ""},
		{"override", filepath.Join(dir, "o"), "csv", export.FormatCSV, false, ""},
		{"stdout needs format", "-", "json", export.FormatJSON, false, ""},
		{"format requires output", "", "json", "", false, "--format requires --output"},
		{"bad extension", filepath.Join(dir, "o.txt"), "", "", false, "cannot infer format"},
		{"bad override", filepath.Join(dir, "o.json"), "yaml", "", false, "invalid --format"},
		{"unwritable dir", filepath.Join(dir, "nope", "o.json"), "", "", false, "cannot write export file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveExportFormat(tt.output, tt.format)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveExportFormat: %v", err)
			}
			if tt.disabled && got != "" {
				t.Fatalf("expected export to be disabled, got format %q", got)
			}
			if !tt.disabled && got != tt.want {
				t.Fatalf("expected format %q, got %q", tt.want, got)
			}
		})
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
