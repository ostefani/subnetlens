// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package export

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ostefani/subnetlens/models"
)

var testStart = time.Date(2026, time.September, 27, 10, 0, 0, 0, time.UTC)

func testScanResult() *models.ScanResult {
	printer := models.NewHost("192.168.1.5")
	printer.ObserveLiveness(true, false, models.HostSourceARP, time.Time{}, time.Time{})
	printer.SetHostname("printer.local")
	printer.SetMAC("00:11:22:33:44:55")
	printer.SetVendor("Acme Printers")
	printer.SetOS("Linux")
	printer.SetDevice("Network Printer")
	printer.SetLatency(150 * time.Millisecond)
	printer.SetProtocolPortsAndMarkAlive("tcp", []models.Port{
		{Number: 80, Protocol: "tcp", State: models.PortOpen, Service: "HTTP", Banner: "Server: Acme"},
		{Number: 443, Protocol: "tcp", State: models.PortOpen, Service: "HTTPS"},
		{Number: 22, Protocol: "tcp", State: models.PortClosed, Service: "SSH"},
	})

	stale := models.NewHost("192.168.1.9")
	stale.ObserveLiveness(false, false, models.HostSourcePTR, time.Time{}, time.Time{})
	stale.SetHostname("old-laptop.local")

	return &models.ScanResult{
		Subnet:     "192.168.1.0/24",
		StartedAt:  testStart,
		FinishedAt: testStart.Add(2500 * time.Millisecond),
		Hosts:      []*models.Host{printer, stale},
		Issues: []models.ScanIssue{{
			At:      testStart.Add(time.Second),
			Level:   models.ScanIssueLevelWarning,
			Source:  "icmp",
			Message: "ICMP probing unavailable",
		}},
	}
}

var hostTimePattern = regexp.MustCompile(`"(seen|updated)_at": "[^"]*"`)

func normalizeHostTimes(t *testing.T, raw []byte) string {
	t.Helper()
	return hostTimePattern.ReplaceAllStringFunc(string(raw), func(match string) string {
		if strings.HasPrefix(match, `"seen_at"`) {
			return `"seen_at": "SEEN"`
		}
		return `"updated_at": "UPDATED"`
	})
}

const wantGoldenJSON = `{
  "version": 1,
  "subnet": "192.168.1.0/24",
  "started_at": "2026-09-27T10:00:00Z",
  "finished_at": "2026-09-27T10:00:02.5Z",
  "duration_ms": 2500,
  "host_count": 2,
  "alive_count": 1,
  "hosts": [
    {
      "ip": "192.168.1.5",
      "hostname": "printer.local",
      "mac": "00:11:22:33:44:55",
      "randomized_mac": false,
      "vendor": "Acme Printers",
      "os": "Linux",
      "device": "Network Printer",
      "source": "arp",
      "alive": true,
      "weak": false,
      "latency_ms": 150,
      "seen_at": "SEEN",
      "updated_at": "UPDATED",
      "ports": [
        {
          "number": 80,
          "protocol": "tcp",
          "state": "open",
          "service": "HTTP",
          "banner": "Server: Acme"
        },
        {
          "number": 443,
          "protocol": "tcp",
          "state": "open",
          "service": "HTTPS"
        }
      ]
    },
    {
      "ip": "192.168.1.9",
      "hostname": "old-laptop.local",
      "randomized_mac": false,
      "source": "ptr",
      "alive": false,
      "weak": false,
      "latency_ms": 0,
      "seen_at": "SEEN",
      "updated_at": "UPDATED",
      "ports": []
    }
  ],
  "issues": [
    {
      "at": "2026-09-27T10:00:01Z",
      "level": "warning",
      "source": "icmp",
      "message": "ICMP probing unavailable"
    }
  ]
}
`

func TestEncodeJSONGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := EncodeJSON(&buf, testScanResult()); err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}
	if got := normalizeHostTimes(t, buf.Bytes()); got != wantGoldenJSON {
		t.Fatalf("JSON mismatch:\n got:\n%s\nwant:\n%s", got, wantGoldenJSON)
	}
	if strings.Contains(buf.String(), `"number": 22`) {
		t.Fatal("expected closed port 22 to be excluded from the export")
	}
}

func TestEncodeCSVRows(t *testing.T) {
	var buf bytes.Buffer
	if err := EncodeCSV(&buf, testScanResult()); err != nil {
		t.Fatalf("EncodeCSV: %v", err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parse exported CSV: %v", err)
	}
	want := [][]string{
		{"ip", "hostname", "mac", "vendor", "os", "device", "source", "alive", "port", "protocol", "state", "service", "banner"},
		{"192.168.1.5", "printer.local", "00:11:22:33:44:55", "Acme Printers", "Linux", "Network Printer", "arp", "true", "80", "tcp", "open", "HTTP", "Server: Acme"},
		{"192.168.1.5", "printer.local", "00:11:22:33:44:55", "Acme Printers", "Linux", "Network Printer", "arp", "true", "443", "tcp", "open", "HTTPS", ""},
		{"192.168.1.9", "old-laptop.local", "", "", "", "", "ptr", "false", "", "", "", "", ""},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("CSV mismatch:\n got: %q\nwant: %q", rows, want)
	}
}

func TestResolveFormat(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		override string
		want     Format
		wantErr  string
	}{
		{"json extension", "out.json", "", FormatJSON, ""},
		{"csv extension", "out.csv", "", FormatCSV, ""},
		{"extension case-insensitive", "OUT.JSON", "", FormatJSON, ""},
		{"override wins", "out.csv", "json", FormatJSON, ""},
		{"override case-insensitive", "out", "CSV", FormatCSV, ""},
		{"dash needs override", "-", "json", FormatJSON, ""},
		{"unknown extension", "out.txt", "", "", "cannot infer format"},
		{"no extension", "out", "", "", "cannot infer format"},
		{"dash without override", "-", "", "", "cannot infer format"},
		{"invalid override", "out.json", "yaml", "", "invalid --format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveFormat(tt.path, tt.override)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveFormat: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected format %q, got %q", tt.want, got)
			}
		})
	}
}

func TestEncodeRejectsUnknownFormat(t *testing.T) {
	if err := Encode(&bytes.Buffer{}, testScanResult(), Format("yaml")); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func TestNewReportHandlesNilResult(t *testing.T) {
	report := NewReport(nil)
	if report.Version != ExportVersion {
		t.Fatalf("expected version %d, got %d", ExportVersion, report.Version)
	}
	if len(report.Hosts) != 0 {
		t.Fatalf("expected no hosts, got %d", len(report.Hosts))
	}
}

func TestWriteFileRoundTripAndOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := WriteFile(path, testScanResult(), FormatJSON); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if !strings.Contains(string(first), `"version": 1`) {
		t.Fatalf("expected a JSON report, got %q", first)
	}

	empty := &models.ScanResult{Subnet: "10.0.0.0/24", StartedAt: testStart, FinishedAt: testStart}
	if err := WriteFile(path, empty, FormatJSON); err != nil {
		t.Fatalf("WriteFile overwrite: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read overwritten export: %v", err)
	}
	if !strings.Contains(string(second), `"subnet": "10.0.0.0/24"`) || strings.Contains(string(second), "printer.local") {
		t.Fatalf("expected the overwrite to replace the file, got %q", second)
	}
}

func TestWriteFileMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope", "out.json")
	if err := WriteFile(path, testScanResult(), FormatJSON); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}

func TestCheckWritable(t *testing.T) {
	if err := CheckWritable("-"); err != nil {
		t.Fatalf("expected stdout to pass, got %v", err)
	}
	if err := CheckWritable(filepath.Join(t.TempDir(), "out.json")); err != nil {
		t.Fatalf("expected temp dir to pass, got %v", err)
	}
	if err := CheckWritable(filepath.Join(t.TempDir(), "nope", "out.json")); err == nil {
		t.Fatal("expected a missing directory to fail")
	}
}

func stubExportClock(t *testing.T, fixed time.Time) {
	t.Helper()
	old := timeNow
	timeNow = func() time.Time { return fixed }
	t.Cleanup(func() { timeNow = old })
}

func stubExportHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func TestDefaultExportPath(t *testing.T) {
	home := t.TempDir()
	stubExportHome(t, home)
	stubExportClock(t, time.Date(2026, time.September, 28, 9, 30, 0, 0, time.UTC))

	path, err := DefaultExportPath(".subnetlens", FormatJSON)
	if err != nil {
		t.Fatalf("DefaultExportPath: %v", err)
	}
	want := filepath.Join(home, ".subnetlens", "scan-20260928-093000.json")
	if path != want {
		t.Fatalf("expected %q, got %q", want, path)
	}
	if info, err := os.Stat(filepath.Join(home, ".subnetlens")); err != nil || !info.IsDir() {
		t.Fatalf("expected the export directory to be created: %v", err)
	}
}

func TestDefaultExportPathDisambiguatesReruns(t *testing.T) {
	home := t.TempDir()
	stubExportHome(t, home)
	stubExportClock(t, time.Date(2026, time.September, 28, 9, 30, 0, 0, time.UTC))

	first, err := DefaultExportPath(".subnetlens", FormatCSV)
	if err != nil {
		t.Fatalf("DefaultExportPath: %v", err)
	}
	if err := os.WriteFile(first, []byte("first"), 0o644); err != nil {
		t.Fatalf("seed first export: %v", err)
	}
	second, err := DefaultExportPath(".subnetlens", FormatCSV)
	if err != nil {
		t.Fatalf("DefaultExportPath rerun: %v", err)
	}
	want := filepath.Join(home, ".subnetlens", "scan-20260928-093000-2.csv")
	if second != want {
		t.Fatalf("expected %q, got %q", want, second)
	}
}

func TestDefaultExportPathRejectsUnknownFormat(t *testing.T) {
	stubExportHome(t, t.TempDir())
	if _, err := DefaultExportPath(".subnetlens", Format("yaml")); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func TestTimestampedExportPath(t *testing.T) {
	dir := t.TempDir()
	stubExportClock(t, time.Date(2026, time.September, 28, 9, 30, 0, 0, time.UTC))

	first, err := TimestampedExportPath(dir, FormatJSON)
	if err != nil {
		t.Fatalf("TimestampedExportPath: %v", err)
	}
	want := filepath.Join(dir, "scan-20260928-093000.json")
	if first != want {
		t.Fatalf("expected %q, got %q", want, first)
	}
	if err := os.WriteFile(first, []byte("first"), 0o644); err != nil {
		t.Fatalf("seed first export: %v", err)
	}
	second, err := TimestampedExportPath(dir, FormatJSON)
	if err != nil {
		t.Fatalf("TimestampedExportPath rerun: %v", err)
	}
	wantSecond := filepath.Join(dir, "scan-20260928-093000-2.json")
	if second != wantSecond {
		t.Fatalf("expected %q, got %q", wantSecond, second)
	}
}

func TestTimestampedExportPathRejectsUnknownFormat(t *testing.T) {
	if _, err := TimestampedExportPath(t.TempDir(), Format("yaml")); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func TestDefaultExportPathFallsBackToWorkingDirectory(t *testing.T) {
	stubExportClock(t, time.Date(2026, time.September, 28, 9, 30, 0, 0, time.UTC))
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	want := filepath.Join(cwd, "scan-20260928-093000.json")

	t.Run("unusable home directory", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, []byte("not a dir"), 0o644); err != nil {
			t.Fatalf("seed blocker file: %v", err)
		}
		stubExportHome(t, blocker)
		path, err := DefaultExportPath(".subnetlens", FormatJSON)
		if err != nil {
			t.Fatalf("DefaultExportPath: %v", err)
		}
		if path != want {
			t.Fatalf("expected %q, got %q", want, path)
		}
	})

	t.Run("unset home directory", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows resolves the home directory from multiple variables")
		}
		stubExportHome(t, "")
		path, err := DefaultExportPath(".subnetlens", FormatJSON)
		if err != nil {
			t.Fatalf("DefaultExportPath: %v", err)
		}
		if path != want {
			t.Fatalf("expected %q, got %q", want, path)
		}
	})
}
