// Copyright (c) 2026 Olha Stefanishyna. MIT License.

// Package export renders scan results to machine-readable files.
//
// The JSON envelope and CSV header row are a stability contract: readers
// (scripts, CI pipelines, future importers) program against them, not
// against the domain model. Within a format version only additive changes
// are allowed (new optional JSON fields, CSV columns appended at the end);
// anything breaking bumps ExportVersion.
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ostefani/subnetlens/models"
)

// ExportVersion is the current file-format version, stamped into every
// JSON report so readers can branch on schema evolution.
const ExportVersion = 1

// Format selects an export encoding.
type Format string

const (
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
)

// Report is the versioned JSON document: scan metadata plus one entry per
// discovered host. Only open ports are included, matching the TUI and
// plain-text presentation.
type Report struct {
	Version    int        `json:"version"`
	Subnet     string     `json:"subnet"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt time.Time  `json:"finished_at"`
	DurationMS int64      `json:"duration_ms"`
	HostCount  int        `json:"host_count"`
	AliveCount int        `json:"alive_count"`
	Hosts      []HostDTO  `json:"hosts"`
	Issues     []IssueDTO `json:"issues,omitempty"`
}

// HostDTO is the serializable projection of models.HostSnapshot.
type HostDTO struct {
	IP            string    `json:"ip"`
	Hostname      string    `json:"hostname"`
	MAC           string    `json:"mac,omitempty"`
	RandomizedMAC bool      `json:"randomized_mac"`
	Vendor        string    `json:"vendor,omitempty"`
	OS            string    `json:"os,omitempty"`
	Device        string    `json:"device,omitempty"`
	Source        string    `json:"source"`
	Alive         bool      `json:"alive"`
	Weak          bool      `json:"weak"`
	LatencyMS     int64     `json:"latency_ms"`
	SeenAt        time.Time `json:"seen_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Ports         []PortDTO `json:"ports"`
}

// PortDTO is the serializable projection of an open models.Port.
type PortDTO struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// IssueDTO is the serializable projection of models.ScanIssue.
type IssueDTO struct {
	At      time.Time `json:"at"`
	Level   string    `json:"level"`
	Source  string    `json:"source"`
	Message string    `json:"message"`
}

// csvHeader is the CSV contract: one row per open port with host columns
// repeated; hosts without open ports emit a single row with empty port
// columns. New columns are always appended at the end.
var csvHeader = []string{
	"ip", "hostname", "mac", "vendor", "os", "device",
	"source", "alive", "port", "protocol", "state", "service", "banner",
}

// NewReport projects a scan result onto the export DTO. It snapshots every
// host, so it is safe to call once the engine has finished.
func NewReport(result *models.ScanResult) Report {
	report := Report{Version: ExportVersion, Hosts: []HostDTO{}}
	if result == nil {
		return report
	}
	report.Subnet = result.Subnet
	report.StartedAt = result.StartedAt
	report.FinishedAt = result.FinishedAt
	report.DurationMS = result.Duration().Milliseconds()
	for _, host := range result.Hosts {
		if host == nil {
			continue
		}
		snapshot := host.Snapshot()
		report.Hosts = append(report.Hosts, newHostDTO(snapshot))
		if snapshot.Alive {
			report.AliveCount++
		}
	}
	report.HostCount = len(report.Hosts)
	for _, issue := range result.Issues {
		report.Issues = append(report.Issues, IssueDTO{
			At:      issue.At,
			Level:   string(issue.Level),
			Source:  issue.Source,
			Message: issue.Message,
		})
	}
	return report
}

func newHostDTO(snapshot models.HostSnapshot) HostDTO {
	dto := HostDTO{
		IP:            snapshot.IP,
		Hostname:      snapshot.Hostname,
		MAC:           snapshot.MAC,
		RandomizedMAC: snapshot.RandomizedMAC,
		Vendor:        snapshot.Vendor,
		OS:            snapshot.OS,
		Device:        snapshot.Device,
		Source:        string(snapshot.Source),
		Alive:         snapshot.Alive,
		Weak:          snapshot.Weak,
		LatencyMS:     snapshot.Latency.Milliseconds(),
		SeenAt:        snapshot.SeenAt,
		UpdatedAt:     snapshot.UpdatedAt,
		Ports:         []PortDTO{},
	}
	for _, port := range snapshot.OpenPorts() {
		dto.Ports = append(dto.Ports, PortDTO{
			Number:   port.Number,
			Protocol: port.Protocol,
			State:    string(port.State),
			Service:  port.Service,
			Banner:   port.Banner,
		})
	}
	return dto
}

// EncodeJSON writes the report as indented JSON.
func EncodeJSON(w io.Writer, result *models.ScanResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(NewReport(result))
}

// EncodeCSV writes the report as CSV rows.
func EncodeCSV(w io.Writer, result *models.ScanResult) error {
	writer := csv.NewWriter(w)
	if err := writer.Write(csvHeader); err != nil {
		return err
	}
	for _, host := range NewReport(result).Hosts {
		rows := hostCSVRows(host)
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return err
			}
		}
	}
	writer.Flush()
	return writer.Error()
}

func hostCSVRows(host HostDTO) [][]string {
	base := []string{
		host.IP,
		host.Hostname,
		host.MAC,
		host.Vendor,
		host.OS,
		host.Device,
		host.Source,
		strconv.FormatBool(host.Alive),
	}
	if len(host.Ports) == 0 {
		return [][]string{append(append([]string(nil), base...), "", "", "", "", "")}
	}
	rows := make([][]string, 0, len(host.Ports))
	for _, port := range host.Ports {
		row := append(append([]string(nil), base...),
			strconv.Itoa(port.Number),
			port.Protocol,
			port.State,
			port.Service,
			port.Banner,
		)
		rows = append(rows, row)
	}
	return rows
}

// FormatFromPath infers the export format from the file extension.
func FormatFromPath(path string) (Format, error) {
	switch strings.ToLower(strings.TrimPrefix(filepath.Ext(path), ".")) {
	case string(FormatJSON):
		return FormatJSON, nil
	case string(FormatCSV):
		return FormatCSV, nil
	default:
		return "", fmt.Errorf("cannot infer format from %q: use a .json or .csv extension or pass --format", path)
	}
}

// ResolveFormat returns the explicit override when set (validating it),
// and otherwise infers the format from the path.
func ResolveFormat(path, override string) (Format, error) {
	if override != "" {
		switch format := Format(strings.ToLower(override)); format {
		case FormatJSON, FormatCSV:
			return format, nil
		default:
			return "", fmt.Errorf("invalid --format %q: want json or csv", override)
		}
	}
	return FormatFromPath(path)
}

// Encode writes the result in the given format.
func Encode(w io.Writer, result *models.ScanResult, format Format) error {
	switch format {
	case FormatJSON:
		return EncodeJSON(w, result)
	case FormatCSV:
		return EncodeCSV(w, result)
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

// CheckWritable reports whether path can plausibly be written by creating
// and removing a temporary sibling file. It is a fail-fast pre-check for
// flag validation ("-" always passes); WriteFile reports the authoritative
// error at write time.
func CheckWritable(path string) error {
	if path == "-" {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".subnetlens-export-*")
	if err != nil {
		return fmt.Errorf("cannot write export file %q: %w", path, err)
	}
	name := tmp.Name()
	tmp.Close()
	return os.Remove(name)
}

// timeNow reports the current time. It is a variable so tests can pin the
// clock when asserting timestamped export names.
var timeNow = time.Now

// TimestampedExportPath returns a fresh scan-<timestamp>.<ext> path inside
// dir (e.g. dir/scan-20260928-093000.json). Each call picks a name that does
// not exist yet (a -2, -3, ... suffix disambiguates reruns within the same
// second), so exports accumulate instead of replacing each other.
//
// Two scans resolving a name concurrently within the same second may still
// pick the same candidate; the check-then-write gap only closes for
// sequential runs, which is all interactive and scheduled use needs.
func TimestampedExportPath(dir string, format Format) (string, error) {
	switch format {
	case FormatJSON, FormatCSV:
	default:
		return "", fmt.Errorf("unsupported export format %q", format)
	}
	base := "scan-" + timeNow().Format("20060102-150405")
	ext := "." + string(format)
	candidate := filepath.Join(dir, base+ext)
	for i := 2; i < 1000; i++ {
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		}
		candidate = filepath.Join(dir, fmt.Sprintf("%s-%d%s", base, i, ext))
	}
	return "", fmt.Errorf("cannot pick a free export name in %q: too many clashes", dir)
}

// DefaultExportPath returns a fresh timestamped export path inside the
// per-user directory $HOME/appDir (created when missing). When the home
// directory is unavailable or unusable (minimal containers, read-only
// homes), the current directory is used instead; the caller announces the
// resolved path, so the file is never a surprise.
func DefaultExportPath(appDir string, format Format) (string, error) {
	dir, err := userExportDir(appDir)
	if err != nil {
		return "", err
	}
	return TimestampedExportPath(dir, format)
}

// userExportDir ensures the per-user export directory exists and returns it.
// A missing or unusable home falls back to the current directory so exports
// keep working where $HOME is unset or read-only.
func userExportDir(appDir string) (string, error) {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dir := filepath.Join(home, appDir)
		if err := os.MkdirAll(dir, 0o755); err == nil {
			return dir, nil
		}
	}
	return os.Getwd()
}

// WriteFile writes the export atomically: the content lands in a temporary
// sibling file first and is renamed over the destination, so a crash or
// interrupt never leaves a half-written export behind. An existing file is
// replaced.
func WriteFile(path string, result *models.ScanResult, format Format) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".subnetlens-export-*")
	if err != nil {
		return fmt.Errorf("create export file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := Encode(tmp, result, format); err != nil {
		tmp.Close()
		return fmt.Errorf("encode export: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write export file: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("write export file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("write export file: %w", err)
	}
	return nil
}
