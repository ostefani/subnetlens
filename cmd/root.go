package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/ostefani/subnetlens/export"
	"github.com/ostefani/subnetlens/internal/textutil"
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner"
	"github.com/ostefani/subnetlens/scanner/discovery"
	"github.com/ostefani/subnetlens/ui/tui"
)

var (
	flagPorts                []int
	flagTimeout              int
	flagConcurrency          int
	flagDiscoveryConcurrency int
	flagBanners              bool
	flagPlain                bool
	flagAllAlive             bool
	flagAllowLargeScan       bool
	flagOutput               string
	flagFormat               string
	flagSort                 string
	flagFilter               string
)

var (
	buildVersion = "dev"
	buildCommit  = "none"
	buildDate    = "unknown"
)

// SetVersionInfo records build-time metadata so --version reports the
// release tag injected via ldflags. Empty values keep the defaults.
// Note: rootCmd.Version is always fully recomputed regardless of empty fields.
func SetVersionInfo(version, commit, date string) {
	if version != "" {
		buildVersion = version
	}
	if commit != "" {
		buildCommit = commit
	}
	if date != "" {
		buildDate = date
	}
	rootCmd.Version = fmt.Sprintf("%s (commit %s, built %s)", buildVersion, buildCommit, buildDate)
}

var rootCmd = &cobra.Command{
	Use:   "subnetlens",
	Short: "subnetlens — fast local network port scanner & visualizer",
	Long: `subnetlens discovers live hosts on your local network and scans their open ports.

With no target (or "local"), the local subnet is detected automatically.

Examples:
  subnetlens scan
  subnetlens scan local
  subnetlens scan 192.168.1.0/24
  subnetlens scan 10.0.0.0/24 --ports 22,80,443 --timeout 300
  subnetlens scan 192.168.1.5  --plain`,
}

var scanCmd = &cobra.Command{
	Use:   "scan [subnet]",
	Short: "Scan a subnet for live hosts and open ports",
	Long: `Scan a subnet for live hosts and open ports.

With no target, or the keyword "local", the local subnet is detected
automatically from the active network interfaces. An auto-detected subnet
over the large-scan threshold narrows to the local /24 unless
--allow-large-scan is given.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().IntSliceVarP(&flagPorts, "ports", "p", nil,
		"Comma-separated ports to scan (default: common ports)")
	scanCmd.Flags().IntVarP(&flagTimeout, "timeout", "t", 500,
		"Per-connection timeout in milliseconds")
	scanCmd.Flags().IntVarP(&flagConcurrency, "concurrency", "c", 100,
		"Max concurrent port scan and banner probes")
	scanCmd.Flags().IntVar(&flagDiscoveryConcurrency, "discovery-concurrency", 0,
		"Max concurrent host discovery probes (0 = use --concurrency)")
	scanCmd.Flags().BoolVarP(&flagBanners, "banners", "b", false,
		"Attempt banner grabbing on open ports")
	scanCmd.Flags().BoolVar(&flagPlain, "plain", false,
		"Plain text output instead of TUI")
	scanCmd.Flags().BoolVar(&flagAllAlive, "all-alive", false,
		"Show all discovered hosts, including those that respond with TCP connection errors")
	scanCmd.Flags().BoolVar(&flagAllowLargeScan, "allow-large-scan", false,
		"Confirm scans expanding to more than 1024 addresses")
	scanCmd.Flags().StringVar(&flagOutput, "output", "",
		"Save the scan report into DIR instead of ~/.subnetlens (the file is named automatically; - prints to stdout)")
	scanCmd.Flags().StringVar(&flagFormat, "format", "",
		"Report format: json or csv (required with --output; without --output, saves to ~/.subnetlens)")
	scanCmd.Flags().StringVar(&flagSort, "sort", scanner.SortDiscovery,
		"Host listing order: discovery, ip, latency, vendor, hostname (--plain prints sorted output when the scan completes)")
	scanCmd.Flags().StringVar(&flagFilter, "filter", "",
		`Only show hosts matching EXPR, e.g. "port:22,os:linux" (keys: ip, host, mac, vendor, os, device, service, port, weak, alive, source; comma = AND, repeated key = OR; --plain prints matches when the scan completes)`)

	rootCmd.AddCommand(scanCmd)
}

// autoScanTarget resolves the zero-config target. It is a variable so tests
// can stub interface detection without touching the host network.
var autoScanTarget = scanner.AutoScanTarget

type resolvedTarget struct {
	subnet       string
	auto         bool
	narrowedFrom string
}

func resolveScanTarget(args []string, allowLarge bool) (resolvedTarget, error) {
	if len(args) == 0 || args[0] == scanner.LocalTargetKeyword {
		subnet, narrowedFrom, err := autoScanTarget(allowLarge)
		if err != nil {
			return resolvedTarget{}, fmt.Errorf("could not determine the local subnet: %v; pass a target explicitly (e.g. subnetlens scan 192.168.1.0/24)", err)
		}
		return resolvedTarget{subnet: subnet, auto: true, narrowedFrom: narrowedFrom}, nil
	}
	return resolvedTarget{subnet: args[0]}, nil
}

// resolveExport validates the export flags before any scanning starts and
// resolves the destination path. It returns "" when export is disabled.
// --format alone saves a timestamped report to ~/.subnetlens; --output
// names an existing folder the report is saved into (named automatically);
// "-" streams to stdout. --format is always required when exporting, since
// there is no extension to infer it from. The checks fail fast on bad
// inputs so a full scan is never wasted; the write path still reports the
// authoritative error at write time.
func resolveExport(output, format string) (string, export.Format, error) {
	if output == "" && format == "" {
		return "", "", nil
	}
	if format == "" {
		return "", "", fmt.Errorf("--format is required with --output (json or csv)")
	}
	resolved, err := export.ResolveFormat("", format)
	if err != nil {
		return "", "", err
	}
	if output == "" {
		path, err := export.DefaultExportPath(".subnetlens", resolved)
		if err != nil {
			return "", "", err
		}
		if err := export.CheckWritable(path); err != nil {
			return "", "", err
		}
		return path, resolved, nil
	}
	if output == "-" {
		return "-", resolved, nil
	}
	info, err := os.Stat(output)
	if err != nil {
		return "", "", fmt.Errorf("--output: cannot use directory %q: %w", output, err)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("--output %q is not a directory: pass an existing folder; the report file is named automatically", output)
	}
	path, err := export.TimestampedExportPath(output, resolved)
	if err != nil {
		return "", "", err
	}
	if err := export.CheckWritable(path); err != nil {
		return "", "", err
	}
	return path, resolved, nil
}

// keepRunningOnClosedStdout reports whether the scan must survive stdout
// pipe closure. With a file export requested, the file is the deliverable
// and previewing stdout (head, less, an exiting jq) must not abort it.
// Stdout streaming keeps standard SIGPIPE death so `| head` still
// terminates early instead of pointlessly finishing the scan.
func keepRunningOnClosedStdout(outputPath string) bool {
	return outputPath != "" && outputPath != "-"
}

func writeExport(path string, result *models.ScanResult, format export.Format) error {
	if path == "-" {
		return export.Encode(os.Stdout, result, format)
	}
	return export.WriteFile(path, result, format)
}

func runScan(cmd *cobra.Command, args []string) error {
	resolved, err := resolveScanTarget(args, flagAllowLargeScan)
	if err != nil {
		return err
	}
	subnet, auto := resolved.subnet, resolved.auto

	exportPath, exportFormat, err := resolveExport(flagOutput, flagFormat)
	if err != nil {
		return err
	}
	if keepRunningOnClosedStdout(exportPath) {
		ignoreSigpipeOnClosedStdout()
	}

	// Listing options fail fast like export flags: a typo must never waste
	// a full scan or silently narrow its output.
	sortOrder, err := scanner.NormalizeSortOrder(flagSort)
	if err != nil {
		return err
	}
	filter, err := scanner.ParseHostFilter(flagFilter)
	if err != nil {
		return err
	}

	opts := models.ScanOptions{
		Subnet:               subnet,
		Ports:                flagPorts,
		Timeout:              time.Duration(flagTimeout) * time.Millisecond,
		Concurrency:          flagConcurrency,
		DiscoveryConcurrency: flagDiscoveryConcurrency,
		GrabBanners:          flagBanners,
		AllAlive:             flagAllAlive,
		AllowLargeScan:       flagAllowLargeScan,
		Sort:                 sortOrder,
		Filter:               strings.TrimSpace(flagFilter),
	}
	if len(opts.Ports) == 0 {
		opts.Ports = models.CommonPorts
	}

	// Fail fast before the TUI/plain runner starts.
	if _, err := discovery.CheckTargetConsent(subnet, opts); err != nil {
		var confirmationErr *discovery.LargeScanConfirmationError
		if errors.As(err, &confirmationErr) {
			if auto {
				return fmt.Errorf("auto-detected target %q expands to %d addresses (over the %d address confirmation threshold): pass a smaller target explicitly or re-run with --allow-large-scan", confirmationErr.Target, confirmationErr.Total, confirmationErr.Threshold)
			}
			return fmt.Errorf("target %q expands to %d addresses (over the %d address confirmation threshold): re-run with --allow-large-scan", confirmationErr.Target, confirmationErr.Total, confirmationErr.Threshold)
		}
		// Syntax errors keep the historical path: the engine reports them
		// as scan issues instead of failing the command here.
	}
	opts, socketBudget, warnings := scanner.PrepareScanOptions(opts)
	switch {
	case resolved.narrowedFrom != "":
		warnings = append([]string{fmt.Sprintf("Auto-detected %s is too large to scan without consent; scanning %s instead (pass an explicit target or --allow-large-scan for the full range).", resolved.narrowedFrom, subnet)}, warnings...)
	case auto:
		warnings = append([]string{fmt.Sprintf("No target given: auto-detected local subnet %s.", subnet)}, warnings...)
	}
	if flagPlain && (sortOrder != scanner.SortDiscovery || filter != nil) {
		warnings = append(warnings, "sort/filter active: matching hosts print when the scan completes.")
	}

	if flagPlain {
		return runPlain(opts, socketBudget, warnings, exportPath, exportFormat, filter)
	}

	result, err := tui.Run(opts, socketBudget, warnings)
	if err != nil {
		return err
	}
	return exportScanResult(exportPath, result, exportFormat)
}

// exportScanResult writes the export file, if requested. A nil result means
// the user quit the TUI before the scan completed: there is nothing
// trustworthy to write, so the export is skipped with a note instead of
// emitting a partial file. Successful file exports announce their path on
// stderr (stdout stays clean for pipes); stdout streaming stays silent.
func exportScanResult(path string, result *models.ScanResult, format export.Format) error {
	if path == "" {
		return nil
	}
	if result == nil {
		fmt.Fprintln(os.Stderr, "Scan quit before completion; skipping export.")
		return nil
	}
	if err := writeExport(path, result, format); err != nil {
		return err
	}
	if path != "-" {
		fmt.Fprintf(os.Stderr, "Exported scan results to %s\n", path)
	}
	return nil
}

// runPlain outputs results as plain text — useful for scripting / CI pipelines.
// When exportPath is set the scan result is also written in exportFormat; when
// exportPath is "-", human-readable stdout is suppressed so the pipe stays clean.
// Without --sort/--filter hosts stream as they complete; with either flag the
// output is buffered so the final listing is complete, filtered, and ordered.
// Exports always carry the full unfiltered result.
func runPlain(opts models.ScanOptions, socketBudget int, warnings []string, exportPath string, exportFormat export.Format, filter *scanner.HostFilter) error {
	printWarnings(warnings)
	human := exportPath != "-"
	local := discovery.LocalDiscoveryInfoForTarget(opts.Subnet)
	buffered := scanner.DefaultSortOrder(opts.Sort) != scanner.SortDiscovery || filter != nil
	if human {
		fmt.Fprintf(os.Stdout, "Scanning %s ...\n\n", opts.Subnet)
		printPlainLocalMachine(local)
	}

	var mu sync.Mutex
	pending := make(map[string]models.HostSnapshot)
	printed := make(map[string]bool)
	order := make([]string, 0)
	if local.InScanRange && local.IP != "" {
		printed[local.IP] = true
	}

	eng := scanner.NewEngine(
		opts,
		socketBudget,
		scanner.WithOnProgress(func(done, total int) {
			fmt.Fprintf(os.Stderr, "\r  Probing hosts: %d/%d", done, total)
		}),
		scanner.WithOnIssue(func(issue models.ScanIssue) {
			fmt.Fprintf(os.Stderr, "\n%s\n", issue.String())
		}),
		scanner.WithOnHost(func(h *models.Host) {
			snapshot := h.Snapshot()

			mu.Lock()
			if _, seen := pending[snapshot.IP]; !seen {
				order = append(order, snapshot.IP)
			}
			pending[snapshot.IP] = snapshot

			// Each update refreshes the buffered snapshot for host.
			// Buffered (sorted/filtered) listings skip streaming: they print
			// once from the finished result instead.
			if buffered || printed[snapshot.IP] || !plainHostReady(snapshot) {
				mu.Unlock()
				return
			}
			printed[snapshot.IP] = true
			mu.Unlock()

			// Print as soon as the host looks complete enough for plain output.
			fmt.Fprintln(os.Stderr)
			if human {
				printPlainHost(snapshot)
			}
		}),
	)

	result := eng.Run(context.Background())
	fmt.Fprintf(os.Stderr, "\r                              \r")

	mu.Lock()
	deferred := make([]models.HostSnapshot, 0, len(order))
	for _, ip := range order {
		if printed[ip] {
			continue
		}
		if snapshot, ok := pending[ip]; ok {
			deferred = append(deferred, snapshot)
			printed[ip] = true
		}
	}
	mu.Unlock()

	if human {
		shown := deferred
		if buffered {
			shown = finalPlainSnapshots(result, local, filter)
			scanner.SortSnapshots(shown, opts.Sort)
		}
		for _, snapshot := range shown {
			printPlainHost(snapshot)
		}

		fmt.Printf("\n─────────────────────────────────────────\n")
		fmt.Printf("Scan complete in %s\n", result.Duration().Round(time.Millisecond))
		if filter != nil {
			fmt.Printf("%d host(s) shown (%d alive on %s)\n", len(shown), len(result.AliveHosts()), opts.Subnet)
		} else {
			fmt.Printf("%d host(s) found on %s\n", len(result.AliveHosts()), opts.Subnet)
		}
	}

	return exportScanResult(exportPath, result, exportFormat)
}

// finalPlainSnapshots collects end-of-scan snapshots for buffered (sorted or
// filtered) plain output. Like the streaming path it hides the local machine,
// which already has its own header box; unlike it, the set is complete, so
// filters judge final port/vendor state instead of mid-scan partials.
func finalPlainSnapshots(result *models.ScanResult, local discovery.LocalDiscoveryInfo, filter *scanner.HostFilter) []models.HostSnapshot {
	if result == nil {
		return nil
	}
	snapshots := make([]models.HostSnapshot, 0, len(result.Hosts))
	for _, host := range result.Hosts {
		if host == nil {
			continue
		}
		snapshot := host.Snapshot()
		if local.InScanRange && local.IP != "" && snapshot.IP == local.IP {
			continue
		}
		snapshots = append(snapshots, snapshot)
	}
	return filter.FilterSnapshots(snapshots)
}

func printWarnings(warnings []string) {
	for _, warning := range warnings {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", warning)
	}
	if len(warnings) > 0 {
		fmt.Fprintln(os.Stderr)
	}
}

func plainHostReady(snapshot models.HostSnapshot) bool {
	return snapshot.Hostname != "" &&
		snapshot.Hostname != snapshot.IP &&
		snapshot.MAC != "" &&
		(snapshot.RandomizedMAC ||
			(snapshot.Vendor != "" && snapshot.Device != ""))
}

// Plain-text column budgets in display cells, mirroring the TUI table
// discipline: every unbounded network string is truncated (see
// textutil.Truncate) so host blocks never wrap on narrow terminals. Worst
// case line stays within 100 cells.
const (
	plainHostnameWidth = 48
	plainOSWidth       = 20
	plainDeviceWidth   = 25
	plainVendorWidth   = 27
	plainServiceWidth  = 10
	plainBannerWidth   = 64
)

// formatPlainHost renders one host block as lines. Snapshot contains the
// authoritative host state after all updates settle.
func formatPlainHost(snapshot models.HostSnapshot) []string {
	hostOS := snapshot.OS
	if hostOS == "" || hostOS == "Unknown" {
		hostOS = "?"
	}

	vendor := snapshot.Vendor
	if snapshot.RandomizedMAC {
		vendor = "Randomized MAC*"
	} else if vendor == "" {
		vendor = "—"
	}

	device := snapshot.Device
	if snapshot.RandomizedMAC {
		device = "Randomized MAC*"
	} else if device == "" {
		device = "—"
	}

	lines := []string{
		"",
		fmt.Sprintf("[+] %-18s  %s", snapshot.IP, textutil.Truncate(snapshot.Hostname, plainHostnameWidth)),
		fmt.Sprintf("    OS: %-20s  Device: %-25s  Vendor: %s",
			textutil.Truncate(hostOS, plainOSWidth),
			textutil.Truncate(device, plainDeviceWidth),
			textutil.Truncate(vendor, plainVendorWidth)),
	}
	for _, p := range snapshot.OpenPorts() {
		service := p.Service
		if service == "" {
			service = "—"
		}
		lines = append(lines, fmt.Sprintf("    %-6d %-5s %-10s %s",
			p.Number, p.Protocol,
			textutil.Truncate(service, plainServiceWidth),
			textutil.Truncate(p.Banner, plainBannerWidth)))
	}
	return lines
}

func printPlainHost(snapshot models.HostSnapshot) {
	for _, line := range formatPlainHost(snapshot) {
		fmt.Println(line)
	}
}

func printPlainLocalMachine(info discovery.LocalDiscoveryInfo) {
	if info.Hostname == "" && info.Interface == "" {
		return
	}

	name := info.Hostname
	if name == "" {
		name = "Local machine"
	}

	fmt.Printf("Local machine: %s\n", name)
	if info.Interface != "" {
		fmt.Printf("  Interface: %s\n", info.Interface)
	}

	if info.InSubnet {
		ip := info.IP
		if ip == "" {
			ip = "—"
		}
		mac := info.MAC
		if mac == "" {
			mac = "—"
		}
		fmt.Printf("  IP: %s\n", ip)
		fmt.Printf("  MAC: %s\n", mac)
		if !info.InScanRange {
			fmt.Printf("  Note: discovery interface is active, but its IP is outside the requested scan range.\n")
		}
		fmt.Println()
		return
	}

	fmt.Printf("  Note: scanning from a different subnet; local IP/MAC details are hidden.\n\n")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
