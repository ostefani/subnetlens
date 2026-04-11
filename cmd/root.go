package cmd

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner"
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
)

var rootCmd = &cobra.Command{
	Use:   "subnetlens",
	Short: "subnetlens — fast local network port scanner & visualizer",
	Long: `subnetlens discovers live hosts on your local network and scans their open ports.

Examples:
  subnetlens scan 192.168.1.0/24
  subnetlens scan 10.0.0.0/24 --ports 22,80,443 --timeout 300
  subnetlens scan 192.168.1.5  --plain`,
}

var scanCmd = &cobra.Command{
	Use:   "scan [subnet]",
	Short: "Scan a subnet for live hosts and open ports",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
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

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	subnet := args[0]

	opts := models.ScanOptions{
		Subnet:               subnet,
		Ports:                flagPorts,
		Timeout:              time.Duration(flagTimeout) * time.Millisecond,
		Concurrency:          flagConcurrency,
		DiscoveryConcurrency: flagDiscoveryConcurrency,
		GrabBanners:          flagBanners,
		AllAlive:             flagAllAlive,
	}
	if len(opts.Ports) == 0 {
		opts.Ports = models.CommonPorts
	}
	opts, socketBudget, warnings := scanner.PrepareScanOptions(opts)

	if flagPlain {
		return runPlain(opts, socketBudget, warnings)
	}

	return tui.Run(opts, socketBudget, warnings)
}

// runPlain outputs results as plain text — useful for scripting / CI pipelines.
func runPlain(opts models.ScanOptions, socketBudget int, warnings []string) error {
	printWarnings(warnings)
	fmt.Fprintf(os.Stdout, "Scanning %s ...\n\n", opts.Subnet)
	local := scanner.LocalDiscoveryInfoForTarget(opts.Subnet)
	printPlainLocalMachine(local)

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
			if printed[snapshot.IP] || !plainHostReady(snapshot) {
				mu.Unlock()
				return
			}
			printed[snapshot.IP] = true
			mu.Unlock()

			// Print as soon as the host looks complete enough for plain output.
			fmt.Fprintln(os.Stderr)
			printPlainHost(snapshot)
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

	for _, snapshot := range deferred {
		printPlainHost(snapshot)
	}

	fmt.Printf("\n─────────────────────────────────────────\n")
	fmt.Printf("Scan complete in %s\n", result.Duration().Round(time.Millisecond))
	fmt.Printf("%d host(s) found on %s\n", len(result.AliveHosts()), opts.Subnet)
	return nil
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

func printPlainHost(snapshot models.HostSnapshot) {
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

	// Snapshot contains the authoritative host state after all updates settle.
	fmt.Printf("\n[+] %-18s  %s\n", snapshot.IP, snapshot.Hostname)
	fmt.Printf("    OS: %-20s  Device: %-25s  Vendor: %s\n", hostOS, device, vendor)
	for _, p := range snapshot.OpenPorts() {
		service := p.Service
		if service == "" {
			service = "—"
		}
		fmt.Printf("    %-6d %-5s %-10s %s\n", p.Number, p.Protocol, service, p.Banner)
	}
}

func printPlainLocalMachine(info scanner.LocalDiscoveryInfo) {
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
