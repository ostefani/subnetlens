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
	flagPorts       []int
	flagTimeout     int
	flagConcurrency int
	flagBanners     bool
	flagPlain       bool
	flagAllAlive    bool
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
		"Number of parallel goroutines")
	scanCmd.Flags().BoolVarP(&flagBanners, "banners", "b", false,
		"Attempt banner grabbing on open ports")
	scanCmd.Flags().BoolVar(&flagPlain, "plain", false,
		"Plain text output instead of TUI")
	scanCmd.Flags().BoolVar(&flagAllAlive, "all-alive", false,
		"Show only hosts with at least one successful connection")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	subnet := args[0]

	opts := models.ScanOptions{
		Subnet:      subnet,
		Ports:       flagPorts,
		Timeout:     time.Duration(flagTimeout) * time.Millisecond,
		Concurrency: flagConcurrency,
		GrabBanners: flagBanners,
		AllAlive:    flagAllAlive,
	}
	if len(opts.Ports) == 0 {
		opts.Ports = models.CommonPorts
	}

	if flagPlain {
		return runPlain(opts)
	}

	return tui.Run(opts)
}

// runPlain outputs results as plain text — useful for scripting / CI pipelines.
func runPlain(opts models.ScanOptions) error {
	fmt.Fprintf(os.Stdout, "Scanning %s ...\n\n", opts.Subnet)
	var mu sync.Mutex
	pending := make(map[string]models.HostSnapshot)
	printed := make(map[string]bool)
	order := make([]string, 0)

	eng := &scanner.Engine{
		Opts: opts,
		OnProgress: func(done, total int) {
			fmt.Fprintf(os.Stderr, "\r  Probing hosts: %d/%d", done, total)
		},
		OnHost: func(h *models.Host) {
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
		},
	}

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

func plainHostReady(snapshot models.HostSnapshot) bool {
	return snapshot.Hostname != "" &&
		snapshot.Hostname != snapshot.IP &&
		snapshot.MAC != "" &&
		snapshot.Vendor != "" &&
		snapshot.Device != ""
}

func printPlainHost(snapshot models.HostSnapshot) {
	hostOS := snapshot.OS
	if hostOS == "" || hostOS == "Unknown" {
		hostOS = "?"
	}

	vendor := snapshot.Vendor
	if vendor == "" {
		vendor = "—"
	}

	device := snapshot.Device
	if device == "" {
		device = "—"
	}

	// Snapshot contains the authoritative host state after all updates settle.
	fmt.Printf("\n[+] %-18s  %s\n", snapshot.IP, snapshot.Hostname)
	fmt.Printf("    OS: %-20s  Device: %-25s  Vendor: %s\n", hostOS, device, vendor)
	for _, p := range snapshot.OpenPorts {
		fmt.Printf("    %-6d %-10s %s\n", p.Number, p.Service, p.Banner)
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
