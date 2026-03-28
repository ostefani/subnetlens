package cmd

import (
	"context"
	"fmt"
	"os"
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
	flagAllAlive bool
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
		AllAlive: flagAllAlive,
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

	eng := &scanner.Engine{
		Opts: opts,
		OnProgress: func(done, total int) {
			fmt.Fprintf(os.Stderr, "\r  Probing hosts: %d/%d", done, total)
		},
		OnHost: func(h *models.Host) {
			fmt.Fprintln(os.Stderr)
			hostOS := h.OS

			if hostOS == "" || hostOS == "Unknown" {
				hostOS = "?"
			}

			vendor := h.Vendor
			if vendor == "" {
				vendor = "—"
			}

			device := h.Device
			if device == "" {
				device = "—"
			}

			fmt.Printf("\n[+] %-18s  %s\n", h.IP, h.Hostname)
			fmt.Printf("    OS: %-20s  Device: %-25s  Vendor: %s\n", hostOS, device, vendor)
			for _, p := range h.OpenPorts {
				fmt.Printf("    %-6d %-10s %s\n", p.Number, p.Service, p.Banner)
			}
		},
	}

	result := eng.Run(context.Background())
	fmt.Fprintf(os.Stderr, "\r                              \r")

	fmt.Printf("\n─────────────────────────────────────────\n")
	fmt.Printf("Scan complete in %s\n", result.Duration().Round(time.Millisecond))
	fmt.Printf("%d host(s) found on %s\n", len(result.AliveHosts()), opts.Subnet)
	return nil
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
