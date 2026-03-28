# ✧ Subnetlens ✧

A fast, concurrent local network scanner with a TUI and plain-text CLI — built in Go.

Supports multiple discovery methods:

- TCP connect scan (no elevated privileges required)
- ICMP echo (requires root / administrator)
- ARP scan (Linux/macOS; Windows requires Npcap)
- mDNS (passive) — listen for local service announcements

Designed for local subnet enumeration and any reachable IP range via TCP and ICMP.

## Features

- **Host discovery** (TCP, ICMP, ARP)
- **Port scanning** (TCP connect)
- **Device hinting** — TLS cert, HTTP headers, MAC vendor (OUI)
- **MAC randomization detection**
- **OS hinting** — heuristic-based fingerprinting
- **Streaming TUI** — live updates during scan
- **Plain mode** — script-friendly output
- **Single binary**

## OUI database (optional)

For MAC vendor resolution, download an OUI CSV from [https://regauth.standards.ieee.org](https://regauth.standards.ieee.org)

Place it at:

```bash
scanner/oui.csv
```

**If omitted, vendor lookup falls back to a built-in truncated OUI table.**

## Quick Start

```bash
git clone https://github.com/ostefani/subnetlens
cd subnetlens

# Update dependencies
go get -u all
go get github.com/some/module@latest

# Install dependencies
go mod tidy

# ---Install---
go install ./... ## binary in $(go env GOPATH)/bin
# or
mv subnetlens /usr/local/bin/

# Build
go build .
# or
go build -o subnetlens

# Add to PATH
export PATH="$PATH:$(go env GOPATH)/bin"
# Make persist
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc
source ~/.zshrc

# 5. Run
subnetlens scan <target>

# Run in debug mode
NETMAP_DEBUG=1 sudo ./subnetlens scan <target> --plain 2>debug.log
```

## Usage

### Scan Your Own Machine

Check interfaces and its assigned IP. Scan only the subnet that matches your WiFi interface (`en0`) to stay on your home network.

```bash
ip addr                      # Linux
ifconfig  | grep "inet "     # macOS
```

```bash
subnetlens scan [subnet] [flags]
```

**Flags:**
`-p`, --ports string Comma-separated ports to scan (default: common 23 ports)
`-t`, --timeout int Per-connection timeout in ms (default: 500)
`-c`, --concurrency int Parallel goroutines (default: 100)
`-b`, --banners Grab service banners
--plain Plain text output (no TUI)

## Platform Support

| Feature  | Linux    | macOS    | Windows            |
| -------- | -------- | -------- | ------------------ |
| TCP scan | ✔        | ✔        | ✔                  |
| ICMP     | ✔ (root) | ✔ (root) | ✔ (admin)          |
| ARP      | ✔        | ✔        | ✔ (Npcap required) |
| mDNS     | ✔        | ✔        | not tested         |

Windows requires Npcap for ARP scanning.

**Examples:**

```bash
  subnetlens scan <IP>
  subnetlens scan <IP start>-<IP end>
  subnetlens scan <IP> --ports 22,80,443,8080
  subnetlens scan <IP> --plain --banners
  subnetlens scan <IP> --concurrency 200 --timeout 300
```

## Project Structure

```
subnetlens /
├── main.go               # Entrypoint
├── cmd/
│   └── root.go           # Cobra CLI commands
├── scanner/
│   ├── arp.go
|   ├── discovery.go
│   ├── engine.go
│   ├── helpers.go
│   ├── icmp.go
│   ├── osdetect.go
│   └── oui.csv        # is not included in the repo, must be downloaded from https://regauth.standards.ieee.org if you want to build locally
├── models/
│   └── models.go
└── ui/
    └── tui/
        └── tui.go
```

## Roadmap

- [x] ARP-based host discovery (requires raw sockets / root)
- [x] MAC address vendor lookup
- [x] mDNS listening
- [ ] UDP port scanning
- [ ] JSON / CSV export (`--output result.json`)
- [ ] GUI with interactive network node graph
- [ ] Scan profiles: `--profile quick|full|stealth`
- [ ] `subnetlens watch` — re-scan on interval, alert on changes

## Contributing

To contribute please consult CONTRIBUTING.md about PR requirements.

## License

MIT © 2026 Olha Stefanishyna

**Disclaimer:** This tool is intended for authorized security testing and network diagnostics only. Do not scan networks or systems without explicit permission.
