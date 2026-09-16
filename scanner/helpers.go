// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/ostefani/subnetlens/internal/textutil"
)

var DebugMode = os.Getenv("SLENS_DEBUG") == "1"

func debugLog(subsystem, format string, args ...any) {
	if !DebugMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[DEBUG][%-10s] %s\n", subsystem, msg)
}

func normalizeMDNSName(name string) string {
	name = strings.TrimSuffix(name, ".local")
	name = strings.TrimSuffix(name, ".")
	return textutil.SanitizeInline(name)
}

func isLocalIP(ip string) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.String() == ip {
				return true
			}
		}
	}
	return false
}
