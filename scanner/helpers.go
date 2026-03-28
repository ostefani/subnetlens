package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unicode"
)

var DebugMode = os.Getenv("NETMAP_DEBUG") == "1"

func debugLog(subsystem, format string, args ...any) {
	if !DebugMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[DEBUG][%-10s] %s\n", subsystem, msg)
}

// isTimeout returns true if the error is a network timeout.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

func deadlineAfter(ms int) time.Time {
	return time.Now().Add(time.Duration(ms) * time.Millisecond)
}

func normalizeMDNSName(name string) string {
	name = strings.TrimSuffix(name, ".local")
    name = strings.TrimSuffix(name, ".")
    return name
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) || r == '\n' || r == '\r' {
			return r
		}
		return -1
	}, strings.TrimSpace(s))
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

func cappedTimeout(ctx context.Context, max time.Duration) time.Duration {
	dl, ok := ctx.Deadline()
	if !ok {
		return max
	}
	if rem := time.Until(dl); rem < max {
		if rem <= 0 {
			return time.Millisecond
		}
		return rem
	}
	return max
}