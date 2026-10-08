// Copyright (c) 2026 Olha Stefanishyna. MIT License.

// Package debuglog is a dependency-free debug logger shared by packages
// that cannot import scanner.
package debuglog

import (
	"fmt"
	"os"
)

var Enabled = os.Getenv("SLENS_DEBUG") == "1"

func Printf(subsystem, format string, args ...any) {
	if !Enabled {
		return
	}
	fmt.Fprintf(os.Stderr, "[DEBUG][%-10s] %s\n", subsystem, fmt.Sprintf(format, args...))
}