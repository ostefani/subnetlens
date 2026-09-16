// Copyright (c) 2026 Olha Stefanishyna. MIT License.
package main

import "github.com/ostefani/subnetlens/cmd"

// Build metadata injected by GoReleaser via ldflags
// (-X main.version / main.commit / main.date).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit, date)
	cmd.Execute()
}
