// Copyright (c) 2026 Olha Stefanishyna. MIT License.

//go:build !windows

package cmd

import (
	"os/signal"
	"syscall"
)

// ignoreSigpipeOnClosedStdout arranges for writes to a closed stdout/stderr
// pipe to fail as EPIPE errors instead of killing the process with SIGPIPE.
// The scan then runs to completion and its file export is still written;
// stdout/stderr writes themselves keep failing silently into the void.
func ignoreSigpipeOnClosedStdout() {
	signal.Ignore(syscall.SIGPIPE)
}
