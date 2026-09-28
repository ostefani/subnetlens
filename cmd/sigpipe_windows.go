// Copyright (c) 2026 Olha Stefanishyna. MIT License.

//go:build windows

package cmd

// ignoreSigpipeOnClosedStdout is a no-op on Windows, which has no SIGPIPE:
// writes to a closed pipe already fail as errors instead of killing the
// process.
func ignoreSigpipeOnClosedStdout() {}
