// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionFlagReportsBuildMetadata(t *testing.T) {
	SetVersionInfo("v9.9.9", "deadbee", "2026-09-16")

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--version"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)
	defer rootCmd.SetErr(nil)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("expected --version to succeed, got %v", err)
	}

	out := buf.String()
	for _, want := range []string{"v9.9.9", "deadbee", "2026-09-16"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected --version output to contain %q, got %q", want, out)
		}
	}
}
