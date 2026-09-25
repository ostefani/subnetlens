// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunScanRefusesLargeTargetWithoutFlag(t *testing.T) {
	if flagAllowLargeScan {
		t.Skip("flagAllowLargeScan is set; refusal path not exercised")
	}

	err := runScan(nil, []string{"10.0.0.0/16"})
	if err == nil {
		t.Fatal("expected large scan without --allow-large-scan to fail")
	}
	if !strings.Contains(err.Error(), "--allow-large-scan") {
		t.Fatalf("expected error to name the opt-in flag, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "65534") {
		t.Fatalf("expected error to state the address count, got %q", err.Error())
	}
}

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
