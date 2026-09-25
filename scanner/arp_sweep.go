// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"context"
	"iter"

	arptransport "github.com/ostefani/subnetlens/transports/arp"
)

func startActiveARPSweep(ctx context.Context, target string, targets iter.Seq[string], arpCache *ARPCache) {
	startActiveARPSweepWithIssues(ctx, target, targets, arpCache, nil)
}

// startActiveARPSweepWithIssues consumes the engine's already-expanded target
// sequence. It never expands the target itself, so the range is built once
// per run; a nil sequence reports the platform as unsupported.
func startActiveARPSweepWithIssues(ctx context.Context, target string, targets iter.Seq[string], arpCache *ARPCache, issues issueReporter) {
	if err := arptransport.StartActiveSweep(ctx, target, targets, arpCache, isLocalIP, func(format string, args ...any) {
		debugLog("arp", format, args...)
	}); err != nil && issues != nil {
		issues.Report(warningIssue("arp", "%v", err))
	}
}
