// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"context"

	arptransport "github.com/ostefani/subnetlens/transports/arp"
)

func startActiveARPSweep(ctx context.Context, target string, arpCache *ARPCache) {
	startActiveARPSweepWithIssues(ctx, target, arpCache, nil)
}

func startActiveARPSweepWithIssues(ctx context.Context, target string, arpCache *ARPCache, issues issueReporter) {
	targets, err := expandTargets(target)
	if err != nil {
		if issues != nil {
			issues.Report(warningIssue("arp", "active ARP sweep skipped: %v", err))
		}
		return
	}

	if err := arptransport.StartActiveSweep(ctx, target, targets.seq, arpCache, isLocalIP, func(format string, args ...any) {
		debugLog("arp", format, args...)
	}); err != nil && issues != nil {
		issues.Report(warningIssue("arp", "%v", err))
	}
}
