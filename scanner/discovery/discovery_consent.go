package discovery

import (
	"fmt"

	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner/contracts"
)

// LargeScanConfirmationError signals a target large enough to require
// explicit user consent. It is not a syntax error: setting AllowLargeScan
// on the scan options clears it. Frontends add their own opt-in guidance
// (e.g. the CLI names its flag); this message stays transport-agnostic.
type LargeScanConfirmationError struct {
	Target    string
	Total     uint64
	Threshold uint64
}

func (e *LargeScanConfirmationError) Error() string {
	return fmt.Sprintf("target %q expands to %d addresses (over the %d address confirmation threshold): large-scan consent required (AllowLargeScan)", e.Target, e.Total, e.Threshold)
}

// CheckTargetConsent expands target and reports its address count. When the
// count exceeds contracts.LargeScanThreshold without consent in opts, it
// returns a *LargeScanConfirmationError. Syntax errors pass through unchanged
// so callers keep their existing invalid-target behavior.
func CheckTargetConsent(target string, opts models.ScanOptions) (uint64, error) {
	spec, err := ExpandTargets(target)
	if err != nil {
		return 0, err
	}
	total := uint64(spec.total)
	if contracts.RequiresLargeScanConsent(total, opts) {
		return total, &LargeScanConfirmationError{Target: target, Total: total, Threshold: contracts.LargeScanThreshold}
	}
	return total, nil
}

// LargeScanWarning describes a consented-to large scan for the warnings
// channel (plain output and TUI). It returns "" for ordinary-sized targets.
func LargeScanWarning(target string, total uint64) string {
	if total <= contracts.LargeScanThreshold {
		return ""
	}
	return fmt.Sprintf("target %q expands to %d addresses: scan will take a while and generate substantial traffic", target, total)
}
