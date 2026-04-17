// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"sync"
	"time"

	"github.com/ostefani/subnetlens/models"
)

type issueReporter interface {
	Report(models.ScanIssue)
}

type issueReporterFunc func(models.ScanIssue)

func (f issueReporterFunc) Report(issue models.ScanIssue) {
	f(issue)
}

type issueRecorder struct {
	mu      sync.Mutex
	result  *models.ScanResult
	onIssue func(models.ScanIssue)
}

func newIssueRecorder(result *models.ScanResult, onIssue func(models.ScanIssue)) *issueRecorder {
	return &issueRecorder{
		result:  result,
		onIssue: onIssue,
	}
}

func (r *issueRecorder) Report(issue models.ScanIssue) {
	if r == nil {
		return
	}
	if issue.At.IsZero() {
		issue.At = time.Now()
	}

	r.mu.Lock()
	if r.result != nil {
		r.result.Issues = append(r.result.Issues, issue)
	}
	onIssue := r.onIssue
	r.mu.Unlock()

	if onIssue != nil {
		onIssue(issue)
	}
}

func warningIssue(source, format string, args ...any) models.ScanIssue {
	return models.ScanIssue{
		Level:   models.ScanIssueLevelWarning,
		Source:  source,
		Message: formatMessage(format, args...),
	}
}
