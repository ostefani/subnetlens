package tui

import (
	"context"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/ostefani/subnetlens/models"
	"github.com/ostefani/subnetlens/scanner"
)

func runScanCmd(opts models.ScanOptions, socketBudget int, hostCh chan *models.Host, progCh chan [2]int, issueCh chan models.ScanIssue) tea.Cmd {
	return func() tea.Msg {
		defer close(hostCh)
		defer close(progCh)
		defer close(issueCh)

		ctx := context.Background()
		var finalDone atomic.Int64
		var finalTotal atomic.Int64
		var lastUpdate time.Time

		eng := scanner.NewEngine(opts, socketBudget)
		eng.OnHost = func(h *models.Host) {
			hostCh <- h

		}
		eng.OnIssue = func(issue models.ScanIssue) {
			select {
			case issueCh <- issue:
			default:
			}
		}

		eng.OnProgress = func(done, total int) {
			finalDone.Store(int64(done))
			finalTotal.Store(int64(total))

			now := time.Now()
			// Only send a UI update every 50ms (20fps) or if it's 100% complete
			if done >= total || now.Sub(lastUpdate) > 50*time.Millisecond {
				select {
				case progCh <- [2]int{done, total}:
					lastUpdate = now
				default:
				}
			}
		}
		result := eng.Run(ctx)
		return scanDoneMsg{
			result:     result,
			finalDone:  int(finalDone.Load()),
			finalTotal: int(finalTotal.Load()),
		}
	}
}

func waitForHostCmd(hostCh chan *models.Host) tea.Cmd {
	return func() tea.Msg {
		h, ok := <-hostCh
		if !ok {
			return nil
		}

		batch := []*models.Host{h}
		for len(batch) < hostBatchSize {
			select {
			case nextH, nextOk := <-hostCh:
				if !nextOk {
					return hostsFoundMsg{hosts: batch}
				}
				batch = append(batch, nextH)
			default:
				return hostsFoundMsg{hosts: batch}
			}
		}

		return hostsFoundMsg{hosts: batch}
	}
}

func waitForProgressCmd(progCh chan [2]int) tea.Cmd {
	return func() tea.Msg {
		v, ok := <-progCh
		if !ok {
			return nil
		}
		return progressMsg{done: v[0], total: v[1]}
	}
}

func waitForIssueCmd(issueCh chan models.ScanIssue) tea.Cmd {
	return func() tea.Msg {
		issue, ok := <-issueCh
		if !ok {
			return nil
		}
		return issueMsg{issue: issue}
	}
}
