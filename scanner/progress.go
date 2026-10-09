// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"sync"
	"sync/atomic"
	"time"
)

const progressInterval = 50 * time.Millisecond // 20 updates/s

// progressReporter adapts a progress source that may call Update
// concurrently and out of order to the contract Engine promises its
// onProgress callback: calls never overlap, done never decreases, calls are
// throttled to progressInterval, and a final call carries the last values.
type progressReporter struct {
	emit  func(done, total int)
	done  atomic.Int64
	total atomic.Int64
	stop  chan struct{}
	wg    sync.WaitGroup
}

func startProgressReporter(emit func(done, total int)) *progressReporter {
	p := &progressReporter{emit: emit, stop: make(chan struct{})}
	p.wg.Add(1)
	go p.loop()
	return p
}

// Update is safe for concurrent use and never blocks. done only moves forward.
func (p *progressReporter) Update(done, total int) {
	for {
		cur := p.done.Load()
		if int64(done) <= cur || p.done.CompareAndSwap(cur, int64(done)) {
			break
		}
	}
	p.total.Store(int64(total))
}

// Stop emits a final snapshot and waits for the reporter goroutine to exit.
// Call it once, after the last Update.
func (p *progressReporter) Stop() {
	close(p.stop)
	p.wg.Wait()
}

func (p *progressReporter) loop() {
	defer p.wg.Done()
	ticker := time.NewTicker(progressInterval)
	defer ticker.Stop()

	var last [2]int64 // owned by this goroutine only
	flush := func() {
		cur := [2]int64{p.done.Load(), p.total.Load()}
		if cur[1] == 0 || cur == last {
			return // nothing known yet, or nothing new
		}
		last = cur
		p.emit(int(cur[0]), int(cur[1]))
	}

	for {
		select {
		case <-ticker.C:
			flush()
		case <-p.stop:
			flush()
			return
		}
	}
}