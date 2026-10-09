// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package scanner

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestProgressReporterContract(t *testing.T) {
	var (
		inCall atomic.Bool
		mu     sync.Mutex
		got    [][2]int
	)
	r := startProgressReporter(func(done, total int) {
		if !inCall.CompareAndSwap(false, true) {
			t.Error("callback invoked concurrently")
		}
		defer inCall.Store(false)
		mu.Lock()
		got = append(got, [2]int{done, total})
		mu.Unlock()
	})

	const total = 1000
	var wg sync.WaitGroup
	for i := 1; i <= total; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r.Update(n, total) // arrives in arbitrary order
		}(i)
	}
	wg.Wait()
	r.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatal("no progress emitted")
	}
	prev := 0
	for _, g := range got {
		if g[0] < prev {
			t.Fatalf("done decreased: %d after %d", g[0], prev)
		}
		prev = g[0]
	}
	if last := got[len(got)-1]; last != [2]int{total, total} {
		t.Fatalf("final = %v, want [%d %d]", last, total, total)
	}
}