// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package netutil

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type stubNetError struct{ timeout bool }

func (e stubNetError) Error() string   { return "stub network error" }
func (e stubNetError) Timeout() bool   { return e.timeout }
func (e stubNetError) Temporary() bool { return e.timeout }

func TestIsTimeoutUnwrapsWrappedErrors(t *testing.T) {
	wrapped := fmt.Errorf("dial tcp: %w", stubNetError{timeout: true})
	if !IsTimeout(wrapped) {
		t.Fatal("expected wrapped net timeout to report true")
	}
}

func TestIsTimeoutTable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"direct timeout", stubNetError{timeout: true}, true},
		{"non-timeout net error", stubNetError{timeout: false}, false},
		{"generic error", fmt.Errorf("boom"), false},
	}
	for _, tc := range cases {
		if got := IsTimeout(tc.err); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDeadlineAfter(t *testing.T) {
	before := time.Now()
	got := DeadlineAfter(300)
	want := before.Add(300 * time.Millisecond)
	if got.Sub(want) < -50*time.Millisecond || got.Sub(want) > 50*time.Millisecond {
		t.Fatalf("DeadlineAfter(300) = %v, want ~%v", got, want)
	}
}

func TestCappedTimeout(t *testing.T) {
	if got := CappedTimeout(context.Background(), 500*time.Millisecond); got != 500*time.Millisecond {
		t.Fatalf("no deadline: got %v, want 500ms", got)
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	defer cancel()
	if got := CappedTimeout(ctx, 500*time.Millisecond); got != 500*time.Millisecond {
		t.Fatalf("far deadline: got %v, want 500ms", got)
	}

	near, cancelNear := context.WithDeadline(context.Background(), time.Now().Add(50*time.Millisecond))
	defer cancelNear()
	if got := CappedTimeout(near, 500*time.Millisecond); got <= 0 || got > 50*time.Millisecond {
		t.Fatalf("near deadline: got %v, want (0,50ms]", got)
	}

	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if got := CappedTimeout(expired, 500*time.Millisecond); got != time.Millisecond {
		t.Fatalf("expired deadline: got %v, want 1ms", got)
	}
}
