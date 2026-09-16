// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package netutil

import (
	"context"
	"errors"
	"net"
	"time"
)

// IsTimeout reports whether err is or wraps a network timeout.
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// DeadlineAfter returns a time.Duration-based deadline ms milliseconds from now.
func DeadlineAfter(ms int) time.Time {
	return time.Now().Add(time.Duration(ms) * time.Millisecond)
}

// CappedTimeout bounds max by the context deadline when one is sooner.
func CappedTimeout(ctx context.Context, max time.Duration) time.Duration {
	dl, ok := ctx.Deadline()
	if !ok {
		return max
	}
	if rem := time.Until(dl); rem < max {
		if rem <= 0 {
			return time.Millisecond
		}
		return rem
	}
	return max
}
