// Copyright (c) 2026 Olha Stefanishyna. MIT License.

//go:build !windows

package scanner

import "golang.org/x/sys/unix"

func systemOpenFileLimit() (uint64, bool) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		return 0, false
	}
	if lim.Cur == unix.RLIM_INFINITY {
		return 0, false
	}
	return lim.Cur, true
}
