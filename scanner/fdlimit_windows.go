//go:build windows

package scanner

func systemOpenFileLimit() (uint64, bool) {
	return 0, false
}
