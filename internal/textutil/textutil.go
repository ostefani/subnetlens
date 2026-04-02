package textutil

import (
	"strings"
	"unicode"

	"github.com/charmbracelet/x/ansi"
)

// SanitizeInline removes terminal control characters and collapses
// whitespace so untrusted network text is safe to render inline.
func SanitizeInline(s string) string {
	if s == "" {
		return ""
	}

	s = ansi.Strip(s)
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsPrint(r):
			return r
		case unicode.IsSpace(r):
			return ' '
		default:
			return -1
		}
	}, s)

	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}
