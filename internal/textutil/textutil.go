// Copyright (c) 2026 Olha Stefanishyna. MIT License.

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

// Truncate shortens s to at most width display cells, appending an ellipsis
// when content was cut, so table layouts never overflow their columns.
// Non-positive widths yield the empty string.
func Truncate(s string, width int) string {
	if width <= 0 {
		return ""
	}
	return ansi.Truncate(s, width, "…")
}
