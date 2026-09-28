// Copyright (c) 2026 Olha Stefanishyna. MIT License.

package textutil

import (
	"strings"
	"testing"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		name  string
		s     string
		width int
		want  string
	}{
		{"short unchanged", "printer", 10, "printer"},
		{"exact unchanged", "printer", 7, "printer"},
		{"empty", "", 10, ""},
		{"zero width", "printer", 0, ""},
		{"long truncated", "hello world", 8, "hello w…"},
		{"unicode truncated", "héllo wörld", 8, "héllo w…"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Truncate(tt.s, tt.width); got != tt.want {
				t.Fatalf("Truncate(%q, %d) = %q, want %q", tt.s, tt.width, got, tt.want)
			}
		})
	}
}

func TestSanitizeInline(t *testing.T) {
	if got := SanitizeInline("  hello\tworld\n"); got != "hello world" {
		t.Fatalf("expected whitespace collapsed, got %q", got)
	}
	if got := SanitizeInline("a\x00b\x01c"); got != "abc" {
		t.Fatalf("expected control characters stripped, got %q", got)
	}
	if got := SanitizeInline(""); got != "" {
		t.Fatalf("expected empty to stay empty, got %q", got)
	}
	if strings.Contains(SanitizeInline("\x1b[31mred\x1b[0m"), "\x1b") {
		t.Fatal("expected ANSI escapes stripped")
	}
}
