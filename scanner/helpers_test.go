package scanner

import (
	"testing"

	"github.com/ostefani/subnetlens/internal/textutil"
)

func TestSanitizeRemovesControlSequencesAndCollapsesWhitespace(t *testing.T) {
	got := textutil.SanitizeInline(" banner\x1b[31m\r\nvalue\tok\x07 ")
	if got != "banner value ok" {
		t.Fatalf("expected inline-safe banner, got %q", got)
	}
}
