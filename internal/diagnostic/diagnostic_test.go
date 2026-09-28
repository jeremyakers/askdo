package diagnostic

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeKnownCredentials(t *testing.T) {
	for _, tc := range []struct{ secret, input, context string }{
		{"q", "qqq late hint", "late hint"},
		{"REDACTED", "before [REDACTED] late hint", "late hint"},
		{"a b", "before a\nb late hint", "late hint"},
		{"a+b", "before a%2Bb late hint", "late hint"},
	} {
		out := Normalize(tc.input, tc.secret)
		if strings.Contains(out, tc.secret) || !strings.Contains(out, tc.context) || len(out) > len(tc.input) || strings.ContainsAny(out, "\n\r") {
			t.Fatalf("unsafe diagnostic for secret length %d: length=%d context=%v", len(tc.secret), len(out), strings.Contains(out, tc.context))
		}
	}
}

func TestNormalizeJSONEscapedCredentialAndMarkerBoundaries(t *testing.T) {
	for _, tc := range []struct{ secret, text string }{
		{`sk"example`, `sk\"example near [REDACTED] late hint`},
		{`REDACTED`, `[REDACTED] late hint REDACTED`},
		{`REDACTED`, `REDACTED[REDACTED] late hint [REDACTED]REDACTED`},
		{`[REDACTED]`, `[REDACTED] late hint [REDACTED]`},
		{`~`, `~[REDACTED] late hint [REDACTED]~`},
		{`a b`, `a\nb late hint a b`},
		{`q`, strings.Repeat("q", 1<<20-80) + ` late hint`},
	} {
		quoted, err := json.Marshal(tc.secret)
		if err != nil {
			t.Fatal(err)
		}
		escaped := string(quoted[1 : len(quoted)-1])
		got := Normalize(tc.text, tc.secret)
		if strings.Contains(got, tc.secret) || strings.Contains(got, escaped) || !strings.Contains(got, "late hint") || len(got) > len(tc.text)+32 {
			t.Fatalf("unsafe diagnostic: secret length=%d diagnostic length=%d input length=%d", len(tc.secret), len(got), len(tc.text))
		}
	}
}

func TestNormalizeBidiFormatRune(t *testing.T) {
	got := Normalize("policy\u202elate hint")
	if strings.ContainsRune(got, '\u202e') || !strings.Contains(got, "policy late hint") {
		t.Fatalf("format rune not visibly separated; length=%d", len(got))
	}
}
