package fleetproto

import (
	"strings"
	"testing"
)

func TestDisplayNameUsesVisibleCanonicalSpelling(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		valid       bool
	}{
		{"  north \t lab\n", "north_lab", true},
		{"north\u00a0lab", "north_lab", true},
		{"north_lab", "north_lab", true},
		{"no\u200brth\u202e_\u2066lab", "north_lab", true},
		{"\u200b\u202e\u2066", "", false},
		{"", "", false},
		{" \t\n\u00a0", "", false},
		{"bad\x00name", "bad\x00name", false},
		{strings.Repeat("x", MaxJoinHostnameBytes+1), strings.Repeat("x", MaxJoinHostnameBytes+1), false},
	} {
		if got := NormalizeDisplayName(tc.input); got != tc.want {
			t.Errorf("normalize %q: %q want %q", tc.input, got, tc.want)
		}
		if got := ValidDisplayName(tc.input); got != tc.valid {
			t.Errorf("validate %q: %t want %t", tc.input, got, tc.valid)
		}
	}
}
