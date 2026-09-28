package jobid

import (
	"math"
	"testing"
)

func TestValidate(t *testing.T) {
	for _, id := range []string{"2026-09-27_#1", "2024-02-29_#9223372036854775807", "0001-01-01_#2"} {
		if err := Validate(id); err != nil {
			t.Errorf("Validate(%q): %v", id, err)
		}
	}
	for _, id := range []string{
		"", "0123456789abcdef0123456789abcdef", "2026-02-29_#1", "2024-04-31_#1",
		"0000-01-01_#1", "2026-13-01_#1", "2026-9-27_#1", "2026-09-27_#0",
		"2026-09-27_#01", "2026-09-27_#-1", "2026-09-27_#+1", "2026-09-27_#1.0",
		"2026-09-27_#9223372036854775808", "2026-09-27_#１", "2026-09-27_#1\n",
	} {
		if err := Validate(id); err == nil {
			t.Errorf("Validate(%q) accepted invalid ID", id)
		}
	}
}

func TestFormat(t *testing.T) {
	for _, tc := range []struct {
		day      string
		sequence int64
		want     string
	}{
		{"2026-09-27", 1, "2026-09-27_#1"},
		{"2024-02-29", math.MaxInt64, "2024-02-29_#9223372036854775807"},
	} {
		got, err := Format(tc.day, tc.sequence)
		if err != nil || got != tc.want {
			t.Errorf("Format(%q, %d) = %q, %v; want %q", tc.day, tc.sequence, got, err, tc.want)
		}
	}
	for _, tc := range []struct {
		day      string
		sequence int64
	}{
		{"2026-02-29", 1}, {"2026-09-27", 0}, {"2026-09-27", -1}, {"0000-01-01", 1}, {"2026-09-27_#1", 2},
	} {
		if id, err := Format(tc.day, tc.sequence); err == nil {
			t.Errorf("Format(%q, %d) accepted invalid input: %q", tc.day, tc.sequence, id)
		}
	}
}
