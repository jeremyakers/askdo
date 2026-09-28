// Package diagnostic normalizes bounded failure text and masks known credentials.
package diagnostic

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

// Normalize keeps failure context on one line without expanding a bounded input.
// secrets are values known to the caller, not guesses about arbitrary upstream text.
// Literal, form-encoded and JSON string-escaped representations are masked
// after normalization, so controls cannot join into a credential in the result.
func Normalize(text string, secrets ...string) string {
	normal := func(s string) string {
		return strings.Map(func(r rune) rune {
			if unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
				return ' '
			}
			return r
		}, strings.ToValidUTF8(s, "?"))
	}
	text = normal(text)
	var variants []string
	for _, secret := range secrets {
		if secret != "" {
			variants = append(variants, normal(secret), normal(url.QueryEscape(secret)))
			// Only the inner escaped value is a diagnostic variant: the
			// surrounding JSON quotes belong to the response, not the key.
			quoted, _ := json.Marshal(secret)
			variants = append(variants, normal(string(quoted[1:len(quoted)-1])))
		}
	}
	sort.Slice(variants, func(i, j int) bool { return len(variants[i]) > len(variants[j]) })
	longMarker := "[REDACTED]"
	for _, secret := range variants {
		if secret != "" && strings.Contains(longMarker, secret) {
			longMarker = ""
			break
		}
	}
	// A single-byte marker keeps short-secret replacement non-expanding.
	// It must not itself be one of the known one-byte credentials.
	shortMarker := ""
	for _, candidate := range []string{"~", "^", "#", "!", "?", "_"} {
		ok := true
		for _, secret := range variants {
			if secret == candidate {
				ok = false
			}
		}
		if ok {
			shortMarker = candidate
			break
		}
	}
	if shortMarker == "" {
		return "(response redacted)"
	}
	mask := func(secret string) string {
		if longMarker != "" && len(secret) >= len(longMarker) {
			return longMarker
		}
		return shortMarker
	}
	for _, secret := range variants {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, mask(secret))
		}
	}
	// A replacement adjacent to unrelated text can create another match.
	// For multi-byte matches each pass decreases length; a one-byte match
	// cannot be recreated by the selected marker itself.
	for {
		changed := false
		for _, secret := range variants {
			if secret != "" && strings.Contains(text, secret) {
				if secret == mask(secret) {
					return "(response redacted)"
				}
				text = strings.ReplaceAll(text, secret, mask(secret))
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return strings.TrimSpace(text)
}
