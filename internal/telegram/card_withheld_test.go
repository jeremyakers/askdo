package telegram

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// The card must disclose withholding; references belong in Details.
const withheldWarning = "Content withheld from AI review"

// The card discloses the count; Details includes every withheld reference.
// Neither surface scores the model's file selections.
func TestCardShowsWithheldCredentialWarning(t *testing.T) {
	in := testCardInput()
	in.WithheldRefs = []string{"/home/u/app/.env", "/home/u/.ssh/id_rsa"}
	in.WithheldCount = 2
	text, _, err := RenderReviewedCard(in, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{withheldWarning, "2 item(s) — see Details"} {
		if !strings.Contains(text, want) {
			t.Errorf("card missing %q", want)
		}
	}

	details, err := RenderDetails(DetailsInput{CardInput: in})
	if err != nil {
		t.Fatal(err)
	}
	joinedDetails := strings.Join(details, "")
	if !strings.Contains(joinedDetails, "/home/u/app/.env") || !strings.Contains(joinedDetails, "/home/u/.ssh/id_rsa") || strings.Contains(joinedDetails, "Coverage detail") {
		t.Fatal("details must disclose withholding without scoring coverage")
	}
}

// Withheld references are model-influenced path text: HTML and control
// characters must be escaped/quoted so no reference can inject tags, fake
// headings, or bidi tricks into the operator card.
func TestWithheldWarningEscapesMaliciousRefs(t *testing.T) {
	in := testCardInput()
	in.WithheldRefs = []string{`/etc/<b>injected</b>&"x"`, "/etc/passwd\r\n<b>Privilege", "/etc/‮fake"}
	in.WithheldCount = 3
	parts, err := RenderDetails(DetailsInput{CardInput: in})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(parts, "")
	for _, forbidden := range []string{"<b>injected</b>", "\r\n<b>Privilege", "‮"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("summary contains unescaped injection %q", forbidden)
		}
	}
	for _, want := range []string{"&lt;b&gt;injected&lt;/b&gt;", "&lt;b&gt;Privilege"} {
		if !strings.Contains(joined, want) {
			t.Errorf("summary missing escaped reference %q", want)
		}
	}
}

// Many withheld references expand only in bounded, balanced Details messages.
func TestWithheldFactsSurviveDetailsChunking(t *testing.T) {
	in := testCardInput()
	refs := make([]string, 0, 16)
	for i := 0; i < 16; i++ {
		ref := fmt.Sprintf("/home/u/.config/service-%02d/<&>token-%s", i, strings.Repeat("y", 210))
		refs = append(refs, ref)
	}
	in.WithheldRefs = refs
	in.WithheldCount = 48
	parts, err := RenderDetails(DetailsInput{CardInput: in})
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) < 2 {
		t.Fatalf("expected chunking with 16 bounded refs, got %d part(s)", len(parts))
	}
	for i, part := range parts {
		if n := utf8.RuneCountInString(part); n > MaxMessageRunes {
			t.Fatalf("part %d has %d runes, exceeds %d", i, n, MaxMessageRunes)
		}
		if err := assertBalancedTags(part); err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
	}
	joined := strings.Join(parts, "")
	if !strings.Contains(joined, "Credential content withheld: 48") {
		t.Fatal("withheld count lost during chunking")
	}
	for _, ref := range []string{refs[0], refs[len(refs)-1]} {
		if !strings.Contains(joined, esc(ref)) {
			t.Errorf("chunked summary dropped reference %q", ref)
		}
	}
	if strings.Contains(joined, "<&>") {
		t.Fatal("unescaped reference survived chunking")
	}
}

// Refs beyond the proto coverage bound (1024 bytes) fail closed instead of
// rendering unbounded model-influenced text.
func TestWithheldRefBeyondProtoBoundRejected(t *testing.T) {
	in := testCardInput()
	in.WithheldRefs = []string{strings.Repeat("a", 1025)}
	in.WithheldCount = 1
	if _, err := RenderSummaryParts(in); err == nil {
		t.Fatal("oversized withheld ref rendered in summary")
	}
	if _, err := RenderDetails(DetailsInput{CardInput: in}); err == nil {
		t.Fatal("oversized withheld ref rendered in details")
	}
}
