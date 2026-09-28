package telegram

import (
	"strings"
	"testing"
)

func TestReviewedSummarySourceContract(t *testing.T) {
	in := testCardInput()
	in.WithheldRefs = []string{"bundle:<secret>&.env"}
	in.WithheldCount = 2
	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(parts, "")
	for _, expected := range []string{"<b>Review summary</b>", "Credential content withheld from AI review: 2", "bundle:&lt;secret&gt;&amp;.env"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in %s", expected, text)
		}
	}
	for _, unwanted := range []string{"LLM-selected review: completeness not mechanically checked", "INCOMPLETE REVIEW", "Coverage detail", "<b>Coverage:", "review_issues", "<secret>"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("unexpected %q in %s", unwanted, text)
		}
	}
	details, err := RenderDetails(DetailsInput{CardInput: in})
	if err != nil || strings.Contains(strings.Join(details, ""), "Coverage detail") {
		t.Fatalf("details=%v err=%v", details, err)
	}
}
