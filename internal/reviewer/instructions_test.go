package reviewer

import (
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

// Test selection and verbatim administrator data, not the wording or internal
// sentence fragments of the built-in prompt. Fixed duties are code-reviewed;
// tool and report boundaries are tested through their executable contracts.
func TestSystemInstructionsWithoutRubricIsTheEmbeddedDefault(t *testing.T) {
	if got := SystemInstructions(nil); got != EmbeddedInstructions {
		t.Fatal("absent rubric changed the embedded default instructions")
	}
}

func TestSystemInstructionsSelectsOnlyTheSuppliedRubric(t *testing.T) {
	// Whitespace, CRLF, tabs and non-ASCII must survive byte for byte.
	rubrics := []string{"  CANARY-7f3a rubric \r\n\ttabbed ✓\n\n", "CANARY-91c0 other", ""}
	seen := map[string]bool{}
	for _, text := range rubrics {
		got := SystemInstructions(&proto.RiskPolicy{Text: text})
		if text != "" && strings.Count(got, text) != 1 {
			t.Fatalf("rubric %q appears %d times, want the exact bytes once", text, strings.Count(got, text))
		}
		if seen[got] || got == EmbeddedInstructions {
			t.Fatalf("rubric %q did not select a distinct instruction set", text)
		}
		seen[got] = true
	}
	for _, other := range rubrics[1:] {
		if strings.Contains(SystemInstructions(&proto.RiskPolicy{Text: rubrics[0]}), other) && other != "" {
			t.Fatalf("rubric %q leaked into another rubric's instructions", other)
		}
	}
}

func TestSystemInstructionsAppendsAccountNotesAfterGuidance(t *testing.T) {
	// Given: ordered administrator payloads, distinct from the host calibration.
	notes := []proto.AccountNote{{Text: "GROUP-A-7f31\n"}, {Text: "GROUP-Z-2ce5\n"}, {Text: "USER-0b96\n"}}
	for _, policy := range []*proto.RiskPolicy{nil, {Text: "HOST-901d\n"}} {
		// When
		got := SystemInstructions(policy, notes...)
		// Then: the base instruction bytes are untouched and payload order is exact.
		base := SystemInstructions(policy)
		if !strings.HasPrefix(got, base) {
			t.Fatal("account notes replaced guidance or fixed instructions")
		}
		position := len(base)
		for _, note := range notes {
			next := strings.Index(got, note.Text)
			if next < position || strings.Count(got, note.Text) != 1 {
				t.Fatal("note payload missing, reordered or rewritten")
			}
			position = next + len(note.Text)
		}
	}
}
