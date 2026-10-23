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
