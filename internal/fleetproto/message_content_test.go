package fleetproto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/modelwire"
)

// ValidMessageContent names the model-message contract Parse already enforces,
// so root can reject an unusable system prompt before a review starts instead
// of failing its first model turn with a generic protocol error.
func TestValidMessageContentMatchesWhatModelTurnParsingAccepts(t *testing.T) {
	for name, content := range map[string]string{
		"newline and tab":     "line\n\tindented",
		"carriage return":     "line\r\nline",
		"control character":   "escape \x1b[0m",
		"exactly at the cap":  strings.Repeat("a", MaxMessageContentBytes),
		"one byte over":       strings.Repeat("a", MaxMessageContentBytes+1),
		"multibyte at limit":  strings.Repeat("é", MaxMessageContentBytes/2),
		"multibyte over":      strings.Repeat("é", MaxMessageContentBytes/2+1),
		"non-ASCII and emoji": "日本語 ✓ 🙂",
	} {
		t.Run(name, func(t *testing.T) {
			turn := ModelTurn{Version: 1, Kind: KindModelTurn, Binding: TurnBinding{HostID: "host1", JobID: "2026-09-28_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: catalogFixture(t).Profiles[0].Revision, Deadline: 200}, Request: modelwire.ModelRequest{Model: "fixture", MaxOutputTokens: 100, Messages: []modelwire.Message{{Role: "system", Content: content}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "Inspect", Schema: json.RawMessage(`{}`)}}}}
			wire, err := json.Marshal(turn)
			if err != nil {
				t.Fatal(err)
			}
			_, parseErr := Parse[ModelTurn](wire)
			if accepted := ValidMessageContent(content); accepted != (parseErr == nil) {
				t.Fatalf("ValidMessageContent=%t but Parse err=%v", accepted, parseErr)
			}
		})
	}
}
