package fleetproto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/modelwire"
)

func TestModelRetryMetadataIsOptionalBoundAndClosed(t *testing.T) {
	// Given an unchanged v1 baseline, when retry support is opted into, then
	// only a bound availability failure may carry secret-free typed metadata.
	turn := ModelTurn{Version: 1, Kind: KindModelTurn, Binding: TurnBinding{HostID: "host1", JobID: "2026-09-28_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: catalogFixture(t).Profiles[0].Revision, Deadline: 200}, Request: modelwire.ModelRequest{Model: "fixture", MaxOutputTokens: 100, Messages: []modelwire.Message{{Role: "user", Content: "evidence"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "Inspect", Schema: json.RawMessage(`{}`)}}}}
	raw, err := json.Marshal(turn)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "retry") {
		t.Fatal("baseline request gained a required extension")
	}
	if _, err := Parse[ModelTurn](raw); err != nil {
		t.Fatal(err)
	}
	// Optional extensions remain typed/closed; omission still accepts baseline.
	for _, extra := range []string{`,"recover_previous":null}`, `,"recover_previous":"true"}`, `,"recover_previous":true,"recover_previous":true}`} {
		if _, err := Parse[ModelTurn]([]byte(strings.TrimSuffix(string(raw), "}") + extra)); err == nil {
			t.Fatal("malformed recovery extension accepted")
		}
	}
	result := ModelResult{Version: 1, Kind: KindModelResult, Binding: turn.Binding, Failure: &Failure{Code: ErrCodeUpstreamTimeout}, Retry: &modelwire.Retry{AfterMS: 250}}
	if CheckModelResult(result, turn, 100) == nil {
		t.Fatal("unsolicited retry permission accepted")
	}
	turn.RetryTransient = true
	if err := CheckModelResult(result, turn, 100); err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{
		strings.Replace(string(raw), `"after_ms":250`, `"after_ms":-1`, 1),
		strings.Replace(string(raw), `"after_ms":250`, `"after_ms":9223372036854775807`, 1),
		strings.Replace(string(raw), `"after_ms":250`, `"after_ms":250,"url":"secret"`, 1),
		strings.Replace(string(raw), `"after_ms":250`, `"after_ms":250,"after_ms":1`, 1),
		strings.Replace(string(raw), `"after_ms":250`, `"After_ms":250`, 1),
		strings.Replace(string(raw), `"after_ms":250`, `"after_ms":null`, 1),
		strings.Replace(string(raw), `"after_ms":250`, ``, 1),
		strings.Replace(string(raw), `"upstream_timeout"`, `"safety"`, 1),
		strings.Replace(string(raw), `"upstream_timeout"`, `"upstream_invalid_config"`, 1),
	} {
		if _, err := Parse[ModelResult]([]byte(change)); err == nil {
			t.Fatalf("invalid retry accepted: %s", change)
		}
	}
}
