package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

// The gateway never selects, reads or stores an administrator rubric: each
// host's root puts that host's snapshot in the first system message. Three
// hosts with colliding job identifiers share one gateway and one upstream; each
// upstream request carries only its own host's instructions, and a host's
// conversation can be continued only with its own prefix.
func TestGatewayCarriesEachHostsSystemInstructionsWithoutCrossTalk(t *testing.T) {
	var mu sync.Mutex
	var firstMessages []modelwire.Message
	service, hostA, turnA, enrollments, _ := sessionFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []modelwire.Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Messages) == 0 {
			t.Errorf("upstream request: %v", err)
		} else {
			mu.Lock()
			firstMessages = append(firstMessages, body.Messages[0])
			mu.Unlock()
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"done"}}]}`))
	}), time.Second, 8)

	enroll := func() AuthenticatedHost {
		t.Helper()
		enrollment, bearer, err := enrollments.Create(context.Background(), EnrollmentPolicy{AllowedProfiles: []string{"local"}, AllowedChannels: []string{"admin"}, DefaultChannel: "admin"})
		if err != nil {
			t.Fatal(err)
		}
		host, err := enrollments.Authenticate(context.Background(), enrollment.HostID, bearer)
		if err != nil {
			t.Fatal(err)
		}
		return host
	}
	hosts := map[string]AuthenticatedHost{"A": hostA, "B": enroll(), "default": enroll()}
	system := map[string]string{
		"A":       reviewer.SystemInstructions(&proto.RiskPolicy{Text: "HOST-A canary\n"}, proto.AccountNote{Text: "GROUP-A canary\n"}, proto.AccountNote{Text: "USER-A canary\n"}),
		"B":       reviewer.SystemInstructions(nil, proto.AccountNote{Text: "GROUP-B canary\n"}, proto.AccountNote{Text: "USER-B canary\n"}),
		"default": reviewer.EmbeddedInstructions,
	}
	user := modelwire.Message{Role: "user", Content: "same job id, same local account name"}
	turnFor := func(name string) fleetproto.ModelTurn {
		turn := turnA // identical job id, attempt, turn and profile on every host
		turn.Binding.HostID = fleetproto.ID(hosts[name].HostID)
		turn.Request.Messages = []modelwire.Message{{Role: "system", Content: system[name]}, user}
		return turn
	}

	// When: colliding job IDs on three authenticated hosts send their own layers.
	for _, name := range []string{"A", "B", "default"} {
		if result := service.modelTurn(context.Background(), hosts[name], turnFor(name), true); result.Response == nil {
			t.Fatalf("host %s first turn: %+v", name, result.Failure)
		}
	}
	// Then: the gateway relays exact system messages and isolates conversations.
	mu.Lock()
	got := append([]modelwire.Message(nil), firstMessages...)
	mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("upstream saw %d requests, want one per host", len(got))
	}
	for i, name := range []string{"A", "B", "default"} {
		if got[i].Role != "system" || got[i].Content != system[name] {
			t.Fatalf("host %s upstream first message role=%q is not that host's instructions", name, got[i].Role)
		}
	}

	// Host B cannot continue A's conversation, nor A continue with B's prefix.
	continued := func(name, prefixOwner string) fleetproto.ModelTurn {
		turn := turnFor(name)
		turn.Binding.Turn = 2
		turn.Request.Messages = append(turnFor(prefixOwner).Request.Messages, modelwire.Message{Role: "assistant", Content: "done"})
		return turn
	}
	for _, tc := range [][2]string{{"B", "A"}, {"A", "B"}, {"default", "A"}} {
		if result := service.modelTurn(context.Background(), hosts[tc[0]], continued(tc[0], tc[1]), true); result.Response != nil {
			t.Fatalf("host %s continued with host %s's conversation", tc[0], tc[1])
		}
	}
	// Each host's own continuation still works and still carries its own prefix.
	for _, name := range []string{"B", "A"} {
		result := service.modelTurn(context.Background(), hosts[name], continued(name, name), true)
		if result.Response == nil {
			t.Fatalf("host %s own continuation: %+v", name, result.Failure)
		}
	}
}
