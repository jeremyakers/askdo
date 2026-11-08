package fleetproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/modelwire"
)

// A newer gateway may add an optional field to anything it signs, and a host
// built before that field existed must still verify and read the message. The
// helpers here add a member that no current type defines, the way a later
// release would, to one object at a time so that every depth is covered.

// signRaw signs payload exactly as given: bytes this build might not produce.
func signRaw(t *testing.T, key ed25519.PrivateKey, payload []byte) []byte {
	t.Helper()
	wire, err := json.Marshal(Envelope{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(SigningDomain), payload...))),
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// opaque names the members whose value is data the protocol carries untouched
// (a tool schema, a model's tool-call arguments), not a typed object.
var opaque = map[string]bool{"parameters": true, "arguments": true}

// extendEachObject calls check once for every typed JSON object in payload,
// with a copy in which only that object carries an additive member.
func extendEachObject(t *testing.T, payload []byte, check func(t *testing.T, extended []byte)) {
	t.Helper()
	decode := func() any {
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.UseNumber()
		var document any
		if err := decoder.Decode(&document); err != nil {
			t.Fatal(err)
		}
		return document
	}
	var paths []string
	var walk func(path string, node any, visit func(path string, object map[string]any))
	walk = func(path string, node any, visit func(string, map[string]any)) {
		switch value := node.(type) {
		case map[string]any:
			visit(path, value)
			for key, child := range value {
				if !opaque[key] {
					walk(path+"."+key, child, visit)
				}
			}
		case []any:
			for i, child := range value {
				walk(fmt.Sprintf("%s[%d]", path, i), child, visit)
			}
		}
	}
	walk("$", decode(), func(path string, _ map[string]any) { paths = append(paths, path) })
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("payload has no JSON object")
	}
	for _, target := range paths {
		document := decode()
		walk("$", document, func(path string, object map[string]any) {
			if path == target {
				object["future_field"] = map[string]any{"added_by": "a newer gateway", "values": []any{1, 2}}
			}
		})
		extended, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(target, func(t *testing.T) { check(t, extended) })
	}
}

// reportIgnoresAdditiveFields signs the report with an additive member added at
// each depth in turn. The host verifies the exact signed bytes, reads the same
// value as without the member, and keeps neither the member nor its text.
func reportIgnoresAdditiveFields[T Payload](t *testing.T, name string, value T) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		extendEachObject(t, payload, func(t *testing.T, extended []byte) {
			got, exact, err := Verify[T](public, signRaw(t, private, extended))
			if err != nil {
				t.Fatalf("report with an additive field rejected: %v", err)
			}
			if !bytes.Equal(exact, extended) {
				t.Fatal("verified payload is not the exact signed bytes")
			}
			if !reflect.DeepEqual(got, value) {
				t.Fatalf("decoded %+v, want %+v", got, value)
			}
			if encoded, err := json.Marshal(got); err != nil || strings.Contains(string(encoded), "future_field") || strings.Contains(string(encoded), "newer gateway") {
				t.Fatalf("unknown field kept: %s, %v", encoded, err)
			}
		})
	})
}

func TestSignedReportsIgnoreAdditiveFieldsAtEveryDepth(t *testing.T) {
	ticket, receipt, decision := fixture(t)
	turn := ModelTurn{Version: Version, Kind: KindModelTurn, Binding: TurnBinding{HostID: "host1", JobID: "2026-09-28_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: catalogFixture(t).Profiles[0].Revision, Deadline: 200}, Request: modelwire.ModelRequest{Model: "fixture", MaxOutputTokens: 100, Messages: []modelwire.Message{{Role: "user", Content: "evidence"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "Inspect", Schema: json.RawMessage(`{"type":"object"}`)}}}}
	reportIgnoresAdditiveFields(t, "catalog", catalogFixture(t))
	reportIgnoresAdditiveFields(t, "ticket", ticket)
	reportIgnoresAdditiveFields(t, "receipt", receipt)
	reportIgnoresAdditiveFields(t, "decision", decision)
	reportIgnoresAdditiveFields(t, "ticket ack", TicketAck{Version: Version, Kind: KindTicketAck, Binding: ticket.Binding, SubmissionHash: Hash(strings.Repeat("a", 64)), State: TicketPending})
	reportIgnoresAdditiveFields(t, "receipt event", Event{Version: Version, Kind: KindEvent, HostID: "host1", JobID: "2026-09-28_#1", Sequence: 1, Type: EventReceipt, Receipt: &receipt})
	reportIgnoresAdditiveFields(t, "decision event", Event{Version: Version, Kind: KindEvent, HostID: "host1", JobID: "2026-09-28_#1", Sequence: 2, Type: EventDecision, Decision: &decision})
	reportIgnoresAdditiveFields(t, "failure event", Event{Version: Version, Kind: KindEvent, HostID: "host1", JobID: "2026-09-28_#1", Sequence: 3, Type: EventFailed, Failure: &Failure{Code: ErrCodeDelivery}})
	reportIgnoresAdditiveFields(t, "model response", ModelResult{Version: Version, Kind: KindModelResult, Binding: turn.Binding, Response: &modelwire.ModelResponse{ToolCalls: []modelwire.ToolCall{{ID: "call1", Name: "inspect", Arguments: json.RawMessage(`{"path":"/tmp"}`)}}}})
	reportIgnoresAdditiveFields(t, "model failure with retry", ModelResult{Version: Version, Kind: KindModelResult, Binding: turn.Binding, Failure: &Failure{Code: ErrCodeUpstreamTimeout}, Retry: &modelwire.Retry{AfterMS: 250}})
}

// The incident this guards against: a gateway newer than a host added an
// optional field to its signed catalog and the older host refused the catalog.
// The signature must keep covering the part the host does not understand.
func TestOlderHostReadsSignedCatalogAndStillVerifiesItsSignature(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want := catalogFixture(t)
	payload, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	extended := append(append([]byte{}, payload[:len(payload)-1]...), []byte(`,"future_policy":{"mode":"strict"}}`)...)
	wire := signRaw(t, private, extended)

	got, exact, err := Verify[Catalog](public, wire)
	if err != nil {
		t.Fatalf("catalog with an additive field rejected: %v", err)
	}
	if !reflect.DeepEqual(got, want) || !bytes.Equal(exact, extended) {
		t.Fatal("catalog changed by the additive field")
	}
	if err := CheckCatalog(got, want, 100); err != nil {
		t.Fatalf("frozen comparison: %v", err)
	}

	// A different key still fails, and so does changing only the bytes the host
	// does not understand: the signature covers them.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := Verify[Catalog](other, wire); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	var envelope Envelope
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Payload = base64.StdEncoding.EncodeToString(bytes.Replace(extended, []byte(`"strict"`), []byte(`"lax"`), 1))
	tampered, _ := json.Marshal(envelope)
	if _, _, err := Verify[Catalog](public, tampered); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered additive field: %v", err)
	}

	// An additive field excuses nothing else: a missing required field or a
	// wrong value in a field the host does define still fails.
	for name, mutate := range map[string]func(string) string{
		"missing required field": func(s string) string { return strings.Replace(s, `"host_id":"host1",`, ``, 1) },
		"wrong value type":       func(s string) string { return strings.Replace(s, `"expires_at":200`, `"expires_at":"soon"`, 1) },
		"wrong version":          func(s string) string { return strings.Replace(s, `"version":1`, `"version":2`, 1) },
	} {
		broken := mutate(string(extended))
		if broken == string(extended) {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, _, err := Verify[Catalog](public, signRaw(t, private, []byte(broken))); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	// Duplicate keys remain refused, including a duplicated additive key.
	duplicated := append(append([]byte{}, payload[:len(payload)-1]...), []byte(`,"future_policy":1,"future_policy":2}`)...)
	if _, _, err := Verify[Catalog](public, signRaw(t, private, duplicated)); err == nil {
		t.Fatal("duplicate additive key accepted")
	}
}

// The envelope only carries the payload and its signature, which covers the
// payload alone. A member a newer gateway adds beside them is not signed and is
// ignored; the signature itself is still required and still checked.
func TestEnvelopeIgnoresAdditiveFields(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want := catalogFixture(t)
	wire, err := Sign(private, want)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["key_id"] = "k2"
	extended, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := Verify[Catalog](public, extended)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("envelope with an additive member: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := Verify[Catalog](other, extended); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	delete(envelope, "signature")
	unsigned, _ := json.Marshal(envelope)
	if _, _, err := Verify[Catalog](public, unsigned); err == nil {
		t.Fatal("unsigned envelope accepted")
	}
}

// Ignoring a field a reader does not know does not extend to a key that is only
// a differently cased spelling of one it does: the decoder would read that as
// the field, and a payload must spell each field one way.
func TestReportsStillRefuseCaseAliasedFields(t *testing.T) {
	payload, err := json.Marshal(catalogFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		suffix string
		ok     bool
	}{
		"unknown field":                    {`,"future":1}`, true},
		"optional field, exact spelling":   {`,"reviewer_webfetch_enabled":true}`, true},
		"optional field, aliased spelling": {`,"Reviewer_Webfetch_Enabled":true}`, false},
		"required field, second spelling":  {`,"Version":2}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			raw := append(append([]byte{}, payload[:len(payload)-1]...), tc.suffix...)
			if _, err := Parse[Catalog](raw); (err == nil) != tc.ok {
				t.Fatalf("ok=%v err=%v", tc.ok, err)
			}
		})
	}
}

// requestRefusesAdditiveFields shows the opposite for what a host asks the
// gateway to do: a field the gateway does not define is refused at any depth
// rather than silently dropped from the request.
func requestRefusesAdditiveFields[T Payload](t *testing.T, name string, value T) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse[T](payload); err != nil {
			t.Fatalf("baseline request rejected: %v", err)
		}
		extendEachObject(t, payload, func(t *testing.T, extended []byte) {
			if _, err := Parse[T](extended); !errors.Is(err, ErrProtocol) {
				t.Fatalf("request with an unknown field accepted: %v", err)
			}
		})
	})
}

func TestHostRequestsRefuseAdditiveFieldsAtEveryDepth(t *testing.T) {
	ticket, _, _ := fixture(t)
	profiles := []ProfileMetadata{catalogFixture(t).Profiles[0]}
	route := RouteSnapshot{Version: Version, Kind: KindRoute, ChannelID: "admin", BotID: 9, TTLSeconds: 100, Recipients: []Recipient{{ChatID: 1, OperatorUserIDs: []int64{2}}}}
	var err error
	if route.Revision, err = HashRoute(route); err != nil {
		t.Fatal(err)
	}
	if ticket.Binding.ProfileHash, err = HashProfiles(profiles); err != nil {
		t.Fatal(err)
	}
	ticket.Binding.RouteHash = route.Revision
	requestRefusesAdditiveFields(t, "ticket submission", TicketSubmission{Version: Version, Kind: KindTicketSubmission, Ticket: ticket, Profiles: profiles, Route: route})
	requestRefusesAdditiveFields(t, "model turn", ModelTurn{Version: Version, Kind: KindModelTurn, Binding: TurnBinding{HostID: "host1", JobID: "2026-09-28_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: profiles[0].Revision, Deadline: 200}, Request: modelwire.ModelRequest{Model: "fixture", MaxOutputTokens: 100, Messages: []modelwire.Message{{Role: "user", Content: "evidence"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "Inspect", Schema: json.RawMessage(`{"type":"object"}`)}}}})

	request, err := MarshalJoinRequest(JoinRequest{Version: JoinVersion, HostID: ID("host_" + strings.Repeat("ab", 32)), BearerHash: Hash(strings.Repeat("cd", 32)), JoinHash: Hash(strings.Repeat("ef", 32)), Commit: Hash(strings.Repeat("12", 32)), Hostname: "lauren-laptop"})
	if err != nil {
		t.Fatal(err)
	}
	reveal, err := MarshalJoinReveal(JoinReveal{Version: JoinVersion, HostNonce: Hash(strings.Repeat("34", 32))})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		payload []byte
		parse   func([]byte) error
	}{
		"join request": {request, func(data []byte) error { _, err := ParseJoinRequest(data); return err }},
		"join reveal":  {reveal, func(data []byte) error { _, err := ParseJoinReveal(data); return err }},
	} {
		t.Run(name, func(t *testing.T) {
			if err := tc.parse(tc.payload); err != nil {
				t.Fatalf("baseline rejected: %v", err)
			}
			extendEachObject(t, tc.payload, func(t *testing.T, extended []byte) {
				if err := tc.parse(extended); !errors.Is(err, ErrProtocol) {
					t.Fatalf("join request with an unknown field accepted: %v", err)
				}
			})
		})
	}
}

// The standard decoder matches field names case-insensitively, so the typed
// shape pass is what holds a request to the exact spelling of the fields it
// defines: a differently cased optional field is not silently read as the
// field it resembles.
func TestRequestsRefuseCaseAliasedOptionalFields(t *testing.T) {
	turn := ModelTurn{Version: Version, Kind: KindModelTurn, Binding: TurnBinding{HostID: "host1", JobID: "2026-09-28_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: catalogFixture(t).Profiles[0].Revision, Deadline: 200}, Request: modelwire.ModelRequest{Model: "fixture", MaxOutputTokens: 100, Messages: []modelwire.Message{{Role: "user", Content: "evidence"}}, Tools: []modelwire.ToolDefinition{{Name: "inspect", Description: "Inspect", Schema: json.RawMessage(`{"type":"object"}`)}}}, RetryTransient: true}
	payload, err := json.Marshal(turn)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Parse[ModelTurn](payload); err != nil || !got.RetryTransient {
		t.Fatalf("baseline: %+v, %v", got, err)
	}
	aliased := bytes.Replace(payload, []byte(`"retry_transient":true`), []byte(`"Retry_Transient":true`), 1)
	if bytes.Equal(aliased, payload) {
		t.Fatalf("test needs updating, retry_transient not found: %s", payload)
	}
	if _, err := Parse[ModelTurn](aliased); !errors.Is(err, ErrProtocol) {
		t.Fatalf("case-aliased optional request field accepted: %v", err)
	}
}

// The gateway's answer to a join is a report like any other signed or unsigned
// answer: an additive field in it must not stop an older host from joining.
func TestJoinResponseIgnoresAdditiveFields(t *testing.T) {
	want, err := ParseJoinResponse(approvedJoinResponseJSON())
	if err != nil {
		t.Fatal(err)
	}
	extendEachObject(t, approvedJoinResponseJSON(), func(t *testing.T, extended []byte) {
		got, err := ParseJoinResponse(extended)
		if err != nil {
			t.Fatalf("join response with an additive field rejected: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})
}
