package fleetproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/modelwire"
)

func catalogFixture(t *testing.T) Catalog {
	t.Helper()
	p := ProfileMetadata{Version: Version, Kind: KindProfile, ProfileID: "local", Upstreams: []Upstream{{API: OpenAIChat, BaseURL: "http://localhost:11434/v1", Model: "fixture", DataBoundary: Local, RequestTimeoutSeconds: 60, MaxOutputTokens: 1000}}}
	var err error
	p.Revision, err = HashProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	r := RouteSnapshot{Version: Version, Kind: KindRoute, ChannelID: "ops", BotID: 9, TTLSeconds: 100, Recipients: []Recipient{{ChatID: -123, OperatorUserIDs: []int64{42}}, {ChatID: -124, OperatorUserIDs: []int64{43}}}}
	r.Revision, err = HashRoute(r)
	if err != nil {
		t.Fatal(err)
	}
	return Catalog{Version: Version, Kind: KindCatalog, HostID: "host1", SubmitterUID: 0, Profiles: []ProfileMetadata{p}, Route: r, ExpiresAt: 200}
}

func TestCatalogSignedSerializationAndFrozenComparison(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	want := catalogFixture(t)
	wire, err := Sign(private, want)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := Verify[Catalog](public, wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCatalog(got, want, 100); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("catalog serialization changed facts")
	}
	for _, field := range []string{"API", "BaseURL", "Model", "DataBoundary", "RequestTimeoutSeconds", "MaxOutputTokens"} {
		t.Run(field, func(t *testing.T) {
			bad := want.Profiles[0]
			bad.Upstreams = append([]Upstream(nil), bad.Upstreams...)
			v := reflect.ValueOf(&bad.Upstreams[0]).Elem().FieldByName(field)
			switch field {
			case "API":
				v.SetString(string(OpenAIResponses))
			case "BaseURL":
				v.SetString("https://upstream.invalid/v1")
			case "DataBoundary":
				v.SetString(string(External))
			case "Model":
				v.SetString("other")
			default:
				v.SetInt(v.Int() + 1)
			}
			h, err := HashProfile(bad)
			if err != nil {
				t.Fatal(err)
			}
			if h == want.Profiles[0].Revision {
				t.Fatal("metadata change not hashed")
			}
			if Validate(bad) == nil {
				t.Fatal("stale revision accepted")
			}
			bad.Revision = h
			changed := want
			changed.Profiles = []ProfileMetadata{bad}
			if err := CheckCatalog(changed, want, 100); !errors.Is(err, ErrBinding) {
				t.Fatalf("root subset: %v", err)
			}
		})
	}
	for _, field := range []string{"ChannelID", "BotID", "TTLSeconds", "ChatID", "OperatorUserIDs"} {
		t.Run(field, func(t *testing.T) {
			r := want.Route
			r.Recipients = append([]Recipient(nil), r.Recipients...)
			switch field {
			case "ChannelID":
				r.ChannelID = "other"
			case "BotID":
				r.BotID++
			case "TTLSeconds":
				r.TTLSeconds++
			case "ChatID":
				r.Recipients[0].ChatID = -999
			case "OperatorUserIDs":
				r.Recipients[0].OperatorUserIDs = []int64{44}
			}
			h, err := HashRoute(r)
			if err != nil {
				t.Fatal(err)
			}
			if h == want.Route.Revision {
				t.Fatal("route change not hashed")
			}
			if Validate(r) == nil {
				t.Fatal("stale revision accepted")
			}
			r.Revision = h
			changed := want
			changed.Route = r
			if err := CheckCatalog(changed, want, 100); !errors.Is(err, ErrBinding) {
				t.Fatalf("root subset: %v", err)
			}
		})
	}
	for _, change := range []func(*Catalog){func(c *Catalog) { c.HostID = "host2" }, func(c *Catalog) { c.SubmitterUID = 1 }, func(c *Catalog) { c.ExpiresAt++ }} {
		bad := want
		change(&bad)
		if CheckCatalog(bad, want, 100) == nil {
			t.Fatal("root identity/expiry changed")
		}
	}
	empty := want
	empty.Profiles = []ProfileMetadata{}
	if _, err := Sign(private, empty); err != nil {
		t.Fatalf("human-only catalog: %v", err)
	}
	if _, err := HashProfiles([]ProfileMetadata{}); err != nil {
		t.Fatal(err)
	}
	if CheckCatalog(want, want, 200) == nil {
		t.Fatal("expired catalog")
	}
}

func TestMetadataRejectsCredentialsVariantsAndBounds(t *testing.T) {
	c := catalogFixture(t)
	for _, u := range []Upstream{{API: "unknown", BaseURL: "https://x.invalid", Model: "m", DataBoundary: Local, RequestTimeoutSeconds: 1, MaxOutputTokens: 1}, {API: OpenAICodex, BaseURL: "https://x.invalid", Model: "m", DataBoundary: Local, RequestTimeoutSeconds: 1, MaxOutputTokens: 1}} {
		p := c.Profiles[0]
		p.Upstreams = []Upstream{u}
		if _, err := HashProfile(p); err == nil {
			t.Fatal("invalid API/boundary")
		}
	}
	for _, base := range []string{"ftp://x.invalid", "https://secret@x.invalid", "https://x.invalid?token=secret", "https://x.invalid#secret", "/relative"} {
		p := c.Profiles[0]
		p.Upstreams = append([]Upstream(nil), p.Upstreams...)
		p.Upstreams[0].BaseURL = base
		if _, err := HashProfile(p); err == nil {
			t.Fatalf("credential/invalid URL %s", base)
		}
	}
	for _, s := range []string{"", "../host", " host", "host/other", strings.Repeat("x", 129)} {
		if _, err := ParseID(s); err == nil {
			t.Fatal("invalid ID accepted")
		}
	}
	for _, s := range []string{"", strings.Repeat("A", 64), strings.Repeat("z", 64), strings.Repeat("a", 63)} {
		if _, err := ParseHash(s); err == nil {
			t.Fatal("invalid hash accepted")
		}
	}
	route := c.Route
	route.Recipients = append(route.Recipients, route.Recipients[0])
	if _, err := HashRoute(route); err == nil {
		t.Fatal("duplicate chat")
	}
}

func TestEverySignedBindingTamperAndResignedFrozenMismatch(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	ticket, receipt, _ := fixture(t)
	route := catalogFixture(t).Route
	route.Recipients = route.Recipients[:1]
	route.Revision, _ = HashRoute(route)
	ticket.Binding.RouteHash = route.Revision
	receipt.Binding = ticket.Binding
	wire, err := Sign(private, receipt)
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.Unmarshal(wire, &env); err != nil {
		t.Fatal(err)
	}
	fields := []string{"HostID", "JobID", "Nonce", "TicketKind", "ManifestDigest", "ProfileHash", "RouteHash", "DisplayHash", "ExpiresAt"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			bad := receipt
			v := reflect.ValueOf(&bad.Binding).Elem().FieldByName(field)
			switch field {
			case "ExpiresAt":
				v.SetInt(201)
			case "TicketKind":
				v.SetString(string(HumanUnreviewed))
			case "Nonce":
				v.SetString(strings.Repeat("c", 32))
			case "JobID":
				v.SetString("2026-09-28_#2")
			case "HostID":
				v.SetString("other")
			default:
				v.SetString(strings.Repeat("c", 64))
			}
			payload, _ := json.Marshal(bad)
			tampered := env
			tampered.Payload = base64.StdEncoding.EncodeToString(payload)
			badwire, _ := json.Marshal(tampered)
			if _, _, err := Verify[Receipt](public, badwire); !errors.Is(err, ErrSignature) {
				t.Fatalf("tamper not caught: %v", err)
			}
			resigned, err := Sign(private, bad)
			if err != nil {
				t.Fatal(err)
			}
			proof, _, err := Verify[Receipt](public, resigned)
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckReceipt(proof, ticket, route, 150); !errors.Is(err, ErrBinding) {
				t.Fatalf("resigned wrong binding: %v", err)
			}
		})
	}
}

func TestReceiptAllRecipientsAndChatScopedOperators(t *testing.T) {
	c := catalogFixture(t)
	ticket, receipt, decision := fixture(t)
	ticket.Binding.RouteHash = c.Route.Revision
	receipt.Binding = ticket.Binding
	receipt.Deliveries = append(receipt.Deliveries, Delivery{Recipient: c.Route.Recipients[1], SummaryMessageIDs: []int64{11}, CardMessageID: 12})
	decision.Binding = ticket.Binding
	decision.ReceiptHash, _ = HashReceipt(receipt)
	if err := CheckDecision(decision, receipt, ticket, c.Route, 150); err != nil {
		t.Fatal(err)
	}
	bad := decision
	bad.OperatorID = 43
	if CheckDecision(bad, receipt, ticket, c.Route, 150) == nil {
		t.Fatal("operator authorized in different chat")
	}
	bad.ChatID = -124
	if err := CheckDecision(bad, receipt, ticket, c.Route, 150); err != nil {
		t.Fatal(err)
	}
	partial := receipt
	partial.Deliveries = partial.Deliveries[:1]
	if CheckReceipt(partial, ticket, c.Route, 150) == nil {
		t.Fatal("partial recipient set")
	}
	substituted := receipt
	substituted.Deliveries = append([]Delivery(nil), receipt.Deliveries...)
	substituted.Deliveries[0].Recipient.OperatorUserIDs = []int64{43}
	if CheckReceipt(substituted, ticket, c.Route, 150) == nil {
		t.Fatal("recipient operator substitution")
	}
	changedDisplay := ticket
	changedDisplay.Display.Operation = "different operation"
	changedDisplay.Binding.DisplayHash, _ = HashDisplay(changedDisplay.Display)
	if CheckReceipt(receipt, changedDisplay, c.Route, 150) == nil {
		t.Fatal("self-supplied display accepted")
	}
	notice := ticket
	notice.Binding.TicketKind = AutoNotice
	receipt.Binding = notice.Binding
	if Validate(receipt) == nil {
		t.Fatal("card accepted as auto notice")
	}
	for i := range receipt.Deliveries {
		receipt.Deliveries[i].CardMessageID = 0
		receipt.Deliveries[i].NoticeMessageID = 12
	}
	if err := CheckReceipt(receipt, notice, c.Route, 150); err != nil {
		t.Fatal(err)
	}
	decision.Binding = notice.Binding
	if Validate(decision) == nil {
		t.Fatal("auto notice has human decision")
	}
}

func TestVariantsAndModelRoundTrip(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	ticket, receipt, decision := fixture(t)
	for _, kind := range []TicketKind{HumanReviewed, HumanUnreviewed, AutoNotice} {
		want := ticket
		want.Binding.TicketKind = kind
		if kind == HumanUnreviewed {
			want.Display.Report = nil
			want.Display.UnreviewedReason = "local manual-review policy"
			want.Display.ModelHistory = []ModelHistoryEntry{}
			want.Binding.DisplayHash, _ = HashDisplay(want.Display)
		}
		wire, err := Sign(private, want)
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := Verify[Ticket](public, wire)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("kind %s: %v", kind, err)
		}
	}
	unreviewed := ticket
	unreviewed.Binding.TicketKind = HumanUnreviewed
	if Validate(unreviewed) == nil {
		t.Fatal("unreviewed report union")
	}
	for _, event := range []Event{{Version: Version, Kind: KindEvent, HostID: "host1", JobID: "2026-09-28_#1", Sequence: 1, Type: EventReceipt, Receipt: &receipt}, {Version: Version, Kind: KindEvent, HostID: "host1", JobID: "2026-09-28_#1", Sequence: 2, Type: EventDecision, Decision: &decision}, {Version: Version, Kind: KindEvent, HostID: "host1", JobID: "2026-09-28_#1", Sequence: 3, Type: EventFailed, Failure: &Failure{Code: ErrCodeDelivery}}} {
		wire, err := Sign(private, event)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Verify[Event](public, wire); err != nil {
			t.Fatal(err)
		}
		event.Receipt = &receipt
		event.Decision = &decision
		if Validate(event) == nil {
			t.Fatal("invalid event union")
		}
	}
	turn := ModelTurn{Version: Version, Kind: KindModelTurn, Binding: TurnBinding{HostID: "host1", JobID: "2026-09-28_#1", Attempt: 1, Turn: 1, ProfileID: "local", ProfileRevision: catalogFixture(t).Profiles[0].Revision, UpstreamIndex: 0, Deadline: 200}, Request: modelwire.ModelRequest{Model: "fixture", MaxOutputTokens: 100, Messages: []modelwire.Message{{Role: "user", Content: "review"}}, Tools: []modelwire.ToolDefinition{{Name: "submit_review", Description: "Submit", Schema: json.RawMessage(`{"type":"object"}`)}}}}
	wire, err := Sign(private, turn)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := Verify[ModelTurn](public, wire)
	if err != nil || !reflect.DeepEqual(got, turn) {
		t.Fatalf("model wire: %v", err)
	}
	response := modelwire.ModelResponse{ToolCalls: []modelwire.ToolCall{{ID: "call1", Name: "submit_review", Arguments: json.RawMessage(`{"risk":"1"}`)}}}
	result := ModelResult{Version: Version, Kind: KindModelResult, Binding: turn.Binding, Response: &response}
	wire, err = Sign(private, result)
	if err != nil {
		t.Fatal(err)
	}
	gotResult, _, err := Verify[ModelResult](public, wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckModelResult(gotResult, turn, 100); err != nil {
		t.Fatal(err)
	}
	result.Binding.Turn++
	if CheckModelResult(result, turn, 100) == nil {
		t.Fatal("cross-turn response")
	}
	result.Binding = turn.Binding
	result.Failure = &Failure{Code: ErrCodeTransport}
	if Validate(result) == nil {
		t.Fatal("response and failure union")
	}
	result.Response = nil
	if err := Validate(result); err != nil {
		t.Fatal(err)
	}
	result.Failure.Code = "unknown"
	if Validate(result) == nil {
		t.Fatal("unknown failure")
	}
	for _, code := range []ErrorCode{ErrCodeAuth, ErrCodeTransport, ErrCodeSignature, ErrCodeProtocol, ErrCodeSession, ErrCodeRevision, ErrCodeRevoked, ErrCodeExpired, ErrCodeDelivery, ErrCodeSafety} {
		if code.IsUpstreamAvailability() {
			t.Fatal("infrastructure classified upstream")
		}
	}
	for _, code := range []ErrorCode{ErrCodeUpstreamQuota, ErrCodeUpstreamTransport, ErrCodeUpstreamTimeout, ErrCodeUpstreamConfig, ErrCodeUpstreamWire, ErrCodeUpstreamReLogin} {
		if !code.IsUpstreamAvailability() {
			t.Fatal("upstream not classified")
		}
	}
}
