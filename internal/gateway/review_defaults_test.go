package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
)

const defaultsBase = `{"config_version":1,"listen":"127.0.0.1:8443","public_url":"https://gateway.example","tls_cert_file":"/keys/cert","tls_key_file":"/keys/tls","signing_key_file":"/keys/sign","database":"/db/gateway.sqlite","profiles":[],"bots":[{"name":"ops","token_file":"/keys/bot"}],"channels":[{"name":"admin","bot":"ops","approval_ttl":600,"recipients":[{"chat_id":-1,"operator_user_ids":[1]}]}]%s}`

// loadDefaults decodes a gateway document carrying the given review_defaults
// value through the same path the operator tooling and the service use.
func loadDefaults(t *testing.T, section string) (*Config, error) {
	t.Helper()
	stubRootFiles(t)
	path := filepath.Join(t.TempDir(), "gateway.json")
	extra := ""
	if section != "" {
		extra = `,"review_defaults":` + section
	}
	if err := os.WriteFile(path, []byte(fmt.Sprintf(defaultsBase, extra)), 0600); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(path)
}

func writePolicy(t *testing.T, name, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(text), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReviewDefaultsConfigAcceptsTheHostShapes(t *testing.T) {
	rubric := writePolicy(t, "risk-policy.md", "File guidance.\n")
	note := writePolicy(t, "ops.md", "Ops note from a file.\n")
	cfg, err := loadDefaults(t, fmt.Sprintf(`{
		"approval_only_users": ["alice"],
		"timestamp_timeout_users": {"carol": 1.5, "alice": 10, "bob": 0.5},
		"auto_approve_grants": [{"user": "alice", "max_risk": 2}],
		"risk_policy": {"file": %q},
		"account_notes": {"users": {"alice": {"text": "Alice administers the fleet.\n"}}, "groups": {"ops": {"file": %q}}}
	}`, rubric, note))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.PolicyFilePaths(), []string{rubric, note}; !reflect.DeepEqual(got, want) {
		t.Fatalf("policy file paths %v, want %v", got, want)
	}
	wire, err := cfg.ReviewDefaults.wire()
	if err != nil {
		t.Fatal(err)
	}
	want := &fleetproto.ReviewDefaults{
		ApprovalOnlyUsers: []string{"alice"},
		// In name order whatever order the file used, minutes converted to the
		// whole seconds a host uses.
		TimestampTimeouts: []fleetproto.UserTimestampTimeout{{User: "alice", Seconds: 600}, {User: "bob", Seconds: 30}, {User: "carol", Seconds: 90}},
		AutoApproveGrants: []fleetproto.UserAutoApproveGrant{{User: "alice", MaxRisk: 2}},
		RiskPolicy:        "File guidance.\n",
		AccountNotes: &fleetproto.AccountNotes{
			Users:  []fleetproto.AccountNote{{Name: "alice", Text: "Alice administers the fleet.\n"}},
			Groups: []fleetproto.AccountNote{{Name: "ops", Text: "Ops note from a file.\n"}},
		},
	}
	if !reflect.DeepEqual(wire, want) {
		t.Fatalf("published %+v\nwant      %+v", wire, want)
	}
}

func TestReviewDefaultsEmptySectionPublishesNothing(t *testing.T) {
	for _, section := range []string{"", `null`, `{}`, `{"approval_only_users":[],"auto_approve_grants":[],"timestamp_timeout_users":{},"account_notes":{"users":{},"groups":{}}}`} {
		cfg, err := loadDefaults(t, section)
		if err != nil {
			t.Fatalf("%q: %v", section, err)
		}
		if wire, err := cfg.ReviewDefaults.wire(); err != nil || wire != nil {
			t.Fatalf("%q published %+v, %v", section, wire, err)
		}
	}
}

// What a host would refuse is refused where the gateway is configured, once,
// instead of by every host on every review the text applies to; and a section
// that would make the signed catalog too large for hosts to accept never starts.
func TestReviewDefaultsConfigRefusesWhatAHostRefuses(t *testing.T) {
	ok := writePolicy(t, "ok.md", "text\n")
	long := strings.Repeat("x", fleetproto.MaxMessageContentBytes+1)
	big := strings.Repeat("y", fleetproto.MaxMessageContentBytes)
	var many strings.Builder
	for i := 0; i < 129; i++ {
		fmt.Fprintf(&many, `{"user":"user%d","max_risk":1},`, i)
	}
	for name, section := range map[string]string{
		"unknown key":                   `{"mode":"approval_only"}`,
		"duplicate key":                 `{"approval_only_users":[],"approval_only_users":[]}`,
		"section as a list":             `[]`,
		"empty exempt login":            `{"approval_only_users":[""]}`,
		"untrimmed exempt login":        `{"approval_only_users":[" alice"]}`,
		"duplicate exempt login":        `{"approval_only_users":["alice","alice"]}`,
		"exemptions as a login":         `{"approval_only_users":"alice"}`,
		"timestamp below 30s":           `{"timestamp_timeout_users":{"alice":0.4}}`,
		"timestamp zero":                `{"timestamp_timeout_users":{"alice":0}}`,
		"timestamp above an hour":       `{"timestamp_timeout_users":{"alice":61}}`,
		"timestamp negative":            `{"timestamp_timeout_users":{"alice":-5}}`,
		"timestamp as text":             `{"timestamp_timeout_users":{"alice":"10m"}}`,
		"timestamp untrimmed login":     `{"timestamp_timeout_users":{"alice ":10}}`,
		"grant risk zero":               `{"auto_approve_grants":[{"user":"alice","max_risk":0}]}`,
		"grant risk five":               `{"auto_approve_grants":[{"user":"alice","max_risk":5}]}`,
		"grant duplicate login":         `{"auto_approve_grants":[{"user":"alice","max_risk":1},{"user":"alice","max_risk":2}]}`,
		"grant empty login":             `{"auto_approve_grants":[{"user":"","max_risk":1}]}`,
		"grant unknown field":           `{"auto_approve_grants":[{"user":"alice","max_risk":1,"extra":1}]}`,
		"more than 128 grants":          `{"auto_approve_grants":[` + strings.TrimSuffix(many.String(), ",") + `]}`,
		"policy needs text or file":     `{"risk_policy":{}}`,
		"policy as a bare string":       `{"risk_policy":"text"}`,
		"policy both text and file":     fmt.Sprintf(`{"risk_policy":{"text":"a","file":%q}}`, ok),
		"policy relative file":          `{"risk_policy":{"file":"risk-policy.md"}}`,
		"policy unclean file":           `{"risk_policy":{"file":"/etc//askdo/risk-policy.md"}}`,
		"policy missing file":           `{"risk_policy":{"file":"/nonexistent/risk-policy.md"}}`,
		"policy NUL":                    `{"risk_policy":{"text":"a\u0000b"}}`,
		"policy CRLF":                   `{"risk_policy":{"text":"a\r\nb"}}`,
		"policy control character":      `{"risk_policy":{"text":"a\u0007b"}}`,
		"policy over the message limit": `{"risk_policy":{"text":"` + long + `"}}`,
		"policy unknown field":          `{"risk_policy":{"text":"a","path":"/x"}}`,
		"note empty login":              `{"account_notes":{"users":{"":{"text":"a"}}}}`,
		"note untrimmed group":          `{"account_notes":{"groups":{" ops":{"text":"a"}}}}`,
		"note needs text or file":       `{"account_notes":{"users":{"alice":{}}}}`,
		"note both":                     fmt.Sprintf(`{"account_notes":{"groups":{"ops":{"text":"a","file":%q}}}}`, ok),
		"note relative file":            `{"account_notes":{"users":{"alice":{"file":"alice.md"}}}}`,
		"note CRLF":                     `{"account_notes":{"users":{"alice":{"text":"a\r\n"}}}}`,
		"notes unknown scope":           `{"account_notes":{"everyone":{}}}`,
		"total over the catalog budget": `{"account_notes":{"users":{"a":{"text":"` + big + `"},"b":{"text":"` + big + `"},"c":{"text":"` + big + `"}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadDefaults(t, section); err == nil {
				t.Fatalf("accepted %.200s", section)
			}
		})
	}
	// The largest section the budget allows is accepted.
	atLimit := `{"account_notes":{"users":{"a":{"text":"` + big + `"},"b":{"text":"` + strings.Repeat("z", fleetproto.MaxReviewDefaultsBytes-fleetproto.MaxMessageContentBytes-200) + `"}}}}`
	if cfg, err := loadDefaults(t, atLimit); err != nil {
		t.Fatalf("section just inside the budget refused: %v", err)
	} else if wire, err := cfg.ReviewDefaults.wire(); err != nil || wire == nil {
		t.Fatalf("section just inside the budget not published: %v", err)
	}

	t.Run("a file that is not root-owned", func(t *testing.T) {
		stubRootFiles(t)
		validateRootFile = func(path string, secret bool) error {
			if path == ok {
				return os.ErrPermission
			}
			return nil
		}
		doc := fmt.Sprintf(defaultsBase, fmt.Sprintf(`,"review_defaults":{"risk_policy":{"file":%q}}`, ok))
		if _, err := DecodeConfig([]byte(doc)); err == nil || !strings.Contains(err.Error(), "risk_policy") {
			t.Fatalf("unsafe policy file accepted: %v", err)
		}
	})
}

// defaultsServer builds the service the way NewServer does from a config, with
// one enrolled host, and returns a function that fetches and verifies the
// signed catalog over the real endpoint.
func defaultsServer(t *testing.T, cfg Config) (*Server, func() fleetproto.Catalog, error) {
	t.Helper()
	stubRootFiles(t)
	stubDBOwner(t)
	store, err := OpenEnrollmentStore(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	enrollment, bearer, err := store.Create(context.Background(), EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"admin"}, DefaultChannel: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	cfg.Channels = []ChannelConfig{{Name: "admin", Bot: "bot", ApprovalTTL: 60, Recipients: []config.TelegramRecipient{{ChatID: 1, OperatorUserIDs: []int64{2}}}}}
	service, err := newServer(cfg, store, key, map[string]int64{"bot": 1}, 1)
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(service.Close)
	server := httptest.NewTLSServer(service.Handler())
	t.Cleanup(server.Close)
	return service, func() fleetproto.Catalog {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/catalog?submitter_uid=1001", nil)
		req.Header.Set("X-Askdo-Host", enrollment.HostID)
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		wire, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("catalog status %d: %s", resp.StatusCode, wire)
		}
		catalog, _, err := fleetproto.Verify[fleetproto.Catalog](key.Public().(ed25519.PublicKey), wire)
		if err != nil {
			t.Fatalf("a host could not verify the catalog: %v", err)
		}
		return catalog
	}, nil
}

// The catalog hosts verify carries the configured defaults exactly. Files are
// read once, at start: an edit afterwards changes nothing until the gateway is
// restarted, and a section that cannot be read or published stops it starting.
func TestServerPublishesReviewDefaultsReadAtStart(t *testing.T) {
	rubric := writePolicy(t, "risk-policy.md", "First guidance.\n")
	_, fetch, err := defaultsServer(t, Config{ReviewDefaults: &ReviewDefaults{
		ApprovalOnlyUsers:     []string{"alice"},
		TimestampTimeoutUsers: map[string]float64{"alice": 10},
		AutoApproveGrants:     nil,
		RiskPolicy:            &PolicyText{File: rubric},
		AccountNotes:          &AccountNotes{Users: map[string]PolicyText{"alice": {Text: "inline note"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := &fleetproto.ReviewDefaults{
		ApprovalOnlyUsers: []string{"alice"},
		TimestampTimeouts: []fleetproto.UserTimestampTimeout{{User: "alice", Seconds: 600}},
		RiskPolicy:        "First guidance.\n",
		AccountNotes:      &fleetproto.AccountNotes{Users: []fleetproto.AccountNote{{Name: "alice", Text: "inline note"}}},
	}
	if got := fetch().ReviewDefaults; !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog carries %+v, want %+v", got, want)
	}
	if err := os.WriteFile(rubric, []byte("Second guidance.\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := fetch().ReviewDefaults; !reflect.DeepEqual(got, want) {
		t.Fatalf("a file edited after start changed the catalog: %+v", got)
	}
}

func TestServerWithoutReviewDefaultsSignsNone(t *testing.T) {
	for name, section := range map[string]*ReviewDefaults{"absent": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			_, fetch, err := defaultsServer(t, Config{ReviewDefaults: section})
			if err != nil {
				t.Fatal(err)
			}
			if got := fetch().ReviewDefaults; got != nil {
				t.Fatalf("catalog carries %+v with no defaults configured", got)
			}
		})
	}
}

func TestServerRefusesToStartWithUnpublishableReviewDefaults(t *testing.T) {
	for name, section := range map[string]*ReviewDefaults{
		"missing file":   {RiskPolicy: &PolicyText{File: "/nonexistent/risk-policy.md"}},
		"invalid grant":  {AutoApproveGrants: nil, TimestampTimeoutUsers: map[string]float64{"alice": 99}},
		"zero window":    {TimestampTimeoutUsers: map[string]float64{"alice": 0}}, // a host-only override, meaningless as a default
		"over the limit": {AccountNotes: &AccountNotes{Users: map[string]PolicyText{"a": {Text: strings.Repeat("a", fleetproto.MaxMessageContentBytes)}, "b": {Text: strings.Repeat("b", fleetproto.MaxMessageContentBytes)}, "c": {Text: strings.Repeat("c", fleetproto.MaxMessageContentBytes)}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := defaultsServer(t, Config{ReviewDefaults: section}); err == nil || !strings.Contains(err.Error(), "review_defaults") {
				t.Fatalf("server started: %v", err)
			}
		})
	}
}
