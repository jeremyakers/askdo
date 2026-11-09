package fleetproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func catalogWithDefaults(t *testing.T) Catalog {
	t.Helper()
	catalog := catalogFixture(t)
	catalog.ReviewDefaults = &ReviewDefaults{
		ApprovalOnlyUsers: []string{"alice", "bob"},
		TimestampTimeouts: []UserTimestampTimeout{{User: "alice", Seconds: 600}},
		AutoApproveGrants: []UserAutoApproveGrant{{User: "alice", MaxRisk: 2}, {User: "bob", MaxRisk: 4}},
		RiskPolicy:        "Treat package upgrades as risk 1.\n",
		AccountNotes: &AccountNotes{
			Users:  []AccountNote{{Name: "alice", Text: "Alice administers the fleet.\n"}},
			Groups: []AccountNote{{Name: "ops", Text: "Operators restart services.\n"}},
		},
	}
	return catalog
}

// The defaults are part of what the gateway signs: they round-trip exactly,
// absence stays absence, and a host comparing against its frozen catalog sees
// any change to any default.
func TestCatalogReviewDefaultsSignedAndBound(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	for name, want := range map[string]Catalog{"absent": catalogFixture(t), "present": catalogWithDefaults(t), "empty object": func() Catalog {
		c := catalogFixture(t)
		c.ReviewDefaults = &ReviewDefaults{}
		return c
	}()} {
		t.Run(name, func(t *testing.T) {
			wire, err := Sign(private, want)
			if err != nil {
				t.Fatal(err)
			}
			got, payload, err := Verify[Catalog](public, wire)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) || CheckCatalog(got, want, 100) != nil {
				t.Fatalf("catalog changed through signing: %+v", got.ReviewDefaults)
			}
			if (want.ReviewDefaults == nil) == strings.Contains(string(payload), `"review_defaults"`) {
				t.Fatalf("field presence changed through signing: %s", payload)
			}
		})
	}

	want := catalogWithDefaults(t)
	for name, change := range map[string]func(*ReviewDefaults){
		"exemption added":   func(d *ReviewDefaults) { d.ApprovalOnlyUsers = append(d.ApprovalOnlyUsers, "carol") },
		"exemption removed": func(d *ReviewDefaults) { d.ApprovalOnlyUsers = d.ApprovalOnlyUsers[:1] },
		"timestamp longer":  func(d *ReviewDefaults) { d.TimestampTimeouts[0].Seconds++ },
		"grant raised":      func(d *ReviewDefaults) { d.AutoApproveGrants[0].MaxRisk++ },
		"policy edited":     func(d *ReviewDefaults) { d.RiskPolicy += "Everything is risk 1.\n" },
		"user note edited":  func(d *ReviewDefaults) { d.AccountNotes.Users[0].Text = "other" },
		"group note edited": func(d *ReviewDefaults) { d.AccountNotes.Groups[0].Name = "wheel" },
		"defaults dropped":  func(d *ReviewDefaults) { *d = ReviewDefaults{} },
	} {
		t.Run("tampered: "+name, func(t *testing.T) {
			wire, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := Parse[Catalog](wire)
			if err != nil {
				t.Fatal(err)
			}
			change(changed.ReviewDefaults)
			if err := CheckCatalog(changed, want, 100); !errors.Is(err, ErrBinding) {
				t.Fatalf("changed defaults accepted: %v", err)
			}
		})
	}
	// Dropping the whole object is also a change.
	stripped := want
	stripped.ReviewDefaults = nil
	if err := CheckCatalog(stripped, want, 100); !errors.Is(err, ErrBinding) {
		t.Fatalf("removed defaults accepted: %v", err)
	}
}

// A host reads the defaults the way it reads every other optional part of a
// signed catalog: an addition at any depth is ignored, never grounds to refuse
// the catalog, because refusing it would stop every review on the host.
func TestCatalogReviewDefaultsIgnoreAdditiveFieldsAtEveryDepth(t *testing.T) {
	reportIgnoresAdditiveFields(t, "catalog with review defaults", catalogWithDefaults(t))
}

// Every field of the defaults is optional on the wire: a gateway may leave out
// whatever it has no default for, an entry may be incomplete, and none of that
// is a reason to refuse the catalog. What a host cannot use it ignores.
func TestCatalogReviewDefaultsEveryFieldIsOptional(t *testing.T) {
	base, err := json.Marshal(catalogFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, defaults := range map[string]string{
		"empty object":       `{}`,
		"only exemptions":    `{"approval_only_users":["alice"]}`,
		"only a policy":      `{"risk_policy":"text"}`,
		"only group notes":   `{"account_notes":{"groups":[{"name":"ops","text":"n"}]}}`,
		"empty notes":        `{"account_notes":{}}`,
		"entries incomplete": `{"timestamp_timeouts":[{}],"auto_approve_grants":[{"user":"alice"}],"account_notes":{"users":[{"name":"alice"}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			payload := append(append([]byte{}, base[:len(base)-1]...), []byte(`,"review_defaults":`+defaults+`}`)...)
			got, err := Parse[Catalog](payload)
			if err != nil || got.ReviewDefaults == nil {
				t.Fatalf("catalog with %s refused: %v", name, err)
			}
		})
	}
	// Still strict where a payload is malformed rather than extended: a wrong
	// type, a duplicate key, a differently cased spelling of a defined field.
	for name, defaults := range map[string]string{
		"wrong type":        `{"approval_only_users":"alice"}`,
		"null object":       `null`,
		"duplicate key":     `{"risk_policy":"a","risk_policy":"b"}`,
		"aliased spelling":  `{"Risk_Policy":"a"}`,
		"NUL in text":       `{"risk_policy":"a\u0000b"}`,
		"aliased the field": `{"account_notes":{"Users":[]}}`,
	} {
		t.Run("refused: "+name, func(t *testing.T) {
			payload := append(append([]byte{}, base[:len(base)-1]...), []byte(`,"review_defaults":`+defaults+`}`)...)
			if _, err := Parse[Catalog](payload); err == nil {
				t.Fatalf("catalog with %s accepted", name)
			}
		})
	}
	aliased := append(append([]byte{}, base[:len(base)-1]...), []byte(`,"Review_Defaults":{}}`)...)
	if _, err := Parse[Catalog](aliased); err == nil {
		t.Fatal("case-aliased review_defaults accepted")
	}
}

// The bound exists so that a signed catalog can never outgrow the payload limit
// hosts enforce: the largest permitted defaults fit beside a catalog of the most
// profiles it may list (with generous 1 KiB base URLs) and the largest route.
func TestReviewDefaultsBoundLeavesRoomForTheRestOfTheCatalog(t *testing.T) {
	if MaxReviewDefaultsBytes <= 0 || MaxReviewDefaultsBytes >= MaxPayloadBytes {
		t.Fatalf("bound %d outside (0,%d)", MaxReviewDefaultsBytes, MaxPayloadBytes)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	catalog := catalogFixture(t)
	catalog.Profiles = nil
	for i := 0; i < MaxCatalogProfiles; i++ {
		profile := ProfileMetadata{Version: Version, Kind: KindProfile, ProfileID: ID(fmt.Sprintf("profile-%03d", i)), Upstreams: []Upstream{{API: OpenAIChat, BaseURL: "https://models.example.com/" + strings.Repeat("p", 1024), Model: strings.Repeat("m", 200), DataBoundary: External, RequestTimeoutSeconds: 120, MaxOutputTokens: 8192}}}
		var err error
		if profile.Revision, err = HashProfile(profile); err != nil {
			t.Fatal(err)
		}
		catalog.Profiles = append(catalog.Profiles, profile)
	}
	route := RouteSnapshot{Version: Version, Kind: KindRoute, ChannelID: "ops", BotID: 9223372036854775807, TTLSeconds: 86400}
	for chat := int64(1); chat <= 64; chat++ {
		recipient := Recipient{ChatID: -1000000000000 - chat}
		for operator := int64(1); operator <= 64; operator++ {
			recipient.OperatorUserIDs = append(recipient.OperatorUserIDs, 9000000000+operator)
		}
		route.Recipients = append(route.Recipients, recipient)
	}
	var err error
	if route.Revision, err = HashRoute(route); err != nil {
		t.Fatal(err)
	}
	catalog.Route = route
	catalog.ReviewDefaults = &ReviewDefaults{RiskPolicy: strings.Repeat("x", MaxReviewDefaultsBytes-len(`{"risk_policy":""}`))}
	if encoded, _ := json.Marshal(catalog.ReviewDefaults); len(encoded) != MaxReviewDefaultsBytes {
		t.Fatalf("fixture is %d bytes, want exactly the bound %d", len(encoded), MaxReviewDefaultsBytes)
	}
	wire, err := Sign(private, catalog)
	if err != nil {
		t.Fatalf("a catalog carrying the largest permitted defaults cannot be signed: %v", err)
	}
	if _, _, err := Verify[Catalog](public, wire); err != nil {
		t.Fatalf("a host refuses a catalog carrying the largest permitted defaults: %v", err)
	}
}
