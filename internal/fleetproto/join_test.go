package fleetproto

import (
	"encoding/json"
	"strings"
	"testing"
)

func validJoinRequestJSON() []byte {
	return []byte(`{"version":1,"host_id":"host_` + strings.Repeat("ab", 32) + `","bearer_hash":"` + strings.Repeat("cd", 32) + `","join_hash":"` + strings.Repeat("ef", 32) + `","hostname":"lauren-laptop"}`)
}

func approvedJoinResponseJSON() []byte {
	return []byte(`{"version":1,"state":"approved","host_id":"host_` + strings.Repeat("ab", 32) + `","expires_at":1790000000,"url":"https://gateway.example","verification_key":"` + strings.Repeat("A", 43) + "=" + `","allowed_profiles":["codex"],"default_profiles":["codex"]}`)
}

func Test_JoinRequest_parse_accepts_valid_request_when_fresh_host_joins(t *testing.T) {
	// Given a well-formed host-generated join request.
	data := validJoinRequestJSON()

	// When the gateway boundary parses it.
	value, err := ParseJoinRequest(data)

	// Then every typed field is preserved and secrets are absent.
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if value.Version != JoinVersion || value.HostID != ID("host_"+strings.Repeat("ab", 32)) {
		t.Fatal(value)
	}
	if value.BearerHash != Hash(strings.Repeat("cd", 32)) || value.JoinHash != Hash(strings.Repeat("ef", 32)) {
		t.Fatal(value)
	}
	if value.Hostname != "lauren-laptop" {
		t.Fatal(value)
	}
}

func Test_JoinRequest_parse_rejects_malformed_input_when_fields_violate_contract(t *testing.T) {
	host := "host_" + strings.Repeat("ab", 32)
	hash := strings.Repeat("cd", 32)
	tests := []struct {
		name string
		fix  func([]byte) []byte
	}{
		{"wrong version", func(d []byte) []byte {
			return []byte(strings.Replace(string(d), `"version":1`, `"version":2`, 1))
		}},
		{"missing version", func(d []byte) []byte {
			return []byte(strings.Replace(string(d), `"version":1,`, ``, 1))
		}},
		{"unknown field", func(d []byte) []byte {
			return []byte(strings.Replace(string(d), `"hostname"`, `"extra":1,"hostname"`, 1))
		}},
		{"duplicate key", func(d []byte) []byte {
			return []byte(strings.Replace(string(d), `"hostname"`, `"version":1,"hostname"`, 1))
		}},
		{"null body", func([]byte) []byte { return []byte("null") }},
		{"wrong host id format", func(d []byte) []byte {
			return []byte(`{"version":1,"host_id":"host_short","bearer_hash":"` + hash + `","join_hash":"` + hash + `","hostname":"h"}`)
		}},
		{"uppercase host id hex", func(d []byte) []byte {
			return []byte(`{"version":1,"host_id":"host_` + strings.Repeat("AB", 32) + `","bearer_hash":"` + hash + `","join_hash":"` + hash + `","hostname":"h"}`)
		}},
		{"bad bearer hash", func(d []byte) []byte {
			return []byte(`{"version":1,"host_id":"` + host + `","bearer_hash":"` + strings.Repeat("cD", 32) + `","join_hash":"` + hash + `","hostname":"h"}`)
		}},
		{"hostname control character", func(d []byte) []byte {
			return []byte(`{"version":1,"host_id":"` + host + `","bearer_hash":"` + hash + `","join_hash":"` + hash + `","hostname":"h\u0000x"}`)
		}},
		{"hostname too long", func(d []byte) []byte {
			return []byte(`{"version":1,"host_id":"` + host + `","bearer_hash":"` + hash + `","join_hash":"` + hash + `","hostname":"` + strings.Repeat("h", 257) + `"}`)
		}},
		{"body too large", func(d []byte) []byte {
			return append(append([]byte(`{"version":1,"host_id":"`), d...), []byte(strings.Repeat("x", 8192))...)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a request that violates the strict join contract.
			data := tt.fix(validJoinRequestJSON())

			// When the boundary parses it.
			_, err := ParseJoinRequest(data)

			// Then it is rejected without any partial result.
			if err == nil {
				t.Fatal("malformed join request accepted")
			}
			if !strings.Contains(err.Error(), "invalid fleet protocol") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func Test_JoinResponse_parse_accepts_approved_facts_when_gateway_approves(t *testing.T) {
	// Given a gateway-approved response carrying enrollment facts.
	data := approvedJoinResponseJSON()

	// When the host parses it.
	value, err := ParseJoinResponse(data)

	// Then the approved facts survive strict parsing.
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if value.State != JoinApproved || value.URL != "https://gateway.example" {
		t.Fatal(value)
	}
	if len(value.AllowedProfiles) != 1 || value.AllowedProfiles[0] != "codex" {
		t.Fatal(value)
	}
	if len(value.DefaultProfiles) != 1 || value.DefaultProfiles[0] != "codex" {
		t.Fatal(value)
	}
	if len(value.VerificationKey) != 44 {
		t.Fatalf("verification key encoding: %q", value.VerificationKey)
	}
}

func Test_JoinResponse_parse_rejects_state_facts_mismatch_when_inconsistent(t *testing.T) {
	host := ID("host_" + strings.Repeat("ab", 32))
	tests := []struct {
		name string
		data []byte
	}{
		{"pending with enrollment facts", []byte(`{"version":1,"state":"pending","host_id":"` + string(host) + `","expires_at":1790000000,"url":"https://gateway.example"}`)},
		{"denied with verification key", []byte(`{"version":1,"state":"denied","host_id":"` + string(host) + `","expires_at":1790000000,"verification_key":"` + strings.Repeat("A", 43) + "=" + `"}`)},
		{"expired with profiles", []byte(`{"version":1,"state":"expired","host_id":"` + string(host) + `","expires_at":1790000000,"allowed_profiles":["codex"]}`)},
		{"approved without url", []byte(`{"version":1,"state":"approved","host_id":"` + string(host) + `","expires_at":1790000000,"verification_key":"` + strings.Repeat("A", 43) + "=" + `","allowed_profiles":["codex"],"default_profiles":["codex"]}`)},
		{"approved with plain http", []byte(`{"version":1,"state":"approved","host_id":"` + string(host) + `","expires_at":1790000000,"url":"http://gateway.example","verification_key":"` + strings.Repeat("A", 43) + "=" + `","allowed_profiles":["codex"],"default_profiles":["codex"]}`)},
		{"approved with bad key", []byte(`{"version":1,"state":"approved","host_id":"` + string(host) + `","expires_at":1790000000,"url":"https://gateway.example","verification_key":"not-base64!","allowed_profiles":["codex"],"default_profiles":["codex"]}`)},
		{"approved default outside allowed", []byte(`{"version":1,"state":"approved","host_id":"` + string(host) + `","expires_at":1790000000,"url":"https://gateway.example","verification_key":"` + strings.Repeat("A", 43) + "=" + `","allowed_profiles":["codex"],"default_profiles":["other"]}`)},
		{"approved duplicate profiles", []byte(`{"version":1,"state":"approved","host_id":"` + string(host) + `","expires_at":1790000000,"url":"https://gateway.example","verification_key":"` + strings.Repeat("A", 43) + "=" + `","allowed_profiles":["codex","codex"],"default_profiles":["codex"]}`)},
		{"unknown state", []byte(`{"version":1,"state":"later","host_id":"` + string(host) + `","expires_at":1790000000}`)},
		{"missing expiry", []byte(`{"version":1,"state":"pending","host_id":"` + string(host) + `"}`)},
		{"host id not join-shaped", []byte(`{"version":1,"state":"pending","host_id":"anything","expires_at":1790000000}`)},
		{"too many default profiles", func() []byte {
			ids := make([]string, 17)
			for i := range ids {
				ids[i] = "profile-" + string(rune('a'+i))
			}
			data := `{"version":1,"state":"approved","host_id":"` + string(host) + `","expires_at":1790000000,"url":"https://gateway.example","verification_key":"` + strings.Repeat("A", 43) + "=" + `","allowed_profiles":[` + quoteJoin(ids) + `],"default_profiles":[` + quoteJoin(ids) + `]}`
			return []byte(data)
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a response whose fields contradict its state.
			// When the host parses it.
			if _, err := ParseJoinResponse(tt.data); err == nil {
				// Then it is rejected rather than half-trusted.
				t.Fatalf("inconsistent response accepted: %s", tt.data)
			}
		})
	}
}

func quoteJoin(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		b, _ := json.Marshal(v)
		quoted[i] = string(b)
	}
	return strings.Join(quoted, ",")
}

func Test_JoinRequestCode_derives_same_short_code_when_both_sides_compute(t *testing.T) {
	// Given one host identity rendered by the CLI and the gateway.
	id := ID("host_" + strings.Repeat("ab", 32))

	// When both derive the operator-facing code.
	first, second := JoinRequestCode(id), JoinRequestCode(id)

	// Then they agree, stay short, and differ for another host.
	if first != second {
		t.Fatal("request code is not deterministic")
	}
	if len(first) != 6 {
		t.Fatalf("request code length: %q", first)
	}
	if other := JoinRequestCode(ID("host_" + strings.Repeat("ba", 32))); other == first {
		t.Fatal("distinct hosts share a request code")
	}
}

func Test_JoinTTL_matches_documented_ten_minutes(t *testing.T) {
	// Given the contract's server-set expiry.
	// When the constant is consulted.
	// Then it stays the documented ten minutes.
	if JoinTTLSeconds != 600 {
		t.Fatalf("join TTL drifted: %d", JoinTTLSeconds)
	}
}

func TestJoinApprovedEmptyProfilesRoundTrip(t *testing.T) {
	// Given an approval-only gateway with an explicit empty selection.
	response := JoinResponse{Version: 1, State: JoinApproved, HostID: ID("host_" + strings.Repeat("ab", 32)), ExpiresAt: 1790000000, URL: "https://gateway.example", VerificationKey: strings.Repeat("A", 43) + "=", AllowedProfiles: []string{}, DefaultProfiles: []string{}}
	// When the approved response goes through the actual server encoding seam.
	wire, err := MarshalJoinResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseJoinResponse(wire)
	// Then empty arrays remain explicit, not absent/null or unparseable.
	if err != nil || parsed.DefaultProfiles == nil || len(parsed.DefaultProfiles) != 0 || parsed.AllowedProfiles == nil {
		t.Fatalf("empty approved profiles lost: %s %+v %v", wire, parsed, err)
	}
}
