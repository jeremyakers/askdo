package fleetproto

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

func validJoinRequestJSON() []byte {
	return []byte(`{"version":2,"host_id":"host_` + strings.Repeat("ab", 32) + `","bearer_hash":"` + strings.Repeat("cd", 32) + `","join_hash":"` + strings.Repeat("ef", 32) + `","commit":"e2f430cf4cc6300975470a4a913c27cf6f450714dea85f8b92872857583c7581","hostname":"lauren-laptop"}`)
}

func approvedJoinResponseJSON() []byte {
	return []byte(`{"version":2,"state":"approved","host_id":"host_` + strings.Repeat("ab", 32) + `","gateway_nonce":"2222222222222222222222222222222222222222222222222222222222222222","expires_at":1790000000,"url":"https://gateway.example","verification_key":"` + strings.Repeat("A", 43) + "=" + `","allowed_profiles":["codex"],"default_profiles":["codex"]}`)
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
			return []byte(strings.Replace(string(d), `"version":2`, `"version":1`, 1))
		}},
		{"missing version", func(d []byte) []byte {
			return []byte(strings.Replace(string(d), `"version":2,`, ``, 1))
		}},
		{"missing commitment", func(d []byte) []byte {
			return []byte(strings.Replace(string(d), `,"commit":"e2f430cf4cc6300975470a4a913c27cf6f450714dea85f8b92872857583c7581"`, "", 1))
		}},
		{"malformed commitment", func(d []byte) []byte {
			return []byte(strings.Replace(string(d), "e2f430cf4cc6300975470a4a913c27cf6f450714dea85f8b92872857583c7581", "bad", 1))
		}},
		{"unknown field", func(d []byte) []byte {
			return []byte(strings.Replace(string(d), `"hostname"`, `"extra":1,"hostname"`, 1))
		}},
		{"duplicate key", func(d []byte) []byte {
			return []byte(strings.Replace(string(d), `"hostname"`, `"version":2,"hostname"`, 1))
		}},
		{"null body", func([]byte) []byte { return []byte("null") }},
		{"wrong host id format", func(d []byte) []byte {
			return []byte(`{"version":2,"host_id":"host_short","bearer_hash":"` + hash + `","join_hash":"` + hash + `","commit":"e2f430cf4cc6300975470a4a913c27cf6f450714dea85f8b92872857583c7581","hostname":"h"}`)
		}},
		{"uppercase host id hex", func(d []byte) []byte {
			return []byte(`{"version":2,"host_id":"host_` + strings.Repeat("AB", 32) + `","bearer_hash":"` + hash + `","join_hash":"` + hash + `","commit":"e2f430cf4cc6300975470a4a913c27cf6f450714dea85f8b92872857583c7581","hostname":"h"}`)
		}},
		{"bad bearer hash", func(d []byte) []byte {
			return []byte(`{"version":2,"host_id":"` + host + `","bearer_hash":"` + strings.Repeat("cD", 32) + `","join_hash":"` + hash + `","commit":"e2f430cf4cc6300975470a4a913c27cf6f450714dea85f8b92872857583c7581","hostname":"h"}`)
		}},
		{"hostname control character", func(d []byte) []byte {
			return []byte(`{"version":2,"host_id":"` + host + `","bearer_hash":"` + hash + `","join_hash":"` + hash + `","commit":"e2f430cf4cc6300975470a4a913c27cf6f450714dea85f8b92872857583c7581","hostname":"h\u0000x"}`)
		}},
		{"hostname too long", func(d []byte) []byte {
			return []byte(`{"version":2,"host_id":"` + host + `","bearer_hash":"` + hash + `","join_hash":"` + hash + `","commit":"e2f430cf4cc6300975470a4a913c27cf6f450714dea85f8b92872857583c7581","hostname":"` + strings.Repeat("h", 257) + `"}`)
		}},
		{"body too large", func(d []byte) []byte {
			return append(append([]byte(`{"version":2,"host_id":"`), d...), []byte(strings.Repeat("x", 8192))...)
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
	invalid := func(change func(map[string]any)) []byte {
		var value map[string]any
		if err := json.Unmarshal(approvedJoinResponseJSON(), &value); err != nil {
			t.Fatal(err)
		}
		change(value)
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	tests := []struct {
		name string
		data []byte
	}{
		{"pending with enrollment facts", invalid(func(v map[string]any) { v["state"] = "pending" })},
		{"denied with verification key", invalid(func(v map[string]any) { v["state"] = "denied" })},
		{"expired with profiles", invalid(func(v map[string]any) { v["state"] = "expired" })},
		{"approved without url", invalid(func(v map[string]any) { delete(v, "url") })},
		{"approved with plain http", invalid(func(v map[string]any) { v["url"] = "http://gateway.example" })},
		{"approved with bad key", invalid(func(v map[string]any) { v["verification_key"] = "not-base64!" })},
		{"approved default outside allowed", invalid(func(v map[string]any) { v["default_profiles"] = []string{"other"} })},
		{"approved duplicate profiles", invalid(func(v map[string]any) { v["allowed_profiles"] = []string{"codex", "codex"} })},
		{"unknown state", invalid(func(v map[string]any) { v["state"] = "later" })},
		{"missing expiry", invalid(func(v map[string]any) { delete(v, "expires_at") })},
		{"host id not join-shaped", invalid(func(v map[string]any) { v["host_id"] = "anything" })},
		{"missing gateway nonce", invalid(func(v map[string]any) { delete(v, "gateway_nonce") })},
		{"malformed gateway nonce", invalid(func(v map[string]any) { v["gateway_nonce"] = "bad" })},
		{"old version", invalid(func(v map[string]any) { v["version"] = 1 })},
		{"too many default profiles", invalid(func(v map[string]any) {
			ids := make([]string, 17)
			for i := range ids {
				ids[i] = "profile-" + string(rune('a'+i))
			}
			v["allowed_profiles"], v["default_profiles"] = ids, ids
		})},
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

func Test_JoinRequestCode_binds_request_and_gateway_certificate(t *testing.T) {
	// Given a fixed request and leaf hash, with an independently calculated
	// version-2 code vector, including the commitment and both nonces.
	request, err := ParseJoinRequest(validJoinRequestJSON())
	if err != nil {
		t.Fatal(err)
	}
	leaf := sha256.Sum256([]byte("fixture leaf DER"))
	// When either side derives the short authentication string.
	code := JoinRequestCode(request, leaf, Hash(strings.Repeat("00", 32)), Hash(strings.Repeat("22", 32)))
	// Then the fixed vector is stable and each bound field affects the code.
	if code != "28AC12" || JoinRequestCode(request, leaf, Hash(strings.Repeat("00", 32)), Hash(strings.Repeat("22", 32))) != code {
		t.Fatalf("wrong certificate-bound code: %q", code)
	}
	for _, field := range []string{"host", "bearer", "join", "certificate", "commit", "host nonce", "gateway nonce"} {
		t.Run(field, func(t *testing.T) {
			changed, otherLeaf := request, leaf
			hostNonce, gatewayNonce := Hash(strings.Repeat("00", 32)), Hash(strings.Repeat("22", 32))
			switch field {
			case "host":
				changed.HostID = ID("host_" + strings.Repeat("ba", 32))
			case "bearer":
				changed.BearerHash = Hash(strings.Repeat("dc", 32))
			case "join":
				changed.JoinHash = Hash(strings.Repeat("fe", 32))
			case "certificate":
				otherLeaf = sha256.Sum256([]byte("another leaf DER"))
			case "commit":
				changed.Commit = Hash(strings.Repeat("01", 32))
			case "host nonce":
				hostNonce = Hash(strings.Repeat("01", 32))
			case "gateway nonce":
				gatewayNonce = Hash(strings.Repeat("01", 32))
			}
			if JoinRequestCode(changed, otherLeaf, hostNonce, gatewayNonce) == code {
				t.Fatal("changed binding did not change authentication string")
			}
		})
	}
}

func TestJoinCommitMatchesIndependentVector(t *testing.T) {
	// Given an all-zero fixture nonce, when committed, then it matches a digest
	// independently calculated from the domain and the 32 raw nonce bytes.
	if JoinCommit([32]byte{}) != "e2f430cf4cc6300975470a4a913c27cf6f450714dea85f8b92872857583c7581" {
		t.Fatal("incorrect commit encoding")
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
	response := JoinResponse{Version: JoinVersion, GatewayNonce: Hash(strings.Repeat("22", 32)), State: JoinApproved, HostID: ID("host_" + strings.Repeat("ab", 32)), ExpiresAt: 1790000000, URL: "https://gateway.example", VerificationKey: strings.Repeat("A", 43) + "=", AllowedProfiles: []string{}, DefaultProfiles: []string{}}
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
