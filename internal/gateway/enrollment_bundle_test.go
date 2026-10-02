package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestEnrollmentBundleStrict(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	b := EnrollmentBundle{Version: 1, URL: "https://gateway.example", HostID: "host_test", Bearer: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), VerificationKey: base64.StdEncoding.EncodeToString(pub), AllowedProfiles: []string{"local"}, DefaultProfiles: []string{"local"}}
	data, _ := json.Marshal(b)
	if _, err := DecodeEnrollmentBundle(data); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*EnrollmentBundle){
		func(b *EnrollmentBundle) { b.Version = 2 },
		func(b *EnrollmentBundle) { b.Bearer = "secret-not-valid" },
		func(b *EnrollmentBundle) { b.VerificationKey = "bad" },
		func(b *EnrollmentBundle) { b.CAPEM = "not a certificate" },
		func(b *EnrollmentBundle) { b.DefaultProfiles = []string{"other"} },
		func(b *EnrollmentBundle) { b.AllowedProfiles = []string{"local", "local"} },
	} {
		bad := b
		mutate(&bad)
		raw, _ := json.Marshal(bad)
		if _, err := DecodeEnrollmentBundle(raw); err == nil {
			t.Fatalf("accepted malformed bundle")
		}
	}
	for _, raw := range [][]byte{append(data[:len(data)-1], []byte(`,"version":1}`)...), append(data[:len(data)-1], []byte(`,"unknown":true}`)...)} {
		if _, err := DecodeEnrollmentBundle(raw); err == nil {
			t.Fatal("accepted ambiguous bundle")
		}
	}
}
