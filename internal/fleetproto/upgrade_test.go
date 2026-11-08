package fleetproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const offerDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func catalogWithOffer(t *testing.T) Catalog {
	t.Helper()
	c := catalogFixture(t)
	c.FleetUpgrade = &FleetUpgradeOffer{Release: "v1.0.1", ManifestSHA256: offerDigest}
	return c
}

func TestCatalogCarriesAnOfferOnlyWhenThereIsOne(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Without an offer the catalog is exactly what a gateway without the field
	// signs: a host that does not know the field never sees it.
	plain, err := json.Marshal(catalogFixture(t))
	if err != nil || bytes.Contains(plain, []byte("fleet_upgrade")) {
		t.Fatalf("catalog without an offer mentions one: %s, %v", plain, err)
	}
	want := catalogWithOffer(t)
	wire, err := Sign(private, want)
	if err != nil {
		t.Fatal(err)
	}
	got, payload, err := Verify[Catalog](public, wire)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("offer did not survive signing: %+v, %v", got, err)
	}
	if !bytes.Contains(payload, []byte(`"fleet_upgrade":{"release":"v1.0.1","manifest_sha256":"`+offerDigest+`"}`)) {
		t.Fatalf("offer is not a plain nested object: %s", payload)
	}
	// The signature covers the offer: changing the release after signing fails.
	var envelope Envelope
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Payload = base64Replace(t, envelope.Payload, "v1.0.1", "v1.0.2")
	tampered, _ := json.Marshal(envelope)
	if _, _, err := Verify[Catalog](public, tampered); !errors.Is(err, ErrSignature) {
		t.Fatalf("offer changed after signing: %v", err)
	}
}

func TestCatalogWithAnOfferIgnoresAdditiveFieldsAtEveryDepth(t *testing.T) {
	reportIgnoresAdditiveFields(t, "catalog with an offer", catalogWithOffer(t))
}

// A catalog is read whole: the offer must never be the reason a host refuses
// the catalog, and with it every review, however odd the gateway's offer is.
func TestAnIncompleteOfferDoesNotMakeTheCatalogUnreadable(t *testing.T) {
	payload, err := json.Marshal(catalogFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, offer := range map[string]string{
		"empty":               `{}`,
		"release only":        `{"release":"v1.0.1"}`,
		"digest only":         `{"manifest_sha256":"` + offerDigest + `"}`,
		"unknown member":      `{"release":"v1.0.1","manifest_sha256":"` + offerDigest + `","signature_hint":"x"}`,
		"not a release":       `{"release":"not-a-release","manifest_sha256":"not hex"}`,
		"unusually long text": `{"release":"` + strings.Repeat("v", 5000) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			raw := append(append([]byte{}, payload[:len(payload)-1]...), `,"fleet_upgrade":`+offer+`}`...)
			if _, err := Parse[Catalog](raw); err != nil {
				t.Fatalf("catalog refused for its offer: %v", err)
			}
		})
	}
	// The offer is not an excuse for anything else: its own spelling is exact.
	raw := append(append([]byte{}, payload[:len(payload)-1]...), `,"Fleet_Upgrade":{}}`...)
	if _, err := Parse[Catalog](raw); err == nil {
		t.Fatal("aliased spelling of the offer accepted")
	}
	dup := append(append([]byte{}, payload[:len(payload)-1]...), `,"fleet_upgrade":{},"fleet_upgrade":{}}`...)
	if _, err := Parse[Catalog](dup); err == nil {
		t.Fatal("duplicate offer accepted")
	}
}

func base64Replace(t *testing.T, encoded, old, replacement string) string {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte(old)) {
		t.Fatalf("payload lacks %q", old)
	}
	return base64.StdEncoding.EncodeToString(bytes.Replace(payload, []byte(old), []byte(replacement), 1))
}

func TestHostStatusRoundTripsThroughTheWire(t *testing.T) {
	want := HostStatus{Version: HostStatusVersion, Hostname: "nas-01", Release: "v1.0.0-rc.34", AutoUpgrade: true, Upgrade: &UpgradeResult{Operation: "up_" + strings.Repeat("0", 32), Release: "v1.0.0-rc.34", State: "succeeded", Detail: "verified", UpdatedAt: 1_700_000_000}}
	data, err := MarshalHostStatus(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseHostStatus(data)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, %v from %s", got, err, data)
	}
	// A host that does not know its release reports none; auto_upgrade stays an
	// explicit false rather than an omitted field.
	data, err = MarshalHostStatus(HostStatus{Version: HostStatusVersion})
	if err != nil || string(data) != `{"version":1,"auto_upgrade":false}` {
		t.Fatalf("minimal report = %s, %v", data, err)
	}
	if _, err := ParseHostStatus(data); err != nil {
		t.Fatal(err)
	}
}

// A host status reports something and asks for nothing, so a field a newer host
// adds is ignored at any depth rather than costing the gateway the whole report.
func TestHostStatusIgnoresAdditiveFieldsAtEveryDepth(t *testing.T) {
	want := HostStatus{Version: HostStatusVersion, Release: "v1.0.0", AutoUpgrade: true, Upgrade: &UpgradeResult{State: "failed", Outcome: "rolled_back"}}
	payload, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	extendEachObject(t, payload, func(t *testing.T, extended []byte) {
		got, err := ParseHostStatus(extended)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("report with an additive member: %+v, %v", got, err)
		}
	})
}

func TestHostStatusStillRefusesWhatIsNotAReport(t *testing.T) {
	for name, body := range map[string]string{
		"empty":                  ``,
		"not an object":          `[]`,
		"null":                   `null`,
		"no version":             `{"auto_upgrade":true}`,
		"another version":        `{"version":2,"auto_upgrade":true}`,
		"no auto_upgrade":        `{"version":1}`,
		"duplicate key":          `{"version":1,"auto_upgrade":true,"release":"v1.0.0","release":"v1.0.1"}`,
		"aliased spelling":       `{"version":1,"auto_upgrade":true,"Release":"v1.0.0"}`,
		"wrong type":             `{"version":1,"auto_upgrade":"yes"}`,
		"trailing value":         `{"version":1,"auto_upgrade":true} {}`,
		"null upgrade result":    `{"version":1,"auto_upgrade":true,"upgrade":null}`,
		"nul in text":            `{"version":1,"auto_upgrade":true,"hostname":"a\u0000b"}`,
		"more than the size cap": `{"version":1,"auto_upgrade":true,"hostname":"` + strings.Repeat("a", MaxHostStatusBytes) + `"}`,
	} {
		if _, err := ParseHostStatus([]byte(body)); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: err = %v, want ErrProtocol", name, err)
		}
	}
	if _, err := MarshalHostStatus(HostStatus{AutoUpgrade: true}); err == nil {
		t.Error("report without a version was encoded")
	}
}

func TestHostStatusTextIsMadeFitToShow(t *testing.T) {
	long := strings.Repeat("x", 10_000)
	dirty := HostStatus{
		Version:  HostStatusVersion,
		Hostname: "nas\x1b[31m-01\n<b>\u202e",
		Release:  long,
		Upgrade:  &UpgradeResult{Operation: long, Release: long, State: long, Outcome: long, Detail: "line one\nline two\x00\u00e9 done " + long},
	}
	got := dirty.Cleaned()
	if got.Hostname != "nas[31m-01<b>" {
		t.Errorf("hostname = %q", got.Hostname)
	}
	if len(got.Release) != MaxStatusRelease || len(got.Upgrade.Operation) != MaxStatusRelease || len(got.Upgrade.Release) != MaxStatusRelease {
		t.Errorf("release text not bounded: %d %d %d", len(got.Release), len(got.Upgrade.Operation), len(got.Upgrade.Release))
	}
	if len(got.Upgrade.State) != 32 || len(got.Upgrade.Outcome) != 64 || len(got.Upgrade.Detail) != MaxStatusDetail {
		t.Errorf("result text not bounded: %d %d %d", len(got.Upgrade.State), len(got.Upgrade.Outcome), len(got.Upgrade.Detail))
	}
	if !strings.HasPrefix(got.Upgrade.Detail, "line oneline two done xxx") {
		t.Errorf("detail = %q", got.Upgrade.Detail)
	}
	for _, s := range []string{got.Hostname, got.Release, got.Upgrade.Detail} {
		for i := 0; i < len(s); i++ {
			if s[i] < 0x20 || s[i] > 0x7e {
				t.Fatalf("non-printable byte %#x survived in %q", s[i], s)
			}
		}
	}
	if dirty.Upgrade.Detail == got.Upgrade.Detail {
		t.Error("Cleaned changed the original report's result in place")
	}
}
