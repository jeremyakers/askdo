package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFleetEnrollmentBundleFilesStrictAndProtected(t *testing.T) {
	stubFleetFiles(t)
	activeFileStat := credentialStat
	credentialStat = func(path string) (os.FileInfo, error) {
		if strings.HasPrefix(path, "/root/") {
			t.Errorf("retained provenance caused file I/O: %s", path)
			return nil, os.ErrNotExist
		}
		return activeFileStat(path)
	}
	credentialLstat = credentialStat
	base := `{"config_version":5,"inspection":{"read_roots":["/"]},"review":{"mode":"approval_only","gateway_profiles":[]},"limits":{},"fleet":{"url":"https://gateway.example","host_id":"host-a","enrollment_file":"/keys/enrollment","verification_key_file":"/keys/verify","ca_file":"/keys/ca","approval_ttl":600%s}}`
	path := filepath.Join(t.TempDir(), "host.json")
	load := func(field string) (*Config, error) {
		t.Helper()
		if err := os.WriteFile(path, []byte(fmt.Sprintf(base, field)), 0600); err != nil {
			t.Fatal(err)
		}
		return Load(path)
	}
	field := `,"enrollment_bundle_files":["/root/host-pi-bundle.json","/root/previous-host.json"]`
	cfg, err := load(field)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/keys/enrollment", "/keys/verify", "/keys/ca", "/root/host-pi-bundle.json", "/root/previous-host.json"}
	if !reflect.DeepEqual(cfg.CredentialPaths(), want) {
		t.Fatalf("unprotected source bundles: %v", cfg.CredentialPaths())
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	roundtrip, err := Load(path)
	if err != nil || !reflect.DeepEqual(roundtrip.CredentialPaths(), want) {
		t.Fatalf("roundtrip lost bundle paths: %v", err)
	}
	// Recorded source paths intentionally need not exist. Removing/recreating a
	// retained bundle must not remove its durable hard-protection provenance.
	if _, err = load(""); err != nil {
		t.Fatal("legacy v5 rejected", err)
	}
	if _, err = load(`,"enrollment_bundle_files":[]`); err != nil {
		t.Fatal("explicit empty array rejected", err)
	}
	for _, raw := range []string{`null`, `"/root/bundle.json"`, `[null]`, `[""]`, `["relative.json"]`, `["/root/../root/bundle.json"]`, `["/root//bundle.json"]`, `["/root/bundle\u0000.json"]`, `["/root/bundle.json","/root/bundle.json"]`, `["` + "/" + strings.Repeat("a", 4096) + `"]`} {
		bad := fmt.Sprintf(base, `,"enrollment_bundle_files":`+raw)
		if _, err = DecodeForFleetMutation([]byte(bad)); err == nil {
			t.Fatalf("mutation accepted malformed bundle provenance: %s", raw)
		}
		if _, err = load(`,"enrollment_bundle_files":` + raw); err == nil {
			t.Fatalf("runtime accepted malformed bundle provenance: %s", raw)
		}
	}
	paths := make([]string, 129)
	for i := range paths {
		paths[i] = fmt.Sprintf("/root/bundle-%d.json", i)
	}
	raw, _ := json.Marshal(paths)
	if _, err = load(`,"enrollment_bundle_files":` + string(raw)); err == nil {
		t.Fatal("accepted excessive protected bundle paths")
	}
	if _, err = DecodeForFleetMutation([]byte(fmt.Sprintf(base, `,"enrollment_bundle_files":`+string(raw)))); err == nil {
		t.Fatal("mutation accepted excessive protected bundle paths")
	}
	raw, _ = json.Marshal(paths[:128])
	if _, err = load(`,"enrollment_bundle_files":` + string(raw)); err != nil {
		t.Fatal("rejected valid provenance bound", err)
	}
	duplicate := field + field
	if _, err = load(duplicate); err == nil {
		t.Fatal("accepted duplicate bundle-path field")
	}
	if _, err = DecodeForFleetMutation([]byte(fmt.Sprintf(base, duplicate))); err == nil {
		t.Fatal("mutation accepted duplicate bundle-path field")
	}
}
