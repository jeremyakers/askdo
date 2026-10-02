package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
)

func TestGatewayRootConnectProtectsRetainedBundlesAcrossReenrollment(t *testing.T) {
	dir, serverPath := gatewayOperatorFixture(t)
	var out, stderr bytes.Buffer
	call := func(args ...string) {
		t.Helper()
		out.Reset()
		stderr.Reset()
		if code := runGateway(args, &out, &stderr); code != 0 {
			t.Fatalf("command failed: %d %s", code, stderr.String())
		}
	}
	first := filepath.Join(dir, "host-pi-bundle.json")
	second := filepath.Join(dir, "different-host-bundle.json")
	for _, path := range []string{first, second} {
		call("hosts", "add", "--config", serverPath, "--output", path, "--channel", "default", "--default-channel", "default")
	}
	firstBytes, _ := os.ReadFile(first)
	secondBytes, _ := os.ReadFile(second)
	host := filepath.Join(dir, "host.json")
	creds := filepath.Join(dir, "custom-credentials")
	before := []byte(`{"config_version":4,"inspection":{"read_roots":["/"],"deny_paths":["/root/local-deny"],"sensitive_masks":["*.secret"]},"review":{"mode":"approval_only","models":[]},"limits":{},"telegram":{"token_file":"/placeholder","operator_user_id":0,"chat_id":0}}`)
	if err := os.WriteFile(host, before, 0600); err != nil {
		t.Fatal(err)
	}
	old, err := config.DecodeForMutation(before)
	if err != nil {
		t.Fatal(err)
	}
	connect := func(source string, force bool) *config.Config {
		t.Helper()
		args := []string{"connect", "--config", host, "--enrollment", source, "--credentials-dir", creds}
		if force {
			args = append(args, "--force")
		}
		call(args...)
		cfg, err := config.Load(host)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	assertPaths := func(cfg *config.Config, sources []string) {
		t.Helper()
		want := append([]string{cfg.Fleet.EnrollmentFile, cfg.Fleet.VerificationKeyFile}, sources...)
		if !reflect.DeepEqual(cfg.CredentialPaths(), want) {
			t.Fatalf("bundle provenance lost: got %v want %v", cfg.CredentialPaths(), want)
		}
		if !reflect.DeepEqual(cfg.Inspection, old.Inspection) {
			t.Fatal("import changed local inspection policy")
		}
	}
	one := connect(first, false)
	assertPaths(one, []string{first})
	originalID := one.Fleet.HostID
	assertPaths(connect(first, true), []string{first})
	two := connect(second, false)
	if two.Fleet.HostID == originalID {
		t.Fatal("fixture did not re-enroll with a different host")
	}
	assertPaths(two, []string{first, second})
	assertPaths(connect(second, true), []string{first, second})
	for _, item := range []struct {
		path   string
		before []byte
	}{{first, firstBytes}, {second, secondBytes}} {
		after, err := os.ReadFile(item.path)
		if err != nil || !bytes.Equal(item.before, after) {
			t.Fatal("import changed or removed owner bundle", err)
		}
	}
	if err = os.Remove(first); err != nil {
		t.Fatal(err)
	}
	still, err := config.Load(host)
	if err != nil {
		t.Fatal("deleted source blocked config load", err)
	}
	assertPaths(still, []string{first, second})
	// Provenance is not a dependency of offline credential/TLS checks either.
	still.Fleet.EnrollmentBundleFiles = append(still.Fleet.EnrollmentBundleFiles, filepath.Join(dir, "deleted-directory", "bundle.json"))
	if code := checkFleetHost(still, false, &out, &stderr); code != 0 {
		t.Fatalf("deleted provenance directory blocked offline check: %d %s", code, stderr.String())
	}
}

func TestGatewayRootConnectBundleHistoryBoundIsAtomicAndDeduplicated(t *testing.T) {
	dir, serverPath := gatewayOperatorFixture(t)
	var out, stderr bytes.Buffer
	first := filepath.Join(dir, "first.json")
	second := filepath.Join(dir, "second.json")
	for _, source := range []string{first, second} {
		if code := runGateway([]string{"hosts", "add", "--config", serverPath, "--output", source, "--channel", "default", "--default-channel", "default"}, &out, &stderr); code != 0 {
			t.Fatalf("add %d %s", code, stderr.String())
		}
	}
	host := filepath.Join(dir, "host.json")
	creds := filepath.Join(dir, "custom-credentials")
	before := []byte(`{"config_version":4,"inspection":{"read_roots":["/"]},"review":{"mode":"approval_only","models":[]},"limits":{},"telegram":{"token_file":"/placeholder","operator_user_id":0,"chat_id":0}}`)
	if err := os.WriteFile(host, before, 0600); err != nil {
		t.Fatal(err)
	}
	args := func(source string) []string {
		return []string{"connect", "--config", host, "--enrollment", source, "--credentials-dir", creds}
	}
	if code := runGateway(args(first), &out, &stderr); code != 0 {
		t.Fatalf("connect %d %s", code, stderr.String())
	}
	cfg, err := config.Load(host)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Fleet.EnrollmentBundleFiles = []string{first}
	for i := 1; i < 128; i++ {
		cfg.Fleet.EnrollmentBundleFiles = append(cfg.Fleet.EnrollmentBundleFiles, fmt.Sprintf("/root/nonexistent-bundle-%d.json", i))
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(host, data, 0600); err != nil {
		t.Fatal(err)
	}
	if code := runGateway(append(args(first), "--force"), &out, &stderr); code != 0 {
		t.Fatalf("reapply duplicated full history: %d %s", code, stderr.String())
	}
	pinned, _ := os.ReadFile(host)
	entriesBefore, _ := os.ReadDir(creds)
	if code := runGateway(args(second), &out, &stderr); code == 0 {
		t.Fatal("accepted 129th bundle source")
	}
	after, _ := os.ReadFile(host)
	entriesAfter, _ := os.ReadDir(creds)
	if !bytes.Equal(pinned, after) || len(entriesBefore) != len(entriesAfter) {
		t.Fatal("history-bound failure changed config or installed credentials")
	}
}
