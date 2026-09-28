package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/client"
	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
)

func TestClientSubmitAdminOnlyMaskDoesNotReachWorker(t *testing.T) {
	const sentinel = "KEY=unique-sentinel\n"
	bundle := t.TempDir()
	for name, content := range map[string]string{"main.sh": "echo ok\n", "admin.privmask": sentinel, "opted.secret": sentinel} {
		if err := os.WriteFile(filepath.Join(bundle, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := testConfig(testUID)
	cfg.Inspection = config.InspectionConfig{ReadRoots: []string{bundle}, SensitiveMasks: []string{"*.privmask", "*.secret"}}
	bootstrap := make(chan proto.Bootstrap, 1)
	h := newBrokerHarnessWithConfig(t, &ScriptedWorker{Config: ScriptedWorkerConfig{Bootstrap: bootstrap}}, nil, cfg)
	var stdout, stderr bytes.Buffer
	_ = client.Run(context.Background(), []string{"--detach", "--reason", "synthetic mask check", "--bundle", bundle, "--entry", "main.sh", "--bundle-include-sensitive", "opted.secret", "--"}, client.Options{SocketPath: h.socket, Stdout: &stdout, Stderr: &stderr, Interrupt: make(chan os.Signal)})
	var boot proto.Bootstrap
	select {
	case boot = <-bootstrap:
	default:
		t.Fatalf("worker never bootstrapped; client stderr=%s", stderr.String())
	}
	index := readJobCaptureIndex(t, h, boot.RequestID)
	for _, name := range []string{"admin.privmask", "opted.secret"} {
		var masked captureRecord
		for _, record := range index.Files {
			if record.Path == name {
				masked = record
			}
		}
		if !masked.Masked {
			t.Fatalf("mask not persisted for %s: %+v", name, masked)
		}
	}
	visible, err := json.Marshal(boot.Operation)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(sentinel))
	if strings.Contains(string(visible), "admin.privmask") || strings.Contains(string(visible), "opted.secret") || strings.Contains(string(visible), fmt.Sprintf("%x", hash)) || strings.Contains(string(visible), "unique-sentinel") {
		t.Fatalf("worker received masked metadata: %s", visible)
	}
	stored, err := h.daemon.store.GetJob(context.Background(), testUID, boot.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(stored.SpoolDir, "reviewer-stderr.log")); err != nil || strings.Contains(string(data), sentinel) {
		t.Fatalf("reviewer stderr contains sentinel or is unreadable: %v", err)
	}
}

func TestCaptureSubmittedBundleRequiresPolicyBeforeWriting(t *testing.T) {
	spool, err := createSpool(t.TempDir(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	request := proto.SubmitRequest{Mode: "bundle", Entry: "main.sh", Files: []proto.BundleFile{{Path: "main.sh", ContentBase64: base64.StdEncoding.EncodeToString([]byte("echo ok\n"))}}}
	if err := captureSubmittedBundle(spool, request, config.LimitsConfig{MaxInspectedFiles: 2, MaxInspectedBytes: 64}, nil); err == nil {
		t.Fatal("nil policy allowed capture")
	}
	for _, path := range []string{spool.bundle, spool.captureIndex} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("nil-policy capture wrote %s: %v", path, err)
		}
	}
}

func TestSensitiveInclusionIsWithheldEvenWhenAdminReplacesDefaultMask(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(testUID)
	cfg.Inspection = config.InspectionConfig{ReadRoots: []string{root}, SensitiveMasks: []string{"*.privmask"}}
	h := newBrokerHarnessWithConfig(t, &ScriptedWorker{}, nil, cfg)
	spool, err := createSpool(filepath.Join(t.TempDir(), "spool"), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	const secret = "BUNDLE_SECRET=synthetic-sentinel\n"
	request := proto.SubmitRequest{Mode: "bundle", Entry: "main.sh", SensitiveInclusions: []string{".env"}, Files: []proto.BundleFile{
		{Path: "main.sh", ContentBase64: base64.StdEncoding.EncodeToString([]byte("echo safe\n"))},
		{Path: ".env", ContentBase64: base64.StdEncoding.EncodeToString([]byte(secret))},
	}}
	if err := captureSubmittedBundle(spool, request, cfg.Limits, h.daemon.policy); err != nil {
		t.Fatal(err)
	}
	index, err := readCaptureIndex(spool.captureIndex)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Files) != 2 || !index.Files[0].Masked && !index.Files[1].Masked {
		t.Fatalf("explicit sensitive inclusion was not broker-masked: %+v", index.Files)
	}
	j := &jobRuntime{daemon: h.daemon, req: request, spool: spool}
	result, err := j.readPath(1, proto.ReadPathRequest{Base: "bundle", Path: ".env", Offset: 0, MaxBytes: 128})
	if err != nil || result.Status != "withheld" || strings.Contains(string(result.Payload), "synthetic-sentinel") {
		t.Fatalf("included secret leaked to reviewer: %+v err=%v", result, err)
	}
}

func TestMaskedBundleStagedButWithheldFromReviewer(t *testing.T) {
	const sentinel = "KEY=unique-sentinel\n"
	root := t.TempDir()
	cfg := testConfig(testUID)
	cfg.Inspection = config.InspectionConfig{ReadRoots: []string{root}, SensitiveMasks: []string{".env", "*.secret"}}
	h := newBrokerHarnessWithConfig(t, &ScriptedWorker{}, nil, cfg)
	spool, err := createSpool(filepath.Join(t.TempDir(), "spool"), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	request := proto.SubmitRequest{Mode: "bundle", Entry: "main.sh", SensitiveInclusions: []string{".env"}, Files: []proto.BundleFile{
		{Path: "main.sh", ContentBase64: base64.StdEncoding.EncodeToString([]byte("echo ok\n"))},
		{Path: ".env", ContentBase64: base64.StdEncoding.EncodeToString([]byte(sentinel))},
		{Path: "admin.secret", ContentBase64: base64.StdEncoding.EncodeToString([]byte(sentinel))},
	}}
	if err := captureSubmittedBundle(spool, request, cfg.Limits, h.daemon.policy); err != nil {
		t.Fatal(err)
	}
	j := &jobRuntime{daemon: h.daemon, req: request, spool: spool}
	index, err := readCaptureIndex(spool.captureIndex)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range index.Files {
		if record.Path == "main.sh" {
			if record.Masked {
				t.Fatal("entry masked")
			}
			continue
		}
		if !record.Masked {
			t.Fatalf("unmasked secret: %s", record.Path)
		}
		data, err := os.ReadFile(filepath.Join(spool.bundle, record.Path))
		if err != nil || string(data) != sentinel {
			t.Fatalf("execution spool %q: %v", record.Path, err)
		}
		for _, result := range []func() (proto.InspectResult, error){
			func() (proto.InspectResult, error) {
				return j.readPath(1, proto.ReadPathRequest{Base: "bundle", Path: record.Path, MaxBytes: 128})
			},
			func() (proto.InspectResult, error) {
				return j.searchPath(2, proto.SearchPathRequest{Base: "bundle", Path: record.Path, Pattern: "KEY=.*"})
			},
			func() (proto.InspectResult, error) {
				return j.listPath(3, proto.ListPathRequest{Base: "bundle", Path: record.Path})
			},
		} {
			got, err := result()
			if err != nil || got.Status != "withheld" || len(got.Payload) != 0 {
				t.Fatalf("masked result=%+v err=%v", got, err)
			}
		}
		if _, ok := j.maskedBundlePaths[record.Path]; !ok {
			t.Fatalf("missing path observation: %s", record.Path)
		}
	}
	visible, err := json.Marshal(j.bootstrap().Operation)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(visible), "secret") || strings.Contains(string(visible), ".env") || strings.Contains(string(visible), "unique-sentinel") || strings.Contains(string(visible), `"captures"`) {
		t.Fatalf("model capture metadata=%s", visible)
	}
	global, err := j.searchPath(4, proto.SearchPathRequest{Base: "bundle", Path: ".", Pattern: "KEY=.*"})
	if err != nil || global.Status != "ok" {
		t.Fatalf("global search=%+v err=%v", global, err)
	}
	var search proto.SearchPathResult
	if err := json.Unmarshal(global.Payload, &search); err != nil {
		t.Fatal(err)
	}
	if len(search.Matches) != 0 || search.SkippedMasked != 2 || strings.Contains(string(global.Payload), "unique-sentinel") {
		t.Fatalf("global search=%s", global.Payload)
	}
}

func TestPrefixScopedSearchSkipsMaskedBundleWithoutLosingOtherMatches(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(testUID)
	cfg.Inspection = config.InspectionConfig{ReadRoots: []string{root}, SensitiveMasks: []string{".env"}}
	h := newBrokerHarnessWithConfig(t, &ScriptedWorker{}, nil, cfg)
	spool, err := createSpool(filepath.Join(t.TempDir(), "spool"), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	request := proto.SubmitRequest{Mode: "bundle", Entry: "sub/main.sh", Files: []proto.BundleFile{
		{Path: "sub/main.sh", ContentBase64: base64.StdEncoding.EncodeToString([]byte("echo public-marker\n"))},
		{Path: "sub/.env", ContentBase64: base64.StdEncoding.EncodeToString([]byte("KEY=unique-secret\n"))},
	}}
	if err := captureSubmittedBundle(spool, request, cfg.Limits, h.daemon.policy); err != nil {
		t.Fatal(err)
	}
	j := &jobRuntime{daemon: h.daemon, req: request, spool: spool}
	inspected, err := j.readPath(0, proto.ReadPathRequest{Base: "bundle", Path: "sub/.env", MaxBytes: 128})
	if err != nil || inspected.Status != "withheld" {
		t.Fatalf("masked path inspection = %+v, %v", inspected, err)
	}
	if _, ok := j.maskedBundlePaths["sub/.env"]; !ok {
		t.Fatal("read_path did not record the masked bundle path")
	}
	result, err := j.searchPath(1, proto.SearchPathRequest{Base: "bundle", Path: "sub", Pattern: "public-marker|unique-secret"})
	if err != nil || result.Status != "ok" {
		t.Fatalf("prefix-scoped search = %+v, %v; want usable unmasked results", result, err)
	}
	var found proto.SearchPathResult
	if err := json.Unmarshal(result.Payload, &found); err != nil {
		t.Fatal(err)
	}
	if found.SkippedMasked != 1 || len(found.Matches) != 1 || found.Matches[0].Path != "sub/main.sh" || strings.Contains(string(result.Payload), "unique-secret") {
		t.Fatalf("masked prefix search exposed or hid data: %+v", found)
	}
}

func TestConfiguredHostMaskRequestedAndResolved(t *testing.T) {
	j, root := newWithheldJob(t, func(cfg *config.Config, root string) { cfg.Inspection.SensitiveMasks = []string{"*.secret"} })
	secret := writeEvidenceFixture(t, root, "admin.secret", "KEY=unique-sentinel\n")
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(secret, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{secret, alias} {
		result := directCall(t, j, "read_path", proto.ReadPathRequest{Base: "host", Path: path, MaxBytes: 128})
		if _, observed := j.withheldPaths[path]; result.Status != "withheld" || len(result.Payload) != 0 || !observed {
			t.Fatalf("host inspect %s=%+v", path, result)
		}
	}
	assertNoSecretInSpool(t, j, "unique-sentinel")
	if err := j.captureEvidence(); err != nil {
		t.Fatal(err)
	}
	index, err := readCaptureIndex(j.spool.captureIndex)
	if err != nil || len(index.Files) != 0 {
		t.Fatalf("host path entered capture index: %+v %v", index, err)
	}
}
