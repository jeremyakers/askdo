package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/operator"
)

func gatewayOperatorFixture(t *testing.T) (string, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("disposable root fixture required")
	}
	dir := t.TempDir()
	if err := operator.TrustedDirectory(dir, false); err != nil {
		t.Skip("TMPDIR must be inside a trusted disposable root directory")
	}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway.example"}, DNSNames: []string{"gateway.example"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certPath := write("tls.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0400)
	keyPath := write("tls.key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)}), 0600)
	bot := write("bot.token", []byte("12345:abcdefghijklmnopqrstuvwxyz0123456789"), 0600)
	path := filepath.Join(dir, "gateway.json")
	var out, stderr bytes.Buffer
	args := []string{"init", "--config", path, "--url", "https://gateway.example", "--listen", "127.0.0.1:9443", "--tls-cert", certPath, "--tls-key", keyPath, "--bot-token-file", bot, "--chat-id", "-100", "--operator-user-id", "77", "--database", filepath.Join(dir, "gateway.db")}
	if code := runGateway(args, &out, &stderr); code != 0 {
		t.Fatalf("init=%d %s", code, stderr.String())
	}
	c, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := gateway.LoadSigningKey(c.SigningKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(filepath.Join(dir, "credentials", "verification.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(pub)) != base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) || len(c.Profiles) != 0 {
		t.Fatal("invalid generated signing identity or human-only template")
	}
	return dir, path
}

func TestGatewayRootEnrollmentLifecycle(t *testing.T) {
	dir, path := gatewayOperatorFixture(t)
	var out, stderr bytes.Buffer
	centralToken := filepath.Join(dir, "central-codex.json")
	if code := runAuth([]string{"status", "openai-codex", "--token-file", centralToken}, &out, &stderr); code != 0 || !strings.Contains(out.String(), centralToken) {
		t.Fatalf("central auth path: %d %s %s", code, out.String(), stderr.String())
	}
	bundlePath := filepath.Join(dir, "enrollment.json")
	call := func(args ...string) int { out.Reset(); stderr.Reset(); return runGateway(args, &out, &stderr) }
	if code := call("hosts", "add", "--config", path, "--output", bundlePath, "--channel", "default", "--default-channel", "default", "--uid-channel", "0=default"); code != 0 {
		t.Fatalf("add=%d %s", code, stderr.String())
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := gateway.DecodeEnrollmentBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String()+stderr.String(), bundle.Bearer) {
		t.Fatal("bearer leaked")
	}
	db, err := os.ReadFile(filepath.Join(dir, "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(bundle.Bearer)
	if bytes.Contains(db, []byte(bundle.Bearer)) || bytes.Contains(db, raw) {
		t.Fatal("database contains bearer")
	}
	if code := call("hosts", "list", "--config", path); code != 0 || !strings.Contains(out.String(), bundle.HostID) || strings.Contains(out.String(), bundle.Bearer) {
		t.Fatalf("list=%d %s", code, out.String())
	}
	if code := call("check", "--config", path); code != 0 {
		t.Fatalf("offline=%d %s", code, stderr.String())
	}
	if code := call("hosts", "add", "--config", path, "--output", bundlePath, "--channel", "default", "--default-channel", "default"); code == 0 {
		t.Fatal("overwrote export")
	}
	c, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := gateway.OpenEnrollmentStore(c.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	hosts, err := store.List(t.Context())
	if err != nil || len(hosts) != 1 {
		t.Fatalf("failed export left enrollment: %v %v", hosts, err)
	}
	if code := call("hosts", "revoke", bundle.HostID, "--config", path); code != 0 {
		t.Fatalf("revoke=%d %s", code, stderr.String())
	}
	if _, err = store.Authenticate(t.Context(), bundle.HostID, bundle.Bearer); err == nil {
		t.Fatal("revoked host authenticates through live store")
	}
}

func TestGatewayRootInitFailureRemovesCreatedSecrets(t *testing.T) {
	dir, path := gatewayOperatorFixture(t)
	c, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	badToken := filepath.Join(dir, "bad-bot.token")
	if err = os.WriteFile(badToken, []byte("invalid-bot-secret-canary"), 0600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "failed.json")
	creds := filepath.Join(dir, "failed-creds")
	db := filepath.Join(dir, "failed.db")
	var out, stderr bytes.Buffer
	args := []string{"init", "--config", dest, "--url", c.PublicURL, "--listen", c.Listen, "--tls-cert", c.TLSCertFile, "--tls-key", c.TLSKeyFile, "--bot-token-file", badToken, "--chat-id", "-100", "--operator-user-id", "77", "--database", db, "--credentials-dir", creds}
	if code := runGateway(args, &out, &stderr); code == 0 {
		t.Fatal("init accepted invalid token")
	}
	for _, p := range []string{dest, db, filepath.Join(creds, "signing.seed"), filepath.Join(creds, "verification.pub")} {
		if _, err = os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("failed init retained %s", p)
		}
	}
	if strings.Contains(out.String()+stderr.String(), "invalid-bot-secret-canary") {
		t.Fatal("invalid token entered error log")
	}
}

func TestGatewayRootConnectPreservesPolicyAndRollsBack(t *testing.T) {
	dir, path := gatewayOperatorFixture(t)
	bundlePath := filepath.Join(dir, "enrollment.json")
	var out, stderr bytes.Buffer
	if code := runGateway([]string{"hosts", "add", "--config", path, "--output", bundlePath, "--channel", "default", "--default-channel", "default"}, &out, &stderr); code != 0 {
		t.Fatalf("add %d %s", code, stderr.String())
	}
	hostPath := filepath.Join(dir, "host.json")
	creds := filepath.Join(dir, "host-credentials")
	before := []byte(`{"config_version":4,"inspection":{"read_roots":[],"deny_paths":["/root/private"],"sensitive_masks":["*.secret"]},"review":{"mode":"required","local_only":true,"models":[{"name":"placeholder","api":"placeholder","base_url":"placeholder","model":"placeholder"}],"request_timeout":"17s","total_timeout":"3m","max_model_calls_per_attempt":5,"max_output_tokens":2345,"webfetch_enabled":true,"auto_approve_grants":[{"user":"root","max_risk":2}]},"limits":{"max_inspected_files":29,"max_inspected_bytes":4096,"max_log_bytes_per_stream":9999},"telegram":{"token_file":"/placeholder","chat_id":0,"operator_user_id":0,"approval_ttl":"13m"}}`)
	if err := os.WriteFile(hostPath, before, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"connect", "--config", hostPath, "--enrollment", bundlePath, "--credentials-dir", creds}
	if code := runGateway(args, &out, &stderr); code == 0 {
		t.Fatal("silently downgraded required review")
	}
	after, _ := os.ReadFile(hostPath)
	if !bytes.Equal(before, after) {
		t.Fatal("failure changed config")
	}
	old, err := config.DecodeForMutation(before)
	if err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := runGateway(append(args, "--approval-only"), &out, &stderr); code != 0 {
		t.Fatalf("connect=%d %s", code, stderr.String())
	}
	next, err := config.Load(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(next.Inspection, old.Inspection) || next.Limits != old.Limits || next.Review.LocalOnly != old.Review.LocalOnly || next.Review.MaxOutputTokens != 2345 || next.Review.MaxModelCallsPerAttempt != 5 || next.Review.RequestTimeout != old.Review.RequestTimeout || next.Review.TotalTimeout != old.Review.TotalTimeout || !reflect.DeepEqual(next.Review.AutoApproveGrants, old.Review.AutoApproveGrants) || !next.Review.WebfetchEnabled || next.Fleet.ApprovalTTL != 780 {
		t.Fatal("connect changed local policy/budgets")
	}
	for _, p := range []string{hostPath, next.Fleet.EnrollmentFile, next.Fleet.VerificationKeyFile} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if p == next.Fleet.VerificationKeyFile {
			want = 0400
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode=%o", p, info.Mode().Perm())
		}
	}
	current, _ := os.ReadFile(hostPath)
	if code := runGateway(args, &out, &stderr); code == 0 {
		t.Fatal("reapplication did not refuse overwrite")
	}
	after, _ = os.ReadFile(hostPath)
	if !bytes.Equal(current, after) {
		t.Fatal("overwrite refusal changed config")
	}
	if code := runGateway(append(args, "--force"), &out, &stderr); code != 0 {
		t.Fatalf("safe reapply %d %s", code, stderr.String())
	}
	// A failure after installing both credential files must remove those files
	// and retain byte-identical input. The invalid retained budget is not hidden.
	badPath := filepath.Join(dir, "bad.json")
	bad := bytes.Replace(before, []byte(`"max_log_bytes_per_stream":9999`), []byte(`"max_log_bytes_per_stream":0`), 1)
	if err := os.WriteFile(badPath, bad, 0600); err != nil {
		t.Fatal(err)
	}
	badCreds := filepath.Join(dir, "bad-credentials")
	badArgs := []string{"connect", "--config", badPath, "--enrollment", bundlePath, "--credentials-dir", badCreds, "--approval-only"}
	if code := runGateway(badArgs, &out, &stderr); code == 0 {
		t.Fatal("accepted invalid retained policy")
	}
	after, _ = os.ReadFile(badPath)
	entries, err := os.ReadDir(badCreds)
	if err != nil || len(entries) != 0 || !bytes.Equal(bad, after) {
		t.Fatal("failed connect not atomic")
	}
	var b gateway.EnrollmentBundle
	data, _ := os.ReadFile(bundlePath)
	if err = json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String()+stderr.String(), b.Bearer) {
		t.Fatal("connect leaked secret")
	}
	linkCreds := filepath.Join(dir, "link-credentials")
	if err = os.Mkdir(linkCreds, 0750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkCreds, b.HostID+".pub")
	if err = os.Symlink(next.Fleet.VerificationKeyFile, link); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(badPath, before, 0600); err != nil {
		t.Fatal(err)
	}
	if code := runGateway([]string{"connect", "--config", badPath, "--enrollment", bundlePath, "--credentials-dir", linkCreds, "--approval-only", "--force"}, &out, &stderr); code == 0 {
		t.Fatal("connect accepted symlink trust target")
	}
	after, _ = os.ReadFile(badPath)
	if !bytes.Equal(before, after) {
		t.Fatal("symlink failure changed config")
	}
	if _, err = os.Lstat(filepath.Join(linkCreds, b.HostID+".bearer")); !os.IsNotExist(err) {
		t.Fatal("symlink failure retained new bearer")
	}
}
