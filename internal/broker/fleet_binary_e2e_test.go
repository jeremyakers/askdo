//go:build askdo_fleet_fixture

package broker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/store"
)

// Binary fleet QA: every operator surface below runs through the actual
// compiled fixture binary: `gateway init`, offline `gateway check`, `hosts
// add`/`list`/`revoke` (revoke against the live gateway database while
// serving), `gateway connect` against v4 host configs with placeholder
// legacy provider/bot sections, offline host `config check`, `gateway
// --help`, and `gateway serve` over verified TLS. The two host root brokers
// run in-process against isolated spool/socket/SQLite paths loading the
// exact v5 configs that `connect` wrote. All credentials, chats and
// providers are disposable loopback fixtures; secrets never appear in argv,
// and bundle bearers are only consumed by `connect` itself.

type binaryFleetHost struct {
	harness *brokerHarness
	root    string
	hostID  string
}

// runFleetCLI executes the compiled fixture binary as the root operator and
// requires a zero exit status, surfacing stderr precisely on failure.
func runFleetCLI(t *testing.T, binary string, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(binary, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("`askdo %s` exit=%v stderr: %s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}

func binaryFleetTLS(t *testing.T, write func(string, []byte, os.FileMode) string) (certPEM []byte, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "askdo-fleet-binary-fixture"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, write("tls.crt", certPEM, 0444), write("tls.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
}

// bundleMeta captures only the non-secret operator metadata of an exported
// enrollment bundle; the bearer is never parsed or logged by this fixture.
type bundleMeta struct {
	URL             string   `json:"url"`
	HostID          string   `json:"host_id"`
	AllowedProfiles []string `json:"allowed_profiles"`
	DefaultProfiles []string `json:"default_profiles"`
}

func parseBundleMeta(t *testing.T, path string) bundleMeta {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var meta bundleMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("bundle %s not valid JSON: %v", path, err)
	}
	if meta.HostID == "" || !strings.HasPrefix(meta.HostID, "host_") {
		t.Fatalf("bundle %s missing host_id", path)
	}
	return meta
}

// hostEnabled parses `gateway hosts list` output into host_id -> enabled.
func hostEnabled(t *testing.T, listOutput string) map[string]bool {
	t.Helper()
	enabled := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(listOutput), "\n") {
		if line == "" || strings.HasPrefix(line, "no ") {
			continue
		}
		fields := strings.Fields(line)
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "enabled=") {
				enabled[fields[0]] = strings.TrimPrefix(f, "enabled=") == "true"
			}
		}
	}
	return enabled
}

func TestBinaryFleetGatewayServeTwoHosts(t *testing.T) {
	requireRootTest(t)
	if os.Getenv("ASKDO_FLEET_BINARY_TEST") != "1" {
		t.Skip("requires disposable binary fleet fixture container (scripts/test-fleet-binary.sh)")
	}
	binary := os.Getenv("ASKDO_FLEET_BINARY")
	if binary == "" {
		t.Fatal("ASKDO_FLEET_BINARY must name the fixture-tagged compiled askdo binary")
	}
	if info, err := os.Stat(binary); err != nil || info.Mode().Perm()&0111 == 0 {
		t.Fatalf("fixture binary not executable: %s (%v)", binary, err)
	}

	// The gateway CLI validates that every credential/database path it loads
	// sits under root-owned, non-group/world-writable directories; /tmp fails,
	// so the whole gateway and host file set lives in a dedicated root-only
	// trusted tree.
	safeDir, err := os.MkdirTemp("/run", "askdo-fleet-binary-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(safeDir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(safeDir) })
	write := func(name string, data []byte, mode os.FileMode) string {
		p := filepath.Join(safeDir, name)
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	var modelCalls atomic.Int64
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modelCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": "", "tool_calls": []any{map[string]any{"id": "call-1", "type": "function", "function": map[string]any{"name": "submit_review", "arguments": `{"risk":"1","summary":"Disposable binary fleet fixture","effects":["Prints root UID"],"warnings":[],"missing_context":[],"reversibility":"No state changed","intent_match":"consistent"}`}}}}, "finish_reason": "tool_calls"}}})
	}))
	t.Cleanup(provider.Close)

	// The reusable fake's token lacks a numeric bot identity; a local HTTP
	// wire proxy changes only the path so the gateway still loads it.
	bot := faketelegram.New(t)
	u, _ := url.Parse(bot.URL())
	proxy := httputil.NewSingleHostReverseProxy(u)
	director := proxy.Director
	gatewayToken := "42:" + strings.Repeat("f", 32)
	proxy.Director = func(r *http.Request) {
		director(r)
		r.URL.Path = strings.Replace(r.URL.Path, "/bot"+gatewayToken+"/", "/bot"+bot.Token()+"/", 1)
	}
	tg := httptest.NewServer(proxy)
	t.Cleanup(tg.Close)

	certPEM, certPath, keyPath := binaryFleetTLS(t, write)
	tokenPath := write("tg.token", []byte(gatewayToken), 0600)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gatewayURL := "https://" + listener.Addr().String()
	listener.Close()

	// Real compiled CLI: initialize the gateway (generates signing seed/pub
	// and the database, seeds the default bot/channel).
	gwCfgPath := filepath.Join(safeDir, "gateway-config.json")
	dbPath := filepath.Join(safeDir, "gateway.db")
	runFleetCLI(t, binary, "gateway", "init",
		"--config", gwCfgPath,
		"--url", gatewayURL,
		"--listen", strings.TrimPrefix(gatewayURL, "https://"),
		"--tls-cert", certPath,
		"--tls-key", keyPath,
		"--bot-token-file", tokenPath,
		"--chat-id", strconv.FormatInt(telegramChat, 10),
		"--operator-user-id", strconv.FormatInt(telegramOperator, 10),
		"--database", dbPath)

	// Authorized operator workflow: declare the disposable synthetic local
	// profile by editing the initialized config JSON, then validate offline.
	gwCfgData, err := os.ReadFile(gwCfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var gwCfg gateway.Config
	if err := json.Unmarshal(gwCfgData, &gwCfg); err != nil {
		t.Fatalf("CLI-initialized gateway config not decodable: %v", err)
	}
	gwCfg.Profiles = []config.ModelConfig{{Name: "local", API: "openai_chat", BaseURL: provider.URL, Model: "fixture", DataBoundary: "local", RequestTimeout: config.Duration(10 * time.Second)}}
	gwCfgJSON, err := json.MarshalIndent(gwCfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gwCfgPath, append(gwCfgJSON, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if out := runFleetCLI(t, binary, "gateway", "check", "--config", gwCfgPath); !strings.Contains(out, "gateway configuration valid") {
		t.Fatalf("binary `gateway check` unexpected output: %s", out)
	}
	if help := runFleetCLI(t, binary, "gateway", "--help"); !strings.Contains(help, "connect") || !strings.Contains(help, "revoke") {
		t.Fatalf("binary `gateway --help` missing documented subcommands: %s", help)
	}

	// Enroll both hosts through the CLI; bundles carry the public metadata
	// this fixture asserts and the bearer that only `connect` consumes.
	metas := make([]bundleMeta, 2)
	bundlePaths := make([]string, 2)
	for i, name := range []string{"bundle-a.json", "bundle-b.json"} {
		bundlePaths[i] = filepath.Join(safeDir, name)
		out := runFleetCLI(t, binary, "gateway", "hosts", "add",
			"--config", gwCfgPath,
			"--output", bundlePaths[i],
			"--profile", "local",
			"--channel", "default",
			"--default-channel", "default",
			"--ca-file", certPath)
		metas[i] = parseBundleMeta(t, bundlePaths[i])
		if !strings.Contains(out, metas[i].HostID) {
			t.Fatalf("`hosts add` output missing exported host ID: %s", out)
		}
		if metas[i].URL != gatewayURL || len(metas[i].DefaultProfiles) != 1 || metas[i].DefaultProfiles[0] != "local" || len(metas[i].AllowedProfiles) != 1 || metas[i].AllowedProfiles[0] != "local" {
			t.Fatalf("bundle %d metadata mismatch: %+v", i, metas[i])
		}
	}
	if metas[0].HostID == metas[1].HostID {
		t.Fatal("CLI exported colliding host IDs")
	}
	listed := hostEnabled(t, runFleetCLI(t, binary, "gateway", "hosts", "list", "--config", gwCfgPath))
	for _, meta := range metas {
		if ok, present := listed[meta.HostID]; !present || !ok {
			t.Fatalf("hosts list does not show %s enabled: %v", meta.HostID, listed)
		}
	}

	// v4 host configs with placeholder legacy provider/bot sections (never
	// read by connect, discarded by the conversion); operator budgets,
	// limits, masks policy and local_only are retained across connect.
	writeHostV4 := func(hroot string) string {
		v4 := map[string]any{
			"config_version": 4,
			"inspection": map[string]any{
				"read_roots": []string{"/usr/bin", "/usr/local/bin"},
				"deny_paths": []string{"/proc", "/sys"},
			},
			"review": map[string]any{
				"mode":       "required",
				"local_only": true,
				"models": []map[string]any{{
					"name":            "standalone-local",
					"api":             "openai_chat",
					"base_url":        "http://127.0.0.1:11434/v1",
					"model":           "placeholder-unused",
					"data_boundary":   "local",
					"request_timeout": "5s",
				}},
				"request_timeout":             "10s",
				"total_timeout":               "1m",
				"max_model_calls_per_attempt": 32,
				"max_output_tokens":           8192,
			},
			"limits": map[string]any{
				"max_inspected_files":      256,
				"max_inspected_bytes":      8 << 20,
				"max_log_bytes_per_stream": 32 << 20,
			},
			"telegram": map[string]any{
				"token_file":       filepath.Join(hroot, "legacy-placeholder.token"),
				"operator_user_id": telegramOperator,
				"chat_id":          telegramChat,
				"approval_ttl":     "10m",
			},
		}
		data, err := json.MarshalIndent(v4, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(hroot, "config.json")
		if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	newHost := func(i int) binaryFleetHost {
		hroot := filepath.Join(safeDir, []string{"host-a", "host-b"}[i])
		if err := os.MkdirAll(hroot, 0700); err != nil {
			t.Fatal(err)
		}
		hostCfgPath := writeHostV4(hroot)
		// Real compiled CLI: apply the enrollment bundle, writing v5 config
		// and credentials with managed root ownership, then check offline.
		runFleetCLI(t, binary, "gateway", "connect", "--config", hostCfgPath, "--enrollment", bundlePaths[i])
		runFleetCLI(t, binary, "config", "check", "--config", hostCfgPath)
		cfg, err := config.Load(hostCfgPath)
		if err != nil {
			t.Fatalf("connect-written v5 host config not loadable: %v", err)
		}
		if cfg.Fleet == nil || cfg.Fleet.HostID != metas[i].HostID || len(cfg.Review.GatewayProfiles) != 1 || cfg.Review.GatewayProfiles[0] != "local" || !cfg.Review.LocalOnly {
			t.Fatalf("connect-written config mismatch: %+v fleet=%+v", cfg.Review, cfg.Fleet)
		}
		uid, gid := reviewerTestCredentials(t)
		worker := &processWorker{binary: binary, home: "/tmp", uid: uid, gid: gid}
		d, listener, err := newDaemon("", daemonOptions{cfg: cfg, socketPath: filepath.Join(hroot, "run", "request.sock"), storePath: filepath.Join(hroot, "jobs.sqlite3"), spoolRoot: filepath.Join(hroot, "jobs"), worker: worker, executor: SystemExecutor{}, skipSocketOwnership: true})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- d.serve(ctx, listener) }()
		h := binaryFleetHost{harness: &brokerHarness{daemon: d, socket: d.socketPath, cancel: cancel, done: done}, root: hroot, hostID: metas[i].HostID}
		t.Cleanup(func() {
			h.harness.cancel()
			if err := <-h.harness.done; err != nil {
				t.Error(err)
			}
			h.harness.daemon.close()
		})
		return h
	}
	hosts := []binaryFleetHost{newHost(0), newHost(1)}

	// Actual compiled gateway process serving the CLI-initialized config;
	// the fixture-tagged binary wires ASKDO_FLEET_TELEGRAM_URL to the strict
	// loopback HTTP override.
	var stderr bytes.Buffer
	cmd := exec.Command(binary, "gateway", "serve", "--config", gwCfgPath)
	cmd.Env = append(os.Environ(), "ASKDO_FLEET_TELEGRAM_URL="+tg.URL)
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start compiled gateway: %v", err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- cmd.Wait() }()
	exited := false
	t.Cleanup(func() {
		if exited {
			return
		}
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			<-stopped
		}
	})

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("fixture CA not parseable")
	}
	probe := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	ready := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-stopped:
			exited = true
			t.Fatalf("compiled gateway exited before serving: %v; stderr: %s", err, stderr.String())
		default:
		}
		resp, err := probe.Get(gatewayURL + "/v1/catalog?submitter_uid=0")
		if err == nil {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("compiled gateway never served verified TLS; stderr: %s", stderr.String())
	}
	t.Log("compiled `askdo gateway serve` answers verified TLS")

	// Colliding canonical job IDs: both fresh local stores issue the same ID.
	idA := reserveForTest(t, hosts[0].harness.socket, 0)
	idB := reserveForTest(t, hosts[1].harness.socket, 0)
	if idA != idB {
		t.Fatalf("canonical job IDs did not collide across isolated hosts: %q vs %q", idA, idB)
	}

	submit := func(h binaryFleetHost, id string) net.Conn {
		request := submitRequest(id, "binary fleet two-host QA")
		request.Argv = []string{"/usr/bin/id", "-u"}
		conn, err := net.Dial("unix", h.harness.socket)
		if err != nil {
			t.Fatal(err)
		}
		sendFrame(t, conn, request)
		readFrame(t, conn)
		return conn
	}
	connA := submit(hosts[0], idA)
	defer connA.Close()
	jobA := awaitRootFleetState(t, connA, hosts[0].harness.daemon.store, idA, store.StateAwaitingHuman, store.StateFailed)
	if jobA.State != store.StateAwaitingHuman {
		t.Fatalf("host A never reached frozen human review: %s", jobA.State)
	}
	cardA, ok := bot.Card()
	if !ok {
		t.Fatal("host A card missing")
	}
	connB := submit(hosts[1], idB)
	defer connB.Close()
	jobB := awaitRootFleetState(t, connB, hosts[1].harness.daemon.store, idB, store.StateAwaitingHuman, store.StateFailed)
	if jobB.State != store.StateAwaitingHuman {
		t.Fatalf("host B never reached frozen human review: %s", jobB.State)
	}
	cardB, ok := bot.Card()
	if !ok || cardB.ID == cardA.ID {
		t.Fatalf("host B card missing or reused: %+v vs %+v", cardB, cardA)
	}

	// Approving host B while host A still waits: one waiting host must not
	// block the other's decision, even with identical local job IDs.
	bot.QueueCallback(1, "binary-b", telegramOperator, telegramChat, cardB.ID, cardB.ButtonData("a:"))
	jobB = awaitRootFleetState(t, connB, hosts[1].harness.daemon.store, idB, store.StateFinished, store.StateFailed)
	if jobB.State != store.StateFinished {
		t.Fatalf("host B state=%s audit=%s", jobB.State, jobB.ApprovalJSON)
	}
	jobA, err = hosts[0].harness.daemon.store.GetJob(context.Background(), 0, idA)
	if err != nil || jobA.State != store.StateAwaitingHuman {
		t.Fatalf("waiting host A disturbed by host B decision: %s %v", jobA.State, err)
	}
	bot.QueueCallback(2, "binary-a", telegramOperator, telegramChat, cardA.ID, cardA.ButtonData("a:"))
	jobA = awaitRootFleetState(t, connA, hosts[0].harness.daemon.store, idA, store.StateFinished, store.StateFailed)
	if jobA.State != store.StateFinished {
		t.Fatalf("host A state=%s audit=%s", jobA.State, jobA.ApprovalJSON)
	}

	// Each host ran the benign root command exactly once.
	for i, job := range []store.Job{jobA, jobB} {
		output, err := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
		if err != nil || string(output) != "0\n" {
			t.Fatalf("host %d not exactly one real root id -u: %q %v", i, output, err)
		}
	}
	if modelCalls.Load() != 2 {
		t.Fatalf("expected one provider turn per host, got %d", modelCalls.Load())
	}

	// Revoke host A through the CLI against the live gateway database, then
	// prove revocation is effective immediately: A's next job is refused
	// closed with no dispatch and no model turn, while host B still
	// completes a full authorized cycle.
	runFleetCLI(t, binary, "gateway", "hosts", "revoke", hosts[0].hostID, "--config", gwCfgPath)
	listed = hostEnabled(t, runFleetCLI(t, binary, "gateway", "hosts", "list", "--config", gwCfgPath))
	if listed[hosts[0].hostID] {
		t.Fatalf("revoked host A still listed enabled: %v", listed)
	}
	if ok, present := listed[hosts[1].hostID]; !present || !ok {
		t.Fatalf("host B disturbed by host A revocation: %v", listed)
	}

	idA2 := reserveForTest(t, hosts[0].harness.socket, 0)
	connA2 := submit(hosts[0], idA2)
	defer connA2.Close()
	jobA2 := awaitRootFleetState(t, connA2, hosts[0].harness.daemon.store, idA2, store.StateFailed)
	if jobA2.State != store.StateFailed {
		t.Fatalf("revoked host A job not failed closed: %s", jobA2.State)
	}
	if output, err := os.ReadFile(filepath.Join(jobA2.SpoolDir, "stdout.log")); err != nil || len(output) != 0 {
		t.Fatalf("revoked host A produced output: %q %v", output, err)
	}
	if modelCalls.Load() != 2 {
		t.Fatalf("revoked host A reached the model provider: %d turns", modelCalls.Load())
	}

	idB2 := reserveForTest(t, hosts[1].harness.socket, 0)
	connB2 := submit(hosts[1], idB2)
	defer connB2.Close()
	jobB2 := awaitRootFleetState(t, connB2, hosts[1].harness.daemon.store, idB2, store.StateAwaitingHuman, store.StateFailed)
	if jobB2.State != store.StateAwaitingHuman {
		t.Fatalf("host B post-revocation job failed: %s", jobB2.State)
	}
	cardB2, ok := bot.Card()
	if !ok {
		t.Fatal("host B post-revocation card missing")
	}
	bot.QueueCallback(3, "binary-b2", telegramOperator, telegramChat, cardB2.ID, cardB2.ButtonData("a:"))
	jobB2 = awaitRootFleetState(t, connB2, hosts[1].harness.daemon.store, idB2, store.StateFinished, store.StateFailed)
	if jobB2.State != store.StateFinished {
		t.Fatalf("host B post-revocation state=%s audit=%s", jobB2.State, jobB2.ApprovalJSON)
	}
	if output, err := os.ReadFile(filepath.Join(jobB2.SpoolDir, "stdout.log")); err != nil || string(output) != "0\n" {
		t.Fatalf("host B post-revocation not exactly one real root id -u: %q %v", output, err)
	}
	if modelCalls.Load() != 3 {
		t.Fatalf("expected exactly one provider turn per successful host job, got %d", modelCalls.Load())
	}

	// Same gateway, colliding local job IDs, proofs bound to separate hosts.
	var submissions [2]fleetproto.TicketSubmission
	for i, job := range []store.Job{jobA, jobB} {
		data, err := os.ReadFile(filepath.Join(job.SpoolDir, "fleet-submission.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &submissions[i]); err != nil {
			t.Fatal(err)
		}
	}
	if submissions[0].Ticket.Binding.JobID != submissions[1].Ticket.Binding.JobID {
		t.Fatal("job ID collision not exercised")
	}
	if submissions[0].Ticket.Binding.HostID == submissions[1].Ticket.Binding.HostID {
		t.Fatal("tickets not bound to separate hosts")
	}
	pubData, err := os.ReadFile(filepath.Join(safeDir, "credentials", "verification.pub"))
	if err != nil {
		t.Fatalf("CLI-generated verification key missing: %v", err)
	}
	pubRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubData)))
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		t.Fatalf("CLI-generated verification key invalid: %v", err)
	}
	pub := ed25519.PublicKey(pubRaw)
	for i, job := range []store.Job{jobA, jobB} {
		if submissions[i].Ticket.Binding.HostID != fleetproto.ID(hosts[i].hostID) {
			t.Fatalf("host %d ticket bound to %s", i, submissions[i].Ticket.Binding.HostID)
		}
		var audit struct {
			FleetEvents [][]byte `json:"fleet_events"`
		}
		if json.Unmarshal(job.ApprovalJSON, &audit) != nil || len(audit.FleetEvents) == 0 {
			t.Fatalf("host %d missing signed audit: %s", i, job.ApprovalJSON)
		}
		for _, envelope := range audit.FleetEvents {
			event, _, err := fleetproto.Verify[fleetproto.Event](pub, envelope)
			if err != nil || event.HostID != fleetproto.ID(hosts[i].hostID) {
				t.Fatalf("host %d audit proof not bound to its host: %v", i, err)
			}
		}
	}
	t.Logf("binary CLI init/check/add/connect/serve/revoke approved colliding job %q for hosts %s and %s; root output 0 once each; revoked host refused closed", idA, hosts[0].hostID, hosts[1].hostID)
}
