//go:build askdo_fleet_fixture

package broker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/faketelegram"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

// No production Telegram URL override is compiled into normal builds. This
// fixture uses production gateway/provider/reviewer/broker code and real SQLite.
type rootFleetFixture struct {
	broker            *brokerHarness
	bot               *faketelegram.Server
	gateway           *gateway.Server
	server            *httptest.Server
	db                *gateway.EnrollmentStore
	gatewayCfg        gateway.Config
	tgURL             string
	active            atomic.Pointer[gateway.Server]
	offline           atomic.Bool
	mu                sync.Mutex
	puts              [][]byte
	modelCalls        atomic.Int64
	modelRequests     atomic.Int64
	lost              chan struct{}
	publicKey         ed25519.PublicKey
	statuses          []int
	modelResponseHeld chan struct{}
	providerRequests  [][]byte
	hostConfigFile    string
	originalBundle    string
	canary            string // disposable enrollment bearer; never printed
}

type rootFixtureStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *rootFixtureStatusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

type rootFleetOptions struct {
	foreground            bool
	maxRisk               int
	profileTimeout        time.Duration
	holdModelResponse     bool
	hostOutputTokens      int
	originalBundle        bool
	protectOriginalBundle bool
	profileCondition      string
	exemptRoot            bool
}

func newRootFleetFixture(t *testing.T, binary, risk string, auto, captured, unreviewed bool, options ...rootFleetOptions) *rootFleetFixture {
	t.Helper()
	opts := rootFleetOptions{maxRisk: 4}
	if len(options) != 0 {
		opts = options[0]
		if opts.maxRisk == 0 {
			opts.maxRisk = 4
		}
	}
	f := &rootFleetFixture{bot: faketelegram.New(t), lost: make(chan struct{}, 1), modelResponseHeld: make(chan struct{}, 1)}
	root := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(root, name)
		mode := os.FileMode(0600)
		if name == "tls.crt" || name == "verify" || name == "ca.crt" {
			mode = 0444
			if opts.originalBundle {
				mode = 0400
			}
		}
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.modelCalls.Add(1)
		raw, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			t.Error("read provider request failed")
			return
		}
		f.mu.Lock()
		f.providerRequests = append(f.providerRequests, append([]byte(nil), raw...))
		f.mu.Unlock()
		var req struct {
			Messages []struct {
				Role string `json:"role"`
			}
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Errorf("model request: %v", err)
			return
		}
		seenResult := false
		for _, m := range req.Messages {
			if m.Role == "tool" {
				seenResult = true
			}
		}
		name, args := "read_path", `{"base":"host","path":"/usr/bin/id","offset":0,"max_bytes":256}`
		if captured {
			args = `{"base":"bundle","path":"stdin","offset":0,"max_bytes":65536}`
		}
		if opts.originalBundle {
			args = fmt.Sprintf(`{"base":"host","path":%q,"offset":0,"max_bytes":4096}`, f.originalBundle)
		}
		if seenResult {
			name = "submit_review"
			args = fmt.Sprintf(`{"risk":%q,"summary":"Disposable fleet root fixture","effects":["Prints root UID"],"warnings":[],"missing_context":[],"reversibility":"No state changed","intent_match":"consistent"}`, risk)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": "", "tool_calls": []any{map[string]any{"id": fmt.Sprintf("call-%d", f.modelCalls.Load()), "type": "function", "function": map[string]any{"name": name, "arguments": args}}}}, "finish_reason": "tool_calls"}}})
	}))
	t.Cleanup(provider.Close)
	// The reusable fake's legacy token lacks a numeric bot identity. A local
	// HTTP wire proxy changes only the path; gateway still loads a numeric token.
	u, _ := url.Parse(f.bot.URL())
	proxy := httputil.NewSingleHostReverseProxy(u)
	director := proxy.Director
	proxy.Director = func(r *http.Request) {
		director(r)
		r.URL.Path = strings.Replace(r.URL.Path, "/bot42:"+strings.Repeat("f", 32)+"/", "/bot"+f.bot.Token()+"/", 1)
	}
	tg := httptest.NewServer(proxy)
	t.Cleanup(tg.Close)
	f.tgURL = tg.URL
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.publicKey = pub
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/model-turns" {
			f.modelRequests.Add(1)
		}
		if r.Method == http.MethodPut {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
			f.mu.Lock()
			f.puts = append(f.puts, append([]byte(nil), data...))
			f.mu.Unlock()
		}
		if f.offline.Load() {
			select {
			case f.lost <- struct{}{}:
			default:
			}
			http.Error(w, "fixture offline", 503)
			return
		}
		s := f.active.Load()
		if s == nil {
			http.Error(w, "fixture starting", 503)
			return
		}
		if opts.holdModelResponse && r.URL.Path == "/v1/model-turns" {
			// A transport fixture holds an actual production-handler signed result;
			// root must bound the HTTPS wait independently of provider completion.
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, r)
			f.modelResponseHeld <- struct{}{}
			<-r.Context().Done()
			return
		}
		tracked := &rootFixtureStatusWriter{ResponseWriter: w, status: 200}
		s.Handler().ServeHTTP(tracked, r)
		f.mu.Lock()
		f.statuses = append(f.statuses, tracked.status)
		f.mu.Unlock()
	}))
	t.Cleanup(f.server.Close)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})
	priv, err := x509.MarshalPKCS8PrivateKey(f.server.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	profileTimeout := opts.profileTimeout
	if profileTimeout == 0 {
		profileTimeout = 5 * time.Second
	}
	f.gatewayCfg = gateway.Config{ConfigVersion: 1, Listen: "127.0.0.1:8443", PublicURL: f.server.URL, TLSCertFile: write("tls.crt", cert), TLSKeyFile: write("tls.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})), SigningKeyFile: write("signing", []byte(base64.StdEncoding.EncodeToString(key))), Database: filepath.Join(root, "gateway.sqlite3"), Profiles: []config.ModelConfig{{Name: "local", API: "openai_chat", BaseURL: provider.URL, Model: "fixture", DataBoundary: "local", RequestTimeout: config.Duration(profileTimeout)}}, Bots: []gateway.BotConfig{{Name: "fixture", TokenFile: write("tg.token", []byte("42:"+strings.Repeat("f", 32)))}}, Channels: []gateway.ChannelConfig{{Name: "ops", Bot: "fixture", ApprovalTTL: 120, Recipients: []config.TelegramRecipient{{ChatID: telegramChat, OperatorUserIDs: []int64{telegramOperator}}}}}}
	if opts.profileCondition == "removed" {
		f.gatewayCfg.Profiles = []config.ModelConfig{}
	} else if opts.profileCondition == "external" {
		f.gatewayCfg.Profiles[0].DataBoundary = "external"
		f.gatewayCfg.Profiles[0].APIKeyFile = write("provider.key", []byte("disposable-provider-key"))
	}
	f.db, err = gateway.OpenEnrollmentStore(f.gatewayCfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	host, bearer, err := f.db.Create(context.Background(), gateway.EnrollmentPolicy{AllowedProfiles: []string{"local"}, AllowedChannels: []string{"ops"}, DefaultChannel: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	f.gateway, err = gateway.NewFixtureServer(f.gatewayCfg, f.db, f.tgURL)
	if err != nil {
		t.Fatal(err)
	}
	f.active.Store(f.gateway)
	t.Cleanup(func() { f.gateway.Close(); f.db.Close() })
	if opts.profileCondition == "permission_revoked" {
		if err := f.db.UpdatePolicy(context.Background(), host.HostID, gateway.EnrollmentPolicy{AllowedProfiles: []string{}, AllowedChannels: []string{"ops"}, DefaultChannel: "ops"}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := testConfig()
	cfg.ConfigVersion = 5
	cfg.Telegram = config.TelegramConfig{}
	cfg.Review.Models = nil
	cfg.Review.GatewayProfiles = []string{"local"}
	cfg.Review.LocalOnly = true
	cfg.Review.RequestTimeout = config.Duration(10 * time.Second)
	cfg.Review.TotalTimeout = config.Duration(time.Minute)
	cfg.Limits.MaxInspectedBytes = 8 << 20
	cfg.Fleet = &config.FleetConfig{URL: f.server.URL, HostID: host.HostID, EnrollmentFile: write("enrollment", []byte(bearer)), VerificationKeyFile: write("verify", []byte(base64.StdEncoding.EncodeToString(pub))), CAFile: write("ca.crt", cert), ApprovalTTL: 120}
	if opts.hostOutputTokens != 0 {
		cfg.Review.MaxOutputTokens = opts.hostOutputTokens
	}
	if opts.originalBundle {
		customDir := filepath.Join(root, "custom-credentials")
		if err := os.Mkdir(customDir, 0700); err != nil {
			t.Fatal(err)
		}
		f.originalBundle = filepath.Join(customDir, "host-pi-bundle.json")
		f.canary = bearer
		bundle, err := json.Marshal(map[string]any{"version": 1, "host_id": host.HostID, "enrollment_token": bearer, "verification_key": base64.StdEncoding.EncodeToString(pub)})
		if err != nil {
			t.Fatal("encode disposable original bundle")
		}
		if err := os.WriteFile(f.originalBundle, bundle, 0600); err != nil {
			t.Fatal(err)
		}
		cfg.Inspection.ReadRoots = append(cfg.Inspection.ReadRoots, root)
		if opts.protectOriginalBundle {
			cfg.Fleet.EnrollmentBundleFiles = []string{f.originalBundle}
		}
	}
	if unreviewed {
		cfg.Review.Mode = "approval_only"
	}
	if opts.exemptRoot {
		cfg.Review.Mode = "required"
		cfg.Review.ApprovalOnlyUsers = []string{"root"}
	}
	if auto {
		grantUser := "root"
		if opts.foreground {
			grantUser = "askdo-human"
		}
		cfg.Review.AutoApproveGrants = []config.AutoApproveGrant{{User: grantUser, MaxRisk: opts.maxRisk}}
		if err := cfg.Review.ResolveAutoApproveGrants(); err != nil {
			t.Fatal(err)
		}
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if opts.hostOutputTokens != 0 || opts.originalBundle || opts.profileCondition != "" || opts.exemptRoot {
		encoded, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		f.hostConfigFile = write("host.json", encoded)
	}
	uid, gid := reviewerTestCredentials(t)
	worker := &processWorker{binary: binary, home: "/tmp", uid: uid, gid: gid}
	socket := filepath.Join(root, "run", "request.sock")
	skipOwnership := true
	if opts.foreground {
		socket = "/run/askdo/request.sock"
		skipOwnership = false
	}
	d, listener, err := newDaemon(f.hostConfigFile, daemonOptions{cfg: cfg, socketPath: socket, storePath: filepath.Join(root, "jobs.sqlite3"), spoolRoot: filepath.Join(root, "jobs"), worker: worker, executor: SystemExecutor{}, skipSocketOwnership: skipOwnership})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.serve(ctx, listener) }()
	f.broker = &brokerHarness{daemon: d, socket: d.socketPath, cancel: cancel, done: done}
	t.Cleanup(func() {
		f.broker.cancel()
		if err := <-f.broker.done; err != nil {
			t.Error(err)
		}
		f.broker.daemon.close()
	})
	if auto {
		prefUID := uint32(0)
		if opts.foreground {
			prefUID = 1001
		}
		if err := d.store.SetAutoApprovalThreshold(context.Background(), prefUID, 5); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestRootFleetEffectiveOutputBudgetActualChild(t *testing.T) {
	requireRootTest(t)
	f := newRootFleetFixture(t, buildFleetReviewer(t), "1", false, false, false, rootFleetOptions{hostOutputTokens: 32768})
	before, err := os.ReadFile(f.hostConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	id := reserveForTest(t, f.broker.socket, 0)
	request := submitRequest(id, "frozen token ceiling QA")
	request.Argv = []string{"/usr/bin/id", "-u"}
	conn, err := net.Dial("unix", f.broker.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, request)
	readFrame(t, conn)
	job := awaitRootFleetState(t, conn, f.broker.daemon.store, id, store.StateAwaitingHuman, store.StateFailed)
	if job.State != store.StateAwaitingHuman {
		t.Fatalf("legitimate host ceiling 32768 cannot complete fleet review: state=%s model_calls=%d", job.State, f.modelCalls.Load())
	}
	card, ok := f.bot.Card()
	if !ok {
		t.Fatal("human card missing")
	}
	f.bot.QueueCallback(1, "tokens", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	job = awaitRootFleetState(t, conn, f.broker.daemon.store, id, store.StateFinished, store.StateFailed)
	if job.State != store.StateFinished {
		t.Fatalf("root dispatch state=%s", job.State)
	}
	f.mu.Lock()
	requests := append([][]byte(nil), f.providerRequests...)
	f.mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("actual provider requests=%d, wanted 2", len(requests))
	}
	for _, raw := range requests {
		var req struct {
			MaxTokens int `json:"max_tokens"`
		}
		if json.Unmarshal(raw, &req) != nil || req.MaxTokens != 16384 {
			t.Fatalf("actual provider max_tokens=%d, wanted 16384", req.MaxTokens)
		}
	}
	after, err := os.ReadFile(f.hostConfigFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("persistent root policy mutated")
	}
	loaded, err := config.Load(f.hostConfigFile)
	if err != nil || loaded.Review.MaxOutputTokens != 32768 || f.broker.daemon.cfg.Review.MaxOutputTokens != 32768 {
		t.Fatal("root policy ceiling was lowered rather than projected")
	}
	output, err := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
	if err != nil || !bytes.Equal(output, []byte("0\n")) {
		t.Fatal("actual root UID command did not complete")
	}
	t.Log("actual unprivileged child: 2 provider requests max_tokens=16384; root UID=0; persistent host ceiling=32768 unchanged")
}

func TestRootFleetOriginalEnrollmentBundleWithheld(t *testing.T) {
	requireRootTest(t)
	// The missing-provenance red control leaks through this exact live flow.
	// Retained-import metadata must protect the arbitrary basename, not a suffix.
	f := newRootFleetFixture(t, buildFleetReviewer(t), "1", false, false, false, rootFleetOptions{originalBundle: true, protectOriginalBundle: true})
	id := reserveForTest(t, f.broker.socket, 0)
	request := submitRequest(id, "original enrollment masking QA")
	request.Argv = []string{"/usr/bin/id", "-u"}
	conn, err := net.Dial("unix", f.broker.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, request)
	readFrame(t, conn)
	job := awaitRootFleetState(t, conn, f.broker.daemon.store, id, store.StateAwaitingHuman, store.StateFailed)
	if job.State != store.StateAwaitingHuman {
		t.Fatalf("private child masking review state=%s", job.State)
	}
	f.mu.Lock()
	requests := append([][]byte(nil), f.providerRequests...)
	f.mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("actual provider requests=%d, wanted 2", len(requests))
	}
	for _, raw := range requests {
		if bytes.Contains(raw, []byte(f.canary)) {
			t.Fatal("original enrollment bearer escaped into provider request")
		}
	}
	var turn struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}
	}
	if json.Unmarshal(requests[1], &turn) != nil {
		t.Fatal("decode actual next provider turn")
	}
	withheld := false
	statuses := []string{}
	for _, message := range turn.Messages {
		if message.Role == "tool" {
			var result struct {
				Status  string `json:"status"`
				Content string `json:"content"`
			}
			if json.Unmarshal([]byte(message.Content), &result) == nil {
				statuses = append(statuses, result.Status)
				if (result.Status == "inspection_denied" || result.Status == "withheld") && result.Content == "" {
					withheld = true
				}
			}
		}
	}
	if !withheld {
		t.Fatalf("original credential read did not return a fixed denied/withheld status to provider: statuses=%v", statuses)
	}
	card, ok := f.bot.Card()
	if !ok {
		t.Fatal("human card missing")
	}
	f.bot.QueueCallback(1, "masked", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	job = awaitRootFleetState(t, conn, f.broker.daemon.store, id, store.StateFinished, store.StateFailed)
	if job.State != store.StateFinished {
		t.Fatalf("masked root dispatch state=%s", job.State)
	}
	var audit struct {
		FleetEvents [][]byte `json:"fleet_events"`
	}
	if json.Unmarshal(job.ApprovalJSON, &audit) != nil || len(audit.FleetEvents) != 2 {
		t.Fatal("complete signed human audit missing")
	}
	for _, envelope := range audit.FleetEvents {
		if _, _, err := fleetproto.Verify[fleetproto.Event](f.publicKey, envelope); err != nil {
			t.Fatal(err)
		}
	}
	output, err := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
	if err != nil || !bytes.Equal(output, []byte("0\n")) {
		t.Fatal("actual root UID command did not complete")
	}
	loaded, err := config.Load(f.hostConfigFile)
	if err != nil || loaded.Fleet == nil || len(loaded.Fleet.EnrollmentBundleFiles) != 1 || loaded.Fleet.EnrollmentBundleFiles[0] != f.originalBundle {
		t.Fatal("retained original bundle provenance missing from persistent root config")
	}
	t.Logf("actual unprivileged child + broad root read scope: original arbitrary-name bundle denied/withheld (status=%v); next provider turn contains no bearer; signed approval executed root UID 0", statuses)
}

func TestRootFleetTurnUsesFrozenChoiceTimeout(t *testing.T) {
	requireRootTest(t)
	f := newRootFleetFixture(t, "/unused/reviewer", "1", false, false, false, rootFleetOptions{profileTimeout: 500 * time.Millisecond, holdModelResponse: true})
	id := reserveForTest(t, f.broker.socket, 0)
	j := &jobRuntime{daemon: f.broker.daemon, uid: 0, req: proto.SubmitRequest{RequestID: id}, done: make(chan struct{})}
	models, err := j.prepareFleet(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	j.models = models
	if len(models) != 1 || models[0].RequestTimeoutMS != 1000 {
		t.Fatalf("frozen rounded profile projection: %+v", models)
	}
	_, request := fleetTurnFixture()
	s, err := (protocolWorker{run: func(_ context.Context, c net.Conn) error { _, err := readWorker(c, proto.BrokerToWorker); return err }}).Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); s.Wait() })
	finished := make(chan error, 1)
	go func() { finished <- j.receiveFleetTurn(s, request) }()
	defer close(j.done)
	select {
	case <-f.modelResponseHeld:
	case <-time.After(5 * time.Second):
		t.Fatal("actual TLS model result did not reach transport gate")
	}
	// Given a one-second frozen choice and a ten-second host budget, when the
	// signed response is held in HTTPS, then root must cancel at the choice cap.
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("held HTTPS response unexpectedly succeeded")
		}
		t.Logf("root HTTPS wait honored frozen %dms choice below global %s: %v", models[0].RequestTimeoutMS, j.daemon.cfg.Review.RequestTimeout.Value(), err)
	case <-time.After(2 * time.Second):
		t.Fatal("root HTTPS wait outlasted the frozen choice timeout")
	}
}

func TestRootFleetEvidenceCancelAndLocalRestart(t *testing.T) {
	requireRootTest(t)
	binary := buildFleetReviewer(t)
	for _, scenario := range []string{"cwd", "captured_bytes", "cancel", "local_restart"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRootFleetFixture(t, binary, "1", false, scenario == "captured_bytes", false)
			id := reserveForTest(t, f.broker.socket, 0)
			request := submitRequest(id, "fleet evidence/root restart QA")
			request.Argv = []string{"/usr/bin/id", "-u"}
			marker := filepath.Join(t.TempDir(), "root-dispatch-marker")
			if scenario == "local_restart" {
				request.Argv = []string{"/usr/bin/bash", "-c", "printf dispatched > " + strconv.Quote(marker) + "; /usr/bin/id -u"}
			}
			if scenario == "captured_bytes" {
				request = capturedRequest(id, "/usr/bin/id -u\n")
			}
			conn, err := net.Dial("unix", f.broker.socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			sendFrame(t, conn, request)
			readFrame(t, conn)
			// Wait for the real post-recordApproval progress frame, not just the
			// earlier durable state change: pending binding and receipt are ready.
			for {
				frame := readFrame(t, conn)
				var stage proto.ProgressEvent
				if err := json.Unmarshal(frame, &stage); err != nil {
					t.Fatal(err)
				}
				if stage.Stage == "awaiting-human" {
					break
				}
				if stage.Op == "result" {
					t.Fatal("job terminated before the committed human stage")
				}
			}
			job, err := f.broker.daemon.store.GetJob(context.Background(), 0, id)
			if err != nil {
				t.Fatal(err)
			}
			if job.State != store.StateAwaitingHuman {
				t.Fatalf("never reached frozen human: %s", job.State)
			}
			card, ok := f.bot.Card()
			if !ok {
				t.Fatal("card missing")
			}
			f.broker.daemon.mu.Lock()
			runtime := f.broker.daemon.jobs[f.broker.daemon.key(0, id)]
			f.broker.daemon.mu.Unlock()
			if runtime == nil {
				t.Fatal("committed human runtime missing")
			}
			var recorded struct {
				FleetEvents [][]byte `json:"fleet_events"`
			}
			originalApproval := append([]byte(nil), job.ApprovalJSON...)
			shutdownFailed := false
			startupState := store.State("")
			if json.Unmarshal(job.ApprovalJSON, &recorded) != nil || len(recorded.FleetEvents) != 1 {
				t.Fatal("complete receipt not durably recorded before shutdown")
			}
			receiptEvent, _, err := fleetproto.Verify[fleetproto.Event](f.publicKey, recorded.FleetEvents[0])
			if err != nil || receiptEvent.Receipt == nil {
				t.Fatal("recorded receipt is not a signed complete receipt")
			}
			if err := fleetproto.CheckReceipt(*receiptEvent.Receipt, runtime.fleet.ticket, runtime.fleet.selection.Catalog.Route, time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "cwd":
				if err := os.Rename(request.CWD, request.CWD+"-moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(request.CWD, 0755); err != nil {
					t.Fatal(err)
				}
			case "captured_bytes":
				if err := os.WriteFile(filepath.Join(job.SpoolDir, "bundle", "stdin"), []byte("modified captured bytes\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				c, err := net.Dial("unix", f.broker.socket)
				if err != nil {
					t.Fatal(err)
				}
				sendFrame(t, c, proto.CancelRequest{Op: "cancel", RequestID: id})
				readFrame(t, c)
				c.Close()
			case "local_restart":
				old := f.broker.daemon
				f.broker.cancel()
				if err := <-f.broker.done; err != nil {
					t.Fatal(err)
				}
				old.close()
				runtime.mu.Lock()
				t.Logf("shutdown runtime state=%s closed=%t detail=%q context_cancelled=%t", runtime.state, runtime.closed, runtime.failureDetail, old.shutdownCtx.Err() != nil)
				shutdownFailed = runtime.state == store.StateFailed && runtime.closed && old.shutdownCtx.Err() != nil &&
					(runtime.failureDetail == "fleet event proof unavailable" || runtime.failureDetail == "fleet ticket expired")
				runtime.mu.Unlock()
				d, listener, err := newDaemon("", daemonOptions{cfg: old.cfg, socketPath: old.socketPath, storePath: filepath.Join(filepath.Dir(old.spoolRoot), "jobs.sqlite3"), spoolRoot: old.spoolRoot, worker: old.worker, executor: SystemExecutor{}, skipSocketOwnership: true})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() { done <- d.serve(ctx, listener) }()
				f.broker = &brokerHarness{daemon: d, socket: d.socketPath, cancel: cancel, done: done}
				startup, err := d.store.GetJob(context.Background(), 0, id)
				if err != nil {
					t.Fatal(err)
				}
				startupState = startup.State
			}
			f.bot.QueueCallback(1, "evidence", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
			if scenario == "cwd" || scenario == "captured_bytes" {
				job = awaitRootFleetState(t, conn, f.broker.daemon.store, id, store.StateFailed)
			} else {
				// Recovered gateway proof exists, but lost local state cannot revive it.
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				event, _, ok, err := f.broker.daemon.fleet.NextEventProof(ctx, fleetproto.ID(id), 1)
				if err != nil || !ok {
					t.Fatalf("gateway decision was not recorded: %v %v", ok, err)
				}
				if event.Decision == nil || event.Sequence != 2 || event.Decision.Action != fleetproto.Approve || fleetproto.CheckDecision(*event.Decision, *receiptEvent.Receipt, runtime.fleet.ticket, runtime.fleet.selection.Catalog.Route, time.Now().Unix()) != nil {
					t.Fatal("recovered decision does not match the original frozen receipt")
				}
				job, err = f.broker.daemon.store.GetJob(context.Background(), 0, id)
				if err != nil {
					t.Fatal(err)
				}
				runtime.mu.Lock()
				t.Logf("recovered signed decision sequence=%d durable=%s runtime=%s receipt_unchanged=%t result=%s", event.Sequence, job.State, runtime.state, bytes.Equal(job.ApprovalJSON, originalApproval), job.ResultJSON)
				runtime.mu.Unlock()
				if !bytes.Equal(job.ApprovalJSON, originalApproval) {
					t.Fatal("recovered proof mutated local receipt audit")
				}
				if scenario == "local_restart" {
					if _, err := os.Stat(marker); !os.IsNotExist(err) {
						t.Fatal("root dispatch marker exists after local restart")
					}
					if job.State != startupState {
						t.Fatal("recovered proof changed local startup terminal state")
					}
					f.broker.daemon.mu.Lock()
					revived := f.broker.daemon.jobs[f.broker.daemon.key(0, id)] != nil
					f.broker.daemon.mu.Unlock()
					if revived {
						t.Fatal("recovered proof recreated a local executable runtime")
					}
				}
				if job.State != store.StateCancelled && job.State != store.StateExpired && !(scenario == "local_restart" && shutdownFailed && job.State == store.StateFailed) {
					t.Fatalf("recovered signed approval did not preserve an explained pre-dispatch terminal state: %s", job.State)
				}
			}
			output, err := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
			if err != nil || len(output) != 0 {
				t.Fatalf("changed/cancelled/restarted job dispatched: %q %v", output, err)
			}
			if scenario == "local_restart" {
				t.Logf("H1 shutdown outcome preserved: startup=%s durable=%s signed_approval_sequence=2 receipt_unchanged=true marker_absent=true stdout_bytes=0 executable_runtime_absent=true", startupState, job.State)
			}
		})
	}
}

func TestForegroundFleetSudoContainer(t *testing.T) {
	requireRootTest(t)
	if os.Getenv("ASKDO_FOREGROUND_CONTAINER_TEST") != "1" {
		t.Skip("requires disposable foreground-helper fixture")
	}
	f := newRootFleetFixture(t, "/usr/local/bin/askdo", "1", true, false, false, rootFleetOptions{foreground: true})
	p := startContainerPTY(t)
	p.until(t, "ASKDO_PROMPT> ")
	p.send(t, "/usr/local/bin/askdo --reason fleet-foreground -- /usr/bin/id -u; echo FLEET_FOREGROUND_EXIT=$?\n")
	p.until(t, "awaiting-human: awaiting decision")
	id := containerJobID(t, p.snapshot())
	card, ok := f.bot.Card()
	if !ok {
		t.Fatal("foreground skipped human card")
	}
	f.bot.QueueCallback(1, "foreground", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	text := p.until(t, "FLEET_FOREGROUND_EXIT=0\r\n")
	job, err := f.broker.daemon.store.GetJob(context.Background(), 1001, id)
	if err != nil || job.State != store.StateFinished {
		t.Fatalf("helper final state=%s err=%v", job.State, err)
	}
	if !strings.Contains(text, "\r\n0\r\n") {
		t.Fatalf("no real root foreground UID: %q", text)
	}
	data, err := os.ReadFile(filepath.Join(job.SpoolDir, "fleet-submission.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sub fleetproto.TicketSubmission
	if err := json.Unmarshal(data, &sub); err != nil {
		t.Fatal(err)
	}
	if sub.Ticket.Binding.TicketKind != fleetproto.HumanReviewed || sub.Ticket.Display.Identity.SubmitterUID != 1001 {
		t.Fatal("foreground root identity/human-only gate changed")
	}
	var audit struct {
		FleetEvents [][]byte `json:"fleet_events"`
	}
	if json.Unmarshal(job.ApprovalJSON, &audit) != nil || len(audit.FleetEvents) != 2 {
		t.Fatalf("missing foreground original proof: %s", job.ApprovalJSON)
	}
	for _, envelope := range audit.FleetEvents {
		if _, _, err := fleetproto.Verify[fleetproto.Event](f.publicKey, envelope); err != nil {
			t.Fatal(err)
		}
	}
	output, err := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
	if err != nil || len(output) != 0 {
		t.Fatalf("foreground leaked into detached executor logs: %q %v", output, err)
	}
	t.Logf("real SO_PEERCRED UID 1001, original PTY, signed human proof, existing sudo helper root UID output: %q", text)
}

func buildFleetReviewer(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "askdo-fleet-child-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "askdo")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", binary, "../../cmd/askdo")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build actual reviewer: %v %s", err, out)
	}
	return binary
}

func TestRootFleetActualChildTLSDispatch(t *testing.T) {
	requireRootTest(t)
	binary := buildFleetReviewer(t)
	for _, tc := range []struct {
		name, action, risk         string
		auto, captured, unreviewed bool
		want                       store.State
	}{
		{"reviewed_approve", "approve", "1", false, false, false, store.StateFinished},
		{"reviewed_deny", "deny", "1", false, false, false, store.StateDenied},
		{"auto_notice", "", "1", true, false, false, store.StateFinished},
		{"captured_always_human", "approve", "1", true, true, false, store.StateFinished},
		{"captured_unreviewed_always_human", "approve", "1", true, true, true, store.StateFinished},
		{"critical_always_human", "deny", "5", true, false, false, store.StateDenied},
		{"unreviewed_always_human", "deny", "1", true, false, true, store.StateDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRootFleetFixture(t, binary, tc.risk, tc.auto, tc.captured, tc.unreviewed)
			id := reserveForTest(t, f.broker.socket, 0)
			request := submitRequest(id, "disposable fleet root QA")
			request.Argv = []string{"/usr/bin/id", "-u"}
			if tc.captured {
				request = capturedRequest(id, "printf 'fleet-captured-root='; /usr/bin/id -u\n")
			}
			request.Reason = "submitter purpose for " + tc.name + " <canary>"
			conn, err := net.Dial("unix", f.broker.socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			sendFrame(t, conn, request)
			t.Logf("submit response: %s", readFrame(t, conn))
			if tc.action != "" {
				job := awaitRootFleetState(t, conn, f.broker.daemon.store, id, store.StateAwaitingHuman, store.StateFailed)
				if job.State == store.StateFailed {
					log, _ := os.ReadFile(filepath.Join(job.SpoolDir, "reviewer-stderr.log"))
					t.Fatalf("fleet failed before card: state=%s worker=%s", job.State, log)
				}
				card, ok := f.bot.Card()
				if !ok {
					t.Fatal("no human card")
				}
				prefix := "a:"
				if tc.action == "deny" {
					prefix = "d:"
				}
				f.bot.QueueCallback(1, "fixture", telegramOperator, telegramChat, card.ID, card.ButtonData(prefix))
			}
			job := awaitRootFleetState(t, conn, f.broker.daemon.store, id, tc.want, store.StateFailed)
			if job.State != tc.want {
				log, _ := os.ReadFile(filepath.Join(job.SpoolDir, "reviewer-stderr.log"))
				t.Fatalf("state=%s audit=%s worker=%s", job.State, job.ApprovalJSON, log)
			}
			var audit struct {
				FleetEvents [][]byte `json:"fleet_events"`
			}
			if json.Unmarshal(job.ApprovalJSON, &audit) != nil || len(audit.FleetEvents) == 0 {
				t.Fatalf("unsigned/missing audit: %s", job.ApprovalJSON)
			}
			for i, envelope := range audit.FleetEvents {
				event, _, err := fleetproto.Verify[fleetproto.Event](f.publicKey, envelope)
				if err != nil || event.Sequence != uint64(i+1) {
					t.Fatalf("audit proof failed: %v", err)
				}
			}
			var sub fleetproto.TicketSubmission
			data, err := os.ReadFile(filepath.Join(job.SpoolDir, "fleet-submission.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &sub); err != nil {
				t.Fatal(err)
			}
			if sub.Ticket.Binding.ManifestDigest != fleetproto.Hash(job.ManifestHash) || sub.Ticket.Display.Identity.SubmitterUID != 0 {
				t.Fatal("root identity/digest binding mismatch")
			}
			display := sub.Ticket.Display
			captured, err := base64.StdEncoding.DecodeString(request.CapturedStdinBase64)
			if err != nil {
				t.Fatal(err)
			}
			if display.Reason != request.Reason || display.CWD != request.CWD || display.CapturedStdinBytes != int64(len(captured)) || strings.Contains(display.Operation, "\nReason:") || strings.Contains(display.Operation, "\nCWD:") || strings.Contains(display.Operation, "\nCaptured stdin:") {
				t.Fatal("root ticket did not separate command and submitter metadata")
			}
			if tc.action == "" && sub.Ticket.Binding.TicketKind != fleetproto.AutoNotice {
				t.Fatal("not an auto ticket")
			}
			if tc.action != "" && sub.Ticket.Binding.TicketKind == fleetproto.AutoNotice {
				t.Fatal("human-only lane became auto")
			}
			if tc.want == store.StateFinished {
				output, err := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasSuffix(string(output), "0\n") {
					t.Fatalf("not real root output: %q", output)
				}
				t.Logf("real root output=%q kind=%s model requests=%d", output, sub.Ticket.Binding.TicketKind, f.modelCalls.Load())
			}
			if tc.unreviewed && f.modelCalls.Load() != 0 {
				t.Fatal("unreviewed lane sent evidence")
			}
		})
	}
}

func TestRootFleetHumanOnlyProfileIndependence(t *testing.T) {
	requireRootTest(t)
	binary := buildFleetReviewer(t)
	for _, tc := range []struct {
		name, condition, action                    string
		exempt, required, forced, revokeEnrollment bool
		want                                       store.State
	}{
		{name: "global_removed_approve", condition: "removed", action: "a:", want: store.StateFinished},
		{name: "global_permission_revoked_deny", condition: "permission_revoked", action: "d:", want: store.StateDenied},
		{name: "global_external_approve", condition: "external", action: "a:", want: store.StateFinished},
		{name: "exempt_removed_deny", condition: "removed", exempt: true, action: "d:", want: store.StateDenied},
		{name: "exempt_permission_revoked_approve", condition: "permission_revoked", exempt: true, action: "a:", want: store.StateFinished},
		{name: "exempt_external_deny", condition: "external", exempt: true, action: "d:", want: store.StateDenied},
		{name: "forced_global_removed", condition: "removed", forced: true, want: store.StateFailed},
		{name: "forced_global_external", condition: "external", forced: true, want: store.StateFailed},
		{name: "forced_exempt_removed", condition: "removed", exempt: true, forced: true, want: store.StateFailed},
		{name: "forced_exempt_external", condition: "external", exempt: true, forced: true, want: store.StateFailed},
		{name: "required_removed", condition: "removed", required: true, want: store.StateFailed},
		{name: "required_external", condition: "external", required: true, want: store.StateFailed},
		{name: "global_enrollment_revoked", condition: "removed", revokeEnrollment: true, want: store.StateFailed},
		{name: "exempt_enrollment_revoked", condition: "external", exempt: true, revokeEnrollment: true, want: store.StateFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given root policy and current gateway permissions, when the actual
			// child exits and a signed human decision arrives, then model-free
			// jobs retain every root dispatch gate without selecting a profile.
			f := newRootFleetFixture(t, binary, "1", false, false, !tc.required && !tc.exempt, rootFleetOptions{profileCondition: tc.condition, exemptRoot: tc.exempt})
			before, err := os.ReadFile(f.hostConfigFile)
			if err != nil {
				t.Fatal(err)
			}
			if tc.revokeEnrollment {
				if err := f.gateway.RevokeHost(context.Background(), f.broker.daemon.cfg.Fleet.HostID); err != nil {
					t.Fatal(err)
				}
			}
			id := reserveForTest(t, f.broker.socket, 0)
			request := submitRequest(id, "human-only profile independence")
			request.Argv = []string{"/usr/bin/id", "-u"}
			request.ForceReview = tc.forced
			conn, err := net.Dial("unix", f.broker.socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			sendFrame(t, conn, request)
			readFrame(t, conn)
			var sub fleetproto.TicketSubmission
			if tc.action != "" {
				job := awaitRootFleetState(t, conn, f.broker.daemon.store, id, store.StateAwaitingHuman, store.StateFailed)
				if job.State != store.StateAwaitingHuman {
					t.Fatalf("human route blocked by unused profile: %s", job.State)
				}
				data, err := os.ReadFile(filepath.Join(job.SpoolDir, "fleet-submission.json"))
				if err != nil || json.Unmarshal(data, &sub) != nil {
					t.Fatal("root ticket not persisted")
				}
				emptyHash, err := fleetproto.HashProfiles([]fleetproto.ProfileMetadata{})
				if err != nil {
					t.Fatal(err)
				}
				binding := sub.Ticket.Binding
				if sub.Profiles == nil || len(sub.Profiles) != 0 || binding.ProfileHash != emptyHash || binding.TicketKind != fleetproto.HumanUnreviewed || binding.HostID != fleetproto.ID(f.broker.daemon.cfg.Fleet.HostID) || binding.JobID != fleetproto.ID(id) || len(binding.Nonce) != 32 || binding.ManifestDigest != fleetproto.Hash(job.ManifestHash) || sub.Ticket.Display.Identity.SubmitterUID != 0 || binding.ExpiresAt <= time.Now().Unix() || binding.ExpiresAt > time.Now().Add(120*time.Second).Unix() {
					t.Fatal("model-free ticket lost root identity, nonce, digest, TTL or empty profile binding")
				}
				if err := fleetproto.CheckTicket(sub.Ticket, sub.Profiles, sub.Route); err != nil {
					t.Fatal(err)
				}
				f.broker.daemon.mu.Lock()
				runtime := f.broker.daemon.jobs[f.broker.daemon.key(0, id)]
				f.broker.daemon.mu.Unlock()
				if runtime == nil || runtime.fleet.selection.Profiles == nil || len(runtime.fleet.selection.Profiles) != 0 || len(runtime.bootstrap().ConfigProjection.Models) != 0 {
					t.Fatal("unused profile reached root snapshot or actual child bootstrap")
				}
				card, ok := f.bot.Card()
				if !ok {
					t.Fatal("human card missing")
				}
				f.bot.QueueCallback(1, "human-only", telegramOperator, telegramChat, card.ID, card.ButtonData(tc.action))
			}
			job := awaitRootFleetState(t, conn, f.broker.daemon.store, id, tc.want, store.StateFailed)
			if job.State != tc.want {
				t.Fatalf("root state=%s want=%s", job.State, tc.want)
			}
			output, err := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
			if err != nil || (tc.want == store.StateFinished && !bytes.Equal(output, []byte("0\n"))) || (tc.want != store.StateFinished && len(output) != 0) {
				t.Fatal("root approve/deny/fail dispatch mismatch")
			}
			f.mu.Lock()
			puts := append([][]byte(nil), f.puts...)
			f.mu.Unlock()
			if f.modelCalls.Load() != 0 || f.modelRequests.Load() != 0 {
				t.Fatal("unused model received a request or evidence")
			}
			if tc.action == "" {
				if len(puts) != 0 || len(job.ApprovalJSON) != 0 || len(f.bot.Sent()) != 0 {
					t.Fatal("required review or revoked enrollment reached ticket/human authority")
				}
			} else {
				if len(puts) == 0 {
					t.Fatal("root ticket never reached gateway")
				}
				for _, put := range puts {
					var sent fleetproto.TicketSubmission
					if json.Unmarshal(put, &sent) != nil || sent.Ticket.Binding != sub.Ticket.Binding || sent.Profiles == nil || len(sent.Profiles) != 0 {
						t.Fatal("TLS PUT changed model-free root ticket")
					}
				}
				var audit struct {
					FleetEvents [][]byte `json:"fleet_events"`
				}
				if json.Unmarshal(job.ApprovalJSON, &audit) != nil || len(audit.FleetEvents) != 2 {
					t.Fatal("complete signed human audit missing")
				}
				receipt, _, err := fleetproto.Verify[fleetproto.Event](f.publicKey, audit.FleetEvents[0])
				if err != nil || receipt.Sequence != 1 || receipt.Receipt == nil || fleetproto.CheckReceipt(*receipt.Receipt, sub.Ticket, sub.Route, time.Now().Unix()) != nil {
					t.Fatal("signed receipt lost frozen human gates")
				}
				decision, _, err := fleetproto.Verify[fleetproto.Event](f.publicKey, audit.FleetEvents[1])
				if err != nil || decision.Sequence != 2 || decision.Decision == nil || fleetproto.CheckDecision(*decision.Decision, *receipt.Receipt, sub.Ticket, sub.Route, time.Now().Unix()) != nil {
					t.Fatal("signed decision lost frozen human gates")
				}
			}
			after, err := os.ReadFile(f.hostConfigFile)
			if err != nil || !bytes.Equal(before, after) || !f.broker.daemon.cfg.Review.LocalOnly || len(f.broker.daemon.cfg.Review.GatewayProfiles) != 1 || f.broker.daemon.cfg.Review.GatewayProfiles[0] != "local" {
				t.Fatal("persistent root profile/local-only policy mutated")
			}
		})
	}
}

func TestRootFleetGatewayRestartExactReconciliation(t *testing.T) {
	requireRootTest(t)
	f := newRootFleetFixture(t, buildFleetReviewer(t), "1", false, false, false)
	id := reserveForTest(t, f.broker.socket, 0)
	r := submitRequest(id, "gateway restart root QA")
	r.Argv = []string{"/usr/bin/id", "-u"}
	conn, err := net.Dial("unix", f.broker.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendFrame(t, conn, r)
	readFrame(t, conn)
	before := awaitRootFleetState(t, conn, f.broker.daemon.store, id, store.StateAwaitingHuman, store.StateFailed)
	if before.State != store.StateAwaitingHuman {
		t.Fatalf("before restart: %s", before.State)
	}
	card, ok := f.bot.Card()
	if !ok {
		t.Fatal("no card")
	}
	sent := len(f.bot.Sent())
	// Given fully recorded pending delivery, when gateway service and SQLite
	// reopen while root is live, then root reconciles the exact original bytes.
	f.offline.Store(true)
	f.gateway.Close()
	f.db.Close()
	select {
	case <-f.lost:
	case <-time.After(5 * time.Second):
		job, _ := f.broker.daemon.store.GetJob(context.Background(), 0, id)
		f.mu.Lock()
		statuses := append([]int(nil), f.statuses...)
		f.mu.Unlock()
		t.Fatalf("root did not attempt bounded reconciliation: local state=%s gateway HTTP responses=%v", job.State, statuses)
	}
	status, err := net.Dial("unix", f.broker.socket)
	if err != nil {
		t.Fatal(err)
	}
	sendFrame(t, status, proto.StatusRequest{Op: "status", RequestID: id})
	reply := readFrame(t, status)
	status.Close()
	if !bytes.Contains(reply, []byte(`"state":"awaiting-human"`)) {
		t.Fatalf("offline status: %s", reply)
	}
	f.db, err = gateway.OpenEnrollmentStore(f.gatewayCfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	f.gateway, err = gateway.NewFixtureServer(f.gatewayCfg, f.db, f.tgURL)
	if err != nil {
		t.Fatal(err)
	}
	f.active.Store(f.gateway)
	f.offline.Store(false)
	f.bot.QueueCallback(1, "restart", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	job := awaitRootFleetState(t, conn, f.broker.daemon.store, id, store.StateFinished, store.StateFailed)
	if job.State != store.StateFinished {
		t.Fatalf("reconciled root state=%s", job.State)
	}
	f.mu.Lock()
	puts := append([][]byte(nil), f.puts...)
	f.mu.Unlock()
	if len(puts) < 2 {
		t.Fatal("ticket was not reconciled")
	}
	for _, put := range puts {
		if !bytes.Equal(put, puts[0]) {
			t.Fatal("reconciliation changed original submission bytes")
		}
	}
	if len(f.bot.Sent()) != sent {
		t.Fatal("restart resent a recorded card")
	}
	f.offline.Store(true)
	attached, err := net.Dial("unix", f.broker.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	sendFrame(t, attached, proto.AttachRequest{Op: "attach", RequestID: id})
	rootOutput := false
	for {
		frame := readFrame(t, attached)
		var kind struct {
			Op   string `json:"op"`
			Data string `json:"data_base64"`
		}
		if err := json.Unmarshal(frame, &kind); err != nil {
			t.Fatal(err)
		}
		if kind.Op == "stdout" {
			data, _ := base64.StdEncoding.DecodeString(kind.Data)
			rootOutput = rootOutput || bytes.Equal(data, []byte("0\n"))
		}
		if kind.Op == "result" {
			break
		}
	}
	if !rootOutput {
		t.Fatal("root output unavailable during gateway outage")
	}
	after, _ := f.broker.daemon.store.GetJob(context.Background(), 0, id)
	if !bytes.Equal(after.ApprovalJSON, job.ApprovalJSON) {
		t.Fatal("offline attach changed authorization")
	}
	t.Logf("reconciled %d exact PUTs; retained root output while gateway offline", len(puts))
}

func TestRootFleetAutoPolicyDeliveryGates(t *testing.T) {
	requireRootTest(t)
	binary := buildFleetReviewer(t)
	for _, tc := range []struct {
		name, risk      string
		cap             int
		partial, revoke bool
		human           bool
		want            store.State
	}{
		{"same_score_root_cap1", "3", 1, false, false, true, store.StateDenied},
		{"same_score_root_cap4", "3", 4, false, false, false, store.StateFinished},
		{"partial_notice_no_dispatch", "1", 4, true, false, false, store.StateFailed},
		{"current_preference_revocation", "1", 4, false, true, false, store.StateFailed},
		{"unknown_always_human", "unknown", 4, false, false, true, store.StateDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRootFleetFixture(t, binary, tc.risk, true, false, false, rootFleetOptions{maxRisk: tc.cap})
			if tc.partial || tc.revoke {
				f.bot.FailSend(func(call int, text string, keyboard bool) *faketelegram.APIError {
					if call == 2 && !keyboard {
						if tc.partial {
							return &faketelegram.APIError{Code: 500, Description: "fixture partial notice"}
						}
						if err := f.broker.daemon.store.SetAutoApprovalThreshold(context.Background(), 0, 0); err != nil {
							t.Error(err)
						}
					}
					return nil
				})
			}
			id := reserveForTest(t, f.broker.socket, 0)
			request := submitRequest(id, "root fleet policy QA")
			request.Argv = []string{"/usr/bin/id", "-u"}
			conn, err := net.Dial("unix", f.broker.socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			sendFrame(t, conn, request)
			readFrame(t, conn)
			if tc.human {
				job := awaitRootFleetState(t, conn, f.broker.daemon.store, id, store.StateAwaitingHuman, store.StateFailed)
				if job.State != store.StateAwaitingHuman {
					t.Fatalf("human gate state=%s", job.State)
				}
				card, ok := f.bot.Card()
				if !ok {
					t.Fatal("human card absent")
				}
				f.bot.QueueCallback(1, "policy", telegramOperator, telegramChat, card.ID, card.ButtonData("d:"))
			}
			job := awaitRootFleetState(t, conn, f.broker.daemon.store, id, tc.want)
			output, err := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == store.StateFinished && !bytes.Equal(output, []byte("0\n")) {
				t.Fatalf("not real root: %q", output)
			}
			if tc.want != store.StateFinished && len(output) != 0 {
				t.Fatalf("unsafe lane dispatched: %q", output)
			}
			if tc.partial || tc.revoke {
				if len(job.ApprovalJSON) != 0 {
					t.Fatalf("auto NULL predicate altered before failed commit: %s", job.ApprovalJSON)
				}
			}
		})
	}
}

func awaitRootFleetState(t *testing.T, conn net.Conn, jobs *store.Store, id string, states ...store.State) store.Job {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for {
		job, err := jobs.GetJob(context.Background(), 0, id)
		if err == nil {
			for _, state := range states {
				if job.State == state {
					return job
				}
			}
		}
		frame := readFrame(t, conn) // synchronize with actual broker progress/terminal frames
		t.Logf("broker event: %s", frame)
	}
}
