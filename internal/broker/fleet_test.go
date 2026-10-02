package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/modelwire"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/reviewer"
	"github.com/jeremyakers/askdo/internal/store"
)

func TestRootFleetPrepareHumanOnlySelection(t *testing.T) {
	requireRootTest(t)
	for _, tc := range []struct {
		name         string
		missing      bool
		external     bool
		approvalOnly bool
		wantCode     fleetproto.ErrorCode
	}{
		{"human_missing", true, false, true, ""},
		{"human_external", false, true, true, ""},
		{"human_local", false, false, true, ""},
		{"required_missing", true, false, false, fleetproto.ErrCodeRevision},
		{"required_external", false, true, false, fleetproto.ErrCodeSafety},
		{"required_local", false, false, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given authenticated signed metadata and a configured profile, when
			// root prepares the job, then only review-required jobs select models.
			j, _ := fleetTurnFixture()
			profiles := j.fleet.selection.Profiles
			if tc.missing {
				profiles = []fleetproto.ProfileMetadata{}
			} else if tc.external {
				profiles[0].Upstreams[0].DataBoundary = fleetproto.External
				profiles[0].Revision, _ = fleetproto.HashProfile(profiles[0])
			}
			route := fleetproto.RouteSnapshot{Version: 1, Kind: fleetproto.KindRoute, ChannelID: "ops", BotID: 42, TTLSeconds: 60, Recipients: []fleetproto.Recipient{{ChatID: 11, OperatorUserIDs: []int64{101}}}}
			route.Revision, _ = fleetproto.HashRoute(route)
			catalog := fleetproto.Catalog{Version: 1, Kind: fleetproto.KindCatalog, HostID: "host", SubmitterUID: 0, Profiles: profiles, Route: route, ExpiresAt: time.Now().Add(time.Minute).Unix()}
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bearer := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			var otherCalls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/catalog" {
					otherCalls.Add(1)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if r.Header.Get("X-Askdo-Host") != "host" || r.Header.Get("Authorization") != "Bearer "+bearer || r.URL.Query().Get("submitter_uid") != "0" {
					t.Error("catalogue authentication or root UID missing")
				}
				wire, err := fleetproto.Sign(key, catalog)
				if err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				_, _ = w.Write(wire)
			}))
			t.Cleanup(server.Close)
			root := t.TempDir()
			j.daemon.store, err = store.Open(filepath.Join(root, "jobs.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { j.daemon.store.Close() })
			write := func(name string, data []byte, mode os.FileMode) string {
				path := filepath.Join(root, name)
				if err := os.WriteFile(path, data, mode); err != nil {
					t.Fatal(err)
				}
				return path
			}
			j.daemon.cfg.Fleet = &config.FleetConfig{URL: server.URL, HostID: "host", EnrollmentFile: write("enrollment", []byte(bearer), 0600), VerificationKeyFile: write("verify", []byte(base64.StdEncoding.EncodeToString(pub)), 0400), CAFile: write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0400), ApprovalTTL: 60}
			j.daemon.cfg.Review.GatewayProfiles = []string{"local"}
			j.daemon.cfg.Review.LocalOnly = true
			j.daemon.cfg.Review.TotalTimeout = config.Duration(time.Minute)
			j.daemon.fleet, err = fleetclient.New(*j.daemon.cfg.Fleet)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(j.daemon.fleet.Close)
			j.fleet = nil
			models, err := j.prepareFleet(context.Background(), tc.approvalOnly)
			if tc.wantCode != "" {
				var typed *fleetclient.Error
				if !errors.As(err, &typed) || typed.Code != tc.wantCode || j.fleet != nil {
					t.Fatalf("selection error=%v, want=%s", err, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			j.models, j.approvalOnly = models, tc.approvalOnly
			wantModels := 1
			if tc.approvalOnly {
				wantModels = 0
			}
			if models == nil || j.fleet.selection.Profiles == nil || len(j.fleet.selection.Profiles) != wantModels || len(j.bootstrap().ConfigProjection.Models) != wantModels {
				t.Fatal("selected profiles and worker projection do not match root policy")
			}
			if j.fleet.selection.Catalog.Route.Revision != route.Revision || j.route.ChannelName != "ops" || !j.fleet.selection.LocalOnly || otherCalls.Load() != 0 {
				t.Fatal("signed route/local-only policy changed or model request sent")
			}
		})
	}
}

func fleetTurnFixture() (*jobRuntime, proto.ModelTurnRequest) {
	p := fleetproto.ProfileMetadata{Version: 1, Kind: fleetproto.KindProfile, ProfileID: "local", Upstreams: []fleetproto.Upstream{{API: fleetproto.OpenAIChat, BaseURL: "http://localhost:11434/v1", Model: "fixture", DataBoundary: fleetproto.Local, RequestTimeoutSeconds: 10, MaxOutputTokens: 100}}}
	p.Revision, _ = fleetproto.HashProfile(p)
	j := &jobRuntime{daemon: &daemon{cfg: &config.Config{Fleet: &config.FleetConfig{HostID: "host"}, Review: config.ReviewConfig{MaxModelCallsPerAttempt: 2, MaxOutputTokens: 100, RequestTimeout: config.Duration(time.Second)}}}, req: proto.SubmitRequest{RequestID: "2026-09-30_#1"}, models: []proto.ProjectedModel{{Name: "local", Model: "fixture"}}, fleet: &fleetJob{selection: fleetclient.Selection{Profiles: []fleetproto.ProfileMetadata{p}}, reviewDeadline: time.Now().Add(time.Minute)}}
	r := proto.ModelTurnRequest{Type: "model_turn_request", RequestSeq: 1, ChoiceName: "local", Request: modelwire.ModelRequest{Model: "fixture", MaxOutputTokens: 100, Messages: []modelwire.Message{{Role: "user", Content: "evidence"}}, Tools: reviewer.DefinitionsWithWebfetch(false)}}
	return j, r
}

func TestFleetWorkerAuthorityFramesRejectCleanExit(t *testing.T) {
	for _, frame := range []any{
		proto.NotificationSent{Type: "notification_sent", Digest: strings.Repeat("a", 64), CardID: 1, MessageIDs: []int64{2}, ExpiryUnixMS: time.Now().Add(time.Minute).UnixMilli()},
		proto.AutoNotificationSent{Type: "auto_notification_sent", Digest: strings.Repeat("a", 64), NoticeID: 1, MessageIDs: []int64{2}, TimeUnixMS: time.Now().UnixMilli()},
		proto.Decision{Type: "decision", Digest: strings.Repeat("a", 64), Action: "approve", OperatorUserID: 1, MessageID: 1, TimeUnixMS: time.Now().UnixMilli()},
	} {
		// Given a frozen fleet review, when the child sends a raw authority frame,
		// then even a successful child exit cannot permit ticket dispatch.
		w := protocolWorker{run: func(ctx context.Context, c net.Conn) error { return writeWorker(c, frame, proto.WorkerToBroker) }}
		s, err := w.Start(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := waitFleetExit(context.Background(), s); err == nil {
			t.Fatalf("accepted worker authority %T", frame)
		}
		s.Close()
		s.Wait()
	}
}

func TestFleetManualEventFailurePreservesExpiry(t *testing.T) {
	for _, tc := range []struct {
		name, detail string
		lapsed       bool
		want         store.State
	}{
		{"expired_empty_poll", "fleet ticket expired", true, store.StateExpired},
		{"expired_proof", "invalid fleet event proof", true, store.StateExpired},
		{"infrastructure_within_ttl", "fleet event proof unavailable", false, store.StateFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a frozen manual approval with no client deadline, when the
			// event path finishes, then actual TTL lapse wins over generic failure.
			// No sweep timer is armed: this isolates the event path deterministically.
			h := newBrokerHarness(t, nil, nil)
			spool, err := createSpool(t.TempDir(), []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			id := reserveForTest(t, h.socket, testUID)
			j := newTestJobRuntime(t, h.daemon, proto.SubmitRequest{RequestID: id, Mode: "argv", Argv: []string{"/usr/bin/true"}}, spool)
			ctx := context.Background()
			if _, err := h.daemon.store.SubmitReservedJob(ctx, store.Job{UID: j.uid, RequestID: id, SubmitBody: []byte(`{}`), OperationJSON: []byte(`{}`), Mode: "argv", SpoolDir: spool.dir, AttemptsJSON: []byte(`[]`)}); err != nil {
				t.Fatal(err)
			}
			for _, step := range [][2]store.State{{store.StateQueued, store.StateReviewing}, {store.StateReviewing, store.StateAwaitingHuman}} {
				if ok, err := j.transition(ctx, step[0], step[1]); !ok || err != nil {
					t.Fatalf("transition: %v %v", ok, err)
				}
			}
			expiry := time.Now().Add(time.Minute).Truncate(time.Second)
			if tc.lapsed {
				expiry = time.Now().Add(-time.Second).Truncate(time.Second)
			}
			j.fleet = &fleetJob{ticket: fleetproto.Ticket{Binding: fleetproto.TicketBinding{ExpiresAt: expiry.Unix()}}}
			j.pendingApproval = &approvalBinding{expiry: expiry}
			j.failFleetEvent(tc.detail)
			row, err := h.daemon.store.GetJob(ctx, j.uid, id)
			if err != nil || row.State != tc.want || j.state != tc.want || row.DeadlineAt != nil {
				t.Fatalf("terminal state: durable=%s runtime=%s deadline=%v err=%v", row.State, j.state, row.DeadlineAt, err)
			}
			if !j.closed || (tc.lapsed && !j.pendingApproval.consumed) || len(h.executor.Snapshot()) != 0 {
				t.Fatal("terminal event retained authority or dispatched")
			}
		})
	}
}

func rootFleetReceiptFixture() (*jobRuntime, fleetproto.Event) {
	j, _ := fleetTurnFixture()
	j.state = store.StateReviewing
	route := fleetproto.RouteSnapshot{Version: 1, Kind: fleetproto.KindRoute, ChannelID: "ops", BotID: 42, TTLSeconds: 60, Recipients: []fleetproto.Recipient{{ChatID: 11, OperatorUserIDs: []int64{101}}, {ChatID: 12, OperatorUserIDs: []int64{102}}}}
	route.Revision, _ = fleetproto.HashRoute(route)
	j.fleet.selection.Catalog.Route = route
	ph, _ := fleetproto.HashProfiles(j.fleet.selection.Profiles)
	display := fleetproto.Display{Operation: "id -u", Identity: fleetproto.Identity{Hostname: "host", Username: "user", SubmitterUID: 1000}, Report: &proto.ReviewReport{Risk: "1", Summary: "safe", Effects: []string{}, Warnings: []proto.ReviewWarning{}, MissingContext: []string{}, Reversibility: "none", IntentMatch: "consistent"}, ModelHistory: []proto.ModelHistoryEntry{{Name: "local", Outcome: "ok"}}, Withholding: []string{}, SummaryParts: 1}
	dh, _ := fleetproto.HashDisplay(display)
	j.fleet.ticket = fleetproto.Ticket{Version: 1, Kind: fleetproto.KindTicket, Binding: fleetproto.TicketBinding{HostID: "host", JobID: fleetproto.ID(j.req.RequestID), Nonce: strings.Repeat("b", 32), TicketKind: fleetproto.HumanReviewed, ManifestDigest: fleetproto.Hash(strings.Repeat("a", 64)), ProfileHash: ph, RouteHash: route.Revision, DisplayHash: dh, ExpiresAt: time.Now().Add(time.Minute).Unix()}, Display: display}
	r := &fleetproto.Receipt{Version: 1, Kind: fleetproto.KindReceipt, Binding: j.fleet.ticket.Binding, DeliveredAt: time.Now().Unix(), Deliveries: []fleetproto.Delivery{{Recipient: route.Recipients[0], SummaryMessageIDs: []int64{1}, CardMessageID: 2}, {Recipient: route.Recipients[1], SummaryMessageIDs: []int64{3}, CardMessageID: 4}}}
	return j, fleetproto.Event{Version: 1, Kind: fleetproto.KindEvent, HostID: "host", JobID: fleetproto.ID(j.req.RequestID), Sequence: 1, Type: fleetproto.EventReceipt, Receipt: r}
}

func TestFleetRootProofBindingMatrix(t *testing.T) {
	j, e := rootFleetReceiptFixture()
	if err := j.validateFleetEvent(e); err != nil {
		t.Fatalf("valid root receipt: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*jobRuntime, *fleetproto.Event)
	}{
		{"host", func(j *jobRuntime, e *fleetproto.Event) { e.Receipt.Binding.HostID = "other" }},
		{"job", func(j *jobRuntime, e *fleetproto.Event) { e.Receipt.Binding.JobID = "2026-09-30_#2" }},
		{"nonce", func(j *jobRuntime, e *fleetproto.Event) { e.Receipt.Binding.Nonce = strings.Repeat("c", 32) }},
		{"digest", func(j *jobRuntime, e *fleetproto.Event) {
			e.Receipt.Binding.ManifestDigest = fleetproto.Hash(strings.Repeat("c", 64))
		}},
		{"profile", func(j *jobRuntime, e *fleetproto.Event) {
			e.Receipt.Binding.ProfileHash = fleetproto.Hash(strings.Repeat("c", 64))
		}},
		{"route", func(j *jobRuntime, e *fleetproto.Event) {
			e.Receipt.Binding.RouteHash = fleetproto.Hash(strings.Repeat("c", 64))
		}},
		{"display", func(j *jobRuntime, e *fleetproto.Event) {
			e.Receipt.Binding.DisplayHash = fleetproto.Hash(strings.Repeat("c", 64))
		}},
		{"kind", func(j *jobRuntime, e *fleetproto.Event) { e.Receipt.Binding.TicketKind = fleetproto.HumanUnreviewed }},
		{"expiry", func(j *jobRuntime, e *fleetproto.Event) { e.Receipt.Binding.ExpiresAt++ }},
		{"expired_root", func(j *jobRuntime, e *fleetproto.Event) { j.fleet.ticket.Binding.ExpiresAt = time.Now().Unix() }},
		{"recipient", func(j *jobRuntime, e *fleetproto.Event) {
			e.Receipt.Deliveries[0].Recipient.OperatorUserIDs = []int64{999}
		}},
		{"partial", func(j *jobRuntime, e *fleetproto.Event) { e.Receipt.Deliveries = e.Receipt.Deliveries[:1] }},
		{"summary", func(j *jobRuntime, e *fleetproto.Event) { e.Receipt.Deliveries[0].SummaryMessageIDs = []int64{1, 9} }},
		{"sequence", func(j *jobRuntime, e *fleetproto.Event) { e.Sequence++ }},
		{"replay", func(j *jobRuntime, e *fleetproto.Event) { j.fleet.cursor = 1; j.fleet.receipt = e.Receipt }},
		{"cancelled", func(j *jobRuntime, e *fleetproto.Event) { j.state = store.StateCancelled }},
		{"restart", func(j *jobRuntime, e *fleetproto.Event) { j.state = store.StateExpired }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j, e := rootFleetReceiptFixture()
			tc.change(j, &e)
			if err := j.validateFleetEvent(e); err == nil {
				t.Fatal("forged/stale root proof accepted")
			}
		})
	}
}

func TestFleetRootTurnBoundary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*jobRuntime, *proto.ModelTurnRequest)
	}{
		{"sequence", func(j *jobRuntime, r *proto.ModelTurnRequest) { r.RequestSeq = 2 }},
		{"choice", func(j *jobRuntime, r *proto.ModelTurnRequest) { r.ChoiceName = "other" }},
		{"model", func(j *jobRuntime, r *proto.ModelTurnRequest) { r.Request.Model = "other" }},
		{"tokens", func(j *jobRuntime, r *proto.ModelTurnRequest) { r.Request.MaxOutputTokens++ }},
		{"tool_description", func(j *jobRuntime, r *proto.ModelTurnRequest) { r.Request.Tools[0].Description = "credential request" }},
		{"tool_schema", func(j *jobRuntime, r *proto.ModelTurnRequest) { r.Request.Tools[0].Schema = json.RawMessage(`{}`) }},
		{"tool_name", func(j *jobRuntime, r *proto.ModelTurnRequest) { r.Request.Tools[0].Name = "exec" }},
		{"calls", func(j *jobRuntime, r *proto.ModelTurnRequest) { j.fleet.turn = 2 }},
		{"deadline", func(j *jobRuntime, r *proto.ModelTurnRequest) { j.fleet.reviewDeadline = time.Now().Add(-time.Second) }},
		{"failed_choice", func(j *jobRuntime, r *proto.ModelTurnRequest) {
			j.fleet.failures = []proto.AvailabilityFailure{{Name: "local", Code: proto.AvailabilityTransport}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given root-owned selected metadata, when a worker changes a bound fact,
			// then rejection happens before a network model request.
			j, r := fleetTurnFixture()
			tc.change(j, &r)
			_, err := j.fleetTurn(r)
			var typed *fleetclient.Error
			if !errors.As(err, &typed) {
				t.Fatalf("wanted typed boundary error, got %v", err)
			}
		})
	}
	j, r := fleetTurnFixture()
	turn, err := j.fleetTurn(r)
	if err != nil || turn.Binding.Attempt != 1 || turn.Binding.Turn != 1 || turn.Binding.UpstreamIndex != 0 || turn.Binding.ProfileRevision != j.fleet.selection.Profiles[0].Revision {
		t.Fatalf("root binding: %+v, %v", turn.Binding, err)
	}
}

func TestFleetOutputCeilingAcrossFrozenFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name string
		caps []int
		want int
	}{
		{"host_cap", []int{200, 300}, 100},
		{"first_choice", []int{80, 90}, 80},
		{"later_fallback", []int{90, 25}, 25},
		{"nonpositive_fails_closed", []int{80, 0}, 0},
		{"approval_only_no_models", nil, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j, r := fleetTurnFixture()
			s, err := store.Open(filepath.Join(t.TempDir(), "jobs.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			j.daemon.store = s
			j.fleet.selection.Profiles = nil
			for i, cap := range tc.caps {
				p := fleetproto.ProfileMetadata{Version: 1, Kind: fleetproto.KindProfile, ProfileID: fleetproto.ID(fmt.Sprintf("choice-%d", i)), Upstreams: []fleetproto.Upstream{{API: fleetproto.OpenAIChat, BaseURL: "http://localhost:11434/v1", Model: "fixture", DataBoundary: fleetproto.Local, RequestTimeoutSeconds: 10, MaxOutputTokens: cap}}}
				p.Revision, _ = fleetproto.HashProfile(p)
				j.fleet.selection.Profiles = append(j.fleet.selection.Profiles, p)
			}
			if tc.caps == nil {
				j.approvalOnly = true
				j.models = []proto.ProjectedModel{}
			}
			if got := j.bootstrap().ConfigProjection.Limits.MaxOutputTokens; got != tc.want {
				t.Fatalf("frozen worker ceiling=%d want=%d", got, tc.want)
			}
			if j.daemon.cfg.Review.MaxOutputTokens != 100 {
				t.Fatal("host root policy mutated")
			}
			if len(tc.caps) > 0 && tc.want < 100 {
				r.Request.MaxOutputTokens = tc.want + 1
				if _, err := j.fleetTurn(r); err == nil {
					t.Fatal("worker exceeded effective frozen ceiling")
				}
			}
		})
	}
}

func TestFleetRegistrySurvivesRealPipeJSON(t *testing.T) {
	// Given the actual registry, when the private pipe compacts RawMessage
	// schemas, then root must recognize the same fixed registry.
	j, r := fleetTurnFixture()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var wire proto.ModelTurnRequest
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if _, err := j.fleetTurn(wire); err != nil {
		t.Fatalf("real pipe registry rejected: %v", err)
	}
}
