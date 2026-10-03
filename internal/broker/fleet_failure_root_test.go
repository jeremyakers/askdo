//go:build askdo_fleet_fixture

package broker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

type failureRootExecutor struct{ starts atomic.Int32 }

func (e *failureRootExecutor) Start(op Operation, stdout, stderr io.Writer) (Execution, error) {
	e.starts.Add(1)
	return (SystemExecutor{}).Start(op, stdout, stderr)
}

func failureRootConnect(t *testing.T, f *rootFleetFixture, id string) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", f.broker.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	r := submitRequest(id, "signed fleet failure fixture")
	r.Argv = []string{"/usr/bin/id", "-u"}
	sendFrame(t, c, r)
	return c
}

func failureRootFrames(t *testing.T, c net.Conn, human bool, message string) proto.ResultEvent {
	t.Helper()
	failedProgress := false
	for {
		wire := readFrame(t, c)
		var header struct {
			Op string `json:"op"`
		}
		if err := json.Unmarshal(wire, &header); err != nil {
			t.Fatal(err)
		}
		switch header.Op {
		case "progress":
			var p proto.ProgressEvent
			if err := json.Unmarshal(wire, &p); err != nil {
				t.Fatal(err)
			}
			if p.Stage == "awaiting-human" && human {
				return proto.ResultEvent{}
			}
			if p.Stage == "failed" {
				failedProgress = true
				if p.Detail != message {
					t.Fatalf("failure progress=%q want=%q", p.Detail, message)
				}
			}
		case "result":
			var r proto.ResultEvent
			if err := json.Unmarshal(wire, &r); err != nil {
				t.Fatal(err)
			}
			if human || r.Message != message || (message != "" && !failedProgress) {
				t.Fatalf("terminal state=%s message=%q human=%t failed-progress=%t", r.State, r.Message, human, failedProgress)
			}
			return r
		}
	}
}

func TestRootFleetSignedFailureReporting(t *testing.T) {
	requireRootTest(t)
	binary := buildFleetReviewer(t)
	baselineFixture := newRootFleetFixture(t, binary, "1", false, false, false)
	executor := &failureRootExecutor{}
	baselineFixture.broker.daemon.executor = executor
	firstID := reserveForTest(t, baselineFixture.broker.socket, 0)
	firstConn := failureRootConnect(t, baselineFixture, firstID)
	failureRootFrames(t, firstConn, true, "")
	card, ok := baselineFixture.bot.Card()
	if !ok {
		t.Fatal("baseline card missing")
	}
	baselineFixture.bot.QueueCallback(1, "failure-baseline", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	firstResult := failureRootFrames(t, firstConn, false, "")
	if firstResult.State != string(store.StateFinished) || firstResult.ExitCode == nil || *firstResult.ExitCode != 0 || executor.starts.Load() != 1 {
		t.Fatal("baseline failed to dispatch once")
	}
	first, err := baselineFixture.broker.daemon.store.GetJob(context.Background(), 0, firstID)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(filepath.Join(first.SpoolDir, "stdout.log"))
	if err != nil || !bytes.Equal(out, []byte("0\n")) {
		t.Fatal("baseline did not execute as root", err)
	}
	var baseline struct {
		FleetEvents [][]byte `json:"fleet_events"`
	}
	if json.Unmarshal(first.ApprovalJSON, &baseline) != nil || len(baseline.FleetEvents) != 2 {
		t.Fatal("baseline proof audit missing")
	}
	for _, wire := range baseline.FleetEvents {
		if _, _, err := fleetproto.Verify[fleetproto.Event](baselineFixture.publicKey, wire); err != nil {
			t.Fatal(err)
		}
	}
	for _, scenario := range []string{"send", "partial_send", "after_receipt", "auto_send", "unreviewed_send"} {
		t.Run(scenario, func(t *testing.T) {
			// Given an actual unprivileged reviewer, root broker, TLS gateway and
			// SQLite, first establish one reviewed, human-authorized root dispatch.
			f := newRootFleetFixture(t, binary, "1", scenario == "auto_send", false, scenario == "unreviewed_send")
			worker, ok := f.broker.daemon.worker.(*processWorker)
			if !ok || worker.uid == 0 || worker.gid == 0 {
				t.Fatal("reviewer not unprivileged")
			}
			f.broker.daemon.executor = executor
			f.gateway.Close()
			u, err := url.Parse(f.tgURL)
			if err != nil {
				t.Fatal(err)
			}
			proxy := httputil.NewSingleHostReverseProxy(u)
			var armed atomic.Bool
			var sends atomic.Int32
			allow := int32(0)
			if scenario == "partial_send" {
				allow = 1
			}
			tg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if armed.Load() && strings.HasSuffix(r.URL.Path, "/sendMessage") && sends.Add(1) > allow {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"untrusted fixture diagnostic"}`))
					return
				}
				proxy.ServeHTTP(w, r)
			}))
			t.Cleanup(tg.Close)
			f.gateway, err = gateway.NewFixtureServer(f.gatewayCfg, f.db, tg.URL)
			if err != nil {
				t.Fatal(err)
			}
			f.active.Store(f.gateway)
			t.Cleanup(func() { f.gateway.Close() })
			if scenario != "after_receipt" {
				armed.Store(true)
			}
			secondID := reserveForTest(t, f.broker.socket, 0)
			secondConn := failureRootConnect(t, f, secondID)
			if scenario == "after_receipt" {
				failureRootFrames(t, secondConn, true, "")
				// Use the actual gateway store/key to append sequence 2. This is
				// terminal failure evidence, not a forged authorization or jobRuntime.
				keyText, err := os.ReadFile(f.gatewayCfg.SigningKeyFile)
				if err != nil {
					t.Fatal(err)
				}
				key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyText)))
				if err != nil {
					t.Fatal(err)
				}
				tickets, err := gateway.NewTicketStore(f.db, ed25519.PrivateKey(key))
				if err != nil {
					t.Fatal(err)
				}
				if err := tickets.Fail(context.Background(), f.broker.daemon.cfg.Fleet.HostID, secondID, fleetproto.ErrCodeDelivery); err != nil {
					t.Fatal(err)
				}
			}
			// When genuine send failure (including partial delivery), or failure
			// after a complete receipt occurs, then root reports only the category.
			result := failureRootFrames(t, secondConn, false, "fleet gateway failure: delivery")
			if result.State != string(store.StateFailed) || executor.starts.Load() != 1 {
				t.Fatal("failed ticket dispatched")
			}
			second, err := f.broker.daemon.store.GetJob(context.Background(), 0, secondID)
			if err != nil || second.State != store.StateFailed {
				t.Fatal("durable failure missing", err)
			}
			out, err := os.ReadFile(filepath.Join(second.SpoolDir, "stdout.log"))
			if err != nil || len(out) != 0 {
				t.Fatal("failed ticket produced stdout", err)
			}
			data, err := os.ReadFile(filepath.Join(second.SpoolDir, "fleet-events.json"))
			if err != nil {
				t.Fatal("signed failure was not persisted", err)
			}
			var proofs [][]byte
			if err := json.Unmarshal(data, &proofs); err != nil {
				t.Fatal(err)
			}
			wantCount := 1
			if scenario == "after_receipt" {
				wantCount = 2
			}
			if len(proofs) != wantCount {
				t.Fatalf("proof count=%d want=%d", len(proofs), wantCount)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for i, wire := range proofs {
				e, _, err := fleetproto.Verify[fleetproto.Event](f.publicKey, wire)
				if err != nil || e.Sequence != uint64(i+1) || string(e.JobID) != secondID || string(e.HostID) != f.broker.daemon.cfg.Fleet.HostID {
					t.Fatal("invalid retained proof", err)
				}
				_, original, exists, err := f.broker.daemon.fleet.NextEventProof(ctx, fleetproto.ID(secondID), uint64(i))
				if err != nil || !exists || !bytes.Equal(original, wire) {
					t.Fatal("original wire not retained", err)
				}
				if i == len(proofs)-1 && (e.Type != fleetproto.EventFailed || e.Failure == nil || e.Failure.Code != fleetproto.ErrCodeDelivery || e.Receipt != nil || e.Decision != nil) {
					t.Fatal("failure acquired authority")
				}
			}
			if scenario == "after_receipt" {
				var audit struct {
					FleetEvents [][]byte `json:"fleet_events"`
					ChannelName string   `json:"channel_name"`
				}
				if json.Unmarshal(second.ApprovalJSON, &audit) != nil || len(audit.FleetEvents) != 1 || !bytes.Equal(audit.FleetEvents[0], proofs[0]) || audit.ChannelName != "ops" {
					t.Fatal("original receipt/route audit lost")
				}
			} else if scenario == "auto_send" {
				if len(second.ApprovalJSON) != 0 {
					t.Fatal("auto NULL approval invariant changed")
				}
			} else {
				frozen, err := os.ReadFile(second.ManifestPath)
				if err != nil || !bytes.Equal(second.ApprovalJSON, frozen) {
					t.Fatal("failure changed frozen human approval bytes", err)
				}
			}
		})
	}
}
