//go:build askdo_fleet_fixture

package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
	"github.com/jeremyakers/askdo/internal/store"
)

func TestRootInspectionMetadataHashPayloadLimitContinues(t *testing.T) {
	requireRootTest(t)
	if os.Getenv("ASKDO_METADATA_CONTAINER") != "1" {
		t.Skip("requires disposable metadata container")
	}
	root := t.TempDir()
	paths := hashOutputLimitPaths(t, root)
	var mu sync.Mutex
	turns := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			t.Error(err)
			return
		}
		var request struct {
			Messages []struct {
				Role, Content string
				ToolCallID    string `json:"tool_call_id"`
			}
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Error(err)
			return
		}
		turns++
		calls := []any{}
		call := func(id, name string, args any) {
			payload, _ := json.Marshal(args)
			calls = append(calls, map[string]any{"id": id, "type": "function", "function": map[string]any{"name": name, "arguments": string(payload)}})
		}
		switch turns {
		case 1:
			call("long", "hash_path", proto.HashPathRequest{Path: paths[0]})
			call("escaped", "hash_path", proto.HashPathRequest{Path: paths[1]})
			call("scope", "inspection_scope", proto.InspectionScopeRequest{})
		case 2:
			results := map[string]string{}
			for _, m := range request.Messages {
				if m.Role == "tool" {
					results[m.ToolCallID] = m.Content
				}
			}
			for _, id := range []string{"long", "escaped"} {
				var status struct {
					Status string `json:"status"`
					Reason string `json:"reason_code"`
				}
				if json.Unmarshal([]byte(results[id]), &status) != nil || status.Status != "limit_exceeded" || status.Reason != "output_limit" {
					t.Errorf("hash output failure did not reach actual reviewer: %s", results[id])
					return
				}
			}
			var scope proto.InspectionScopeResult
			if json.Unmarshal([]byte(results["scope"]), &scope) != nil || !scope.Capabilities.HashPathEnabled {
				t.Error("inspection did not continue after hash output limit")
				return
			}
			call("report", "submit_review", map[string]any{"risk": "1", "summary": "Both hash observations exceeded the metadata output limit", "effects": []string{"Prints root UID"}, "warnings": []proto.ReviewWarning{{Message: "Neither requested executable hash could be returned", Evidence: "Both hash_path results reported limit_exceeded/output_limit"}}, "missing_context": []string{"Long-path executable hash unavailable: output_limit", "Escaped-path executable hash unavailable: output_limit"}, "reversibility": "No target state changed", "intent_match": "consistent"})
		default:
			t.Error("unexpected model turn")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": "", "tool_calls": calls}, "finish_reason": "tool_calls"}}}); err != nil {
			t.Error(err)
		}
	})
	// The metadata runner keeps fixtures below /root; the dropped reviewer
	// needs a traversable binary directory, without exposing the fixture files.
	tmp := os.Getenv("TMPDIR")
	t.Setenv("TMPDIR", "/tmp")
	binary := buildFleetReviewer(t)
	t.Setenv("TMPDIR", tmp)
	f := newRootFleetFixture(t, binary, "1", false, false, false, rootFleetOptions{providerHandler: handler, configure: func(c *config.Config) {
		c.Inspection.ReadRoots = append(c.Inspection.ReadRoots, root)
		c.Inspection.HashPathEnabled = true
	}})
	if worker, ok := f.broker.daemon.worker.(*processWorker); !ok || worker.uid == 0 {
		t.Fatal("reviewer not isolated")
	}
	id := reserveForTest(t, f.broker.socket, 0)
	request := submitRequest(id, "hash output limit regression")
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
		t.Fatal("output failure terminated review", job.State)
	}
	mu.Lock()
	count := turns
	mu.Unlock()
	if count != 2 {
		t.Fatal("actual reviewer did not continue", count)
	}
	var manifest approvalManifest
	frozen, err := os.ReadFile(job.ManifestPath)
	if err != nil || json.Unmarshal(frozen, &manifest) != nil {
		t.Fatal("manifest unavailable", err)
	}
	if manifest.Inspection == nil || manifest.Inspection.HashAttempts != 2 || manifest.Inspection.HashedWorkBytes != 2 || manifest.Inspection.MetadataRequests != 3 || len(manifest.Inspection.Observations) != 3 || len(manifest.Report.MissingContext) != 2 {
		t.Fatal("charged failures or uncertainty missing from frozen evidence")
	}
	for _, obs := range manifest.Inspection.Observations[:2] {
		if obs.Reason != "output_limit" || !obs.SelectorRedacted || obs.Selector != nil || len(obs.Metadata) != 0 {
			t.Fatal("output-limit observation leaked evidence")
		}
	}
	audit, err := os.ReadFile(filepath.Join(job.SpoolDir, "inspection-evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(audit, []byte(fmt.Sprintf("%x", sha256.Sum256([]byte("x"))))) {
		t.Fatal("digest persisted")
	}
	for _, path := range paths {
		encoded, _ := json.Marshal(path)
		if bytes.Contains(audit, encoded) {
			t.Fatal("denied selector persisted")
		}
	}
	output, err := os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
	if err != nil || len(output) != 0 {
		t.Fatal("execution preceded human decision")
	}
	card, ok := f.bot.Card()
	if !ok {
		t.Fatal("human card missing")
	}
	f.bot.QueueCallback(1, "hash-output", telegramOperator, telegramChat, card.ID, card.ButtonData("a:"))
	job = awaitRootFleetState(t, conn, f.broker.daemon.store, id, store.StateFinished, store.StateFailed)
	output, err = os.ReadFile(filepath.Join(job.SpoolDir, "stdout.log"))
	if job.State != store.StateFinished || err != nil || strings.TrimSpace(string(output)) != "0" {
		t.Fatal("benign approved command did not execute as root", job.State, err)
	}
	t.Log("actual isolated reviewer/private pipe and TLS gateway continued after two serialized hash output limits, froze charged redacted evidence and uncertainty, then executed only after human approval")
}
