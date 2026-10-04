package broker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyakers/askdo/internal/inspection"
	"github.com/jeremyakers/askdo/internal/proto"
)

type waitingMetadataReader struct{ started chan context.Context }

func (f *waitingMetadataReader) ServiceStatus(ctx context.Context, _ string) (proto.ServiceStatusResult, inspection.Status, string) {
	f.started <- ctx
	<-ctx.Done()
	return proto.ServiceStatusResult{}, inspection.StatusUnknown, "private-cancellation-cause"
}

func (f *waitingMetadataReader) SudoPolicy(ctx context.Context, _ uint32) (proto.SudoPolicyResult, inspection.Status, string) {
	f.started <- ctx
	<-ctx.Done()
	return proto.SudoPolicyResult{}, inspection.StatusUnknown, "private-cancellation-cause"
}

func TestRootMetadataContextLifecycleCancellation(t *testing.T) {
	for _, op := range []string{"service_status", "sudo_policy"} {
		for _, lifecycle := range []string{"caller", "job", "daemon", "deadline"} {
			t.Run(op+"/"+lifecycle, func(t *testing.T) {
				j := directJob(t, t.TempDir(), nil)
				j.daemon.cfg.Inspection.ServiceStatusEnabled = true
				j.daemon.cfg.Inspection.SudoPolicyEnabled = true
				reader := &waitingMetadataReader{started: make(chan context.Context, 1)}
				j.metadataReader = reader
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				shutdown, stop := context.WithCancel(context.Background())
				defer stop()
				j.daemon.shutdownCtx = shutdown
				if lifecycle == "deadline" {
					j.inspectionDeadline = time.Now().Add(100 * time.Millisecond)
				}
				var args any = proto.ServiceStatusRequest{Unit: "fixture.service"}
				if op == "sudo_policy" {
					args = proto.SudoPolicyRequest{UID: j.uid}
				}
				payload, _ := json.Marshal(args)
				r := proto.InspectRequest{Type: "inspect_request", Op: op, Payload: payload}
				done := make(chan proto.InspectResult, 1)
				go func() {
					result, err := j.handleInspectContext(ctx, r)
					if err != nil {
						t.Error(err)
					}
					done <- result
				}()
				select {
				case leafCtx := <-reader.started:
					if deadline, ok := leafCtx.Deadline(); !ok || deadline.After(j.reviewDeadline()) {
						t.Error("leaf lost original deadline")
					}
				case <-time.After(time.Second):
					t.Fatal("reader not started")
				}
				switch lifecycle {
				case "caller":
					cancel()
				case "job":
					close(j.done)
				case "daemon":
					stop()
				}
				select {
				case result := <-done:
					if result.Status != "unknown" || result.ReasonCode != "timeout" || len(result.Payload) != 0 {
						t.Fatal(result)
					}
				case <-time.After(time.Second):
					t.Fatal("metadata reader ignored lifecycle cancellation")
				}
				obs := j.inspectionEvidence().Observations
				if len(obs) != 1 || obs[0].Reason != "timeout" || len(obs[0].Metadata) != 0 || !obs[0].SelectorRedacted {
					t.Fatal("unsafe canceled observation")
				}
			})
		}
	}
}

func TestRootMetadataCanceledHashNeverOpensOrReturnsDigest(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "executable")
	if err := os.WriteFile(path, []byte("private-file-content"), 0755); err != nil {
		t.Fatal(err)
	}
	j := directJob(t, root, nil)
	j.daemon.cfg.Inspection.HashPathEnabled = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	payload, _ := json.Marshal(proto.HashPathRequest{Path: path})
	r, err := j.handleInspectContext(ctx, proto.InspectRequest{Type: "inspect_request", Op: "hash_path", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if r.ReasonCode != "timeout" || len(r.Payload) != 0 || j.hashedWorkBytes != 0 || j.hashAttempts != 0 {
		t.Fatal("canceled hash performed work", r)
	}
}

func TestRootMetadataOriginalDeadlineAndSingleHashAttemptLimit(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "executable")
	if err := os.WriteFile(path, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	j := directJob(t, root, nil)
	j.daemon.cfg.Inspection.HashPathEnabled = true
	j.daemon.cfg.Limits.MaxInspectedFiles = 1
	deadline := j.reviewDeadline()
	if time.UnixMilli(j.bootstrap().ReviewDeadlineUnixMS).UnixMilli() != deadline.UnixMilli() {
		t.Fatal("bootstrap extended original review deadline")
	}
	if r := directCall(t, j, "hash_path", proto.HashPathRequest{Path: path}); r.Status != "ok" {
		t.Fatal(r)
	}
	if r := directCall(t, j, "hash_path", proto.HashPathRequest{Path: path}); r.ReasonCode != "file_count_limit" {
		t.Fatal(r)
	}
	if !j.reviewDeadline().Equal(deadline) {
		t.Fatal("tool call extended review deadline")
	}
}
