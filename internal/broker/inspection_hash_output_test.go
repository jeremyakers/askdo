package broker

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

func hashOutputLimitPaths(t *testing.T, root string) []string {
	t.Helper()
	long := root
	for i := 0; i < 4; i++ {
		long = filepath.Join(long, strings.Repeat("a", 180))
	}
	if err := os.MkdirAll(long, 0700); err != nil {
		t.Fatal(err)
	}
	// Quotes and backslashes are valid filename bytes, but JSON doubles them.
	escaped := filepath.Join(root, strings.Repeat(`"\`, 100))
	if err := os.Mkdir(escaped, 0700); err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(long, "executable"), filepath.Join(escaped, "executable")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("x"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if len(paths[1]) > 400 {
		t.Fatal("escaped fixture no longer short")
	}
	return paths
}

func TestRootMetadataHashPayloadLimitContinues(t *testing.T) {
	root := t.TempDir()
	paths := hashOutputLimitPaths(t, root)
	j := directJob(t, root, nil)
	j.daemon.cfg.Inspection.HashPathEnabled = true
	for _, path := range paths {
		payload, _ := json.Marshal(proto.HashPathRequest{Path: path})
		r := proto.InspectRequest{Type: "inspect_request", Op: "hash_path", RequestSeq: 1, Payload: payload}
		if err := proto.ValidateWorkerMessage(r, proto.WorkerToBroker); err != nil {
			t.Fatal("fixture request invalid", err)
		}
		result, err := j.handleInspect(r)
		if err != nil {
			t.Fatalf("valid hash request terminated review: %v", err)
		}
		if result.Status != "limit_exceeded" || result.ReasonCode != "output_limit" || len(result.Payload) != 0 {
			t.Fatal("oversized hash evidence not safely refused", result)
		}
		if err := proto.ValidateInspectResultFor(r, result); err != nil {
			t.Fatal(err)
		}
	}
	if j.hashAttempts != 2 || j.hashedWorkBytes != 2 || j.metadataRequests != 2 || j.metadataResponseBytes != 0 {
		t.Fatal("output failure refunded work or charged unreturned bytes")
	}
	if result := directCall(t, j, "inspection_scope", proto.InspectionScopeRequest{}); result.Status != "ok" {
		t.Fatal("review cannot continue", result)
	}
	evidence := j.inspectionEvidence()
	for _, obs := range evidence.Observations[:2] {
		if obs.Reason != "output_limit" || !obs.SelectorRedacted || obs.Selector != nil || len(obs.Metadata) != 0 {
			t.Fatal("failure persisted evidence")
		}
	}
	audit, err := os.ReadFile(filepath.Join(j.spool.dir, "inspection-evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(audit), fmt.Sprintf("%x", sha256.Sum256([]byte("x")))) {
		t.Fatal("unreturned digest persisted")
	}
	for _, path := range paths {
		encoded, _ := json.Marshal(path)
		if strings.Contains(string(audit), string(encoded)) {
			t.Fatal("unreturned selector persisted")
		}
	}
}
