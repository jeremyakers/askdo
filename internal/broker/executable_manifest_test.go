package broker

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyakers/askdo/internal/proto"
)

func TestFrozenApprovalBindsOriginalResolvedExecutable(t *testing.T) {
	for _, mode := range []string{"reviewed", "approval_only"} {
		t.Run(mode, func(t *testing.T) {
			h := newBrokerHarness(t, nil, nil)
			job, ctx := newFreezeTestJob(t, h)
			alias := filepath.Join(t.TempDir(), "multicall")
			if err := os.Symlink("/bin/sh", alias); err != nil {
				t.Fatal(err)
			}
			job.req.Argv = []string{alias}
			if err := job.captureEvidence(); err != nil {
				t.Fatal(err)
			}
			original := job.resolvedExecutable
			if err := os.Remove(alias); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/usr/bin/false", alias); err != nil {
				t.Fatal(err)
			}

			bootstrap := job.bootstrap().Operation
			if bootstrap.Argv[0] != alias || bootstrap.Executable != original {
				t.Fatalf("review bootstrap lost pinned executable: %+v", bootstrap)
			}
			var encoded []byte
			var err error
			if mode == "reviewed" {
				encoded, _, err = job.freezeReview(ctx, validWorkerReview(proto.WorkerOperation{}))
			} else {
				_, err = job.freezeApprovalOnly(ctx, "administrator policy", nil)
				if err == nil {
					encoded, err = os.ReadFile(job.spool.approval)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			var manifest struct {
				Operation manifestOperation `json:"operation"`
			}
			if err := json.Unmarshal(encoded, &manifest); err != nil {
				t.Fatal(err)
			}
			if manifest.Operation.Argv[0] != alias || manifest.Operation.Executable != original {
				t.Fatalf("frozen operation lost pinned executable: %+v", manifest.Operation)
			}

			var document map[string]any
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatal(err)
			}
			document["operation"].(map[string]any)["executable"] = "/usr/bin/false"
			altered, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(encoded) == sha256.Sum256(altered) {
				t.Fatal("manifest digest does not bind the resolved executable")
			}
		})
	}
}
