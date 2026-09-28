package broker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
)

func newWithheldJob(t *testing.T, configure func(*config.Config, string)) (*jobRuntime, string) {
	t.Helper()
	root := t.TempDir()
	cfg := testConfig(testUID)
	cfg.Inspection = config.InspectionConfig{ReadRoots: []string{root}}
	if configure != nil {
		configure(cfg, root)
	}
	h := newBrokerHarnessWithConfig(t, nil, nil, cfg)
	spool, err := createSpool(t.TempDir(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	j := newTestJobRuntime(t, h.daemon, proto.SubmitRequest{Mode: "argv", Argv: []string{"/usr/bin/true"}, RequestID: reserveForTest(t, h.socket, h.peerUID.Load())}, spool)
	return j, root
}

func assertNoSecretInSpool(t *testing.T, j *jobRuntime, secret string) {
	t.Helper()
	_ = filepath.Walk(j.spool.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			data, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			if strings.Contains(string(data), secret) {
				t.Errorf("secret appeared in spool file %s", path)
			}
		}
		return nil
	})
}

// Metadata-only executable resolution never reads credential-like contents.
func TestSubmitTimeSensitiveExecutableWithheld(t *testing.T) {
	job, root := newWithheldJob(t, nil)
	secret := writeEvidenceFixture(t, root, ".env", "SECRET_TOKEN=hunter2\n")
	job.req.Argv = []string{secret}
	err := job.captureEvidence()
	if err != nil || len(job.withheldPaths) != 1 {
		t.Fatalf("metadata resolution err=%v withheld=%v", err, job.withheldPaths)
	}
	index, indexErr := readCaptureIndex(job.spool.captureIndex)
	if indexErr != nil {
		t.Fatal(indexErr)
	}
	if len(index.Files) != 0 {
		t.Fatalf("sensitive executable captured: %+v", index.Files)
	}
	if refs, count := job.withheldFacts(index); count != 1 || refs[0] != secret {
		t.Fatalf("operator lacks broker-owned withheld warning: %v %d", refs, count)
	}
	assertNoSecretInSpool(t, job, "hunter2")
}

func TestSubmitTimeSensitiveSymlinkExecutableWithheld(t *testing.T) {
	job, root := newWithheldJob(t, nil)
	secret := writeEvidenceFixture(t, root, ".env", "SECRET_TOKEN=hunter2\n")
	alias := filepath.Join(root, "launcher")
	if err := os.Symlink(secret, alias); err != nil {
		t.Fatal(err)
	}
	job.req.Argv = []string{alias}
	err := job.captureEvidence()
	if err != nil || job.resolvedArgv[0] != secret || len(job.withheldPaths) != 2 {
		t.Fatalf("metadata resolution err=%v argv=%v withheld=%v", err, job.resolvedArgv, job.withheldPaths)
	}
	if _, ok := job.withheldPaths[alias]; !ok {
		t.Fatalf("requested alias missing from operator warning: %v", job.withheldPaths)
	}
	if _, ok := job.withheldPaths[secret]; !ok {
		t.Fatalf("resolved credential path missing from operator warning: %v", job.withheldPaths)
	}
	assertNoSecretInSpool(t, job, "hunter2")
}

func TestSubmitTimeSensitiveInterpreterNotRead(t *testing.T) {
	job, root := newWithheldJob(t, nil)
	secret := writeEvidenceFixture(t, root, ".env", "SECRET_TOKEN=hunter2\n")
	alias := filepath.Join(root, "fake-interpreter")
	if err := os.Symlink(secret, alias); err != nil {
		t.Fatal(err)
	}
	script := writeEvidenceFixture(t, root, "tool", "#!"+alias+"\necho hi\n")
	job.req.Argv = []string{script}
	err := job.captureEvidence()
	if err != nil || job.resolvedArgv[0] != script {
		t.Fatalf("script metadata resolution err=%v argv=%v", err, job.resolvedArgv)
	}
	assertNoSecretInSpool(t, job, "hunter2")
}

func TestSubmitTimeOrdinaryExecutableNotCaptured(t *testing.T) {
	job, root := newWithheldJob(t, nil)
	tool := writeEvidenceFixture(t, root, "tool", "echo hi\n")
	job.req.Argv = []string{tool}
	if err := job.captureEvidence(); err != nil {
		t.Fatal(err)
	}
	index, err := readCaptureIndex(job.spool.captureIndex)
	if err != nil || len(index.Files) != 0 || job.resolvedArgv[0] != tool {
		t.Fatalf("capture index=%+v err=%v", index, err)
	}
}

func TestMetadataOnlyApprovedPATHResolution(t *testing.T) {
	job, _ := newWithheldJob(t, nil)
	job.req.Argv = []string{"id", "-u"}
	if err := job.captureEvidence(); err != nil {
		t.Fatal(err)
	}
	want, err := resolveExecutableMetadata("/usr/bin/id")
	if err != nil {
		t.Fatal(err)
	}
	if job.resolvedArgv[0] != want || job.bootstrap().Operation.Argv[0] != want || job.operation().Argv[0] != want || job.resolvedArgv[1] != "-u" {
		t.Fatalf("bootstrap/dispatch diverged: resolved=%v bootstrap=%v operation=%v", job.resolvedArgv, job.bootstrap().Operation.Argv, job.operation().Argv)
	}
	index, err := readCaptureIndex(job.spool.captureIndex)
	if err != nil || len(index.Files) != 0 {
		t.Fatalf("PATH lookup captured content: %+v err=%v", index, err)
	}
}

func TestExecutablePreflightRejectsInvalidInvocation(t *testing.T) {
	for _, argv0 := range []string{"../id", "/usr/bin/../bin/id", "/no/such/executable", "/usr/bin"} {
		t.Run(argv0, func(t *testing.T) {
			job, _ := newWithheldJob(t, nil)
			job.req.Argv = []string{argv0}
			if err := job.captureEvidence(); err == nil || len(job.resolvedArgv) != 0 {
				t.Fatalf("invalid executable accepted: argv=%v err=%v", job.resolvedArgv, err)
			}
		})
	}
}
