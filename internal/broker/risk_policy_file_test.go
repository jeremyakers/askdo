package broker

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/proto"
)

// riskPolicyFixture is an isolated tree owned by the test runner. Production
// trusts root and verifies from "/"; a fixture can only change who may own the
// tree and where verification starts. The write-permission, symlink and
// descriptor rules under test are the production ones.
func riskPolicyFixture(t *testing.T) (riskPolicyTrust, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return riskPolicyTrust{owner: uint32(os.Geteuid()), anchor: root}, root
}

// writeRiskPolicyFile creates path (and parents) with an explicit mode that
// does not depend on the process umask.
func writeRiskPolicyFile(t *testing.T, path string, data []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadRiskPolicyReturnsExactBytesOfOwnedNonWritableFiles(t *testing.T) {
	trust, root := riskPolicyFixture(t)
	exact := []byte("\xef\xbb\xbf  tab\there\r\nnaïve ✓ <b>&</b>\n\n  ")
	for _, mode := range []os.FileMode{0o644, 0o600, 0o444} {
		path := writeRiskPolicyFile(t, filepath.Join(root, "etc", "policy.md"), exact, mode)
		got, err := readRiskPolicy(trust, path, int64(proto.MaxFrameLength))
		if err != nil || !bytes.Equal(got, exact) {
			t.Fatalf("mode %o: bytes=%q err=%v, want exact fixture", mode, got, err)
		}
	}
	empty := writeRiskPolicyFile(t, filepath.Join(root, "etc", "empty.md"), nil, 0o644)
	if got, err := readRiskPolicy(trust, empty, int64(proto.MaxFrameLength)); err != nil || len(got) != 0 {
		t.Fatalf("empty rubric: %q %v", got, err)
	}
}

func TestReadRiskPolicyRejectsWritableLinkedAndForeignProvenance(t *testing.T) {
	good := []byte("trusted rubric")
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, trust *riskPolicyTrust, root string) string
	}{
		{"group writable file", func(t *testing.T, _ *riskPolicyTrust, root string) string {
			return writeRiskPolicyFile(t, filepath.Join(root, "p.md"), good, 0o664)
		}},
		{"world writable file", func(t *testing.T, _ *riskPolicyTrust, root string) string {
			return writeRiskPolicyFile(t, filepath.Join(root, "p.md"), good, 0o666)
		}},
		{"group writable ancestor", func(t *testing.T, _ *riskPolicyTrust, root string) string {
			path := writeRiskPolicyFile(t, filepath.Join(root, "a", "b", "p.md"), good, 0o644)
			if err := os.Chmod(filepath.Join(root, "a", "b"), 0o775); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"world writable ancestor", func(t *testing.T, _ *riskPolicyTrust, root string) string {
			path := writeRiskPolicyFile(t, filepath.Join(root, "a", "b", "p.md"), good, 0o644)
			if err := os.Chmod(filepath.Join(root, "a"), 0o757); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"final symlink", func(t *testing.T, _ *riskPolicyTrust, root string) string {
			target := writeRiskPolicyFile(t, filepath.Join(root, "real.md"), good, 0o644)
			link := filepath.Join(root, "link.md")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
		{"directory symlink in path", func(t *testing.T, _ *riskPolicyTrust, root string) string {
			writeRiskPolicyFile(t, filepath.Join(root, "real", "p.md"), good, 0o644)
			if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "alias")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(root, "alias", "p.md")
		}},
		{"directory instead of file", func(t *testing.T, _ *riskPolicyTrust, root string) string {
			if err := os.Mkdir(filepath.Join(root, "p.md"), 0o755); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(root, "p.md")
		}},
		{"fifo", func(t *testing.T, _ *riskPolicyTrust, root string) string {
			if err := syscall.Mkfifo(filepath.Join(root, "p.md"), 0o644); err != nil {
				t.Skipf("no fifo support: %v", err)
			}
			return filepath.Join(root, "p.md")
		}},
		{"owned by someone else", func(t *testing.T, trust *riskPolicyTrust, root string) string {
			path := writeRiskPolicyFile(t, filepath.Join(root, "p.md"), good, 0o644)
			trust.owner++ // the fixture tree is now foreign-owned
			return path
		}},
		{"relative path", func(t *testing.T, _ *riskPolicyTrust, root string) string {
			writeRiskPolicyFile(t, filepath.Join(root, "p.md"), good, 0o644)
			return "p.md"
		}},
		{"unclean path", func(t *testing.T, _ *riskPolicyTrust, root string) string {
			writeRiskPolicyFile(t, filepath.Join(root, "p.md"), good, 0o644)
			return root + "/x/../p.md" // filepath.Join would silently clean it
		}},
		{"outside the trusted tree", func(t *testing.T, trust *riskPolicyTrust, root string) string {
			other := t.TempDir()
			return writeRiskPolicyFile(t, filepath.Join(other, "p.md"), good, 0o644)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trust, root := riskPolicyFixture(t)
			path := tc.build(t, &trust, root)
			got, err := readRiskPolicy(trust, path, int64(proto.MaxFrameLength))
			if len(got) != 0 || !errors.Is(err, errRiskPolicyUnsafe) {
				t.Fatalf("data=%q err=%v, want errRiskPolicyUnsafe and no bytes", got, err)
			}
		})
	}
}

// Every other test varies who owns its fixture. Production does not: it needs
// root ownership all the way from "/", so a tree owned by an unprivileged test
// runner (or sitting under the world-writable temp directory) is never trusted.
func TestProductionTrustRefusesAnUnprivilegedTree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root-owned fixture is legitimately trusted by the production rule")
	}
	_, root := riskPolicyFixture(t)
	path := writeRiskPolicyFile(t, filepath.Join(root, "p.md"), []byte("rubric"), 0o644)
	if got, err := readRiskPolicy(rootRiskPolicyTrust(), path, int64(proto.MaxFrameLength)); len(got) != 0 || !errors.Is(err, errRiskPolicyUnsafe) {
		t.Fatalf("production trust accepted an unprivileged tree: %q %v", got, err)
	}
}

// Real root ownership needs real root, so this runs only in the disposable root
// harness: the production rule accepts a root-owned tree and rejects the same
// file once ownership or write access is no longer the administrator's.
func TestRootRiskPolicyTrustWithRealRootOwnership(t *testing.T) {
	requireRootTest(t)
	base := t.TempDir()
	trust := rootRiskPolicyTrust()
	dir := filepath.Join(base, "policies")
	path := writeRiskPolicyFile(t, filepath.Join(dir, "a.md"), []byte("root rubric\n"), 0o644)
	if got, err := readRiskPolicy(trust, path, int64(proto.MaxFrameLength)); err != nil || string(got) != "root rubric\n" {
		t.Fatalf("root-owned tree rejected: %q %v", got, err)
	}
	const nobody = 65534
	for name, mutate := range map[string]func() error{
		"file owned by another account":      func() error { return os.Chown(path, nobody, nobody) },
		"directory owned by another account": func() error { return os.Chown(dir, nobody, nobody) },
		"file writable by its group":         func() error { return os.Chmod(path, 0o664) },
		"directory writable by others":       func() error { return os.Chmod(dir, 0o757) },
	} {
		if err := os.Chown(path, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(dir, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := mutate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, err := readRiskPolicy(trust, path, int64(proto.MaxFrameLength)); len(got) != 0 || !errors.Is(err, errRiskPolicyUnsafe) {
			t.Fatalf("%s: accepted (%q, %v)", name, got, err)
		}
	}
}

func TestReadRiskPolicyReportsMissingFilesAsAbsent(t *testing.T) {
	trust, root := riskPolicyFixture(t)
	for _, path := range []string{filepath.Join(root, "missing.md"), filepath.Join(root, "no", "such", "dir", "p.md")} {
		if got, err := readRiskPolicy(trust, path, int64(proto.MaxFrameLength)); len(got) != 0 || !errors.Is(err, errRiskPolicyAbsent) {
			t.Fatalf("%s: data=%q err=%v, want errRiskPolicyAbsent", path, got, err)
		}
	}
}

// makeRiskPolicyDir creates dir with an explicit mode that ignores the umask.
func makeRiskPolicyDir(t *testing.T, dir string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	return dir
}

// loadRubric selects and reads a rubric the way the start of an AI review does,
// for a broker whose rubric trust is the given fixture. A non-nil files map is
// resolved like review.account_notes.users at Load.
func loadRubric(t *testing.T, trust riskPolicyTrust, hostDefault string, uid uint32, files map[string]string) (*riskPolicySnapshot, error) {
	t.Helper()
	cfg := testConfig()
	cfg.Review.AccountNotes = &config.AccountNotesConfig{Users: files}
	if err := cfg.Review.ResolveAccountNotes(); err != nil {
		t.Fatal(err)
	}
	job := &jobRuntime{daemon: &daemon{cfg: cfg, riskPolicyDefault: hostDefault, riskPolicyTrust: trust}, uid: uid, req: proto.SubmitRequest{RequestID: "2026-10-21_#1"}}
	return job.loadRiskPolicy()
}

// riskPolicyLayout is a place a rubric can sit: the trust to verify with
// (trust.anchor is the fixture root) and the directory under test. Only the
// first layout is fully administrator-controlled; the others worked before
// rubrics existed, for example an alternate --config directory owned by a
// service account or kept in shared scratch space.
type riskPolicyLayout struct {
	name    string
	trusted bool
	build   func(t *testing.T) (riskPolicyTrust, string)
}

func existingRiskPolicyLayouts() []riskPolicyLayout {
	return []riskPolicyLayout{
		{"administrator-controlled directory", true, func(t *testing.T) (riskPolicyTrust, string) {
			trust, root := riskPolicyFixture(t)
			return trust, root
		}},
		{"world-writable directory", false, func(t *testing.T) (riskPolicyTrust, string) {
			trust, root := riskPolicyFixture(t)
			return trust, makeRiskPolicyDir(t, filepath.Join(root, "shared"), 0o777)
		}},
		{"group-writable ancestor", false, func(t *testing.T) (riskPolicyTrust, string) {
			trust, root := riskPolicyFixture(t)
			makeRiskPolicyDir(t, filepath.Join(root, "group"), 0o775)
			return trust, makeRiskPolicyDir(t, filepath.Join(root, "group", "instance"), 0o755)
		}},
		{"tree owned by another account", false, func(t *testing.T) (riskPolicyTrust, string) {
			trust, root := riskPolicyFixture(t)
			trust.owner++
			return trust, makeRiskPolicyDir(t, filepath.Join(root, "service"), 0o755)
		}},
	}
}

// riskPolicyLayoutsWithMissingDir adds a layout whose directory does not exist.
func riskPolicyLayoutsWithMissingDir() []riskPolicyLayout {
	return append(existingRiskPolicyLayouts(), riskPolicyLayout{"directory does not exist", true, func(t *testing.T) (riskPolicyTrust, string) {
		trust, root := riskPolicyFixture(t)
		return trust, filepath.Join(root, "no", "such", "dir")
	}})
}

// The host default is optional. Until an administrator creates it there is
// nothing to substitute, so no provenance is demanded of the directories around
// it: an ordinary layout that was valid before rubrics existed stays valid and
// the review simply uses the embedded default.
func TestAbsentHostDefaultIsNoPolicyWhateverTheAncestors(t *testing.T) {
	for _, layout := range riskPolicyLayoutsWithMissingDir() {
		t.Run(layout.name, func(t *testing.T) {
			trust, dir := layout.build(t)
			snapshot, err := loadRubric(t, trust, filepath.Join(dir, riskPolicyFileName), uint32(os.Getuid()), nil)
			if snapshot != nil || err != nil {
				t.Fatalf("absent host default: snapshot=%+v err=%v, want no policy and no error", snapshot, err)
			}
		})
	}
}

// A host default that exists is held to the full rule, whatever the layout, and
// a layout that satisfies the rule still loads it.
func TestPresentHostDefaultIsStillHeldToTheTrustRule(t *testing.T) {
	uid := uint32(os.Getuid())
	const rubric = "host rubric\n"
	for _, layout := range existingRiskPolicyLayouts() {
		t.Run(layout.name, func(t *testing.T) {
			trust, dir := layout.build(t)
			path := writeRiskPolicyFile(t, filepath.Join(dir, riskPolicyFileName), []byte(rubric), 0o644)
			snapshot, err := loadRubric(t, trust, path, uid, nil)
			if layout.trusted {
				if err != nil || snapshot == nil || len(snapshot.layers) != 1 || snapshot.layers[0].Text != rubric || snapshot.layers[0].Scope != riskPolicyScopeHost || snapshot.layers[0].SHA256 != revisionOf(rubric) {
					t.Fatalf("trusted layout: snapshot=%+v err=%v", snapshot, err)
				}
				return
			}
			if snapshot != nil || !errors.Is(err, errRiskPolicyUnsafe) {
				t.Fatalf("snapshot=%+v err=%v, want errRiskPolicyUnsafe and no policy", snapshot, err)
			}
		})
	}
	// Something is at the path, so it is not "absent": an alias or a directory
	// in the policy's place is refused rather than skipped.
	for name, place := range map[string]func(t *testing.T, path, root string){
		"dangling symlink": func(t *testing.T, path, root string) {
			if err := os.Symlink(filepath.Join(root, "nowhere"), path); err != nil {
				t.Fatal(err)
			}
		},
		"symlink to a valid file": func(t *testing.T, path, root string) {
			target := writeRiskPolicyFile(t, filepath.Join(root, "real.md"), []byte(rubric), 0o644)
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, path, _ string) {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"file writable by others": func(t *testing.T, path, _ string) {
			writeRiskPolicyFile(t, path, []byte(rubric), 0o666)
		},
	} {
		t.Run(name, func(t *testing.T) {
			trust, root := riskPolicyFixture(t)
			path := filepath.Join(root, riskPolicyFileName)
			place(t, path, root)
			if snapshot, err := loadRubric(t, trust, path, uid, nil); snapshot != nil || !errors.Is(err, errRiskPolicyUnsafe) {
				t.Fatalf("snapshot=%+v err=%v, want errRiskPolicyUnsafe and no policy", snapshot, err)
			}
		})
	}
}

// A rubric the administrator deliberately assigned to an account is required:
// missing is an error in every layout, and a present host default never stands
// in for it.
func TestConfiguredUserRubricIsStillRequiredWhateverTheAncestors(t *testing.T) {
	accounts := namedRouteAccounts(t)
	user := accounts[0]
	for _, layout := range riskPolicyLayoutsWithMissingDir() {
		t.Run(layout.name, func(t *testing.T) {
			trust, dir := layout.build(t)
			// A valid host default inside the same trust anchor: if the loader
			// ever fell back to it, the trusted layouts would return a policy.
			hostDefault := writeRiskPolicyFile(t, filepath.Join(trust.anchor, "decoy", riskPolicyFileName), []byte("host rubric"), 0o644)
			missing := filepath.Join(dir, "user.md")
			snapshot, err := loadRubric(t, trust, hostDefault, user.uid, map[string]string{user.login: missing})
			if snapshot != nil || err == nil {
				t.Fatalf("missing configured rubric: snapshot=%+v err=%v, want an error and no policy", snapshot, err)
			}
			if layout.trusted && !errors.Is(err, errRiskPolicyAbsent) {
				t.Fatalf("err=%v, want errRiskPolicyAbsent", err)
			}
		})
	}
}

// End to end at the job level: an AI-required review under such a layout runs
// exactly as it did before rubrics existed, with the embedded default and no
// audit record.
func TestAbsentHostDefaultUnderUntrustedAncestorDoesNotFailAIReviews(t *testing.T) {
	env := newRiskPolicyEnv(t)
	alt := makeRiskPolicyDir(t, filepath.Join(env.root, "alt-instance"), 0o777)
	boots := make(chan proto.Bootstrap, 1)
	h := env.harness(t, testConfig(), nil, filepath.Join(alt, riskPolicyFileName), &ScriptedWorker{Config: ScriptedWorkerConfig{Bootstrap: boots}})
	result, id := runRiskPolicyJob(t, h, env.b.uid, "alternate config layout")
	boot := nextBootstrap(t, boots)
	if result.State != "finished" || boot.RiskPolicy != nil {
		t.Fatalf("state=%s message=%q rubric=%+v, want a finished review with no rubric", result.State, result.Message, boot.RiskPolicy)
	}
	if manifest := frozenManifestBytes(t, h, env.b.uid, id); bytes.Contains(manifest, []byte("administrator_layers")) {
		t.Fatalf("default review manifest gained a rubric record: %s", manifest)
	}
}

func TestReadRiskPolicyRejectsContentTheProtocolCannotCarry(t *testing.T) {
	trust, root := riskPolicyFixture(t)
	for name, data := range map[string][]byte{
		"invalid UTF-8": []byte("ru\xffbric"),
		"NUL":           []byte("ru\x00bric"),
	} {
		path := writeRiskPolicyFile(t, filepath.Join(root, "p.md"), data, 0o644)
		if got, err := readRiskPolicy(trust, path, int64(proto.MaxFrameLength)); len(got) != 0 || !errors.Is(err, errRiskPolicyInvalid) {
			t.Fatalf("%s: data=%q err=%v, want errRiskPolicyInvalid", name, got, err)
		}
	}
	// The cap is the protocol frame ceiling the bootstrap must fit in; a sparse
	// file proves it without reading or allocating that much.
	big := filepath.Join(root, "big.md")
	writeRiskPolicyFile(t, big, nil, 0o644)
	if err := os.Truncate(big, int64(proto.MaxFrameLength)+1); err != nil {
		t.Skipf("sparse file unsupported: %v", err)
	}
	if got, err := readRiskPolicy(trust, big, int64(proto.MaxFrameLength)); len(got) != 0 || !errors.Is(err, errRiskPolicyInvalid) {
		t.Fatalf("oversize: %d bytes err=%v, want errRiskPolicyInvalid", len(got), err)
	}
}
