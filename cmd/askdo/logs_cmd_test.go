package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/jobid"
	"github.com/jeremyakers/askdo/internal/store"
)

// logsJobFixture describes one synthetic store row plus its on-disk spool.
type logsJobFixture struct {
	uid       uint32
	requestID string
	// spoolName is the job spool directory under the fixture spool root.
	// When empty the row points at a spool directory that is never created.
	spoolName string
	// log is written as reviewer-stderr.log. nil means the log file is
	// absent; a non-nil empty slice means a zero-byte log.
	log []byte
	// logSymlink, when set, makes reviewer-stderr.log a symlink to this
	// target instead of a regular file.
	logSymlink string
	// logDir makes reviewer-stderr.log a directory instead of a file.
	logDir bool
	// compact retention-compacts the row (spool_dir becomes NULL).
	compact bool
	// spoolDirOverride replaces the row's spool_dir verbatim (escape cases).
	spoolDirOverride string
}

// setupLogsFixture builds a synthetic store and spool tree and injects the
// unexported logs command paths at it. No production path is ever touched.
func setupLogsFixture(t *testing.T, fixtures ...logsJobFixture) (storePath, spoolRoot string) {
	t.Helper()
	root := t.TempDir()
	storePath = filepath.Join(root, "jobs.sqlite3")
	spoolRoot = filepath.Join(root, "jobs")
	if err := os.MkdirAll(spoolRoot, 0700); err != nil {
		t.Fatalf("create spool root: %v", err)
	}

	jobStore, err := store.Open(storePath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	for _, fixture := range fixtures {
		spoolDir := filepath.Join(spoolRoot, fixture.spoolName)
		if fixture.spoolDirOverride != "" {
			spoolDir = fixture.spoolDirOverride
		}
		job := store.Job{
			UID:           fixture.uid,
			RequestID:     fixture.requestID,
			State:         store.StateQueued,
			SubmitBody:    []byte(`{"request_id":"` + fixture.requestID + `"}`),
			OperationJSON: []byte(`{"argv":["/bin/true"]}`),
			SpoolDir:      spoolDir,
		}
		if jobid.Validate(fixture.requestID) == nil {
			day, err := time.ParseInLocation("2006-01-02", fixture.requestID[:10], time.Local)
			if err != nil {
				t.Fatal(err)
			}
			id, err := jobStore.ReserveJobID(context.Background(), fixture.uid, day)
			if err != nil || id != fixture.requestID {
				t.Fatalf("ReserveJobID = %q, %v; want %q", id, err, fixture.requestID)
			}
			_, err = jobStore.SubmitReservedJob(context.Background(), job)
			if err != nil {
				t.Fatalf("SubmitReservedJob %q: %v", fixture.requestID, err)
			}
		} else {
			seedHistoricalLogsJob(t, storePath, job)
		}
		if fixture.spoolName != "" && fixture.spoolDirOverride == "" {
			if err := os.MkdirAll(spoolDir, 0700); err != nil {
				t.Fatalf("create spool dir: %v", err)
			}
			logPath := filepath.Join(spoolDir, "reviewer-stderr.log")
			switch {
			case fixture.logSymlink != "":
				if err := os.Symlink(fixture.logSymlink, logPath); err != nil {
					t.Fatalf("symlink log: %v", err)
				}
			case fixture.logDir:
				if err := os.Mkdir(logPath, 0700); err != nil {
					t.Fatalf("mkdir log: %v", err)
				}
			case fixture.log != nil:
				if err := os.WriteFile(logPath, fixture.log, 0600); err != nil {
					t.Fatalf("write log: %v", err)
				}
			}
		}
		if fixture.compact {
			if ok, err := jobStore.Transition(context.Background(), fixture.uid, fixture.requestID, store.StateQueued, store.StateFinished); err != nil || !ok {
				t.Fatalf("Transition %q to finished = (%t, %v)", fixture.requestID, ok, err)
			}
			if _, _, err := jobStore.RetentionCleanup(context.Background(), 0, 1); err != nil {
				t.Fatalf("RetentionCleanup: %v", err)
			}
		}
	}
	if err := jobStore.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}

	origStorePath, origSpoolRoot := logsStorePath, logsSpoolRoot
	logsStorePath, logsSpoolRoot = storePath, spoolRoot
	t.Cleanup(func() { logsStorePath, logsSpoolRoot = origStorePath, origSpoolRoot })
	return storePath, spoolRoot
}

func seedHistoricalLogsJob(t *testing.T, path string, job store.Job) {
	t.Helper()
	// Schema 4 forbids new unreserved jobs. Model a migrated historical row.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(context.Background(), `INSERT INTO jobs
		(uid, request_id, state, submit_body, operation_json, spool_dir, created_at, canonical_job)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)`, job.UID, job.RequestID, job.State,
		job.SubmitBody, job.OperationJSON, job.SpoolDir, time.Now().UnixNano())
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("seed historical job %q: %v", job.RequestID, err)
	}
}

func stubLogsEUID(t *testing.T, euid int) {
	t.Helper()
	orig := getEUID
	getEUID = func() int { return euid }
	t.Cleanup(func() { getEUID = orig })
}

const (
	logsJobID       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	logsJobIDOther  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	logsJobIDAbsent = "cccccccccccccccccccccccccccccccc"
	logsCanonicalID = "2026-09-27_#1"
)

func runLogsCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runLogs(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestLogsRequiresRootBeforeAnyOpen pins the privilege gate: a non-root
// invoker is refused before the database file or any log is opened — the
// injected store path must still not exist afterwards.
func TestLogsRequiresRootBeforeAnyOpen(t *testing.T) {
	stubLogsEUID(t, 998)
	storePath, _ := setupLogsFixture(t, logsJobFixture{uid: 1001, requestID: logsJobID, spoolName: "spool", log: []byte("secret\n")})
	if err := os.Remove(storePath); err != nil {
		t.Fatalf("remove store: %v", err)
	}

	code, stdout, stderr := runLogsCommand(t, "logs", logsJobID)
	if code != 125 || stdout != "" || !strings.Contains(stderr, "requires root") {
		t.Fatalf("exit=%d stdout=%q stderr=%q, want 125 with a requires-root refusal", code, stdout, stderr)
	}
	if _, err := os.Stat(storePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-root run touched the store path (stat err=%v)", err)
	}
}

// TestLogsDispatchBeforeClientFallback pins main's routing: `logs` is the
// operator subcommand, never forwarded to the loopback client.
func TestLogsDispatchBeforeClientFallback(t *testing.T) {
	stubLogsEUID(t, 998)
	if code := run([]string{"logs", logsJobID}); code != 125 {
		t.Fatalf("run(logs) exit=%d, want 125 from the operator command, not the client fallback", code)
	}
}

func TestLogsUsageErrors(t *testing.T) {
	stubLogsEUID(t, 0)
	setupLogsFixture(t)
	for _, args := range [][]string{
		{},
		{"not-hex"},
		{"2026-02-30_#1"},
		{"2026-09-27_#01"},
		{"2026-09-27_#0"},
		{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, // 31 chars
		{logsJobID, logsJobIDOther},
	} {
		if code, _, _ := runLogsCommand(t, args...); code != 125 {
			t.Fatalf("logs %v exit=%d, want 125 usage", args, code)
		}
	}
	if code, _, _ := runLogsCommand(t, "--uid", "not-a-number", logsJobID); code != 125 {
		t.Fatal("--uid with a non-numeric value did not fail as usage")
	}
}

// TestLogsPrintsReviewerStderr is the happy path: a root operator reads the
// bounded tail of the root-only reviewer log, warned on stderr.
func TestLogsPrintsReviewerStderr(t *testing.T) {
	stubLogsEUID(t, 0)
	setupLogsFixture(t, logsJobFixture{uid: 1001, requestID: logsJobID, spoolName: "spool-a", log: []byte("reviewer transcript line\n")})

	code, stdout, stderr := runLogsCommand(t, logsJobID)
	if code != 0 || stdout != "reviewer transcript line\n" {
		t.Fatalf("exit=%d stdout=%q, want the log contents", code, stdout)
	}
	if !strings.Contains(stderr, "provider") || !strings.Contains(stderr, "secret") {
		t.Fatalf("stderr=%q, want a provider-text/secrets warning", stderr)
	}
}

// Canonical IDs are the same operator-facing identifiers stored in the job
// row; a UID filter must still enforce ownership rather than select another log.
func TestLogsCanonicalIDAndOwnership(t *testing.T) {
	stubLogsEUID(t, 0)
	setupLogsFixture(t, logsJobFixture{
		uid: 1001, requestID: logsCanonicalID, spoolName: "canonical", log: []byte("complete reviewer transcript\n"),
	})
	for _, args := range [][]string{{logsCanonicalID, "--all"}, {"--uid", "1001", logsCanonicalID, "--all"}} {
		code, stdout, stderr := runLogsCommand(t, args...)
		if code != 0 || stdout != "complete reviewer transcript\n" || !strings.Contains(stderr, logsWarning) {
			t.Fatalf("logs %v: exit=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
	code, stdout, stderr := runLogsCommand(t, logsCanonicalID, "--uid", "1002", "--all")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "unknown job") || !strings.Contains(stderr, logsCanonicalID) {
		t.Fatalf("wrong UID: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestLogsCanonicalIDRequiresRootBeforeOpen(t *testing.T) {
	stubLogsEUID(t, 998)
	storePath, _ := setupLogsFixture(t, logsJobFixture{
		uid: 1001, requestID: logsCanonicalID, spoolName: "canonical", log: []byte("private\n"),
	})
	if err := os.Remove(storePath); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runLogsCommand(t, logsCanonicalID)
	if code != 125 || stdout != "" || !strings.Contains(stderr, "requires root") {
		t.Fatalf("non-root: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if _, err := os.Stat(storePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-root touched store: %v", err)
	}
}

func TestLogsUnknownJob(t *testing.T) {
	stubLogsEUID(t, 0)
	setupLogsFixture(t)
	code, stdout, stderr := runLogsCommand(t, logsJobIDAbsent)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "unknown job") {
		t.Fatalf("exit=%d stdout=%q stderr=%q, want 1 unknown-job", code, stdout, stderr)
	}
}

func TestLogsRetentionCompactedJob(t *testing.T) {
	stubLogsEUID(t, 0)
	setupLogsFixture(t, logsJobFixture{uid: 1001, requestID: logsJobID, spoolName: "spool-a", log: []byte("gone\n"), compact: true})
	code, stdout, stderr := runLogsCommand(t, logsJobID)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "compact") {
		t.Fatalf("exit=%d stdout=%q stderr=%q, want 1 retention-compacted", code, stdout, stderr)
	}
}

func TestLogsMissingAndEmptyLog(t *testing.T) {
	stubLogsEUID(t, 0)
	setupLogsFixture(t,
		logsJobFixture{uid: 1001, requestID: logsJobID, spoolName: "spool-a", log: nil},
		logsJobFixture{uid: 1001, requestID: logsJobIDOther, spoolName: "spool-b", log: []byte{}},
	)

	code, stdout, stderr := runLogsCommand(t, logsJobID)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "missing") {
		t.Fatalf("missing log: exit=%d stdout=%q stderr=%q, want 1", code, stdout, stderr)
	}

	code, stdout, stderr = runLogsCommand(t, logsJobIDOther)
	if code != 0 || stdout != "" || !strings.Contains(stderr, "empty") {
		t.Fatalf("empty log: exit=%d stdout=%q stderr=%q, want 0 with an empty note", code, stdout, stderr)
	}
}

// TestLogsUIDCollision: a request ID bound to two UIDs must be rejected
// outright — never silently pick one — until the operator disambiguates.
func TestLogsUIDCollision(t *testing.T) {
	stubLogsEUID(t, 0)
	setupLogsFixture(t,
		logsJobFixture{uid: 1001, requestID: logsJobID, spoolName: "spool-a", log: []byte("uid-1001 log\n")},
		logsJobFixture{uid: 1002, requestID: logsJobID, spoolName: "spool-b", log: []byte("uid-1002 log\n")},
	)

	code, stdout, stderr := runLogsCommand(t, logsJobID)
	if code != 1 || stdout != "" {
		t.Fatalf("collision exit=%d stdout=%q, want 1 with no log bytes", code, stdout)
	}
	if !strings.Contains(stderr, "1001") || !strings.Contains(stderr, "1002") || !strings.Contains(stderr, "--uid") {
		t.Fatalf("collision stderr=%q, want both UIDs and the --uid remedy", stderr)
	}

	code, stdout, _ = runLogsCommand(t, logsJobID, "--uid", "1001")
	if code != 0 || stdout != "uid-1001 log\n" {
		t.Fatalf("--uid 1001 exit=%d stdout=%q, want uid 1001's log", code, stdout)
	}
	code, stdout, _ = runLogsCommand(t, "--uid", "1002", logsJobID)
	if code != 0 || stdout != "uid-1002 log\n" {
		t.Fatalf("--uid 1002 exit=%d stdout=%q, want uid 1002's log", code, stdout)
	}
}

// TestLogsRejectsSpoolEscape: a stored spool_dir outside the spool root (or
// the root itself) is rejected before the log path is even opened.
func TestLogsRejectsSpoolEscape(t *testing.T) {
	stubLogsEUID(t, 0)
	storePath, spoolRoot := setupLogsFixture(t)
	outside := filepath.Join(filepath.Dir(spoolRoot), "outside")
	if err := os.MkdirAll(outside, 0700); err != nil {
		t.Fatal(err)
	}
	secret := []byte("escape target\n")
	if err := os.WriteFile(filepath.Join(outside, "reviewer-stderr.log"), secret, 0600); err != nil {
		t.Fatal(err)
	}
	for uid, requestID := range map[uint32]string{1001: logsJobID, 1002: logsJobIDOther} {
		spoolDir := outside
		if uid == 1002 {
			spoolDir = spoolRoot // the root itself is not a job spool
		}
		seedHistoricalLogsJob(t, storePath, store.Job{
			UID: uid, RequestID: requestID, State: store.StateQueued,
			SubmitBody: []byte(`{}`), SpoolDir: spoolDir,
		})
	}

	for _, requestID := range []string{logsJobID, logsJobIDOther} {
		code, stdout, stderr := runLogsCommand(t, requestID)
		if code != 1 || stdout != "" || !strings.Contains(stderr, "spool") {
			t.Fatalf("escape %s: exit=%d stdout=%q stderr=%q, want 1 spool rejection", requestID, code, stdout, stderr)
		}
	}
}

// TestLogsRejectsSymlinkAndNonRegularLog: the reviewer log must be a regular
// file reached without following symlinks; anything else is refused.
func TestLogsRejectsSymlinkAndNonRegularLog(t *testing.T) {
	stubLogsEUID(t, 0)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("symlink secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setupLogsFixture(t,
		logsJobFixture{uid: 1001, requestID: logsJobID, spoolName: "spool-a", logSymlink: target},
		logsJobFixture{uid: 1001, requestID: logsJobIDOther, spoolName: "spool-b", logDir: true},
	)

	code, stdout, stderr := runLogsCommand(t, logsJobID)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "symlink") {
		t.Fatalf("symlink: exit=%d stdout=%q stderr=%q, want 1 symlink refusal", code, stdout, stderr)
	}
	code, stdout, _ = runLogsCommand(t, logsJobIDOther)
	if code != 1 || stdout != "" {
		t.Fatalf("non-regular: exit=%d stdout=%q, want 1", code, stdout)
	}
}

// TestLogsDefaultTailBound: the default prints only the last 16KiB of a
// larger log and notes the bound on stderr.
func TestLogsDefaultTailBound(t *testing.T) {
	stubLogsEUID(t, 0)
	prefix := bytes.Repeat([]byte("A"), 4096)
	tail := bytes.Repeat([]byte("B"), 16*1024)
	setupLogsFixture(t, logsJobFixture{uid: 1001, requestID: logsJobID, spoolName: "spool-a", log: append(prefix, tail...)})

	code, stdout, stderr := runLogsCommand(t, logsJobID)
	if code != 0 || stdout != string(tail) {
		t.Fatalf("exit=%d stdout len=%d, want the last 16KiB", code, len(stdout))
	}
	if !strings.Contains(stderr, "last") {
		t.Fatalf("stderr=%q, want a bound note", stderr)
	}

	code, stdout, _ = runLogsCommand(t, logsJobID, "--all")
	if code != 0 || stdout != string(append(prefix, tail...)) {
		t.Fatalf("--all exit=%d stdout len=%d, want the full log", code, len(stdout))
	}
}

// TestLogsAllStreamsBeyondStreamCap exercises the actual command on a private
// reviewer log larger than 32 MiB without retaining the log or output in RAM.
func TestLogsAllStreamsBeyondStreamCap(t *testing.T) {
	stubLogsEUID(t, 0)
	_, spoolRoot := setupLogsFixture(t, logsJobFixture{uid: 1001, requestID: logsJobID, spoolName: "spool-a"})
	logPath := filepath.Join(spoolRoot, "spool-a", "reviewer-stderr.log")
	file, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	first, last := []byte("FIRST_FAILURE\n"), []byte("LAST_FAILURE\n")
	chunk := bytes.Repeat([]byte("x"), 1024*1024)
	if _, err := file.Write(first); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 33; i++ {
		if _, err := file.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := file.Write(last); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	input, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.New()
	size, err := io.Copy(expected, input) // all fixture bytes are printable or newline
	if err != nil {
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}

	output := &boundedLogOutput{digest: sha256.New()}
	var stderr bytes.Buffer
	if code := runLogs([]string{"--all", logsJobID}, output, &stderr); code != 0 {
		t.Fatalf("--all exit=%d stderr=%q", code, stderr.String())
	}
	if output.count != size || !bytes.Equal(output.digest.Sum(nil), expected.Sum(nil)) ||
		!bytes.Equal(output.first, first) || !bytes.Equal(output.last, last) {
		t.Fatalf("--all count=%d want=%d first=%q last=%q hash matches=%t", output.count, size, output.first, output.last, bytes.Equal(output.digest.Sum(nil), expected.Sum(nil)))
	}
	if strings.Contains(stderr.String(), "showing the last") || !strings.Contains(stderr.String(), "secret") {
		t.Fatalf("--all stderr=%q, want warning without truncation notice", stderr.String())
	}

	var tail, tailErr bytes.Buffer
	if code := runLogs([]string{logsJobID}, &tail, &tailErr); code != 0 {
		t.Fatalf("default exit=%d stderr=%q", code, tailErr.String())
	}
	if tail.Len() != 16*1024 || !bytes.HasSuffix(tail.Bytes(), last) || bytes.Contains(tail.Bytes(), first) ||
		!strings.Contains(tailErr.String(), "showing the last 16384") {
		t.Fatalf("default tail len=%d stderr=%q, want last 16KiB with notice", tail.Len(), tailErr.String())
	}
}

// boundedLogOutput tracks the full stream's digest and only its edge markers.
type boundedLogOutput struct {
	digest hash.Hash
	count  int64
	first  []byte
	last   []byte
}

func (w *boundedLogOutput) Write(p []byte) (int, error) {
	n, err := w.digest.Write(p)
	w.count += int64(n)
	if len(w.first) < len("FIRST_FAILURE\n") {
		w.first = append(w.first, p[:min(n, len("FIRST_FAILURE\n")-len(w.first))]...)
	}
	w.last = append(w.last, p[:n]...)
	if len(w.last) > len("LAST_FAILURE\n") {
		w.last = append(w.last[:0], w.last[len(w.last)-len("LAST_FAILURE\n"):]...)
	}
	return n, err
}

// TestLogsSanitizesTerminalControl pins the output boundary: printable text,
// newlines, and tabs pass through verbatim while every non-printing control
// or format rune (ESC/OSC52, backspace, CR, bidi override, NUL, C1) and every
// invalid UTF-8 byte is encoded as a visible escape. No raw control byte may
// ever reach the operator's terminal.
func TestLogsSanitizesTerminalControl(t *testing.T) {
	stubLogsEUID(t, 0)
	content := "plain line\twith tab\n" +
		"\x1b]52;c;Y2xpcGJvYXJkLWtleXN0cm9rZQ==\x07\n" + // OSC52 clipboard write
		"ab\x08c\n" + // backspace
		"overwrite\rmagic\n" + // carriage return
		"admin\u202etxt\n" + // bidi right-to-left override
		"nul\x00byte\n" +
		"c1\u0085control\n" + // C1 NEL as a valid rune
		"bad\xff\xfebytes\n" + // invalid UTF-8
		"truncated\xe2\x82" // dangling prefix bytes at EOF
	setupLogsFixture(t, logsJobFixture{uid: 1001, requestID: logsJobID, spoolName: "spool-a", log: []byte(content)})

	for _, args := range [][]string{{logsJobID}, {"--all", logsJobID}} {
		code, stdout, stderr := runLogsCommand(t, args...)
		if code != 0 {
			t.Fatalf("logs %v exit=%d stderr=%q", args, code, stderr)
		}
		for _, want := range []string{
			"plain line\twith tab\n",
			`\x1b]52;c;Y2xpcGJvYXJkLWtleXN0cm9rZQ==\x07`,
			`ab\x08c`,
			`overwrite\x0dmagic`,
			`admin`,
			`nul\x00byte`,
			`c1\x85control`,
			`bad\xff\xfebytes`,
			`truncated\xe2\x82`,
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("logs %v stdout missing %q:\n%s", args, want, stdout)
			}
		}
		if !strings.Contains(stdout, `\u202e`) {
			t.Fatalf("logs %v stdout missing the bidi escape:\n%s", args, stdout)
		}
		// No actual ESC, control, or bidi bytes on the wire; stdout must be
		// valid UTF-8 with no control bytes other than \n and \t.
		if !utf8.ValidString(stdout) {
			t.Fatalf("logs %v stdout is not valid UTF-8", args)
		}
		if strings.ContainsRune(stdout, '\u202e') || strings.ContainsAny(stdout, "\x1b\x00\x07\x08\x0d") {
			t.Fatalf("logs %v stdout carries raw control/format bytes:\n%q", args, stdout)
		}
		for _, r := range stdout {
			if r != '\n' && r != '\t' && !unicode.IsPrint(r) {
				t.Fatalf("logs %v stdout carries non-printing rune %U", args, r)
			}
		}
		if !strings.Contains(stderr, "secret") {
			t.Fatalf("logs %v stderr=%q, want the secrets warning retained", args, stderr)
		}
	}
}

// TestLogsTailMidUTF8: a bounded tail that starts inside a multi-byte UTF-8
// sequence must show the dangling bytes as escapes rather than emitting an
// invalid byte or silently dropping them.
func TestLogsTailMidUTF8(t *testing.T) {
	stubLogsEUID(t, 0)
	orig := logsTailBytes
	logsTailBytes = 4 // lands inside the 3-byte euro sign
	t.Cleanup(func() { logsTailBytes = orig })

	setupLogsFixture(t, logsJobFixture{uid: 1001, requestID: logsJobID, spoolName: "spool-a", log: []byte("AB€CD")})

	code, stdout, _ := runLogsCommand(t, logsJobID)
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if stdout != `\x82\xacCD` {
		t.Fatalf("stdout=%q, want the dangling sequence bytes escaped", stdout)
	}
}

// appendAfterStatWriter appends to the spooled log file on the first stdout
// write — which happens after logsPrintTail's Stat and Seek — simulating a
// live reviewer appending mid-read.
type appendAfterStatWriter struct {
	dst        *bytes.Buffer
	logPath    string
	appendData []byte
	done       bool
}

func (w *appendAfterStatWriter) Write(p []byte) (int, error) {
	if !w.done {
		w.done = true
		file, err := os.OpenFile(w.logPath, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return 0, err
		}
		if _, err := file.Write(w.appendData); err != nil {
			_ = file.Close()
			return 0, err
		}
		if err := file.Close(); err != nil {
			return 0, err
		}
	}
	return w.dst.Write(p)
}

// TestLogsAppendAfterStatStaysWithinCap: a reviewer appending to its log
// after the size snapshot must never push output beyond the promised byte
// window — the cap is measured against the stat-time size, not a live EOF.
func TestLogsAppendAfterStatStaysWithinCap(t *testing.T) {
	stubLogsEUID(t, 0)
	orig := logsTailBytes
	logsTailBytes = 4096
	t.Cleanup(func() { logsTailBytes = orig })

	// Initial content exceeds the bufio fill size so the reader must refill —
	// and would see the appended bytes — mid-stream.
	initial := bytes.Repeat([]byte("A"), 8000)
	appended := bytes.Repeat([]byte("B"), 4000)
	setupLogsFixture(t, logsJobFixture{uid: 1001, requestID: logsJobID, spoolName: "spool-a", log: initial})

	spoolDir := filepath.Join(logsSpoolRoot, "spool-a")
	stdout := &bytes.Buffer{}
	writer := &appendAfterStatWriter{dst: stdout, logPath: filepath.Join(spoolDir, "reviewer-stderr.log"), appendData: appended}
	var stderr bytes.Buffer
	code := runLogs([]string{logsJobID}, writer, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	want := string(initial[len(initial)-4096:])
	if stdout.String() != want {
		t.Fatalf("stdout len=%d, want exactly the %d-byte stat-time tail window (appended bytes must not leak)", stdout.Len(), len(want))
	}
}

func TestLogsAllStopsAtStatTimeSize(t *testing.T) {
	stubLogsEUID(t, 0)
	initial := bytes.Repeat([]byte("A"), 8000) // force a refill after the append
	setupLogsFixture(t, logsJobFixture{uid: 1001, requestID: logsJobID, spoolName: "spool-a", log: initial})
	stdout := &bytes.Buffer{}
	writer := &appendAfterStatWriter{
		dst: stdout, logPath: filepath.Join(logsSpoolRoot, "spool-a", "reviewer-stderr.log"),
		appendData: []byte("APPENDED_AFTER_STAT"),
	}
	var stderr bytes.Buffer
	if code := runLogs([]string{"--all", logsJobID}, writer, &stderr); code != 0 {
		t.Fatalf("--all exit=%d stderr=%q", code, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), initial) {
		t.Fatalf("--all output len=%d, want only %d stat-time bytes", stdout.Len(), len(initial))
	}
}
