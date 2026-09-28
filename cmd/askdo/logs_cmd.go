package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/jobid"
	"github.com/jeremyakers/askdo/internal/store"
	"golang.org/x/sys/unix"
)

// Historical pre-reservation jobs can still be looked up for read-only logs.
var logsLegacyJobIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Test seams: the store path and spool root are the daemon's defaults; tests
// inject a synthetic tree. logsTailBytes is the default bounded tail.
var (
	logsStorePath = "/var/lib/askdo/jobs.sqlite3"
	logsSpoolRoot = "/var/lib/askdo/jobs"
	logsTailBytes = int64(16 * 1024)
)

// logsWarning is printed on stderr whenever log bytes are disclosed: the
// reviewer log can contain provider request/response text and anything the
// review tooling wrote to stderr, including secrets.
const logsWarning = "warning: reviewer logs can contain provider text and secrets; do not paste into untrusted channels"

// runLogs implements the root-only operator command
// `askdo logs JOB_ID [--uid UID] [--all]`: it locates a job's reviewer
// stderr log via the store (never an operator-supplied path or SQL) and
// prints the default bounded tail or, with --all, the entire stat-time file.
// The root gate runs before any DB or log open.
func runLogs(args []string, stdout, stderr io.Writer) int {
	if getEUID() != 0 {
		fmt.Fprintln(stderr, "askdo logs requires root: the job store and reviewer logs are root-only (re-run with sudo)")
		return 125
	}
	flags := flag.NewFlagSet("logs", flag.ContinueOnError)
	flags.SetOutput(stderr)
	all := flags.Bool("all", false, "print the entire reviewer log instead of the last 16KiB")
	uidFlag := flags.String("uid", "", "optional submitter UID; disambiguates historical ID collisions")
	positional, err := parseInterleaved(flags, args)
	if err != nil || len(positional) != 1 {
		fmt.Fprintln(stderr, "usage: askdo logs JOB_ID [--uid UID] [--all]")
		return 125
	}
	requestID := positional[0]
	if jobid.Validate(requestID) != nil && !logsLegacyJobIDPattern.MatchString(requestID) {
		fmt.Fprintf(stderr, "askdo logs: %q is not a job ID (YYYY-MM-DD_#N, or a historical 32 lowercase hex ID)\n", requestID)
		fmt.Fprintln(stderr, "usage: askdo logs JOB_ID [--uid UID] [--all]")
		return 125
	}
	var uid uint32
	useUID := false
	if *uidFlag != "" {
		parsed, err := strconv.ParseUint(*uidFlag, 10, 32)
		if err != nil {
			fmt.Fprintf(stderr, "askdo logs: --uid %q is not a valid UID\n", *uidFlag)
			return 125
		}
		uid = uint32(parsed)
		useUID = true
	}

	jobStore, err := store.OpenReadOnly(logsStorePath)
	if err != nil {
		fmt.Fprintf(stderr, "askdo logs: open job store: %v\n", err)
		return 1
	}
	defer func() { _ = jobStore.Close() }()

	job, code := logsLookup(jobStore, requestID, uid, useUID, stderr)
	if code != 0 {
		return code
	}

	if job.SpoolDir == "" {
		fmt.Fprintf(stderr, "askdo logs: job %s was retention-compacted; its reviewer log no longer exists\n", requestID)
		return 1
	}
	spoolRoot := filepath.Clean(logsSpoolRoot)
	spoolDir := filepath.Clean(job.SpoolDir)
	if spoolDir == spoolRoot || filepath.Dir(spoolDir) != spoolRoot {
		fmt.Fprintf(stderr, "askdo logs: job %s records a spool dir outside the spool root; refusing to follow it\n", requestID)
		return 1
	}
	return logsPrintTail(filepath.Join(spoolDir, "reviewer-stderr.log"), *all, stdout, stderr)
}

// logsLookup resolves requestID to one job, rejecting historical cross-UID
// collisions rather than guessing. It returns a nonzero exit code on failure.
func logsLookup(jobStore *store.Store, requestID string, uid uint32, useUID bool, stderr io.Writer) (store.Job, int) {
	ctx := context.Background()
	if useUID {
		job, err := jobStore.GetJob(ctx, uid, requestID)
		if err != nil {
			var notFound *store.ErrNotFound
			if errors.As(err, &notFound) {
				fmt.Fprintf(stderr, "askdo logs: unknown job %s for uid %d\n", requestID, uid)
			} else {
				fmt.Fprintf(stderr, "askdo logs: read job store: %v\n", err)
			}
			return store.Job{}, 1
		}
		return job, 0
	}
	jobs, err := jobStore.GetJobsByRequestID(ctx, requestID)
	if err != nil {
		fmt.Fprintf(stderr, "askdo logs: read job store: %v\n", err)
		return store.Job{}, 1
	}
	switch len(jobs) {
	case 0:
		fmt.Fprintf(stderr, "askdo logs: unknown job %s\n", requestID)
		return store.Job{}, 1
	case 1:
		return jobs[0], 0
	}
	uids := make([]byte, 0, len(jobs)*8)
	for index, job := range jobs {
		if index > 0 {
			uids = append(uids, ", "...)
		}
		uids = strconv.AppendUint(uids, uint64(job.UID), 10)
	}
	fmt.Fprintf(stderr, "askdo logs: job %s is bound to more than one uid (%s); re-run with --uid UID\n", requestID, uids)
	return store.Job{}, 1
}

// logsPrintTail opens the reviewer log without following symlinks, requires
// a regular file, and prints the bounded tail or full stat-time file to stdout. Missing logs and
// non-regular entries are operator-facing errors; an empty log is a noted
// success. No temporary files are created.
func logsPrintTail(logPath string, all bool, stdout, stderr io.Writer) int {
	fd, err := unix.Open(logPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR):
			fmt.Fprintf(stderr, "askdo logs: reviewer log is missing at the recorded spool dir (the job may predate reviewer logging, or the spool was removed)\n")
		case errors.Is(err, unix.ELOOP):
			fmt.Fprintf(stderr, "askdo logs: reviewer log is a symlink; refusing to follow it\n")
		default:
			fmt.Fprintf(stderr, "askdo logs: open reviewer log: %v\n", err)
		}
		return 1
	}
	file := os.NewFile(uintptr(fd), logPath)
	defer func() { _ = file.Close() }()

	stat, err := file.Stat()
	if err != nil {
		fmt.Fprintf(stderr, "askdo logs: stat reviewer log: %v\n", err)
		return 1
	}
	if !stat.Mode().IsRegular() {
		fmt.Fprintf(stderr, "askdo logs: reviewer log is not a regular file; refusing to read it\n")
		return 1
	}
	size := stat.Size()
	if size == 0 {
		fmt.Fprintln(stderr, "askdo logs: reviewer log is empty")
		return 0
	}

	offset := int64(0)
	if !all && size > logsTailBytes {
		offset = size - logsTailBytes
		fmt.Fprintf(stderr, "askdo logs: showing the last %d of %d bytes; use --all for the full log\n", logsTailBytes, size)
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		fmt.Fprintf(stderr, "askdo logs: seek reviewer log: %v\n", err)
		return 1
	}
	fmt.Fprintln(stderr, logsWarning)
	// The byte window is frozen at the stat-time size: a reviewer appending
	// mid-read must never push output past the stat-time window, so reads stop at
	// offset+(size-offset) rather than a live EOF.
	if err := sanitizeLogStream(stdout, io.LimitReader(file, size-offset)); err != nil {
		fmt.Fprintf(stderr, "askdo logs: stream reviewer log: %v\n", err)
		return 1
	}
	return 0
}

// sanitizeLogStream copies src to dst, passing printable runes, newlines, and
// tabs through verbatim and encoding every other rune — terminal controls
// (ESC/OSC52, backspace, CR, NUL, C1), format runes such as the bidi
// override, and invalid UTF-8 bytes — as a visible \xNN, \uXXXX, or
// \UXXXXXXXX escape. Reviewer stderr is attacker/provider-influenced, so no
// raw control or format byte may reach the operator's terminal; the exact
// raw bytes remain in the root-only log file for forensic use. Runes are
// streamed one at a time (bounded memory, safe across read boundaries and
// mid-sequence tail offsets) and the first read or write error is returned.
func sanitizeLogStream(dst io.Writer, src io.Reader) error {
	reader, ok := src.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReader(src)
	}
	var encoded [utf8.UTFMax]byte
	for {
		r, size, err := reader.ReadRune()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		var out []byte
		switch {
		case r == utf8.RuneError && size == 1:
			// Invalid UTF-8: escape the raw byte itself. The rune read
			// consumed exactly that byte, so unread and re-read it.
			if err := reader.UnreadRune(); err != nil {
				return err
			}
			b, err := reader.ReadByte()
			if err != nil {
				return err
			}
			out = fmt.Appendf(nil, `\x%02x`, b)
		case r == '\n' || r == '\t' || unicode.IsPrint(r):
			out = utf8.AppendRune(encoded[:0], r)
		case r <= 0xff:
			out = fmt.Appendf(nil, `\x%02x`, r)
		case r <= 0xffff:
			out = fmt.Appendf(nil, `\u%04x`, r)
		default:
			out = fmt.Appendf(nil, `\U%08x`, r)
		}
		if _, err := dst.Write(out); err != nil {
			return err
		}
	}
}
