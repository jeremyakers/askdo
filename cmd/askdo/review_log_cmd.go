package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/reviewlog"
)

var reviewLogPath = reviewlog.DefaultPath

// Test-only observer for compact-mode retained job count.
var reviewLogRetainedJobs func(int)

func runReviewLog(args []string, stdout, stderr io.Writer) int {
	if getEUID() != 0 {
		fmt.Fprintln(stderr, "askdo review log requires root: the review journal is root-only (re-run with sudo)")
		return 125
	}
	fs := flag.NewFlagSet("review log", flag.ContinueOnError)
	fs.SetOutput(stderr)
	since := 24 * time.Hour
	fs.Func("since", "show activity within this duration (default 24h; e.g. 7d or 168h; 0 for all history)", func(value string) error {
		multiplier := time.Duration(1)
		if strings.HasSuffix(value, "d") {
			value = strings.TrimSuffix(value, "d")
			if strings.Trim(value, "0123456789.+-") != "" {
				return errors.New("day duration must be a number followed by d")
			}
			value += "h"
			multiplier = 24
		}
		duration, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		// Keep the existing nonnegative time.Duration range when expanding days.
		if duration < 0 || duration > time.Duration(1<<63-1)/multiplier {
			return errors.New("duration must be nonnegative and within the supported range")
		}
		since = duration * multiplier
		return nil
	})
	job := fs.String("job", "", "filter by exact job ID")
	raw := fs.Bool("json", false, "emit original JSONL records rather than joined summaries")
	positional, err := parseInterleaved(fs, args)
	if err != nil || len(positional) != 0 {
		fmt.Fprintln(stderr, "usage: askdo review log [--since DURATION] [--job ID] [--json]")
		return 125
	}
	file, err := os.Open(reviewLogPath)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "review log:", err)
		return 1
	}
	defer file.Close()
	cutoff := time.Time{}
	if since > 0 {
		cutoff = time.Now().Add(-since)
	}
	type joined struct {
		review, outcome *reviewlog.Event
		latest          time.Time
	}
	type jobKey struct {
		id  string
		uid uint32
	}
	// First retain only keys with recent activity. The second pass can then
	// join their older review context without keeping unrelated history.
	// --since 0 requests all history; an exact --job already bounds selection.
	var recent map[jobKey]struct{}
	if !*raw && !cutoff.IsZero() && *job == "" {
		recent = make(map[jobKey]struct{})
		reader := bufio.NewReader(file)
		for {
			data, readErr := reader.ReadBytes('\n')
			if event, valid := decodeReviewLogRecord(data); valid && !event.Time.Before(cutoff) {
				recent[jobKey{event.JobID, event.SubmitterUID}] = struct{}{}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				fmt.Fprintln(stderr, "review log:", readErr)
				return 1
			}
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			fmt.Fprintln(stderr, "review log:", err)
			return 1
		}
	}
	jobs := make(map[jobKey]*joined)
	reader := bufio.NewReader(file)
	for line := 1; ; line++ {
		data, readErr := reader.ReadBytes('\n')
		if len(data) > 0 {
			event, valid := decodeReviewLogRecord(data)
			key := jobKey{event.JobID, event.SubmitterUID}
			_, selected := recent[key]
			if !valid {
				fmt.Fprintf(stderr, "review log: skipping malformed line %d\n", line)
			} else if (*job == "" || event.JobID == *job) && (recent == nil || selected) {
				if *raw {
					if !event.Time.Before(cutoff) {
						if _, err := stdout.Write(append(bytes.TrimSuffix(data, []byte{'\n'}), '\n')); err != nil {
							fmt.Fprintln(stderr, "review log:", err)
							return 1
						}
					}
				} else {
					j := jobs[key]
					if j == nil {
						j = &joined{}
						jobs[key] = j
					}
					if event.Time.After(j.latest) {
						j.latest = event.Time
					}
					switch event.Event {
					case "review", "unreviewed":
						j.review = &event
					case "outcome":
						j.outcome = &event
					}
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			fmt.Fprintln(stderr, "review log:", readErr)
			return 1
		}
	}
	if reviewLogRetainedJobs != nil {
		reviewLogRetainedJobs(len(jobs))
	}
	ids := make([]jobKey, 0, len(jobs))
	for id, j := range jobs {
		if !j.latest.Before(cutoff) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(a, b int) bool {
		x, y := jobs[ids[a]].latest, jobs[ids[b]].latest
		if x.Equal(y) {
			if ids[a].id != ids[b].id {
				return ids[a].id < ids[b].id
			}
			return ids[a].uid < ids[b].uid
		}
		return x.After(y)
	})
	// bufio.Writer retains the first write/short-write failure, including any
	// implicit flush while formatting; the final Flush reports it once.
	out := bufio.NewWriter(stdout)
	for _, id := range ids {
		j := jobs[id]
		fmt.Fprintf(out, "%s job=%q uid=%d", j.latest.UTC().Format(time.RFC3339Nano), id.id, id.uid)
		if r := j.review; r != nil {
			risk := "NO AI"
			if r.Report != nil {
				risk = r.Report.Risk
			}
			command := r.Argv
			if r.Mode == "bundle" || r.Entry != "" {
				command = append([]string{r.Entry}, r.Args...)
			}
			quoted := make([]string, len(command))
			for i, arg := range command {
				quoted[i] = fmt.Sprintf("%q", arg)
			}
			fmt.Fprintf(out, " host=%q submitter=%q(%d) risk=%q command=%s", r.Host, r.SubmitterName, r.SubmitterUID, risk, strings.Join(quoted, " "))
		}
		if o := j.outcome; o != nil {
			fmt.Fprintf(out, " state=%q decision=%q approval=%q", o.State, o.Decision, o.ApprovalKind)
			if o.ResultKind != "" {
				fmt.Fprintf(out, " result=%q", o.ResultKind)
			}
			if o.Signal != nil {
				fmt.Fprintf(out, " signal=%d", *o.Signal)
			}
			if o.ExitCode != nil {
				fmt.Fprintf(out, " exit=%d", *o.ExitCode)
			}
		} else {
			fmt.Fprint(out, " outcome=not-recorded")
		}
		fmt.Fprintln(out)
		if r := j.review; r != nil && r.Report != nil {
			fmt.Fprintf(out, "  summary: %q\n", r.Report.Summary)
			for _, w := range r.Report.Warnings {
				fmt.Fprintf(out, "  warning: %q evidence=%q\n", w.Message, w.Evidence)
			}
			for _, u := range r.Report.MissingContext {
				fmt.Fprintf(out, "  uncertainty: %q\n", u)
			}
		}
	}
	if err := out.Flush(); err != nil {
		fmt.Fprintln(stderr, "review log:", err)
		return 1
	}
	return 0
}

func decodeReviewLogRecord(data []byte) (reviewlog.Event, bool) {
	var event reviewlog.Event
	if err := json.Unmarshal(data, &event); err != nil || event.Version != 1 || event.JobID == "" || event.Time.IsZero() || (event.Event != "review" && event.Event != "unreviewed" && event.Event != "outcome") {
		return reviewlog.Event{}, false
	}
	return event, true
}
