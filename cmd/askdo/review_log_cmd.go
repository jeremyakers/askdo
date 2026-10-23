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

func runReviewLog(args []string, stdout, stderr io.Writer) int {
	if getEUID() != 0 {
		fmt.Fprintln(stderr, "askdo review log requires root: the review journal is root-only (re-run with sudo)")
		return 125
	}
	fs := flag.NewFlagSet("review log", flag.ContinueOnError)
	fs.SetOutput(stderr)
	since := fs.Duration("since", 24*time.Hour, "show activity within this duration (0 for all history)")
	job := fs.String("job", "", "filter by exact job ID")
	raw := fs.Bool("json", false, "emit original JSONL records rather than joined summaries")
	positional, err := parseInterleaved(fs, args)
	if err != nil || len(positional) != 0 || *since < 0 {
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
	if *since > 0 {
		cutoff = time.Now().Add(-*since)
	}
	type joined struct {
		review, outcome *reviewlog.Event
		latest          time.Time
	}
	jobs := make(map[string]*joined)
	reader := bufio.NewReader(file)
	for line := 1; ; line++ {
		data, readErr := reader.ReadBytes('\n')
		if len(data) > 0 {
			var event reviewlog.Event
			if err := json.Unmarshal(data, &event); err != nil || event.Version != 1 || event.JobID == "" || event.Time.IsZero() || (event.Event != "review" && event.Event != "unreviewed" && event.Event != "outcome") {
				fmt.Fprintf(stderr, "review log: skipping malformed line %d\n", line)
			} else if *job == "" || event.JobID == *job {
				if *raw {
					if !event.Time.Before(cutoff) {
						if _, err := stdout.Write(append(bytes.TrimSuffix(data, []byte{'\n'}), '\n')); err != nil {
							fmt.Fprintln(stderr, "review log:", err)
							return 1
						}
					}
				} else {
					j := jobs[event.JobID]
					if j == nil {
						j = &joined{}
						jobs[event.JobID] = j
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
	ids := make([]string, 0, len(jobs))
	for id, j := range jobs {
		if !j.latest.Before(cutoff) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(a, b int) bool {
		x, y := jobs[ids[a]].latest, jobs[ids[b]].latest
		if x.Equal(y) {
			return ids[a] < ids[b]
		}
		return x.After(y)
	})
	for _, id := range ids {
		j := jobs[id]
		fmt.Fprintf(stdout, "%s job=%q", j.latest.UTC().Format(time.RFC3339Nano), id)
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
			fmt.Fprintf(stdout, " host=%q submitter=%q(%d) risk=%q command=%s", r.Host, r.SubmitterName, r.SubmitterUID, risk, strings.Join(quoted, " "))
		}
		if o := j.outcome; o != nil {
			fmt.Fprintf(stdout, " state=%q decision=%q approval=%q", o.State, o.Decision, o.ApprovalKind)
			if o.ExitCode != nil {
				fmt.Fprintf(stdout, " exit=%d", *o.ExitCode)
			}
		} else {
			fmt.Fprint(stdout, " outcome=not-recorded")
		}
		fmt.Fprintln(stdout)
		if r := j.review; r != nil && r.Report != nil {
			fmt.Fprintf(stdout, "  summary: %q\n", r.Report.Summary)
			for _, w := range r.Report.Warnings {
				fmt.Fprintf(stdout, "  warning: %q evidence=%q\n", w.Message, w.Evidence)
			}
			for _, u := range r.Report.MissingContext {
				fmt.Fprintf(stdout, "  uncertainty: %q\n", u)
			}
		}
	}
	return 0
}
