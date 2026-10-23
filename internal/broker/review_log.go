package broker

import (
	"log/slog"
	"sort"
	"time"

	"github.com/jeremyakers/askdo/internal/reviewlog"
)

func (j *jobRuntime) reviewLogEvent(context manifestContext, operation manifestOperation, captures []captureRecord, inspection *manifestInspectionEvidence, digest string) reviewlog.Event {
	e := reviewlog.Event{Version: 1, Event: "review", Time: time.Now().UTC(), JobID: j.req.RequestID,
		Host: context.Host, SubmitterUID: context.SubmitterUID, SubmitterName: context.SubmitterName,
		TargetUID: 0, Mode: operation.Mode, CWD: operation.CWD, Reason: j.req.Reason, ManifestDigest: digest}
	// Match the approval display, not the bundle's internal staging argv.
	if j.req.Mode == "bundle" {
		e.Entry = j.req.Entry
		e.Args = append([]string{}, j.req.Args...)
	} else {
		e.Argv = append([]string{}, operation.Argv...)
	}
	for _, c := range captures {
		e.Captures = append(e.Captures, reviewlog.Capture{Path: c.Path, Size: c.Size, SHA256: c.SHA256, Masked: c.Masked})
	}
	if inspection != nil {
		type key struct{ op, status, reason string }
		counts := make(map[key]int)
		for _, o := range inspection.Observations {
			counts[key{o.Operation, o.Status, o.Reason}]++
		}
		for k, count := range counts {
			e.Inspection = append(e.Inspection, reviewlog.ObservationCount{Operation: k.op, Status: k.status, Reason: k.reason, Count: count})
		}
		sort.Slice(e.Inspection, func(a, b int) bool {
			x, y := e.Inspection[a], e.Inspection[b]
			if x.Operation != y.Operation {
				return x.Operation < y.Operation
			}
			if x.Status != y.Status {
				return x.Status < y.Status
			}
			return x.Reason < y.Reason
		})
	}
	return e
}

func (j *jobRuntime) appendReviewLog(event reviewlog.Event) {
	if err := reviewlog.Append(j.daemon.reviewLogPath, event); err != nil {
		slog.Warn("review log append failed", "request_id", j.req.RequestID, "event", event.Event, "error", err)
	}
}
