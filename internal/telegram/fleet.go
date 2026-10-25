package telegram

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// FleetRendering is pure deterministic rendering of the frozen display facts.
// Root calls RenderFleet before hashing Display to set SummaryParts to len(Parts).
// SummaryParts itself is deliberately not an input to rendering.
type FleetRendering struct {
	Parts    []string
	Final    string
	Keyboard *InlineKeyboardMarkup
	Details  []string
}

// RenderFleet renders a ticket identically on the broker and the gateway. It
// fails when Details would exceed what a Details tap may send, so neither side
// delivers a card whose Details could never be shown.
func RenderFleet(ticket fleetproto.Ticket) (FleetRendering, error) {
	out, err := renderFleet(ticket)
	if err == nil && len(out.Details) > MaxDetailsParts {
		return FleetRendering{}, fmt.Errorf("telegram: fleet details exceed %d parts", MaxDetailsParts)
	}
	return out, err
}

func renderFleet(ticket fleetproto.Ticket) (FleetRendering, error) {
	d, b := ticket.Display, ticket.Binding
	out := FleetRendering{}
	if d.Report == nil {
		in := ApprovalOnlyInput{Host: d.Identity.Hostname, JobID: string(b.JobID), Operation: d.Operation, Reason: d.Reason, CWD: d.CWD, CapturedStdinBytes: d.CapturedStdinBytes, SubmitterName: d.Identity.Username, SubmitterUID: d.Identity.SubmitterUID, Expiry: time.Unix(b.ExpiresAt, 0), Failures: d.AvailabilityHistory}
		in.CapturedStdinKind = d.CapturedStdinKind
		in.WithheldCount = fleetWithheldCount(d.Withholding)
		var err error
		out.Parts, err = RenderApprovalOnlySummaryParts(in)
		if err != nil {
			return out, err
		}
		out.Details, err = RenderApprovalOnlyDetails(in)
		if err != nil {
			return out, err
		}
		// Unreviewed withholding facts use the same escaping and chunking machinery.
		if len(d.Withholding) > 0 {
			blocks := []string{"<b>Credential content withheld</b>\n"}
			for _, fact := range d.Withholding {
				blocks = append(blocks, esc(fact)+"\n")
			}
			extra, err := chunkBlocks(blocks, func(i, n int) string { return "Withholding facts\n" })
			if err != nil {
				return out, err
			}
			out.Details = append(out.Details, extra...)
		}
		var kb InlineKeyboardMarkup
		out.Final, kb, err = RenderApprovalOnlyCard(in, b.Nonce)
		out.Keyboard = &kb
		return out, err
	}
	model := ""
	for _, h := range d.ModelHistory {
		if h.Outcome == "ok" {
			model = h.Name
		}
	}
	in := CardInput{Host: d.Identity.Hostname, JobID: string(b.JobID), Operation: d.Operation, Reason: d.Reason, CWD: d.CWD, CapturedStdinBytes: d.CapturedStdinBytes, Report: *d.Report, ReviewerModel: model, SubmitterName: d.Identity.Username, SubmitterUID: d.Identity.SubmitterUID, Expiry: time.Unix(b.ExpiresAt, 0)}
	in.CapturedStdinKind = d.CapturedStdinKind
	in.WithheldCount = fleetWithheldCount(d.Withholding)
	// Withholding is display text rather than path references; escape all facts
	// with the existing chunker rather than reinterpret them as filesystem paths.
	var err error
	out.Parts, err = RenderSummaryParts(in)
	if err != nil {
		return out, err
	}
	out.Details, err = RenderDetails(DetailsInput{CardInput: in, ModelHistory: d.ModelHistory})
	if err != nil {
		return out, err
	}
	if len(d.Withholding) > 0 {
		blocks := []string{"<b>Credential content withheld from AI review</b>\n"}
		for _, fact := range d.Withholding {
			blocks = append(blocks, esc(fact)+"\n")
		}
		extra, e := chunkBlocks(blocks, func(i, n int) string { return "Withholding facts\n" })
		if e != nil {
			return out, e
		}
		out.Details = append(out.Details, extra...)
	}
	if b.TicketKind == fleetproto.AutoNotice {
		score, e := strconv.Atoi(d.Report.Risk)
		if e != nil {
			return out, errors.New("telegram: invalid auto risk")
		}
		out.Final, err = RenderAutoNotice(in, score)
	} else {
		var kb InlineKeyboardMarkup
		out.Final, kb, err = RenderReviewedCard(in, b.Nonce)
		out.Keyboard = &kb
	}
	return out, err
}

// The existing frozen display encodes the broker's total before its bounded
// reference list. Preserve that total without changing the fleet report wire.
// Other display facts still get a visible withholding notice and full Details.
func fleetWithheldCount(facts []string) int {
	if len(facts) == 0 {
		return 0
	}
	if total, ok := strings.CutSuffix(facts[0], " credential-like paths withheld"); ok {
		if count, err := strconv.Atoi(total); err == nil && count > 0 && count <= 1000000 {
			return count
		}
	}
	return len(facts)
}

// ParseCallbackData exposes the exact a/d/v/r + lowercase nonce parser.
func ParseCallbackData(data string) (action, nonce string, ok bool) { return parseCallbackData(data) }

// TokenIdentity returns only the fingerprint and numeric identity of the exact
// immutable token loaded by this client. No credential is exported. Gateway
// aliases deduplicate on the fingerprint, not a path or configured bot name.
func (c *Client) TokenIdentity() (string, int64, error) {
	prefix, _, ok := strings.Cut(c.token, ":")
	id, err := strconv.ParseInt(prefix, 10, 64)
	if !ok || err != nil || id <= 0 || strconv.FormatInt(id, 10) != prefix {
		return "", 0, errors.New("telegram: invalid bot identity")
	}
	sum := sha256.Sum256([]byte(c.token))
	return hex.EncodeToString(sum[:]), id, nil
}
