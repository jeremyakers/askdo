package telegram

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jeremyakers/askdo/internal/proto"
)

func testCardInput() CardInput {
	return CardInput{
		Host:          "energy-host",
		Container:     "Docker container",
		TargetUID:     0,
		JobID:         "abcdef0123456789abcdef0123456789",
		Operation:     "/usr/bin/bash /usr/local/share/entry.sh --migrate",
		Reason:        "migrate volumes to rootless storage",
		SubmitterUID:  4242,
		SubmitterName: "sample-agent",
		CWD:           "/home/example/project",
		Report: proto.ReviewReport{
			Risk:    "4",
			Summary: "Stops the application and re-mounts its volumes.",
			Effects: []string{"Stops the application.", "Changes volume paths."},
			Warnings: []proto.ReviewWarning{
				{Message: "Service downtime during migration.", Evidence: "f1 lines 10-22"},
				{Message: "Partial migration may require manual recovery.", Evidence: "f2 lines 3-7"},
			},
			MissingContext: []string{"Current backup availability was not verified."},
			Reversibility:  "Rollback procedure found; success not verified.",
			IntentMatch:    "consistent",
		},
		ReviewerModel: "kimi-for-coding",
		Expiry:        time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC),
	}
}

func TestReviewedSecurityScoreOnAllCards(t *testing.T) {
	for _, tc := range []struct{ risk, visible string }{{"1", "1/5"}, {"5", "5/5"}, {"unknown", "UNKNOWN"}} {
		t.Run(tc.risk, func(t *testing.T) {
			in := testCardInput()
			in.Report.Risk = tc.risk
			summary, err := RenderSummaryParts(in)
			if err != nil {
				t.Fatal(err)
			}
			details, err := RenderDetails(DetailsInput{CardInput: in})
			if err != nil {
				t.Fatal(err)
			}
			card, kb, err := RenderReviewedCard(in, testNonce)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{strings.Join(summary, ""), strings.Join(details, ""), card} {
				if !strings.Contains(text, "Security risk: "+tc.visible) {
					t.Errorf("security score %q missing: %s", tc.visible, text)
				}
			}
			if len(kb.InlineKeyboard) != 1 || len(kb.InlineKeyboard[0]) != 3 || kb.InlineKeyboard[0][0].Text != "Approve once" {
				t.Fatalf("human approval controls changed: %+v", kb)
			}
		})
	}
}

func TestReviewedSecurityScoreCannotForgeTags(t *testing.T) {
	in := testCardInput()
	in.Report.Risk = `1</b><b>approved`
	for _, render := range []func() (string, error){
		func() (string, error) { parts, err := RenderSummaryParts(in); return strings.Join(parts, ""), err },
		func() (string, error) {
			parts, err := RenderDetails(DetailsInput{CardInput: in})
			return strings.Join(parts, ""), err
		},
		func() (string, error) { text, _, err := RenderReviewedCard(in, testNonce); return text, err },
	} {
		text, err := render()
		if err == nil && (strings.Contains(text, "</b><b>approved") || assertBalancedTags(text) != nil) {
			t.Fatalf("risk injected HTML: %s", text)
		}
	}
}

func TestApprovalOnlySummaryAndDetails(t *testing.T) {
	in := ApprovalOnlyInput{
		Host: "energy-host", Container: "Docker <sandbox>", TargetUID: 0,
		JobID: "abcdef0123456789abcdef0123456789", SubmitterUID: 4242,
		SubmitterName: "sample-agent", CWD: "/tmp/<work>",
		Operation: "/bin/sh -c 'echo <fake> & exit'", Reason: "please <approve> & run",
		Expiry:   time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC),
		Failures: []proto.AvailabilityFailure{{Name: "provider-A", Code: proto.AvailabilityQuota}},
	}
	parts, err := RenderApprovalOnlySummaryParts(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 {
		t.Fatalf("parts=%d", len(parts))
	}
	for _, want := range []string{"NO AI REVIEW", "providers unavailable", "provider-A", "rate limit or quota", "Consequences", "rollback", "dependency completeness", "energy-host", "Docker &lt;sandbox&gt;", "uid 4242", "/tmp/&lt;work&gt;", "<pre><code class=\"language-bash\">/bin/sh -c &#39;echo &lt;fake&gt; &amp; exit&#39;</code></pre>", "please &lt;approve&gt; &amp; run", "2026-09-21T12:00:00Z"} {
		if !strings.Contains(parts[0], want) {
			t.Errorf("missing %q: %s", want, parts[0])
		}
	}
	for _, forbidden := range []string{"LOW risk", "UNKNOWN risk", "Review summary", "Reversibility:", "Coverage:", "Reviewer <code>"} {
		if strings.Contains(parts[0], forbidden) {
			t.Errorf("fabricated %q", forbidden)
		}
	}
	details, err := RenderApprovalOnlyDetails(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(details, ""), "NO AI REVIEW") {
		t.Fatal("details obscured unreviewed status")
	}
	in.Failures = nil
	policy, err := RenderApprovalOnlySummaryParts(in)
	if err != nil || !strings.Contains(policy[0], "administrator policy") || strings.Contains(policy[0], "providers unavailable") {
		t.Fatalf("policy=%v %v", policy, err)
	}
}

func TestApprovalOnlyHostileContentChunking(t *testing.T) {
	in := ApprovalOnlyInput{Host: "host", JobID: "job", Operation: "cmd " + strings.Repeat("😃<&'", 900), Reason: strings.Repeat("<reason>&", 700), Expiry: time.Now().Add(time.Minute), Failures: []proto.AvailabilityFailure{{Name: "<script>secret/path</script>", Code: proto.AvailabilityTransport}}}
	parts, err := RenderApprovalOnlySummaryParts(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) < 2 {
		t.Fatalf("expected chunking: %d", len(parts))
	}
	if !strings.Contains(parts[0], "NO AI REVIEW") || !strings.Contains(parts[0], "dependency completeness") {
		t.Fatal("first part missing warning")
	}
	for _, part := range parts {
		if utf8.RuneCountInString(part) > MaxMessageRunes {
			t.Fatal("part too long")
		}
		if err := assertBalancedTags(part); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(part, "<script>") || strings.Contains(part, "secret/path") {
			t.Fatal("unsanitized provider failure name")
		}
	}
	if !strings.Contains(strings.Join(parts, ""), "&lt;reason&gt;&amp;") {
		t.Fatal("reason lost")
	}
	if _, err := RenderApprovalOnlyDetails(in); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalOnlyEveryChunkLeadsWithUnreviewedWarning(t *testing.T) {
	in := ApprovalOnlyInput{
		Host: "verified-host", Container: "verified-container", JobID: "job-123",
		Operation: "/bin/sh -c '" + strings.Repeat("echo safe; ", 700) + "FINAL-COMMAND'",
		Reason:    strings.Repeat("submitted reason ", 300), SubmitterUID: 1001,
		SubmitterName: "submitter", TargetUID: 0, CWD: "/verified/cwd",
		Expiry:   time.Now().Add(time.Minute),
		Failures: []proto.AvailabilityFailure{{Name: "remote", Code: proto.AvailabilityTransport}},
	}
	parts, err := RenderApprovalOnlySummaryParts(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) < 3 {
		t.Fatalf("wanted long command and reason chunking, got %d parts", len(parts))
	}
	const prefix = "<b>NO AI REVIEW</b>\n"
	for i, part := range parts {
		if !strings.HasPrefix(part, prefix) {
			t.Errorf("part %d does not lead with unreviewed warning: %.160q", i+1, part)
		}
		if !strings.Contains(part, "unreviewed summary part") || !strings.Contains(part, "providers unavailable after fallback") || !strings.Contains(part, "No independent AI assessment took place") || !strings.Contains(part, "NOT assessed") {
			t.Errorf("part %d lacks persistent context: %.240q", i+1, part)
		}
		if utf8.RuneCountInString(part) > MaxMessageRunes {
			t.Errorf("part %d exceeds Telegram cap", i+1)
		}
		if err := assertBalancedTags(part); err != nil {
			t.Errorf("part %d has unbalanced HTML: %v", i+1, err)
		}
	}
	joined := strings.Join(parts, "\n")
	if !strings.Contains(joined, "FINAL-COMMAND") || !strings.Contains(joined, "verified-host") || !strings.Contains(joined, "/verified/cwd") || !strings.Contains(joined, "submitted reason") || !strings.Contains(joined, "connection unavailable") {
		t.Fatal("chunked operation context was lost")
	}

	// A compact summary remains a single readable message without an extra
	// generic header duplicated on top of the required prominent heading.
	in.Operation = "/usr/bin/id -u"
	in.Reason = "inspect identity"
	short, err := RenderApprovalOnlySummaryParts(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(short) != 1 || !strings.HasPrefix(short[0], "<b>NO AI REVIEW</b>\n") || strings.Count(short[0], "<b>NO AI REVIEW</b>") != 1 {
		t.Fatalf("short summary header duplicated or missing: %v", short)
	}
}

func TestRenderSummaryRequiredFields(t *testing.T) {
	parts, err := RenderSummaryParts(testCardInput())
	if err != nil {
		t.Fatalf("RenderSummaryParts: %v", err)
	}
	if len(parts) != 1 {
		t.Fatalf("expected single part, got %d", len(parts))
	}
	text := parts[0]
	for _, want := range []string{
		"<b>Privilege approval · Security risk: 4/5</b>",
		"<b>Host:</b> <code>energy-host</code>",
		"<b>Environment:</b> Docker container",
		"<b>Submitted by:</b> <code>sample-agent</code> (uid 4242) → root",
		"<b>Working directory:</b>", "<code>/home/example/project</code>",
		"<pre><code class=\"language-bash\">/usr/bin/bash /usr/local/share/entry.sh --migrate</code></pre>",
		"<b>Reason</b>", "migrate volumes to rootless storage",
		"<b>Review summary</b>", "Stops the application and re-mounts its volumes.",
		"<b>Effects</b>", "- Stops the application.", "- Changes volume paths.",
		"<b>Warnings</b>", "• Service downtime during migration.", "• Partial migration may require manual recovery.",
		"<b>Uncertainties</b>", "• Current backup availability was not verified.",
		"<b>Reversibility:</b> Rollback procedure found; success not verified.",
		"Reviewer <code>kimi-for-coding</code>", "expires 2026-09-21T12:00:00Z",
		"job <code>abcdef0123456789abcdef0123456789</code>",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("summary missing %q\n---\n%s", want, text)
		}
	}
	// Single part carries no part header.
	if strings.Contains(text, "part 1/") {
		t.Fatal("single part must not be numbered")
	}
	if utf8.RuneCountInString(text) > MaxMessageRunes {
		t.Fatal("summary exceeds hard cap")
	}
	if strings.Contains(text, "No script source was inspected") {
		t.Fatal("summary with reviewed source must not show an uninspected source warning")
	}
}

func TestRenderSummaryLongCommandStartsWithApprovalFacts(t *testing.T) {
	in := testCardInput()
	in.Operation = strings.Repeat("/long/command ", 500)
	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) < 2 {
		t.Fatalf("expected overflow, got %d part(s)", len(parts))
	}
	first := parts[0]
	for _, want := range []string{"<b>Privilege approval · Security risk: 4/5</b>", "<b>Host:</b>"} {
		if !strings.Contains(first, want) {
			t.Errorf("first summary part missing %q", want)
		}
	}
	if strings.Contains(first, "Reviewer-selected dependencies may be incomplete") {
		t.Fatal("shell-command classifier still adds an unrequested review judgment")
	}
	if err := assertBalancedTags(first); err != nil {
		t.Fatal(err)
	}
}

func TestReviewSummaryDoesNotClassifyCommandSyntax(t *testing.T) {
	for _, command := range []string{"/usr/bin/id -u", "/bin/sh -c 'echo hi'"} {
		in := testCardInput()
		in.Operation = command
		parts, err := RenderSummaryParts(in)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(parts, "")
		if strings.Count(text, "<b>Review summary</b>") != 1 || strings.Contains(text, "Reviewer-selected dependencies may be incomplete") {
			t.Fatalf("command syntax added a reviewer judgment: %s", text)
		}
	}
}

func TestReviewedMessagesDoNotAddMechanicalCompletenessDisclaimer(t *testing.T) {
	in := testCardInput()
	summary, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatal(err)
	}
	details, err := RenderDetails(DetailsInput{CardInput: in, ModelHistory: []proto.ModelHistoryEntry{}})
	if err != nil {
		t.Fatal(err)
	}
	card, _, err := RenderCard(in.JobID, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	for _, surface := range []string{strings.Join(summary, ""), strings.Join(details, ""), card} {
		if strings.Contains(surface, "LLM-selected review: completeness not mechanically checked") {
			t.Fatalf("mechanical disclaimer remained in reviewed Telegram output: %s", surface)
		}
	}
	if !strings.Contains(strings.Join(summary, ""), in.Report.Summary) {
		t.Fatal("removing the disclaimer also removed the model's review")
	}
}

func TestCommandDisplayEscapesHostileInlineText(t *testing.T) {
	in := testCardInput()
	in.Operation = `/bin/dash -c "echo <b>fake</b> & done"`
	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(parts, "")
	for _, want := range []string{"&lt;b&gt;fake&lt;/b&gt; &amp; done"} {
		if !strings.Contains(text, want) {
			t.Errorf("summary missing safely rendered content %q: %s", want, text)
		}
	}
	if strings.Contains(text, "<b>fake</b>") {
		t.Fatal("hostile command text injected HTML")
	}
	if err := assertBalancedTags(text); err != nil {
		t.Fatal(err)
	}
}

func TestRenderSummaryCWDDisplaysExactPath(t *testing.T) {
	for _, cwd := range []string{
		"/tmp/a\tb", "/tmp/a\nb", "/tmp/a\u202eb", "/tmp/a\\tb",
		"/tmp/quotes\"\\andé\t<b>Host:</b>",
	} {
		t.Run(strconv.Quote(cwd), func(t *testing.T) {
			in := testCardInput()
			in.CWD = cwd
			parts, err := RenderSummaryParts(in)
			if err != nil {
				t.Fatal(err)
			}
			if len(parts) != 1 {
				t.Fatalf("unexpected part count: %d", len(parts))
			}
			text := parts[0]
			const prefix = "<b>Working directory:</b>\n<code>"
			start := strings.Index(text, prefix)
			if start < 0 {
				t.Fatal("missing working directory label")
			}
			rest := text[start+len(prefix):]
			end := strings.Index(rest, "</code>")
			if end < 0 {
				t.Fatal("unclosed working directory code tag")
			}
			visible := html.UnescapeString(rest[:end])
			got := visible
			if strings.ContainsAny(cwd, "\t\n\u202e") {
				got, err = strconv.Unquote(visible)
				if err != nil {
					t.Fatalf("path has no reversible visible encoding: %q: %v", visible, err)
				}
			} else if strings.HasPrefix(visible, `"`) {
				t.Fatalf("ordinary paths should keep their original layout: %q", visible)
			}
			if got != cwd {
				t.Fatalf("displayed cwd=%q, actual cwd=%q", got, cwd)
			}
			if strings.Count(text, "<b>Host:</b>") != 1 || strings.Contains(text, "\u202e") || strings.Contains(text, "\t") {
				t.Fatalf("path injected a label or invisible control: %q", text)
			}
			if err := assertBalancedTags(text); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRenderSummarySubmitterFallback(t *testing.T) {
	in := testCardInput()
	in.SubmitterName = ""
	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatalf("RenderSummaryParts: %v", err)
	}
	if !strings.Contains(strings.Join(parts, ""), "<b>Submitted by:</b> <code>uid 4242</code> (uid 4242) → root") {
		t.Fatalf("empty submitter name must render uid fallback:\n%s", strings.Join(parts, ""))
	}
	// The container line is omitted when no environment evidence exists.
	in2 := testCardInput()
	in2.Container = ""
	parts2, err := RenderSummaryParts(in2)
	if err != nil {
		t.Fatalf("RenderSummaryParts: %v", err)
	}
	if strings.Contains(strings.Join(parts2, ""), "Environment") {
		t.Fatal("environment line must be omitted without container evidence")
	}
}

func TestRenderSummaryValidation(t *testing.T) {
	bad := testCardInput()
	bad.Host = " "
	if _, err := RenderSummaryParts(bad); err == nil {
		t.Fatal("expected error for empty host")
	}
	bad = testCardInput()
	bad.Expiry = time.Time{}
	if _, err := RenderSummaryParts(bad); err == nil {
		t.Fatal("expected error for zero expiry")
	}
	bad = testCardInput()
	bad.ReviewerModel = ""
	if _, err := RenderSummaryParts(bad); err == nil {
		t.Fatal("expected error for missing reviewer model")
	}
}

func TestRenderSummaryHTMLEscapesDynamicContent(t *testing.T) {
	in := testCardInput()
	in.Operation = `rm -rf / && echo "<b>fake</b><a href='https://evil.example'>link</a>"`
	in.Reason = "<script>alert('x')</script> & < > quotes \"'"
	in.Report.Summary = "summary with <b>tags</b> & entities &amp; more"
	in.Report.Warnings = []proto.ReviewWarning{{Message: "warning & <i>markup</i>", Evidence: "e1"}}
	in.SubmitterName = "<operator>&co"
	in.CWD = "/tmp/<dir>&ok"

	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatalf("RenderSummaryParts: %v", err)
	}
	text := strings.Join(parts, "")
	for _, want := range []string{
		html.EscapeString(`rm -rf / && echo "<b>fake</b><a href='https://evil.example'>link</a>"`),
		html.EscapeString("<script>alert('x')</script> & < > quotes \"'"),
		html.EscapeString("summary with <b>tags</b> & entities &amp; more"),
		html.EscapeString("warning & <i>markup</i>"),
		html.EscapeString("<operator>&co"),
		html.EscapeString("/tmp/<dir>&ok"),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("dynamic text not escaped as %q in:\n%s", want, text)
		}
	}
	// None of the raw hostile markup survives.
	for _, raw := range []string{"<b>fake</b>", "<a href=", "<script>", "<i>markup</i>"} {
		if strings.Contains(text, raw) {
			t.Errorf("raw hostile markup %q leaked unescaped", raw)
		}
	}
	// All tags that remain are the renderer's own balanced wrappers.
	if err := assertBalancedTags(text); err != nil {
		t.Fatalf("renderer tags not balanced: %v\n%s", err, text)
	}
}

// assertBalancedTags checks that every opening tag has a matching closing
// tag in order and nothing dangling remains (code/pre/b only; no other
// tags are emitted by this package).
func assertBalancedTags(text string) error {
	depth := map[string]int{}
	for _, tok := range tokenizeTags(text) {
		switch {
		case strings.HasPrefix(tok, "</"):
			name := strings.Trim(tok, "</>")
			depth[name]--
			if depth[name] < 0 {
				return fmt.Errorf("closing </%s> without opener near %q", name, tok)
			}
		default:
			name := strings.TrimRight(strings.TrimLeft(tok, "<"), ">")
			if i := strings.IndexByte(name, ' '); i >= 0 {
				name = name[:i]
			}
			depth[name]++
		}
	}
	for name, n := range depth {
		if n != 0 {
			return fmt.Errorf("unclosed <%s> (%d)", name, n)
		}
	}
	return nil
}

// tokenizeTags splits text into HTML tags and inter-tag text, returning
// only the tags. An unterminated "<" is returned as a token ending without
// ">" so callers treat it as unbalanced.
func tokenizeTags(text string) []string {
	var toks []string
	for {
		start := strings.IndexByte(text, '<')
		if start < 0 {
			return toks
		}
		end := strings.IndexByte(text[start:], '>')
		if end < 0 {
			toks = append(toks, text[start:])
			return toks
		}
		toks = append(toks, text[start:start+end+1])
		text = text[start+end+1:]
	}
}

func TestRenderSummaryChunkingPreservesWarnings(t *testing.T) {
	in := testCardInput()
	// 24 warnings x ~500 runes forces a multi-part summary.
	warnings := make([]proto.ReviewWarning, 24)
	for i := range warnings {
		warnings[i] = proto.ReviewWarning{
			Message:  fmt.Sprintf("warning-%02d %s", i, strings.Repeat("material detail ", 28)),
			Evidence: fmt.Sprintf("f%d lines 1-2", i),
		}
	}
	in.Report.Warnings = warnings

	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatalf("RenderSummaryParts: %v", err)
	}
	if len(parts) < 2 {
		t.Fatalf("expected multiple parts, got %d", len(parts))
	}
	for i, p := range parts {
		if n := utf8.RuneCountInString(p); n > MaxMessageRunes {
			t.Fatalf("part %d has %d runes, exceeds %d", i, n, MaxMessageRunes)
		}
		if err := assertBalancedTags(p); err != nil {
			t.Fatalf("part %d tags not balanced: %v\n%s", i, err, p)
		}
		wantHeader := fmt.Sprintf("summary part %d/%d", i+1, len(parts))
		if !strings.HasPrefix(p, "Job "+in.JobID+" — "+wantHeader) {
			t.Fatalf("part %d missing ordered header, starts: %.80q", i, p)
		}
	}
	// No warning text may be lost across chunks.
	joined := strings.Join(parts, "")
	for _, w := range warnings {
		if !strings.Contains(joined, html.EscapeString(w.Message)) {
			t.Fatalf("warning lost in chunking: %q", w.Message[:40])
		}
	}
	// Required sections still present after chunking.
	for _, want := range []string{"<b>Privilege approval · Security risk: 4/5</b>", "<b>Warnings</b>", "Reversibility:", "Reviewer <code>kimi-for-coding</code>", "<b>Uncertainties</b>"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("chunked summary lost %q", want)
		}
	}
	// The heading must precede the warnings section (field order preserved).
	if strings.Index(joined, "<b>Privilege approval") > strings.Index(joined, "<b>Warnings</b>") {
		t.Fatal("field order not preserved across chunks")
	}
}

func TestRenderSummaryMidFieldContinuation(t *testing.T) {
	in := testCardInput()
	in.Reason = strings.Repeat("A", 3000) + strings.Repeat("B", 3000)
	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatalf("RenderSummaryParts: %v", err)
	}
	if len(parts) < 2 {
		t.Fatalf("expected split, got %d part(s)", len(parts))
	}
	var sawMarker bool
	for i, p := range parts {
		if utf8.RuneCountInString(p) > MaxMessageRunes {
			t.Fatalf("part %d exceeds cap", i)
		}
		if err := assertBalancedTags(p); err != nil {
			t.Fatalf("part %d tags not balanced: %v", i, err)
		}
		if strings.Contains(p, continuationMarker) {
			sawMarker = true
		}
	}
	if !sawMarker {
		t.Fatal("expected continuation markers for over-long field")
	}
	// Removing continuation scaffolding must restore the full reason.
	cleaned := strings.ReplaceAll(strings.Join(parts, ""), "\n"+continuationMarker+"\n", "")
	cleaned = strings.ReplaceAll(cleaned, continuationMarker+"\n", "")
	if !strings.Contains(cleaned, strings.Repeat("A", 2000)) || !strings.Contains(cleaned, strings.Repeat("B", 2000)) {
		t.Fatal("reason content lost across continuation split")
	}
}

func TestRenderSummaryLongCommandNeverTruncated(t *testing.T) {
	// A command far beyond one message must survive chunking complete:
	// every fragment of the command body is present in order, and the
	// suffix (its "arguments") is retained — no silent ellipsis.
	suffix := "--final-argument-value-ZZZZ"
	in := testCardInput()
	in.Operation = strings.Repeat("/very/long/command/component/ ", 160) + suffix
	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatalf("RenderSummaryParts: %v", err)
	}
	if len(parts) < 2 {
		t.Fatalf("expected split, got %d part(s)", len(parts))
	}
	joined := strings.Join(parts, "")
	if !strings.Contains(joined, html.EscapeString(suffix)) {
		t.Fatalf("command suffix %q dropped by chunking", suffix)
	}
	// Every fragment of the escaped command body survives in order.
	escaped := html.EscapeString(in.Operation)
	runes := []rune(escaped)
	step := 400
	for i := 0; i+step <= len(runes); i += step {
		frag := string(runes[i : i+step])
		if !strings.Contains(joined, frag) {
			t.Fatalf("command fragment %d lost across chunks", i/step)
		}
	}
	for i, p := range parts {
		if err := assertBalancedTags(p); err != nil {
			t.Fatalf("part %d tags not balanced: %v", i, err)
		}
	}
}

func TestRenderSummaryHugeCommandMultiContinuation(t *testing.T) {
	// A command several message-lengths long exercises repeated
	// continuation splits of the wrapped code block: every part must keep
	// balanced tags, the content must survive in order, and the suffix
	// (the trailing arguments) must never be dropped.
	suffix := "--tail-argument-END"
	in := testCardInput()
	in.Operation = strings.Repeat("arg-%02d-value-", 6) + "x" + strings.Repeat("/long/path/component/", 400) + suffix
	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatalf("RenderSummaryParts: %v", err)
	}
	if len(parts) < 3 {
		t.Fatalf("expected >=3 parts, got %d", len(parts))
	}
	joined := strings.Join(parts, "\n")
	for i, p := range parts {
		if err := assertBalancedTags(p); err != nil {
			t.Fatalf("part %d tags not balanced: %v", i, err)
		}
		if n := utf8.RuneCountInString(p); n > MaxMessageRunes {
			t.Fatalf("part %d exceeds cap", i)
		}
	}
	esc := html.EscapeString(in.Operation)
	step := 300
	for i := 0; i+step <= len([]rune(esc)); i += step {
		if !strings.Contains(joined, string([]rune(esc)[i:i+step])) {
			t.Fatalf("command fragment at %d lost across repeated continuation splits", i)
		}
	}
	if !strings.Contains(joined, html.EscapeString(suffix)) {
		t.Fatal("command suffix dropped after repeated continuations")
	}
}

func TestRenderSummaryChunkedEntitiesAndHostileJobID(t *testing.T) {
	in := testCardInput()
	in.JobID = `job<&"'` // A direct renderer caller must not inject markup through continuation headers.
	in.Operation = "/usr/bin/command " + strings.Repeat("😃<&'", 850) + " --last-arg"
	in.CWD = "/" + strings.Repeat("<&", 1100)
	in.Reason = strings.Repeat("reason<&", 850)
	in.Report.Warnings = []proto.ReviewWarning{{Message: "warning: " + strings.Repeat("é<&'", 850), Evidence: "f1"}}
	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) < 3 {
		t.Fatalf("expected command and warning continuations, got %d parts", len(parts))
	}
	var command strings.Builder
	for i, part := range parts {
		if !strings.HasPrefix(part, "Job "+html.EscapeString(in.JobID)+" — summary part ") {
			t.Errorf("part %d job header not escaped: %.90q", i, part)
		}
		if utf8.RuneCountInString(part) > MaxMessageRunes || !utf8.ValidString(part) {
			t.Fatalf("part %d exceeds cap or contains invalid UTF-8", i)
		}
		decoder := xml.NewDecoder(strings.NewReader(part))
		for {
			_, err := decoder.Token()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("part %d has unbalanced HTML or broken entity: %v\n%s", i, err, part)
			}
		}
		const open, close = `<pre><code class="language-bash">`, `</code></pre>`
		if start := strings.Index(part, open); start >= 0 {
			end := strings.Index(part[start+len(open):], close)
			if end < 0 {
				t.Fatalf("part %d lost code block close", i)
			}
			command.WriteString(part[start+len(open) : start+len(open)+end])
		}
	}
	if got := html.UnescapeString(command.String()); got != in.Operation {
		t.Fatalf("chunked command changed: got %d bytes, want %d", len(got), len(in.Operation))
	}
	joined := strings.Join(parts, "")
	if strings.Count(joined, "é") != 850 {
		t.Fatal("warning lost after multiple continuations")
	}
}

func TestStripControlCharacters(t *testing.T) {
	in := testCardInput()
	in.Operation = "run\x00me\x07\x1b[2J\x85neutral ​‎‮\ufeffdone"
	in.Reason = "line one\nline two\twith tab"
	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatalf("RenderSummaryParts: %v", err)
	}
	text := strings.Join(parts, "")
	for _, bad := range []string{"\x00", "\x07", "\x1b", "\x85", "\u200b", "\u200e", "\u202e", "\ufeff", "\t"} {
		if strings.Contains(text, bad) {
			t.Fatalf("control character %q survived sanitization", bad)
		}
	}
	if !strings.Contains(text, "line one\nline two") {
		t.Fatal("newline must be preserved")
	}
	if !strings.Contains(text, "runmeneutraldone") && !strings.Contains(text, "runme") {
		t.Fatal("printable content damaged by sanitization")
	}
}

func TestRenderCard(t *testing.T) {
	text, kb, err := RenderCard("job-123", testNonce)
	if err != nil {
		t.Fatalf("RenderCard: %v", err)
	}
	if !strings.Contains(text, "Approval required for job job-123") || !strings.Contains(text, "details above") {
		t.Fatalf("card text wrong: %q", text)
	}
	if len(kb.InlineKeyboard) != 1 || len(kb.InlineKeyboard[0]) != 3 {
		t.Fatalf("keyboard shape wrong: %+v", kb)
	}
	want := map[string]string{
		"Approve once": "a:" + testNonce,
		"Deny":         "d:" + testNonce,
		"Details":      "v:" + testNonce,
	}
	for _, btn := range kb.InlineKeyboard[0] {
		data, ok := want[btn.Text]
		if !ok {
			t.Fatalf("unexpected button %q", btn.Text)
		}
		if btn.CallbackData != data {
			t.Fatalf("button %q callback_data = %q, want %q", btn.Text, btn.CallbackData, data)
		}
		if len(btn.CallbackData) != 34 || len(btn.CallbackData) > MaxCallbackDataBytes {
			t.Fatalf("callback_data length %d", len(btn.CallbackData))
		}
	}
	// Hostile job ID cannot inject markup.
	if hostile, _, err := RenderCard("<b>job</b>", testNonce); err != nil || strings.Contains(hostile, "<b>") {
		t.Fatalf("job ID markup not escaped: %q err=%v", hostile, err)
	}
	if _, _, err := RenderCard("job", "not-hex"); err == nil {
		t.Fatal("expected error for bad nonce")
	}
	if _, err := CallbackData("x", testNonce); err == nil {
		t.Fatal("expected error for unknown action")
	}
}

func TestRenderDetails(t *testing.T) {
	in := DetailsInput{
		CardInput: testCardInput(),
		ModelHistory: []proto.ModelHistoryEntry{
			{Name: "quota-model", Outcome: "api_error", Error: "quota exhausted"},
			{Name: "kimi-for-coding", Outcome: "ok"},
		},
	}
	parts, err := RenderDetails(in)
	if err != nil {
		t.Fatalf("RenderDetails: %v", err)
	}
	text := strings.Join(parts, "")
	for _, want := range []string{
		"Details for job abcdef0123456789abcdef0123456789",
		"evidence: f1 lines 10-22",
		"evidence: f2 lines 3-7",
		"Current backup availability was not verified.",
		"<b>Reversibility:</b> Rollback procedure found",
		"quota-model: api_error (quota exhausted)",
		"kimi-for-coding: ok",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("details missing %q", want)
		}
	}
	for i, p := range parts {
		if utf8.RuneCountInString(p) > MaxMessageRunes {
			t.Fatalf("details part %d exceeds cap", i)
		}
		if err := assertBalancedTags(p); err != nil {
			t.Fatalf("details part %d tags not balanced: %v", i, err)
		}
	}
}

func TestRenderDetailsDoesNotClaimStaticExhaustiveness(t *testing.T) {
	parts, err := RenderDetails(DetailsInput{CardInput: testCardInput()})
	if err != nil {
		t.Fatal(err)
	}
	if text := strings.Join(parts, ""); strings.Contains(text, "Dependency inference") || strings.Contains(text, "parser-proven") || strings.Contains(text, "statically proven") {
		t.Fatal("details must not claim parser-proven or statically exhaustive dependencies")
	}
}

func TestRenderDetailsLongInlineCodeReferencesRemainBalanced(t *testing.T) {
	ref := "/" + strings.Repeat("<>&", 341) // 1024 raw bytes; escapes beyond one chunk.
	in := DetailsInput{CardInput: testCardInput(), ModelHistory: []proto.ModelHistoryEntry{{Name: "local", Outcome: "api_error", Error: strings.Repeat("<>&", 600) + " final-error"}}}
	in.WithheldRefs = []string{ref}
	in.WithheldCount = 1
	parts, err := RenderDetails(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) < 3 {
		t.Fatalf("expected long references to span parts, got %d", len(parts))
	}
	var paths strings.Builder
	for i, part := range parts {
		if utf8.RuneCountInString(part) > MaxMessageRunes {
			t.Fatalf("details part %d exceeds Telegram cap", i)
		}
		decoder := xml.NewDecoder(strings.NewReader(part))
		inCode := false
		for {
			token, err := decoder.Token()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("details part %d has unbalanced HTML or split entity: %v", i, err)
			}
			switch tok := token.(type) {
			case xml.StartElement:
				if tok.Name.Local == "code" {
					inCode = true
				}
			case xml.EndElement:
				if tok.Name.Local == "code" {
					inCode = false
				}
			case xml.CharData:
				if inCode {
					paths.Write(tok)
				}
			}
		}
	}
	if !strings.Contains(paths.String(), ref) {
		t.Fatalf("reference lost or altered: got %d bytes", paths.Len())
	}
	joined := strings.Join(parts, "")
	for _, want := range []string{"Credential content withheld", "final-error"} {
		if !strings.Contains(joined, want) {
			t.Errorf("details dropped %q", want)
		}
	}
}

func TestRenderDetailsControlPathReferencesAreReversible(t *testing.T) {
	ref := "/tmp/a\tb\u202e<fake>"
	denied := "/tmp/a\\tb\nquotes\"é"
	in := DetailsInput{CardInput: testCardInput()}
	in.WithheldRefs = []string{ref, denied}
	in.WithheldCount = 2
	parts, err := RenderDetails(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 {
		t.Fatalf("unexpected part count: %d", len(parts))
	}
	text := parts[0]
	for _, path := range []string{ref, denied} {
		encoded := "<code>" + html.EscapeString(strconv.Quote(path)) + "</code>"
		if !strings.Contains(text, encoded) {
			t.Errorf("reference %q has no reversible escaped encoding", path)
		}
		got, err := strconv.Unquote(html.UnescapeString(strings.TrimSuffix(strings.TrimPrefix(encoded, "<code>"), "</code>")))
		if err != nil || got != path {
			t.Fatalf("reference display did not decode to original: %q %v", got, err)
		}
	}
	if strings.Contains(text, "<fake>") || strings.Contains(text, "\u202e") || strings.Contains(text, "\t") {
		t.Fatalf("unsafe reference text survived unescaped: %q", text)
	}
	if err := assertBalancedTags(text); err != nil {
		t.Fatal(err)
	}
}

func TestSendApprovalOrdersPartsBeforeCard(t *testing.T) {
	bot := newFakeBot(t, nil)
	client := bot.client(t)

	parts := []string{"<b>part one</b>", "<b>part two</b>", "<b>part three</b>"}
	cardText, kb, err := RenderCard("job-9", testNonce)
	if err != nil {
		t.Fatal(err)
	}
	messageIDs, cardID, err := SendApproval(context.Background(), client, 424242, parts, cardText, kb)
	if err != nil {
		t.Fatalf("SendApproval: %v", err)
	}
	if len(messageIDs) != 3 || cardID == 0 {
		t.Fatalf("messageIDs=%v cardID=%d", messageIDs, cardID)
	}

	sent := bot.byMethod("sendMessage")
	if len(sent) != 4 {
		t.Fatalf("sendMessage calls = %d, want 4", len(sent))
	}
	for i, part := range parts {
		if sent[i].body["text"] != part {
			t.Fatalf("part %d text = %v", i, sent[i].body["text"])
		}
		if sent[i].body["parse_mode"] != "HTML" {
			t.Fatalf("summary part %d parse_mode = %v, want HTML", i, sent[i].body["parse_mode"])
		}
		if _, hasKeyboard := sent[i].body["reply_markup"]; hasKeyboard {
			t.Fatalf("summary part %d must not carry buttons", i)
		}
	}
	if sent[3].body["text"] != cardText {
		t.Fatalf("card text mismatch: %v", sent[3].body["text"])
	}
	if sent[3].body["parse_mode"] != "HTML" {
		t.Fatalf("card parse_mode = %v, want HTML", sent[3].body["parse_mode"])
	}
	if _, hasKeyboard := sent[3].body["reply_markup"]; !hasKeyboard {
		t.Fatal("approval card must carry the inline keyboard")
	}
	if _, ok := sent[3].body["chat_id"].(float64); !ok {
		t.Fatal("card chat_id missing")
	}
}

func TestSendApprovalLongSummaryBeforeCard(t *testing.T) {
	in := testCardInput()
	in.Operation = strings.Repeat("/long/command ", 500)
	parts, err := RenderSummaryParts(in)
	if err != nil {
		t.Fatal(err)
	}
	card, kb, err := RenderCard(in.JobID, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	bot := newFakeBot(t, nil)
	if _, _, err := SendApproval(context.Background(), bot.client(t), 42, parts, card, kb); err != nil {
		t.Fatal(err)
	}
	sent := bot.byMethod("sendMessage")
	if len(sent) != len(parts)+1 || len(parts) < 2 {
		t.Fatalf("sent %d messages for %d summary parts", len(sent), len(parts))
	}
	if !strings.Contains(sent[0].body["text"].(string), "<b>Privilege approval") {
		t.Fatal("first delivered summary omitted the approval heading")
	}
	for i, part := range parts {
		if sent[i].body["text"] != part {
			t.Fatalf("summary part %d was not delivered in order", i)
		}
		if _, hasKeyboard := sent[i].body["reply_markup"]; hasKeyboard {
			t.Fatalf("summary part %d carried approval buttons", i)
		}
	}
	if sent[len(parts)].body["text"] != card {
		t.Fatal("approval card was not delivered after every summary part")
	}
	if _, hasKeyboard := sent[len(parts)].body["reply_markup"]; !hasKeyboard {
		t.Fatal("approval card omitted buttons")
	}
}

func TestSendApprovalPartialFailurePostsNoCard(t *testing.T) {
	call := 0
	bot := newFakeBot(t, func(method string, _ map[string]any) (any, *fakeAPIError) {
		if method != "sendMessage" {
			return true, nil
		}
		call++
		if call == 2 {
			return nil, &fakeAPIError{code: 500, description: "internal error"}
		}
		return map[string]any{"message_id": 2000 + int64(call)}, nil
	})
	client := bot.client(t)

	_, kb, err := RenderCard("job-9", testNonce)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = SendApproval(context.Background(), client, 1, []string{"p1", "p2", "p3"}, "card", kb)
	if err == nil {
		t.Fatal("expected error when part 2 fails")
	}
	if !errors.Is(err, ErrAPI) {
		t.Fatalf("error %v is not ErrAPI", err)
	}
	sent := bot.byMethod("sendMessage")
	if len(sent) != 2 {
		t.Fatalf("sendMessage calls = %d, want exactly 2 (no card attempt)", len(sent))
	}
	for _, r := range sent {
		if _, hasKeyboard := r.body["reply_markup"]; hasKeyboard {
			t.Fatal("approval card was attempted despite summary failure")
		}
	}
}

func TestSendApprovalRequiresParts(t *testing.T) {
	bot := newFakeBot(t, nil)
	client := bot.client(t)
	if _, _, err := SendApproval(context.Background(), client, 1, nil, "card", InlineKeyboardMarkup{}); err == nil {
		t.Fatal("expected error for empty summary parts")
	}
	if len(bot.recorded()) != 0 {
		t.Fatal("no request may be sent when parts are missing")
	}
}

func TestSendDetailsUsesHTML(t *testing.T) {
	bot := newFakeBot(t, nil)
	client := bot.client(t)
	parts := []string{"<b>details one</b>", "<b>details two</b>"}
	if _, err := SendDetails(context.Background(), client, 7, parts); err != nil {
		t.Fatalf("SendDetails: %v", err)
	}
	sent := bot.byMethod("sendMessage")
	if len(sent) != 2 {
		t.Fatalf("sendMessage calls = %d, want 2", len(sent))
	}
	for i, r := range sent {
		if r.body["text"] != parts[i] || r.body["parse_mode"] != "HTML" {
			t.Fatalf("details part %d wrong: %v", i, r.body)
		}
	}
}

// TestRenderedCardDemo prints one full approval request — ordered summary
// parts plus the approval card — for human inspection of wording and
// warnings (Wave 5 real-surface QA). Run: go test -v -run DemoCard ./internal/telegram/
func TestRenderedCardDemo(t *testing.T) {
	parts, err := RenderSummaryParts(testCardInput())
	if err != nil {
		t.Fatal(err)
	}
	card, kb, err := RenderCard(testCardInput().JobID, "00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	for i, part := range parts {
		t.Logf("--- summary part %d/%d ---\n%s", i+1, len(parts), part)
	}
	t.Logf("--- approval card ---\n%s", card)
	for row, buttons := range kb.InlineKeyboard {
		for col, b := range buttons {
			t.Logf("button[%d][%d]: %q callback_data=%q (%d bytes)", row, col, b.Text, b.CallbackData, len(b.CallbackData))
		}
	}
}
