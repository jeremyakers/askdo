package telegram

import (
	"github.com/jeremyakers/askdo/internal/proto"
	"strings"
	"testing"
)

func TestRenderAutoNoticeNoActionsOrForgedMarkup(t *testing.T) {
	// Given: reviewed request facts and a policy-selected score.
	in := testCardInput()
	in.JobID = "job<&>"
	// When: the non-actionable notice renders.
	text, err := RenderAutoNotice(in, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Then: the verdict and request facts accompany an explicit policy attribution.
	for _, want := range []string{"job&lt;&amp;&gt;", "🟢 <b>Auto-approved by policy · Risk 1/5</b>", in.Report.Summary, "No human approval was requested.", "<b>Runs:</b>", "<b>Why:</b>", in.Report.Warnings[0].Message} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q: %s", want, text)
		}
	}
	// An auto-approved command never waits for a decision, so a deadline would
	// only suggest the operator still has time to stop it.
	if strings.Contains(text, "expires") || strings.Contains(text, expiryText(in.Expiry)) {
		t.Errorf("auto notice shows a decision deadline: %s", text)
	}
	for _, bad := range []struct {
		job   string
		score int
	}{{"", 1}, {"x\x00y", 1}, {"job", 0}, {"job", 5}, {strings.Repeat("x", 65), 1}} {
		in.JobID = bad.job
		if _, err := RenderAutoNotice(in, bad.score); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestAutoNoticeNeverPointsToDetails(t *testing.T) {
	// Given: an auto-approved report with more warnings than the notice shows,
	// and content withheld from the AI review.
	in := testCardInput()
	in.Report.Warnings = []proto.ReviewWarning{{Message: "One."}, {Message: "Two."}, {Message: "Three."}, {Message: "Four."}, {Message: "Five."}}
	in.WithheldCount, in.WithheldRefs = 2, []string{"bundle:secret.env"}
	// When: the auto notice renders (it has no buttons and no Details).
	notice, err := RenderAutoNotice(in, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Then: nothing refers to Details; overflow and withholding point to the
	// host's review log for this job, which records the full review.
	if strings.Contains(notice, "Details") {
		t.Errorf("auto notice refers to Details:\n%s", notice)
	}
	for _, want := range []string{"+2 more", "sudo askdo review log --job " + in.JobID + " --since 0", "Content withheld from AI review: 2 item(s)"} {
		if !strings.Contains(notice, want) {
			t.Errorf("auto notice lacks %q:\n%s", want, notice)
		}
	}
}

func TestTruncatedAutoNoticeCommandPointsToTheFullCommand(t *testing.T) {
	// Given: an auto-approved command too long for the notice, with no extra
	// warnings or withheld content that would otherwise add a pointer.
	in := testCardInput()
	in.Operation = "/usr/bin/printf " + strings.Repeat("x", 600)
	in.Report.Warnings = []proto.ReviewWarning{}
	in.WithheldCount, in.WithheldRefs = 0, nil
	// When: the auto notice renders.
	notice, err := RenderAutoNotice(in, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Then: the cut-off command says where the full command is.
	if !strings.Contains(notice, "…") || !strings.Contains(notice, "full command: <code>sudo askdo review log --job "+in.JobID+" --since 0</code>") {
		t.Errorf("truncated command has no pointer:\n%s", notice)
	}
}
