package telegram

import (
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
