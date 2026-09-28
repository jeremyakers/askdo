package telegram

import (
	"strings"
	"testing"
)

func TestRenderAutoNoticeNoActionsOrForgedMarkup(t *testing.T) {
	text, err := RenderAutoNotice("job<&>", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"job&lt;&amp;&gt;", "1/5", "prelaunch checks", "No human approval"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q: %s", want, text)
		}
	}
	for _, bad := range []struct {
		job   string
		score int
	}{{"", 1}, {"x\x00y", 1}, {"job", 0}, {"job", 5}, {strings.Repeat("x", 65), 1}} {
		if _, err := RenderAutoNotice(bad.job, bad.score); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
