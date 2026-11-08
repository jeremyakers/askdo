package telegram

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestUpgradeNoticeSaysWhatHappenedToWhichHost(t *testing.T) {
	const id = "host_0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		outcome string
		want    []string
	}{
		{"succeeded", []string{"askdo upgraded", "Now running <code>v1.0.1</code>"}},
		{"rolled_back", []string{"rolled back", "restored and verified", "runs <code>v1.0.0</code> again"}},
		{"rollback_failed", []string{"so did its rollback", "manual recovery"}},
		{"no_changes", []string{"upgrade failed", "before it changed anything"}},
		{"failed", []string{"askdo upgrade", "failed"}},
		{"unknown", []string{"outcome unknown", "Inspect the host"}},
		{"refused", []string{"upgrade refused", "nothing was changed"}},
		{"lease_expired", []string{"not reported", "reported no outcome"}},
	} {
		t.Run(tc.outcome, func(t *testing.T) {
			in := UpgradeNoticeInput{Outcome: tc.outcome, Hostname: "nas-01", HostID: id, Release: "v1.0.1", Running: "v1.0.0", Detail: "start askdo.service failed"}
			text := RenderUpgradeNotice(in)
			for _, want := range append([]string{"<code>nas-01</code>", "<code>0123456789ab</code>"}, tc.want...) {
				if !strings.Contains(text, want) && !strings.Contains(strings.ToLower(text), strings.ToLower(want)) {
					t.Errorf("notice lacks %q:\n%s", want, text)
				}
			}
			if strings.Contains(text, "Rollout paused") {
				t.Errorf("notice says the rollout paused when it did not:\n%s", text)
			}
			if err := assertBalancedTags(text); err != nil {
				t.Errorf("tags not balanced: %v\n%s", err, text)
			}
		})
	}
}

func TestUpgradeNoticeNamesTheCommandThatResumesAPausedRollout(t *testing.T) {
	text := RenderUpgradeNotice(UpgradeNoticeInput{Outcome: "rolled_back", HostID: "host_abc", Release: "v1.0.1", Paused: true})
	if want := "Rollout paused:</b> no other host is offered <code>v1.0.1</code> until you run <code>askdo-config gateway upgrade-target v1.0.1</code>"; !strings.Contains(text, want) {
		t.Fatalf("notice lacks the resume instruction:\n%s", text)
	}
	if err := assertBalancedTags(text); err != nil {
		t.Fatalf("tags not balanced: %v\n%s", err, text)
	}
}

// What a host reports is display text, never markup: it is escaped and bounded
// however hostile, and it adds no control to a message that has none.
func TestUpgradeNoticeTreatsWhatAHostReportedAsData(t *testing.T) {
	hostile := `<a href="https://evil.example">x</a><b>&amp;</b>` + "\x1b[31m\u202e"
	text := RenderUpgradeNotice(UpgradeNoticeInput{
		Outcome: "failed", Hostname: hostile + strings.Repeat("h", 2000), HostID: "host_" + strings.Repeat("a", 64),
		Release: hostile + strings.Repeat("r", 2000), Running: hostile, Detail: hostile + strings.Repeat("d", 5000), Paused: true,
	})
	for _, raw := range []string{`<a href`, `</a>`, "<b>&amp;", "\x1b", "\u202e"} {
		if strings.Contains(text, raw) {
			t.Errorf("hostile %q leaked unescaped:\n%s", raw, text)
		}
	}
	if err := assertBalancedTags(text); err != nil {
		t.Errorf("tags not balanced: %v", err)
	}
	if n := utf8.RuneCountInString(text); n > 2000 {
		t.Errorf("notice is %d characters; Telegram messages are limited and the text must be bounded", n)
	}
}

func TestUpgradeNoticeNeedsNoHostName(t *testing.T) {
	text := RenderUpgradeNotice(UpgradeNoticeInput{Outcome: "succeeded", HostID: "host_abcdef0123456789", Release: "v1.0.1"})
	if !strings.Contains(text, "<b>Host:</b> <code>abcdef012345</code>\n") {
		t.Fatalf("host line = %q", text)
	}
}
