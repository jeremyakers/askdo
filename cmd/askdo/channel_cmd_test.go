package main

// channel_cmd_test.go — T9.5 e2e tests for `channel add telegram` /
// `channel list`: scripted-stdin flows, bad numeric re-prompting, token
// keep/replace semantics, non-interactive flag equivalence, and secret
// containment.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChannelAddTelegramScripted(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"telegram", "--config", configPath, "--credentials-dir", credDir}
	// The discovery offer is declined; the numeric IDs are entered manually.
	code := channelAdd(args, scripted("tg-TEST-TOKEN-123", "n", "12345", "67890"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	t.Logf("channel add wizard transcript (stderr prompts + stdout result):\n%s%s", stderr.String(), stdout.String())
	tg := readTelegram(t, configPath)
	tokenPath := filepath.Join(credDir, "telegram.token")
	if tg.TokenFile != tokenPath || tg.OperatorUserID != 12345 || tg.ChatID != 67890 {
		t.Fatalf("telegram section %+v", tg)
	}
	if got := fileContent(t, tokenPath); got != "tg-TEST-TOKEN-123\n" {
		t.Fatalf("token content %q", got)
	}
	if info, _ := os.Stat(tokenPath); info.Mode().Perm() != 0640 {
		t.Fatalf("token mode %04o, want 0640", info.Mode().Perm())
	}
	assertNoLeak(t, &stdout, &stderr, "tg-TEST-TOKEN-123")
}

func TestChannelAddTelegramBadNumericsReprompt(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"telegram", "--config", configPath, "--credentials-dir", credDir}
	// The discovery offer is declined; non-numeric operator ID and chat ID
	// are rejected and re-prompted; a negative chat ID (supergroup style)
	// is valid.
	code := channelAdd(args, scripted("tg-tok2", "n", "not-a-number", "12345", "nope", "-100"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 12345 || tg.ChatID != -100 {
		t.Fatalf("telegram section %+v", tg)
	}
	if !strings.Contains(stderr.String(), "enter a whole number") {
		t.Fatalf("stderr=%s, want re-prompt message", stderr.String())
	}
	assertNoLeak(t, &stdout, &stderr, "tg-tok2")
}

func TestChannelAddTelegramRerunKeepsTokenOnEmpty(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	configPath, _ = onboardFixtureIn(dir, "", `"token_file": "`+filepath.Join(credDir, "telegram.token")+`", "operator_user_id": 12345, "chat_id": 67890`)
	tokenPath := filepath.Join(credDir, "telegram.token")
	if err := os.WriteFile(tokenPath, []byte("OLD-TELEGRAM-TOKEN\n"), 0640); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"telegram", "--config", configPath, "--credentials-dir", credDir}
	// Discovery is not offered against an existing section. Empty token
	// answer keeps the file; operator ID changes; chat ID kept.
	code := channelAdd(args, scripted("", "54321", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if got := fileContent(t, tokenPath); got != "OLD-TELEGRAM-TOKEN\n" {
		t.Fatalf("empty token answer must keep the existing file, got %q", got)
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 54321 || tg.ChatID != 67890 {
		t.Fatalf("telegram section %+v", tg)
	}
	if !strings.Contains(stdout.String(), "(unchanged)") {
		t.Fatalf("stdout=%s, want unchanged marker", stdout.String())
	}
	assertNoLeak(t, &stdout, &stderr, "OLD-TELEGRAM-TOKEN")
}

func TestChannelAddTelegramRerunReplacesToken(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	configPath, _ = onboardFixtureIn(dir, "", `"token_file": "`+filepath.Join(credDir, "telegram.token")+`", "operator_user_id": 12345, "chat_id": 67890`)
	tokenPath := filepath.Join(credDir, "telegram.token")
	if err := os.WriteFile(tokenPath, []byte("OLD-TELEGRAM-TOKEN\n"), 0640); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"telegram", "--config", configPath, "--credentials-dir", credDir}
	// Discovery is not offered against an existing section. A new token
	// atomically replaces the file; empty ID answers keep them.
	code := channelAdd(args, scripted("tg-NEW-TOKEN", "", ""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if got := fileContent(t, tokenPath); got != "tg-NEW-TOKEN\n" {
		t.Fatalf("token not replaced, got %q", got)
	}
	tg := readTelegram(t, configPath)
	if tg.OperatorUserID != 12345 || tg.ChatID != 67890 {
		t.Fatalf("telegram section %+v", tg)
	}
	if !strings.Contains(stdout.String(), "(updated)") {
		t.Fatalf("stdout=%s, want updated marker", stdout.String())
	}
	assertNoLeak(t, &stdout, &stderr, "tg-NEW-TOKEN", "OLD-TELEGRAM-TOKEN")
}

func TestChannelAddTelegramNonInteractiveEquivalence(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	run := func(flags bool) (string, string) {
		configPath, dir := onboardFixture(t, "", "")
		credDir := filepath.Join(dir, "credentials")
		if err := os.Mkdir(credDir, 0750); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		var code int
		if flags {
			tokenFile := filepath.Join(dir, "token.import")
			if err := os.WriteFile(tokenFile, []byte("tg-EQUIV\n"), 0600); err != nil {
				t.Fatal(err)
			}
			code = channelAdd([]string{"telegram", "--token-file", tokenFile, "--operator-user-id", "12345", "--chat-id", "67890", "--yes",
				"--config", configPath, "--credentials-dir", credDir}, scripted(), &stdout, &stderr)
		} else {
			code = channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir},
				scripted("tg-EQUIV", "n", "12345", "67890"), &stdout, &stderr)
		}
		if code != 0 {
			t.Fatalf("flags=%v exit=%d stderr=%s", flags, code, stderr.String())
		}
		assertNoLeak(t, &stdout, &stderr, "tg-EQUIV")
		tg := readTelegram(t, configPath)
		// The token path embeds the per-run temp dir; compare its base name.
		// The interactive flow prints the discovery offer banner before the
		// summary, so equivalence compares the final summary line, not the
		// whole stream.
		lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(stdout.String(), dir, "DIR")), "\n")
		section := filepath.Base(tg.TokenFile) + "|" +
			lines[len(lines)-1] + "|" +
			fmt.Sprint(tg.OperatorUserID, tg.ChatID, tg.ApprovalTTL.Value())
		return section, fileContent(t, filepath.Join(credDir, "telegram.token"))
	}
	interactiveSection, interactiveToken := run(false)
	flagsSection, flagsToken := run(true)
	if interactiveSection != flagsSection || interactiveToken != flagsToken {
		t.Fatalf("flag run diverged:\ninteractive %s %q\nflags %s %q", interactiveSection, interactiveToken, flagsSection, flagsToken)
	}
}

func TestChannelAddYesRequiresTokenFileWhenFresh(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--operator-user-id", "1", "--chat-id", "2", "--yes",
		"--config", configPath, "--credentials-dir", dir}, scripted(), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "--token-file") {
		t.Fatalf("exit=%d stderr=%s, want --token-file guidance (no secret in argv)", code, stderr.String())
	}
}

func TestChannelAddRequiresRoot(t *testing.T) {
	configPath, dir := onboardFixture(t, "", "")
	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", dir}, scripted(), &stdout, &stderr)
	if code != 125 || !strings.Contains(stderr.String(), "requires root") {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
}

func TestChannelListSanitized(t *testing.T) {
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(credDir, "telegram.token")
	configPath, _ = onboardFixtureIn(dir, "", `"token_file": "`+tokenPath+`", "operator_user_id": 12345, "chat_id": 67890`)
	if err := os.WriteFile(tokenPath, []byte("tg-LIST-SECRET\n"), 0640); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := channelList([]string{"--config", configPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"telegram", tokenPath, "(present)", "12345", "67890", "10m0s"} {
		if !strings.Contains(out, want) {
			t.Fatalf("channel list missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "tg-LIST-SECRET") {
		t.Fatal("channel list leaked the token")
	}
	// Empty section reports the not-yet-configured state.
	freshPath, _ := onboardFixture(t, "", "")
	stdout.Reset()
	if code := channelList([]string{"--config", freshPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stdout.String(), "no notification channels configured") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}
