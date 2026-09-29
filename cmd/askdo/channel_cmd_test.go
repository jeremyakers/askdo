package main

// channel_cmd_test.go — T9.5 e2e tests for `channel add telegram` /
// `channel list`: scripted-stdin flows, bad numeric re-prompting, token
// keep/replace semantics, non-interactive flag equivalence, and secret
// containment.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyakers/askdo/internal/config"
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

// namedTelegramFixture is a raw telegram object in the NEW named form with two
// channels (one shared group chat with several operator users), used to drive
// the named-aware list/add/route verbs. The %[2]s slot splices an optional
// routes object; %[1]s is the credentials directory.
const namedTelegramFixture = `"default_channel": "ops", "channels": [
	{"name": "alice", "token_file": "%[1]s/telegram-alice.token", "recipients": [{"chat_id": 11, "operator_user_ids": [111]}]},
	{"name": "ops", "token_file": "%[1]s/telegram-ops.token", "recipients": [
		{"chat_id": 21, "operator_user_ids": [111, 222]},
		{"chat_id": -100, "operator_user_ids": [111, 222, 333]}
	]}
]%[2]s, "approval_ttl": "10m"`

// namedFixturePath renders the named form into a fresh config file. routeLogin
// ("" = no routes object) must be a login real NSS can resolve, so a saved
// named config stays loadable by config.Load (route logins pin to UIDs at
// Load) — the test runner's own login always is.
func namedFixturePath(t *testing.T, credDir, routeLogin string) string {
	t.Helper()
	routes := ""
	if routeLogin != "" {
		routes = `, "routes": {"` + routeLogin + `": "ops"}`
	}
	configPath, _ := onboardFixtureIn(t.TempDir(), localModelEntry("ops-model", "openai_chat", "http://127.0.0.1:9/v1"), fmt.Sprintf(namedTelegramFixture, credDir, routes))
	return configPath
}

func namedFixture(t *testing.T, credDir string) string {
	t.Helper()
	return namedFixturePath(t, credDir, "")
}

// TestChannelListNamed shows each channel name with recipient/chat and operator
// user counts and the routes, without ever printing a token file's contents.
func TestChannelListNamed(t *testing.T) {
	stubCredentials(t)
	dir := t.TempDir()
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credDir, "telegram-alice.token"), []byte("tg-ALICE-SECRET\n"), 0640); err != nil {
		t.Fatal(err)
	}
	// ops token intentionally absent -> MISSING.
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	configPath := namedFixturePath(t, credDir, current.Username)

	var stdout, stderr bytes.Buffer
	if code := channelList([]string{"--config", configPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"channel: alice", "(default)", "channel: ops", // names, default marker
		"chats: 1", "operator users: 1", // alice private chat
		"chats: 2", "operator users: 3", // ops: the widest recipient (2+3+3 slots)
		"(present)", "(MISSING)", // token file state
		// Route logins are quoted for display, matching the existing
		// printExemptUsers precedent that keeps control characters inert.
		`route: "` + current.Username + `" -> "ops"`, // login route
		"approval_ttl: 10m0s",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("named channel list missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "tg-ALICE-SECRET") {
		t.Fatal("named channel list leaked a token value")
	}
	// A config with no routes object must say so without an empty section.
	noRoutes := namedFixture(t, credDir)
	stdout.Reset()
	if code := channelList([]string{"--config", noRoutes}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stdout.String(), "routes: none") {
		t.Fatalf("stdout=%s, want 'routes: none'", stdout.String())
	}
}

// TestChannelListNamedProgrammaticNoRouteLeak ensures a route login that
// resolves nowhere is still only displayed as a name, never as a secret.
func TestChannelAddNamedIntoLegacyConfigRefused(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	dir := t.TempDir()
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	configPath, _ := onboardFixtureIn(dir, "", `"token_file": "`+filepath.Join(credDir, "telegram.token")+`", "operator_user_id": 12345, "chat_id": 67890`)
	before := fileContent(t, configPath)
	tokenFile := filepath.Join(dir, "token.import")
	if err := os.WriteFile(tokenFile, []byte("tg-NAME\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	// Named add onto a legacy flat config must NOT silently mix the forms or
	// delete the legacy bot: it errors and instructs a manual config edit.
	code := channelAdd([]string{"telegram", "alice", "--token-file", tokenFile, "--operator-user-id", "111", "--chat-id", "1", "--yes",
		"--config", configPath, "--credentials-dir", credDir}, scripted(), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("named add onto legacy config succeeded; stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "legacy") || !strings.Contains(stderr.String(), "edit") {
		t.Fatalf("stderr=%s, want a clear legacy-migration config-edit error", stderr.String())
	}
	if fileContent(t, configPath) != before {
		t.Fatal("refused named add changed the config")
	}
	// No credential was written for the refused named channel.
	if _, err := os.Stat(filepath.Join(credDir, "telegram-alice.token")); !os.IsNotExist(err) {
		t.Fatal("refused named add wrote a channel token file")
	}
	assertNoLeak(t, &stdout, &stderr, "tg-NAME")
}

func TestChannelAddNamedFromUntouchedInstallerTemplate(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	dir := t.TempDir()
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile("../../askdo-config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, template, 0600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "newbot.token")
	if err := os.WriteFile(tokenFile, []byte("tg-NEW-TEMPLATE-BOT\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "ops", "--token-file", tokenFile, "--operator-user-id", "111", "--chat-id", "222", "--yes",
		"--config", configPath, "--credentials-dir", credDir}, scripted(), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("untouched installer template rejected named onboarding: exit=%d stderr=%s", code, stderr.String())
	}
	tg := readTelegram(t, configPath)
	if tg.DefaultChannel != "ops" || len(tg.Channels) != 1 || tg.Channels[0].Name != "ops" || tg.TokenFile != "" || tg.OperatorUserID != 0 || tg.ChatID != 0 {
		t.Fatalf("installer template did not become a named channel: %+v", tg)
	}
	if _, err := os.Stat(filepath.Join(credDir, "telegram-ops.token")); err != nil {
		t.Fatalf("named bot credential missing: %v", err)
	}
	assertNoLeak(t, &stdout, &stderr, "tg-NEW-TEMPLATE-BOT")
}

// TestChannelAddNamedFirstChannelBecomesDefault: adding to a fresh (un-
// configured) telegram section creates the named form and pins the first
// channel as the default, atomically and root-only.
func TestChannelAddNamedFirstChannelBecomesDefault(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "token.import")
	if err := os.WriteFile(tokenFile, []byte("tg-FIRST\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "alice", "--token-file", tokenFile, "--operator-user-id", "111", "--chat-id", "11", "--yes",
		"--config", configPath, "--credentials-dir", credDir}, scripted(), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	tg := readTelegram(t, configPath)
	if tg.DefaultChannel != "alice" {
		t.Fatalf("first named channel not made default: %+v", tg)
	}
	if len(tg.Channels) != 1 || tg.Channels[0].Name != "alice" ||
		tg.Channels[0].TokenFile != filepath.Join(credDir, "telegram-alice.token") {
		t.Fatalf("named channel wrong: %+v", tg.Channels)
	}
	if len(tg.Channels[0].Recipients) != 1 || tg.Channels[0].Recipients[0].ChatID != 11 ||
		len(tg.Channels[0].Recipients[0].OperatorUserIDs) != 1 || tg.Channels[0].Recipients[0].OperatorUserIDs[0] != 111 {
		t.Fatalf("named recipient wrong: %+v", tg.Channels[0].Recipients)
	}
	// The legacy flat fields must NOT be pinned alongside the named form.
	if tg.TokenFile != "" || tg.OperatorUserID != 0 || tg.ChatID != 0 {
		t.Fatalf("named add pinned legacy fields: %+v", tg)
	}
	if got := fileContent(t, filepath.Join(credDir, "telegram-alice.token")); got != "tg-FIRST\n" {
		t.Fatalf("token content %q", got)
	}
	assertNoLeak(t, &stdout, &stderr, "tg-FIRST")
}

// TestChannelAddNamedAppendsToExistingNamed: on an already-named config, a new
// NAME appends one channel + recipient, leaves the default and other channels
// intact, and refuses a duplicate name.
func TestChannelAddNamedAppendsToExistingNamed(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	dir := t.TempDir()
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	configPath := namedFixture(t, credDir)
	before := readTelegram(t, configPath)
	tokenFile := filepath.Join(dir, "token.import")
	if err := os.WriteFile(tokenFile, []byte("tg-BOB\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "bob", "--token-file", tokenFile, "--operator-user-id", "321", "--chat-id", "-100", "--yes",
		"--config", configPath, "--credentials-dir", credDir}, scripted(), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	tg := readTelegram(t, configPath)
	if tg.DefaultChannel != "ops" {
		t.Fatalf("default changed: %q", tg.DefaultChannel)
	}
	if len(tg.Channels) != 3 || tg.Channels[2].Name != "bob" {
		t.Fatalf("channel not appended: %+v", tg.Channels)
	}
	// The two pre-existing channels are untouched.
	if tg.Channels[0].Name != before.Channels[0].Name || tg.Channels[1].Name != before.Channels[1].Name {
		t.Fatal("named add disturbed existing channels")
	}
	if _, err := os.Stat(filepath.Join(credDir, "telegram-bob.token")); err != nil {
		t.Fatal("bob token not written", err)
	}

	// A duplicate name is refused without changing the config.
	dupBefore := fileContent(t, configPath)
	stdout.Reset()
	stderr.Reset()
	code = channelAdd([]string{"telegram", "bob", "--token-file", tokenFile, "--operator-user-id", "321", "--chat-id", "-100", "--yes",
		"--config", configPath, "--credentials-dir", credDir}, scripted(), &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "already") || fileContent(t, configPath) != dupBefore {
		t.Fatalf("duplicate named add exit=%d stderr=%s", code, stderr.String())
	}
}

// TestChannelAddNamedRequiresRootAndToken: named add is root-gated and, like the
// legacy wizard, never accepts a token in argv (only --token-file / hidden
// prompt), and there is no --token flag.
func TestChannelAddNamedRequiresRoot(t *testing.T) {
	dir := t.TempDir()
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	configPath := namedFixture(t, credDir)
	var stdout, stderr bytes.Buffer
	code := channelAdd([]string{"telegram", "bob", "--config", configPath, "--credentials-dir", credDir}, scripted(), &stdout, &stderr)
	if code != 125 || !strings.Contains(stderr.String(), "requires root") {
		t.Fatalf("nonroot named add exit=%d stderr=%s", code, stderr.String())
	}
	// --yes without a token on a channel that has none is refused (secret never
	// in argv).
	stubRoot(t)
	var s2 bytes.Buffer
	if code := channelAdd([]string{"telegram", "carol", "--operator-user-id", "1", "--chat-id", "1", "--yes",
		"--config", configPath, "--credentials-dir", credDir}, scripted(), &stdout, &s2); code == 0 ||
		!strings.Contains(s2.String(), "--token-file") {
		t.Fatalf("named --yes without token exit=%d stderr=%s", code, s2.String())
	}
}

// TestChannelAddNamedInteractive drives the named wizard over scripted stdin:
// hidden token prompt, chat ID, and a comma-separated operator-user list. The
// discovery offer must never appear (network use is legacy-wizard only), and
// the token value must never be echoed.
func TestChannelAddNamedInteractive(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	configPath, dir := onboardFixture(t, "", "")
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	// token, chat ID, operator user IDs (two admins).
	code := channelAdd([]string{"telegram", "ops", "--config", configPath, "--credentials-dir", credDir},
		scripted("tg-INTERACTIVE", "55", "777, 888"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	tg := readTelegram(t, configPath)
	if len(tg.Channels) != 1 || tg.Channels[0].Name != "ops" ||
		tg.Channels[0].Recipients[0].ChatID != 55 ||
		len(tg.Channels[0].Recipients[0].OperatorUserIDs) != 2 {
		t.Fatalf("interactive named add wrong: %+v", tg)
	}
	if got := fileContent(t, filepath.Join(credDir, "telegram-ops.token")); got != "tg-INTERACTIVE\n" {
		t.Fatalf("token content %q", got)
	}
	assertNoLeak(t, &stdout, &stderr, "tg-INTERACTIVE")
}

// TestChannelAddNamedRejectsUnsafeName: a NAME that is not a single path-safe
// component (it derives the token file name) is refused before any prompt or
// write.
func TestChannelAddNamedRejectsUnsafeName(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	dir := t.TempDir()
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	configPath := namedFixture(t, credDir)
	before := fileContent(t, configPath)
	for _, name := range []string{"../escape", "with/slash", " spaced"} {
		var stdout, stderr bytes.Buffer
		code := channelAdd([]string{"telegram", name, "--config", configPath, "--credentials-dir", credDir}, scripted(), &stdout, &stderr)
		if code == 0 || !strings.Contains(stderr.String(), "channel name") {
			t.Fatalf("unsafe name %q exit=%d stderr=%s", name, code, stderr.String())
		}
	}
	if fileContent(t, configPath) != before {
		t.Fatal("refused names changed the config")
	}
}

// TestChannelAddLegacyAgainstNamedRefused: the legacy wizard run against an
// already-named config refuses before any prompt or credential write, so the
// two forms never mix and the named channels are never disturbed.
func TestChannelAddLegacyAgainstNamedRefused(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	dir := t.TempDir()
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	configPath := namedFixture(t, credDir)
	before := fileContent(t, configPath)
	var stdout, stderr bytes.Buffer
	// Scripted input is deliberately empty: the verb must fail without ever
	// prompting (no secret prompt consumes a line).
	code := channelAdd([]string{"telegram", "--config", configPath, "--credentials-dir", credDir}, scripted(), &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "named") || fileContent(t, configPath) != before {
		t.Fatalf("legacy add against named config exit=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(credDir, "telegram.token")); !os.IsNotExist(err) {
		t.Fatal("refused legacy add wrote a flat token credential")
	}
}

func TestChannelRouteSet(t *testing.T) {
	stubCredentials(t)
	dir := t.TempDir()
	credDir := filepath.Join(dir, "credentials")
	if err := os.Mkdir(credDir, 0750); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"alice", "ops"} {
		if err := os.WriteFile(filepath.Join(credDir, "telegram-"+n+".token"), []byte("tk\n"), 0640); err != nil {
			t.Fatal(err)
		}
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	login := current.Username

	// Nonroot is refused.
	configPath := namedFixture(t, credDir)
	var stdout, stderr bytes.Buffer
	if code := channelRouteSet([]string{login, "alice", "--config", configPath}, &stdout, &stderr); code != 125 || !strings.Contains(stderr.String(), "requires root") {
		t.Fatalf("nonroot route set exit=%d stderr=%s", code, stderr.String())
	}

	stubRoot(t)
	// A login that NSS cannot resolve is refused and nothing is written.
	before := fileContent(t, configPath)
	stdout.Reset()
	stderr.Reset()
	if code := channelRouteSet([]string{"askdo-no-such-login-9713", "alice", "--config", configPath}, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "resolve") {
		t.Fatalf("unknown login exit=%d stderr=%s", code, stderr.String())
	}
	if fileContent(t, configPath) != before {
		t.Fatal("failed route set changed the config")
	}

	// A route to an unknown channel is refused (ValidateTelegramSection blocks
	// it) and nothing is written.
	stdout.Reset()
	stderr.Reset()
	if code := channelRouteSet([]string{login, "ghost", "--config", configPath}, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "unknown channel") {
		t.Fatalf("unknown channel exit=%d stderr=%s", code, stderr.String())
	}
	if fileContent(t, configPath) != before {
		t.Fatal("failed channel route set changed the config")
	}

	// A valid route set persists and the saved config still passes the whole-
	// file strict Load, and prints the new binding.
	stdout.Reset()
	stderr.Reset()
	if code := channelRouteSet([]string{login, "alice", "--config", configPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("valid route set exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `-> channel "alice"`) || !strings.Contains(stdout.String(), "(UID ") {
		t.Fatalf("route set summary missing UID+binding: %s", stdout.String())
	}
	tg := readTelegram(t, configPath)
	if tg.Routes[login] != "alice" {
		t.Fatalf("route not persisted: %v", tg.Routes)
	}
	// The named config remains strictly loadable and the existing alice->ops
	// route from the fixture is preserved alongside the new one.
	if _, err := config.Load(configPath); err != nil {
		t.Fatalf("route set broke the config for Load: %v", err)
	}

	// Legacy flat config: route verbs require the named form and must not mix.
	legacyPath, _ := onboardFixtureIn(t.TempDir(), "", `"token_file": "`+filepath.Join(credDir, "telegram-alice.token")+`", "operator_user_id": 1, "chat_id": 2`)
	legacyBefore := fileContent(t, legacyPath)
	stdout.Reset()
	stderr.Reset()
	if code := channelRouteSet([]string{login, "ops", "--config", legacyPath}, &stdout, &stderr); code == 0 ||
		!strings.Contains(stderr.String(), "named") || fileContent(t, legacyPath) != legacyBefore {
		t.Fatalf("legacy route set exit=%d stderr=%s", code, stderr.String())
	}
}

func TestChannelRouteSetAtCapacity(t *testing.T) {
	stubRoot(t)
	stubCredentials(t)
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		existing       bool
		invalidSibling bool
		wantError      string
	}{
		{name: "replace existing login", existing: true},
		{name: "refuse new login", wantError: "at most 128 logins"},
		{name: "replacement still validates section", existing: true, invalidSibling: true, wantError: "chat_id must be non-zero"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes := make(map[string]string, maxTelegramRoutes)
			// Only the target login needs real NSS resolution for this mutation.
			// Synthetic unrelated logins avoid creating 128 OS users; section
			// validation checks their shape and targets, not startup UID pinning.
			for i := 0; i < maxTelegramRoutes; i++ {
				login := fmt.Sprintf("askdo-route-capacity-fixture-%03d", i)
				if _, err := user.Lookup(login); err == nil {
					t.Fatalf("synthetic fixture login %q unexpectedly resolves", login)
				}
				routes[login] = "ops"
			}
			if tc.existing {
				delete(routes, "askdo-route-capacity-fixture-000")
				routes[current.Username] = "ops"
			}
			routeJSON, err := json.Marshal(routes)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			telegram := fmt.Sprintf(namedTelegramFixture, dir, `, "routes": `+string(routeJSON))
			if tc.invalidSibling {
				telegram = strings.Replace(telegram, `"chat_id": 11`, `"chat_id": 0`, 1)
			}
			// An unfinished review section must not block a telegram-only save.
			configPath, _ := onboardFixture(t, "", telegram)
			before := fileContent(t, configPath)
			wantTelegram := readTelegram(t, configPath)
			var stdout, stderr bytes.Buffer
			code := channelRouteSet([]string{current.Username, "alice", "--config", configPath}, &stdout, &stderr)
			if tc.wantError != "" {
				if code != 1 || !strings.Contains(stderr.String(), tc.wantError) || stdout.Len() != 0 {
					t.Fatalf("exit=%d stdout=%s stderr=%s, want refusal containing %q", code, stdout.String(), stderr.String(), tc.wantError)
				}
				if fileContent(t, configPath) != before {
					t.Fatal("refused route set changed the original config bytes")
				}
				return
			}
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("replacement at capacity exit=%d stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), fmt.Sprintf("login %q (UID %s) -> channel %q", current.Username, current.Uid, "alice")) {
				t.Fatalf("replacement summary missing: %s", stdout.String())
			}
			wantTelegram.Routes[current.Username] = "alice"
			got := readTelegram(t, configPath)
			if len(got.Routes) != maxTelegramRoutes || !reflect.DeepEqual(got, wantTelegram) {
				t.Fatalf("replacement changed route count or unrelated telegram settings: %+v", got)
			}
			if err := config.ValidateTelegramSection(got); err != nil {
				t.Fatalf("saved telegram section is invalid: %v", err)
			}
			if len(readModels(t, configPath)) != 0 {
				t.Fatal("telegram save changed the unfinished review section")
			}
			info, err := os.Stat(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatalf("saved config mode %04o, want 0600", info.Mode().Perm())
			}
		})
	}
}

func TestChannelDispatchUnknownAndRouteUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// A route subcommand without the required two positionals is a usage error.
	if code := runChannel([]string{"route", "set", "onlylogin", "--config", "/nope-askdo"}, nil, &stdout, &stderr); code != 125 {
		t.Fatalf("route set too few args exit=%d", code)
	}
	if code := runChannel([]string{"frobnicate"}, nil, &stdout, &stderr); code != 125 {
		t.Fatalf("unknown channel subcommand exit=%d", code)
	}
	if code := runChannel([]string{}, nil, &stdout, &stderr); code != 125 {
		t.Fatalf("empty channel args exit=%d", code)
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
