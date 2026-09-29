package main

// channel_cmd.go — `askdo channel add telegram [NAME]`, `channel list`, and
// `channel route set`. The channel namespace is the seam for future
// notification backends; telegram is the only one in v1.
//
// Re-running `channel add telegram` against an existing legacy flat section is
// an edit: prompts show current values as defaults, an empty token answer
// keeps the existing token file, and a new token atomically replaces the file
// — it is never deleted without a valid replacement.
//
// The named multi-channel form (config `default_channel` + `channels[]` +
// `routes{}`) is managed with `channel add telegram NAME` (append one bot and
// one recipient via the same credential wizard) and `channel route set LOGIN
// CHANNEL`. A named form and a legacy flat form never mix: adding a NAME onto
// a legacy config is refused with an explicit manual-edit instruction rather
// than silently migrating (which would drop the existing bot). `channel list`
// shows either form's structure (names, chat/operator-user counts, routes) and
// never prints any token value.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/operator"
	"github.com/jeremyakers/askdo/internal/prompt"
)

// telegramTokenFile is the conventional credential file name for the bot
// token inside the credentials directory.
const telegramTokenFile = "telegram.token"

const channelUsage = "usage: askdo channel add telegram [NAME] [flags] | list | route set LOGIN CHANNEL"

// runChannel routes `askdo channel <subcommand>`.
func runChannel(args []string, r prompt.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, channelUsage)
		return 125
	}
	switch args[0] {
	case "add":
		return channelAdd(args[1:], r, stdout, stderr)
	case "list":
		return channelList(args[1:], stdout, stderr)
	case "route":
		if len(args) < 2 || args[1] != "set" {
			fmt.Fprintf(stderr, "unknown channel route subcommand %q\n%s\n", safeSubcommand(args, 1), channelUsage)
			return 125
		}
		return channelRouteSet(args[2:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown channel subcommand %q\n%s\n", args[0], channelUsage)
		return 125
	}
}

// safeSubcommand reports args[i] when present, so dispatch errors never index
// past the end of argv.
func safeSubcommand(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

func channelAdd(args []string, r prompt.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("channel add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	credDir := fs.String("credentials-dir", defaultCredentialsDir, "credential directory")
	tokenFile := fs.String("token-file", "", "import the bot token from this file (secrets never travel in argv; there is no --token flag)")
	operatorUserID := fs.Int64("operator-user-id", 0, "numeric Telegram user ID allowed to decide")
	chatID := fs.Int64("chat-id", 0, "private Telegram chat ID for approval cards")
	yes := fs.Bool("yes", false, "non-interactive: required values must come from flags; an existing token is kept")
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return 125
	}
	// positional[0] is "telegram"; an optional positional[1] is a channel NAME
	// that selects the named multi-bot form instead of the legacy flat section.
	if len(positional) < 1 || len(positional) > 2 || positional[0] != "telegram" {
		fmt.Fprintln(stderr, "usage: askdo channel add telegram [NAME] [flags]")
		return 125
	}
	name := ""
	if len(positional) == 2 {
		name = positional[1]
	}
	if !requireRoot("channel add", stderr) {
		return 125
	}
	store, err := operator.LoadForMutation(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "channel add:", err)
		return 1
	}
	if name != "" {
		return channelAddNamed(name, store, *configPath, *credDir, *tokenFile, *operatorUserID, *chatID, *yes, r, stdout, stderr)
	}
	return channelAddLegacy(store, *configPath, *credDir, *tokenFile, *operatorUserID, *chatID, *yes, r, stdout, stderr)
}

// channelAddLegacy is the original `channel add telegram` edit wizard over the
// flat token_file/operator_user_id/chat_id section. It refuses to run against
// a named-form config so the two forms never mix.
func channelAddLegacy(store *operator.ConfigStore, configPath, credDir, tokenFile string, operatorUserID, chatID int64, yes bool, r prompt.Reader, stdout, stderr io.Writer) int {
	cfg := store.Config()
	if telegramIsNamed(cfg.Telegram) {
		fmt.Fprintln(stderr, "channel add telegram: this config uses the named channels form; add another bot with `askdo channel add telegram NAME` (edit the named section for the default/routing)")
		return 1
	}
	tokenPath := filepath.Join(credDir, telegramTokenFile)
	if cfg.Telegram.TokenFile != "" {
		// Preserve a previously configured (possibly non-default) path.
		tokenPath = cfg.Telegram.TokenFile
	}
	info, tokenErr := os.Stat(tokenPath)
	hasToken := tokenErr == nil && info.Mode().IsRegular()
	// The example config names a token file but leaves both IDs at zero.
	// It is not an existing channel: offer discovery once a token is entered.
	existing := hasToken && cfg.Telegram.OperatorUserID > 0 && cfg.Telegram.ChatID != 0
	p := prompt.New(r, stderr)

	// Token: --token-file import, keep on empty answer against an existing
	// section, else a hidden prompt. The token value is never echoed.
	var tokenData []byte
	switch {
	case tokenFile != "":
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			fmt.Fprintf(stderr, "channel add: read --token-file: %v\n", err)
			return 1
		}
		if strings.TrimSpace(string(data)) == "" {
			fmt.Fprintln(stderr, "channel add: --token-file is empty")
			return 1
		}
		tokenData = data
	case yes:
		if !hasToken {
			fmt.Fprintln(stderr, "channel add: --token-file is required with --yes when no token is configured yet (secrets never travel in argv)")
			return 1
		}
	default:
		secret, err := p.Secret("Telegram bot token (input hidden; empty keeps the existing token)", hasToken)
		if err != nil {
			return wizardError("channel add", err, stderr)
		}
		if secret != "" {
			tokenData = []byte(secret + "\n")
		}
	}

	userID, chat := int64(0), int64(0)
	// Auto-discovery is offered only for a fresh interactive setup with no
	// explicit ID flags: --yes, explicit --operator-user-id/--chat-id, and
	// re-runs against an existing telegram section never call the API.
	if !yes && operatorUserID == 0 && chatID == 0 && !existing {
		ids, confirmed, err := offerTelegramDiscovery(tokenData, tokenPath, p, stdout)
		if err != nil {
			return wizardError("channel add", err, stderr)
		}
		if confirmed {
			userID, chat = ids.userID, ids.chatID
		}
	}
	if userID == 0 {
		var err error
		userID, err = channelIDField(p, stderr, yes, operatorUserID, cfg.Telegram.OperatorUserID, existing,
			"Operator Telegram user ID", "--operator-user-id", func(v int64) bool { return v > 0 }, "must be a positive number (your numeric Telegram user ID, e.g. from @userinfobot)")
		if err != nil {
			return wizardError("channel add", err, stderr)
		}
	}
	if chat == 0 {
		var err error
		chat, err = channelIDField(p, stderr, yes, chatID, cfg.Telegram.ChatID, existing,
			"Telegram chat ID", "--chat-id", func(v int64) bool { return v != 0 }, "must be a non-zero number (the private chat with the bot)")
		if err != nil {
			return wizardError("channel add", err, stderr)
		}
	}

	// Commit: credential first (section validation stats token_file), the
	// config write last; a failed save removes a token file this run created.
	commit := new(operator.Commit)
	if tokenData != nil {
		_, statErr := os.Stat(tokenPath)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			fmt.Fprintf(stderr, "channel add: stat %s: %v\n", tokenPath, statErr)
			return 1
		}
		if err := commit.WriteCredential(filepath.Dir(tokenPath), filepath.Base(tokenPath), tokenData, operator.CredentialKey, statErr == nil); err != nil {
			fmt.Fprintf(stderr, "channel add: write token file: %v\n", err)
			return 1
		}
	}
	cfg.Telegram.TokenFile = tokenPath
	cfg.Telegram.OperatorUserID = userID
	cfg.Telegram.ChatID = chat
	if err := store.Save(operator.SectionTelegram); err != nil {
		_ = commit.Rollback()
		fmt.Fprintf(stderr, "channel add: save config: %v\n(the config was not written)\n", err)
		return 1
	}
	commit.Success()
	tokenState := "unchanged"
	if tokenData != nil {
		tokenState = "updated"
	}
	fmt.Fprintf(stdout, "telegram channel configured: token file %s (%s), operator_user_id %d, chat_id %d\n", tokenPath, tokenState, userID, chat)
	return 0
}

// channelAddNamed appends one bot + recipient (a channel NAME) to the named
// multi-channel form using the same credential wizard. On a fresh config it
// starts the named form with this channel as the default. It never writes to
// a legacy flat config: that case is refused before any prompt so an
// in-flight bot is never dropped.
func channelAddNamed(name string, store *operator.ConfigStore, configPath, credDir, tokenFile string, operatorUserID, chatID int64, yes bool, r prompt.Reader, stdout, stderr io.Writer) int {
	tg := &store.Config().Telegram
	if err := validateChannelName(name); err != nil {
		fmt.Fprintf(stderr, "channel add telegram %s: %v\n", name, err)
		return 1
	}
	// Mixed-form guard: a named add never silently mutates a legacy config, and
	// a legacy config is never dropped/replaced without the operator's edit.
	if !telegramIsNamed(*tg) && legacyTgConfigured(*tg) && !untouchedStarterTelegram(*tg) {
		fmt.Fprintf(stderr, "channel add telegram %s: this config uses the legacy single-bot form (token_file/operator_user_id/chat_id).\n"+
			"Migrating to named channels would drop the existing bot, so it is not done automatically.\n"+
			"To add this channel, edit %s by hand: move the legacy token_file/operator_user_id/chat_id into a telegram.channels entry, set telegram.default_channel, then re-run this command.\n"+
			"(The config was not written.)\n", name, configPath)
		return 1
	}
	for _, existing := range tg.Channels {
		if existing.Name == name {
			fmt.Fprintf(stderr, "channel add telegram %s: a channel with this name already exists (channel add never overwrites a bot; edit %s to change it)\n", name, configPath)
			return 1
		}
	}
	if len(tg.Channels) >= maxTelegramChannels {
		fmt.Fprintf(stderr, "channel add telegram %s: the named form holds at most %d channels (edit %s to replace one)\n", name, maxTelegramChannels, configPath)
		return 1
	}
	tokenPath := filepath.Join(credDir, "telegram-"+name+".token")
	p := prompt.New(r, stderr)

	// Token: --token-file import, or a hidden prompt that never echoes. A new
	// channel always needs a token, so an empty answer is not accepted, and
	// --yes without --token-file is refused (secrets never travel in argv).
	var tokenData []byte
	switch {
	case tokenFile != "":
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			fmt.Fprintf(stderr, "channel add telegram %s: read --token-file: %v\n", name, err)
			return 1
		}
		if strings.TrimSpace(string(data)) == "" {
			fmt.Fprintf(stderr, "channel add telegram %s: --token-file is empty\n", name)
			return 1
		}
		tokenData = data
	case yes:
		if _, err := os.Stat(tokenPath); err != nil {
			fmt.Fprintf(stderr, "channel add telegram %s: --token-file is required with --yes when the channel has no token yet (secrets never travel in argv)\n", name)
			return 1
		}
	default:
		secret, err := p.Secret(fmt.Sprintf("Telegram bot token for channel %q (input hidden)", name), false)
		if err != nil {
			return wizardError("channel add telegram "+name, err, stderr)
		}
		tokenData = []byte(secret + "\n")
	}

	// Chat: the flag wins; --yes requires it; interactive prompts once. Auto
	// discovery is legacy-wizard only — a named add never touches the network.
	chat := chatID
	if chat == 0 {
		if yes {
			fmt.Fprintln(stderr, "channel add telegram: --chat-id is required with --yes for a named channel")
			return 1
		}
		var err error
		chat, err = channelIDField(p, stderr, false, 0, 0, false,
			fmt.Sprintf("Telegram chat ID for channel %q", name), "--chat-id",
			func(v int64) bool { return v != 0 }, "must be a non-zero number (the private chat with the bot, or a group chat ID)")
		if err != nil {
			return wizardError("channel add telegram "+name, err, stderr)
		}
	}

	// Operators: one or more numeric user IDs allowed to decide in that chat.
	// An explicit --operator-user-id is the whole list (the flag wins, exactly
	// as in the legacy wizard); interactive mode prompts for the list; --yes
	// without the flag is refused.
	operators := []int64(nil)
	if operatorUserID != 0 {
		operators = []int64{operatorUserID}
	} else if yes {
		fmt.Fprintln(stderr, "channel add telegram: --operator-user-id is required with --yes for a named channel")
		return 1
	} else {
		var err error
		operators, err = channelOperatorIDs(p, name, stderr)
		if err != nil {
			return wizardError("channel add telegram "+name, err, stderr)
		}
	}

	// Commit: credential first (section validation stats the channel token
	// file), the config write last; a failed save removes a token this run
	// created and leaves the config untouched.
	commit := new(operator.Commit)
	if tokenData != nil {
		_, statErr := os.Stat(tokenPath)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			fmt.Fprintf(stderr, "channel add telegram %s: stat %s: %v\n", name, tokenPath, statErr)
			return 1
		}
		if err := commit.WriteCredential(filepath.Dir(tokenPath), filepath.Base(tokenPath), tokenData, operator.CredentialKey, statErr == nil); err != nil {
			fmt.Fprintf(stderr, "channel add telegram %s: write token file: %v\n", name, err)
			return 1
		}
	}
	// The shipped template names a token path but has no valid recipient. It
	// cannot be a working legacy bot; replacing its placeholder leaves any
	// credential file untouched and lets a new install choose the named form.
	if untouchedStarterTelegram(*tg) {
		tg.TokenFile = ""
	}
	tg.Channels = append(tg.Channels, config.TelegramChannel{
		Name:       name,
		TokenFile:  tokenPath,
		Recipients: []config.TelegramRecipient{{ChatID: chat, OperatorUserIDs: operators}},
	})
	if tg.DefaultChannel == "" {
		// The first named channel is necessarily the default; the strict
		// decoder requires one and never guesses a precedence.
		tg.DefaultChannel = name
	}
	if err := store.Save(operator.SectionTelegram); err != nil {
		_ = commit.Rollback()
		fmt.Fprintf(stderr, "channel add telegram %s: save config: %v\n(the config was not written)\n", name, err)
		return 1
	}
	commit.Success()
	tokenState := "kept"
	if tokenData != nil {
		tokenState = "written"
	}
	fmt.Fprintf(stdout, "telegram channel %q configured: token file %s (%s), chat_id %d, %d operator user(s); default channel %q (routes are managed with `askdo channel route set LOGIN CHANNEL` or by editing %s)\n",
		name, tokenPath, tokenState, chat, len(operators), tg.DefaultChannel, configPath)
	return 0
}

// maxTelegramChannels mirrors config.ValidateTelegramSection's channel bound so
// the CLI refuses an 9th channel with a clear message instead of a validation
// dump.
const maxTelegramChannels = 8

// validateChannelName enforces the same name rules the config validator does:
// non-empty, no surrounding whitespace, at most 128 bytes. It also refuses a
// name that could not be a credential base name, since the token file is
// derived from it.
func validateChannelName(name string) error {
	if name == "" || strings.TrimSpace(name) != name || len(name) > 128 {
		return errors.New("channel name must be non-empty, free of surrounding whitespace, and at most 128 characters")
	}
	if strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return errors.New("channel name must be a single path-safe component (it names the bot token file)")
	}
	return nil
}

// telegramIsNamed reports whether the section is already in the named form.
func telegramIsNamed(tg config.TelegramConfig) bool {
	return len(tg.Channels) != 0 || tg.DefaultChannel != "" || tg.Routes != nil
}

// legacyTgConfigured reports whether the legacy flat fields carry any value,
// i.e. whether a real single-bot config is present to protect.
func legacyTgConfigured(tg config.TelegramConfig) bool {
	return tg.TokenFile != "" || tg.OperatorUserID != 0 || tg.ChatID != 0
}

func untouchedStarterTelegram(tg config.TelegramConfig) bool {
	return tg.TokenFile == "/etc/askdo/credentials/telegram.token" && tg.OperatorUserID == 0 && tg.ChatID == 0
}

// channelOperatorIDs prompts for the comma-separated numeric Telegram user IDs
// allowed to decide in a named channel's chat, re-prompting (with the reason
// on stderr) until every token parses as a positive ID and the list fits the
// config's 1..8 bound.
func channelOperatorIDs(p *prompt.Prompt, name string, stderr io.Writer) ([]int64, error) {
	label := fmt.Sprintf("Operator Telegram user IDs for channel %q (comma-separated, each positive, e.g. from @userinfobot)", name)
	for {
		answer, err := p.Text(label, "")
		if err != nil {
			return nil, err
		}
		ids, err := parseOperatorIDs(answer)
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			continue
		}
		return ids, nil
	}
}

// parseOperatorIDs splits a comma-separated list of positive Telegram user IDs,
// rejecting duplicates and an empty or over-long list.
func parseOperatorIDs(answer string) ([]int64, error) {
	fields := strings.Split(answer, ",")
	ids := make([]int64, 0, len(fields))
	seen := make(map[int64]struct{}, len(fields))
	for _, field := range fields {
		id, err := strconv.ParseInt(strings.TrimSpace(field), 10, 64)
		if err != nil || id <= 0 {
			return nil, errors.New("every operator user ID must be a positive number (your numeric Telegram user ID, e.g. from @userinfobot)")
		}
		if _, exists := seen[id]; exists {
			return nil, errors.New("operator user IDs must be distinct")
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) > maxTelegramOperators {
		return nil, fmt.Errorf("a chat authorizes at most %d operator users", maxTelegramOperators)
	}
	return ids, nil
}

// maxTelegramOperators mirrors config.ValidateTelegramSection's per-recipient
// operator-user bound.
const maxTelegramOperators = 8

// channelRouteSet implements `askdo channel route set LOGIN CHANNEL`: a
// root-only atomic mutation of telegram.routes validated through the same
// login→UID resolution and section validation the daemon uses at startup. The
// submitter never chooses a route; only the root-owned config does.
func channelRouteSet(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("channel route set", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return 125
	}
	if len(positional) != 2 {
		fmt.Fprintln(stderr, "usage: askdo channel route set LOGIN CHANNEL [--config PATH]")
		return 125
	}
	login, channel := positional[0], positional[1]
	if !requireRoot("channel route set", stderr) {
		return 125
	}
	store, err := operator.LoadForMutation(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "channel route set:", err)
		return 1
	}
	tg := &store.Config().Telegram
	if !telegramIsNamed(*tg) {
		fmt.Fprintln(stderr, "channel route set: per-user routing needs the named channels form (telegram.channels plus telegram.default_channel); the legacy single-bot config routes every UID to that one bot — edit the config to name channels first")
		return 1
	}
	if login == "" || strings.TrimSpace(login) != login {
		fmt.Fprintln(stderr, "channel route set: login must be a plain OS user name (a numeric UID is rejected)")
		return 1
	}
	// Resolve the login exactly as Load pins routes to UIDs, so an unresolvable
	// name fails here instead of at daemon startup.
	account, err := user.Lookup(login)
	if err != nil {
		fmt.Fprintf(stderr, "channel route set: resolve login %q: %v\n(the config was not written)\n", login, err)
		return 1
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		fmt.Fprintf(stderr, "channel route set: invalid UID %q for login %q\n(the config was not written)\n", account.Uid, login)
		return 1
	}
	known := false
	for _, existing := range tg.Channels {
		if existing.Name == channel {
			known = true
			break
		}
	}
	if !known {
		fmt.Fprintf(stderr, "channel route set: %q names an unknown channel (add it with `askdo channel add telegram %s` first)\n(the config was not written)\n", channel, channel)
		return 1
	}
	if tg.Routes == nil {
		tg.Routes = map[string]string{}
	}
	if _, exists := tg.Routes[login]; !exists && len(tg.Routes) >= maxTelegramRoutes {
		fmt.Fprintf(stderr, "channel route set: telegram.routes holds at most %d logins (edit the config to replace one)\n", maxTelegramRoutes)
		return 1
	}
	// A second login resolving to this UID would be an ambiguous route; reject
	// it the same way Load does, before writing anything.
	for existing := range tg.Routes {
		if existing == login {
			continue
		}
		if account, err := user.Lookup(existing); err == nil && account.Uid == strconv.FormatUint(uid, 10) {
			fmt.Fprintf(stderr, "channel route set: logins %q and %q both resolve to UID %d (routes must be unique per UID)\n(the config was not written)\n", existing, login, uid)
			return 1
		}
	}
	tg.Routes[login] = channel
	if err := store.Save(operator.SectionTelegram); err != nil {
		fmt.Fprintf(stderr, "channel route set: config not written: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "telegram route set: login %q (UID %d) -> channel %q\n", login, uid, channel)
	return 0
}

// maxTelegramRoutes mirrors config.ValidateTelegramSection's route bound.
const maxTelegramRoutes = 128

// channelIDField resolves one numeric telegram field: the flag wins; --yes
// keeps the existing value or fails; interactive mode prompts with the
// current value as default and re-prompts until valid.
func channelIDField(p *prompt.Prompt, stderr io.Writer, yes bool, flagVal, existingVal int64, existing bool, label, flagName string, valid func(int64) bool, hint string) (int64, error) {
	if flagVal != 0 {
		if !valid(flagVal) {
			return 0, fmt.Errorf("%s %d %s", flagName, flagVal, hint)
		}
		return flagVal, nil
	}
	if yes {
		if existing && valid(existingVal) {
			return existingVal, nil
		}
		return 0, fmt.Errorf("%s is required with --yes", flagName)
	}
	def := existingVal
	if !existing {
		def = 0
	}
	for {
		value, err := p.Int(label, int(def))
		if err != nil {
			return 0, err
		}
		if valid(int64(value)) {
			return int64(value), nil
		}
		fmt.Fprintf(stderr, "%s\n", hint)
	}
}

func channelList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("channel list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "configuration file")
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return 125
	}
	if len(positional) != 0 {
		fmt.Fprintln(stderr, "usage: askdo channel list")
		return 125
	}
	store, err := operator.LoadForMutation(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "channel list:", err)
		return 1
	}
	tg := store.Config().Telegram
	if telegramIsNamed(tg) {
		return channelListNamed(tg, stdout)
	}
	if tg.TokenFile == "" {
		fmt.Fprintln(stdout, "no notification channels configured (use `askdo channel add telegram`)")
		return 0
	}
	state := "present"
	if _, err := os.Stat(tg.TokenFile); err != nil {
		state = "MISSING"
	}
	fmt.Fprintln(stdout, "channel: telegram")
	fmt.Fprintf(stdout, "  token file:       %s (%s)\n", tg.TokenFile, state)
	fmt.Fprintf(stdout, "  operator_user_id: %d\n", tg.OperatorUserID)
	fmt.Fprintf(stdout, "  chat_id:          %d\n", tg.ChatID)
	fmt.Fprintf(stdout, "  approval_ttl:     %s\n", tg.ApprovalTTL.Value())
	return 0
}

// channelListNamed renders the named multi-channel form: one block per channel
// with its token-file state and recipient/chat/operator-user counts, plus the
// login→channel routes. Token values are never read or printed; the legacy
// flat form keeps its original output shape.
func channelListNamed(tg config.TelegramConfig, stdout io.Writer) int {
	for _, channel := range tg.Channels {
		suffix := ""
		if channel.Name == tg.DefaultChannel {
			suffix = " (default)"
		}
		fmt.Fprintf(stdout, "channel: %s%s\n", channel.Name, suffix)
		state := "present"
		if _, err := os.Stat(channel.TokenFile); err != nil {
			state = "MISSING"
		}
		fmt.Fprintf(stdout, "  token file: %s (%s)\n", channel.TokenFile, state)
		users := make(map[int64]struct{})
		for _, recipient := range channel.Recipients {
			for _, id := range recipient.OperatorUserIDs {
				users[id] = struct{}{}
			}
		}
		fmt.Fprintf(stdout, "  chats: %d, operator users: %d\n", len(channel.Recipients), len(users))
		for _, recipient := range channel.Recipients {
			fmt.Fprintf(stdout, "  chat %d: %d operator user(s)\n", recipient.ChatID, len(recipient.OperatorUserIDs))
		}
		ttl := channel.ApprovalTTL
		if ttl.Value() != 0 {
			fmt.Fprintf(stdout, "  approval_ttl: %s\n", ttl.Value())
		}
	}
	if len(tg.Routes) == 0 {
		fmt.Fprintln(stdout, "routes: none")
	} else {
		fmt.Fprintln(stdout, "routes:")
		logins := make([]string, 0, len(tg.Routes))
		for login := range tg.Routes {
			logins = append(logins, login)
		}
		sort.Strings(logins)
		for _, login := range logins {
			// Logins and channel names are operator-owned strings: %q quotes
			// anything control-character-ish instead of letting it reach a
			// terminal raw.
			fmt.Fprintf(stdout, "  route: %s -> %s\n", strconv.Quote(login), strconv.Quote(tg.Routes[login]))
		}
	}
	fmt.Fprintf(stdout, "approval_ttl: %s\n", tg.ApprovalTTL.Value())
	return 0
}
