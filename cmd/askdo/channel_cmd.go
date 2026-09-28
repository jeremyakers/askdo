package main

// channel_cmd.go — `askdo channel add telegram` and `channel list`.
// The channel namespace is the seam for future notification backends;
// telegram is the only one in v1.
//
// Re-running `channel add telegram` against an existing section is an edit:
// prompts show current values as defaults, an empty token answer keeps the
// existing token file, and a new token atomically replaces the file — it is
// never deleted without a valid replacement.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyakers/askdo/internal/operator"
	"github.com/jeremyakers/askdo/internal/prompt"
)

// telegramTokenFile is the conventional credential file name for the bot
// token inside the credentials directory.
const telegramTokenFile = "telegram.token"

// runChannel routes `askdo channel <subcommand>`.
func runChannel(args []string, r prompt.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: askdo channel add telegram | list")
		return 125
	}
	switch args[0] {
	case "add":
		return channelAdd(args[1:], r, stdout, stderr)
	case "list":
		return channelList(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown channel subcommand %q\nusage: askdo channel add telegram | list\n", args[0])
		return 125
	}
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
	if len(positional) != 1 || positional[0] != "telegram" {
		fmt.Fprintln(stderr, "usage: askdo channel add telegram [flags]")
		return 125
	}
	if !requireRoot("channel add", stderr) {
		return 125
	}
	store, err := operator.LoadForMutation(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "channel add:", err)
		return 1
	}
	cfg := store.Config()
	tokenPath := filepath.Join(*credDir, telegramTokenFile)
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
	case *tokenFile != "":
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(stderr, "channel add: read --token-file: %v\n", err)
			return 1
		}
		if strings.TrimSpace(string(data)) == "" {
			fmt.Fprintln(stderr, "channel add: --token-file is empty")
			return 1
		}
		tokenData = data
	case *yes:
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
	if !*yes && *operatorUserID == 0 && *chatID == 0 && !existing {
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
		userID, err = channelIDField(p, stderr, *yes, *operatorUserID, cfg.Telegram.OperatorUserID, existing,
			"Operator Telegram user ID", "--operator-user-id", func(v int64) bool { return v > 0 }, "must be a positive number (your numeric Telegram user ID, e.g. from @userinfobot)")
		if err != nil {
			return wizardError("channel add", err, stderr)
		}
	}
	if chat == 0 {
		var err error
		chat, err = channelIDField(p, stderr, *yes, *chatID, cfg.Telegram.ChatID, existing,
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
