package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/codexauth"
)

// defaultCredentialsDir holds the broker-only credential files, including the
// Codex OAuth token JSON written by `auth login`.
const defaultCredentialsDir = "/etc/askdo/credentials"

// codexCredentialsFile is the only auth provider credential v1 supports.
const codexCredentialsFile = "openai-codex.json"

// Test seams: the root check, issuer client construction, and credentials-dir
// validation are pinned by tests that cannot be root or reach auth.openai.com.
var (
	getEUID        = os.Geteuid
	newCodexClient = func() *codexauth.Client { return codexauth.NewClient() }
	checkCredDir   = validateCredentialsDir
)

const authUsage = "usage: askdo auth login|status|logout [openai-codex] [--config PATH] [--credentials-dir DIR] [--token-file PATH]"

// runAuth dispatches `askdo auth login|status|logout [openai-codex]`.
// openai-codex is the only provider; the positional argument is optional and
// must name it when present. Explicit help exits 0; usage errors exit 125.
func runAuth(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, authUsage)
		return 125
	}
	sub := args[0]
	if isHelpWord(sub) {
		writeAuthHelp(stdout)
		return 0
	}
	if sub != "login" && sub != "status" && sub != "logout" {
		fmt.Fprintf(stderr, "unknown auth subcommand %q\n%s\n", sub, authUsage)
		return 125
	}
	flags := flag.NewFlagSet("auth "+sub, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {} // help goes to stdout below; parse errors keep their message
	credDir := flags.String("credentials-dir", defaultCredentialsDir, "directory holding the provider credential files")
	tokenFile := flags.String("token-file", "", "explicit root-private Codex token path (central gateway credentials)")
	configPath := flags.String("config", "", "host or gateway configuration naming the openai_codex token file")
	// Accept flags and the optional positional provider in any order (the
	// stdlib flag package alone stops at the first positional).
	var positional []string
	rest := args[1:]
	for {
		if err := flags.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				writeAuthHelp(stdout)
				return 0
			}
			fmt.Fprintln(stderr, authUsage)
			return 125
		}
		rest = flags.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
	switch len(positional) {
	case 0:
	case 1:
		if positional[0] != "openai-codex" {
			fmt.Fprintf(stderr, "unknown auth provider %q (only openai-codex is supported)\n", positional[0])
			return 125
		}
	default:
		fmt.Fprintln(stderr, authUsage)
		return 125
	}
	explicitDir := false
	flags.Visit(func(f *flag.Flag) { explicitDir = explicitDir || f.Name == "credentials-dir" })
	path := filepath.Join(*credDir, codexCredentialsFile)
	switch {
	case *tokenFile != "":
		if !filepath.IsAbs(*tokenFile) || filepath.Clean(*tokenFile) != *tokenFile {
			fmt.Fprintln(stderr, "auth: --token-file must be an absolute clean path")
			return 125
		}
		if err := authTrustedDir(filepath.Dir(*tokenFile), false); err != nil {
			fmt.Fprintln(stderr, "auth: unsafe token parent:", err)
			return 125
		}
		path = *tokenFile
		*credDir = filepath.Dir(path)
	case explicitDir:
	default:
		// Root is checked before touching root-private configuration so an
		// unprivileged login gets the clear message, not a read error.
		if sub == "login" && getEUID() != 0 {
			return authLogin(path, *credDir, stdout, stderr)
		}
		var err error
		if path, *credDir, err = resolveCodexTarget(*configPath, *configPath != ""); err != nil {
			fmt.Fprintln(stderr, "auth:", err)
			return 125
		}
	}
	switch sub {
	case "login":
		return authLogin(path, *credDir, stdout, stderr)
	case "status":
		return authStatus(path, stdout, stderr)
	default: // logout
		return authLogout(path, stdout, stderr)
	}
}

// authLogin runs the device flow and writes the token set as root:root 0600.
// Root is required because the file holds the refresh token and must be
// readable by the broker alone — unlike worker-readable API key files.
func authLogin(path, credDir string, stdout, stderr io.Writer) int {
	if getEUID() != 0 {
		fmt.Fprintln(stderr, "auth login requires root: the credential file holds the OAuth refresh token and must be root:root 0600 (re-run with sudo)")
		return 125
	}
	// The directory is provisioning, not login: fail with the install
	// command rather than creating it with guessed ownership.
	if err := checkCredDir(credDir); err != nil {
		fmt.Fprintf(stderr, "credentials directory not ready: %v\ninstall it with:\n  install -d -m 0750 -o root -g askdo-review %s\n", err, credDir)
		return 125
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code := 1
	if err := codexauth.WithTokenLock(ctx, path, func() error { code = authLoginLocked(ctx, path, stdout, stderr); return nil }); err != nil {
		fmt.Fprintln(stderr, "auth login:", err)
		return 1
	}
	return code
}

func authLoginLocked(ctx context.Context, path string, stdout, stderr io.Writer) int {
	set, err := newCodexClient().Login(ctx, func(auth codexauth.DeviceAuth) {
		fmt.Fprintf(stdout, "\nTo authorize askdo with your ChatGPT account:\n\n  1. Open %s\n  2. Enter code:  %s\n\nWaiting for authorization (device code expires after 15 minutes)...\n", auth.VerificationURL, auth.UserCode)
	})
	if err != nil {
		fmt.Fprintln(stderr, "auth login:", err)
		return 1
	}
	if err := codexauth.NewStore(path, *set).Save(); err != nil {
		fmt.Fprintln(stderr, "auth login:", err)
		return 1
	}
	// Save already guarantees mode 0600; pin root:root ownership. In tests
	// the euid seam fakes root while the real uid is unprivileged, so the
	// chown is conditioned on the real euid.
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 0, 0); err != nil {
			fmt.Fprintf(stderr, "auth login: chown %s to root:root: %v\n", path, err)
			return 1
		}
	}
	fmt.Fprintf(stdout, "login ok: account %s\ncredentials: %s (root:root 0600)\n", set.AccountID, path)
	return 0
}

// authStatus reports account ID, access-token expiry, last refresh, and file
// presence. It NEVER prints token material.
func authStatus(path string, stdout, stderr io.Writer) int {
	store, err := codexauth.Load(path)
	if codexauth.IsNotExist(err) {
		fmt.Fprintf(stdout, "openai-codex: not logged in (no credential file at %s)\n", path)
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "auth status: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "provider:      openai-codex\n")
	fmt.Fprintf(stdout, "account:       %s\n", store.AccountID)
	if store.RefreshPending {
		fmt.Fprintln(stdout, "refresh:       previous outcome uncertain; re-login required")
	}
	if expiry, err := codexauth.AccessTokenExpiry(store.AccessToken); err != nil {
		fmt.Fprintf(stdout, "access token:  expiry unknown (%v)\n", err)
	} else {
		state := "valid"
		if !expiry.After(time.Now()) {
			state = "expired"
		} else if !expiry.After(time.Now().Add(codexauth.RefreshWindow)) {
			state = "expiring soon (inside the refresh window)"
		}
		fmt.Fprintf(stdout, "access token:  expires %s (%s)\n", expiry.Format(time.RFC3339), state)
	}
	fmt.Fprintf(stdout, "last refresh:  %s\n", store.LastRefresh.UTC().Format(time.RFC3339))
	fmt.Fprintf(stdout, "credential:    %s\n", path)
	return 0
}

// authLogout revokes the refresh token best-effort and removes the credential
// file. Revocation failure is a warning; local logout proceeds regardless.
func authLogout(path string, stdout, stderr io.Writer) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code := 1
	if err := codexauth.WithTokenLock(ctx, path, func() error { code = authLogoutLocked(ctx, path, stdout, stderr); return nil }); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stdout, "openai-codex: already logged out (no credential file at %s)\n", path)
			return 0
		}
		fmt.Fprintln(stderr, "auth logout:", err)
		return 1
	}
	return code
}

func authLogoutLocked(ctx context.Context, path string, stdout, stderr io.Writer) int {
	store, err := codexauth.Load(path)
	if err != nil && !codexauth.IsNotExist(err) {
		fmt.Fprintf(stderr, "auth logout: read credentials: %v (continuing with local removal)\n", err)
	}
	if store != nil && store.RefreshToken != "" {
		if err := newCodexClient().Revoke(ctx, store.RefreshToken); err != nil {
			fmt.Fprintf(stderr, "warning: token revocation failed (continuing): %v\n", err)
		}
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stdout, "openai-codex: already logged out (no credential file at %s)\n", path)
			return 0
		}
		fmt.Fprintf(stderr, "auth logout: remove %s: %v\n", path, err)
		return 1
	}
	fmt.Fprintf(stdout, "openai-codex: logged out; removed %s\n", path)
	return 0
}

// validateCredentialsDir enforces the provisioned shape of the credentials
// directory: an existing directory, owned by root, with no access for other
// users. `auth login` refuses to create it — it must be provisioned with the
// documented install command so ownership and mode are deliberate.
func validateCredentialsDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine ownership of %s", dir)
	}
	if st.Uid != 0 {
		return fmt.Errorf("%s must be owned by root", dir)
	}
	if perm := info.Mode().Perm(); perm&0007 != 0 {
		return fmt.Errorf("%s must not be accessible by other users (mode %04o)", dir, perm)
	}
	return nil
}
