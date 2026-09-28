package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
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

// runAuth dispatches `askdo auth login|status|logout [openai-codex]`.
// openai-codex is the only provider; the positional argument is optional and
// must name it when present.
func runAuth(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: askdo auth login|status|logout [openai-codex] [--credentials-dir DIR]")
		return 125
	}
	sub := args[0]
	if sub != "login" && sub != "status" && sub != "logout" {
		fmt.Fprintf(stderr, "unknown auth subcommand %q\nusage: askdo auth login|status|logout [openai-codex] [--credentials-dir DIR]\n", sub)
		return 125
	}
	flags := flag.NewFlagSet("auth "+sub, flag.ContinueOnError)
	flags.SetOutput(stderr)
	credDir := flags.String("credentials-dir", defaultCredentialsDir, "directory holding the provider credential files")
	// Accept flags and the optional positional provider in any order (the
	// stdlib flag package alone stops at the first positional).
	var positional []string
	rest := args[1:]
	for {
		if flags.Parse(rest) != nil {
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
		fmt.Fprintln(stderr, "usage: askdo auth "+sub+" [openai-codex] [--credentials-dir DIR]")
		return 125
	}
	path := filepath.Join(*credDir, codexCredentialsFile)
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
	set, err := newCodexClient().Login(context.Background(), func(auth codexauth.DeviceAuth) {
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
	store, err := codexauth.Load(path)
	if err != nil && !codexauth.IsNotExist(err) {
		fmt.Fprintf(stderr, "auth logout: read credentials: %v (continuing with local removal)\n", err)
	}
	if store != nil && store.RefreshToken != "" {
		if err := newCodexClient().Revoke(context.Background(), store.RefreshToken); err != nil {
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
