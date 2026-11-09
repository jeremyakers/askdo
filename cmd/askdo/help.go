package main

import (
	"fmt"
	"io"
)

// topHelpRequested reports whether args is exactly a top-level help request.
// Only a lone leading help word qualifies: a command's own argv (after the
// runner flags or a `--`) is never inspected.
func topHelpRequested(args []string) bool {
	return len(args) == 1 && isHelpWord(args[0])
}

func isHelpWord(arg string) bool {
	return arg == "--help" || arg == "-h" || arg == "help"
}

func writeTopHelp(w io.Writer) {
	fmt.Fprint(w, `usage: askdo [-u USER] [-k] [-n] [--reason TEXT] [--timeout DURATION] [--detach] [--review=yes] [--verbose] COMMAND [ARG...]
       askdo [-u USER] [-k] [-n] (-s | -i) [--reason TEXT] [--] [COMMAND [ARG...]]
       askdo [-u USER] [-k] [-n] -v
       askdo -k
       askdo -K
       askdo [-u USER] -l
       askdo [--reason TEXT] --bundle DIR --entry FILE [--bundle-include-sensitive FILE]... [--] [ARG...]
       askdo [--reason TEXT] --script PATH [--bundle-include-sensitive FILE] [--] [ARG...]
       askdo status|attach JOB_ID
       askdo cancel --handle-file PATH [--force]
       askdo cancel JOB_ID                 legacy jobs, before dispatch only
       askdo auto-approve status | set N | off
       askdo upgrade [--release TAG] [--operation ID]

Run COMMAND with privilege after approval. Use -- before COMMAND if its name
collides with an askdo subcommand (including a legacy operator command) or starts
with -; command flags are passed through unchanged either way.

Sudo-style options:
  -k, --reset-timestamp   like sudo -k: forget this terminal's approval (with COMMAND: ask again this once)
  -K, --remove-timestamp  like sudo -K: forget approvals on all your terminals
  -v, --validate          like sudo -v: refresh the approval window without running anything
  -n, --non-interactive   like sudo -n: fail instead of waiting for a Telegram card
  -s, --shell             like sudo -s: run the target's shell (with COMMAND: shell -c)
  -i, --login             like sudo -i: run the target's login shell in its home
  -l, --list              like sudo -l: show your askdo permissions and approval window

-v requires timestamp_timeout to be enabled for your account.

-u USER (or --user USER) runs COMMAND as that account instead of root, like
sudo -u: a login name or #UID that must exist on this host. The broker
resolves it before the request is recorded, the approval card shows
"submitter → USER (uid N)", and the command gets that account's uid, groups,
HOME, USER and LOGNAME. Omit -u to run as root. --bundle and --script run as
root only; to run a script as USER, pipe it: askdo -u USER bash < script.
If foreground approval timestamps are enabled, reuse is per resolved target UID:
a name and #UID for the same account share a window. Changing target (including
omitting -u for root) requires fresh approval and replaces the window on handoff.

  askdo -u tyme npm start                     run as the tyme account
  askdo -u '#1001' id -u                      by numeric uid; quote #UID so
                                              the shell does not read # as
                                              a comment
  askdo -u tyme --reason 'Rebuild' make       with runner flags before COMMAND
  askdo -u tyme -i                           target's login shell in its home
  askdo -n /usr/bin/id                       fail if human approval is needed

Upgrade requires human approval and needs no sudo. Without --release, it selects
the newest stable release, or a prerelease if none exists. --operation resumes
observing an upgrade without resubmitting.

--script captures only PATH, preserving its basename and bytes, as a one-file
bundle. Like --bundle, it runs with /bin/bash from the invocation directory;
ARGs go to the script. No executable bit is required. Sensitive basenames need
--bundle-include-sensitive BASENAME. Use --bundle with --entry for sidecars or
dependencies. --script cannot be combined with --bundle, --entry, or captured
stdin. Ordinary COMMAND argv stays raw/live; scripts there are not snapshotted.

Foreground jobs print one review prompt and only the command's output.
Use --verbose for lifecycle diagnostics and JOB_ID/CANCEL_HANDLE_FILE; detached
jobs always print them. Keep the handle file to interrupt your own running
command; --force requests SIGKILL explicitly. A stop acknowledgment is not
proof of exit. Use status or attach to confirm.

Configuration and operator commands: askdo-config --help
Re-authorize Codex: askdo-config auth login
Details: askdo-config auth --help
`)
}

func writeConfigHelp(w io.Writer) {
	fmt.Fprint(w, `usage: askdo-config COMMAND [ARG...]

  askdo-config review mode [required|approval-only] | exempt add|remove|list ...
  askdo-config review timestamp_timeout set USER VALUE | clear USER | list
  askdo-config review log [--since DURATION] [--job ID] [--json]
  askdo-config channel add telegram [NAME] | list | route set LOGIN CHANNEL
  askdo-config config check [--config PATH] [--live] | install FILE [--force]
  askdo-config auth login|status|logout [openai-codex] [--config PATH]
  askdo-config inspection check PATH [--config PATH]
  askdo-config reviewer add|edit|delete|moveup|movedown|list ...
  askdo-config gateway init|hosts add|hosts list|hosts revoke|upgrade-target|connect|check|serve ...
  askdo-config fleet join https://gateway[:port] [--ca-file PATH]
  askdo-config logs JOB_ID [--uid UID] [--all]
  askdo-config daemon [--config PATH]                 service mode (root only)

Run askdo-config as yourself; do not use sudo. Commands that change askdo's
configuration or read root-only state (review mode/exempt/timestamp_timeout,
channel, config install, auth, reviewer, gateway setup, logs) automatically
request the usual Telegram approval and run in the foreground, including
interactive prompts. Read-only views you can already access run without
approval. Root executes directly. Exceptions that still need sudo: fleet join
(it has its own enrollment approval) and the service modes daemon and
gateway serve.

  askdo-config review timestamp_timeout set jeremy 10    reuse approvals 10 minutes
  askdo-config review timestamp_timeout clear jeremy     stop reusing approvals
  askdo-config review exempt add jeremy                  skip AI review, keep Telegram
  sudo askdo-config fleet join https://gateway:8443

timestamp_timeout matches sudo: plain VALUE is minutes (decimals allowed).
Go durations such as 90s, 10m and 1h also work; the range is 30s through 1h.
A VALUE of 0 turns reuse off for that user even where a fleet gateway offers a
window; clear removes the entry instead, so the gateway's default applies again.
It controls how long one approval is reused on the same terminal, per target
user. The legacy review timestamp alias still interprets plain values as seconds.

Run shell commands and manage your own jobs with askdo; see askdo --help.
`)
}

func writeAuthHelp(w io.Writer) {
	fmt.Fprint(w, `usage: askdo-config auth login|status|logout [openai-codex] [--config PATH] [--credentials-dir DIR] [--token-file PATH]

  login    run the ChatGPT device flow and save the token (root; run again to re-authorize)
  status   show account and token expiry (never prints token material)
  logout   revoke the refresh token and remove the credential file

The token file is the configured openai_codex api_key_file. With no override,
the installed /etc/askdo/config.json (review.models) and
/etc/askdo-gateway/config.json (profiles) are read and the single configured
file is used; several distinct files are an error, so choose with --config.
A fleet-only host has no local file: run auth on the gateway host.

Target selection, highest priority first:
  --token-file PATH       explicit token path (first provisioning); config is not read
  --credentials-dir DIR   DIR/openai-codex.json; config is not read
  --config PATH           read this host or gateway config instead of the defaults
  (none)                  installed configs, else /etc/askdo/credentials/openai-codex.json

The token file is saved root:root 0600. Examples:
  askdo-config auth login
  askdo-config auth login --config /etc/askdo-gateway/config.json
  askdo-config auth login --token-file /etc/askdo-gateway/credentials/codex.json
  askdo-config auth status
`)
}
