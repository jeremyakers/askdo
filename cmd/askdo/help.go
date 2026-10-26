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
	fmt.Fprint(w, `usage: askdo [--reason TEXT] [--timeout DURATION] [--detach] [--review=yes] [--verbose] -- COMMAND [ARG...]
       askdo [--reason TEXT] --bundle DIR --entry FILE [--bundle-include-sensitive FILE]... [--] [ARG...]
       askdo [--reason TEXT] --script PATH [--bundle-include-sensitive FILE] [--] [ARG...]
       askdo status|attach JOB_ID
       askdo cancel --handle-file PATH [--force]
       askdo cancel JOB_ID                 legacy jobs, before dispatch only
       askdo auto-approve status | set N | off
       askdo upgrade [--release TAG] [--operation ID]

Run COMMAND with privilege after approval. Put -- before COMMAND so its own
flags are passed to it unchanged.

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

Operator commands (root):
  askdo fleet join https://gateway[:port] [--ca-file PATH]
  askdo auth login|status|logout [openai-codex] [--config PATH] [--credentials-dir DIR] [--token-file PATH]
  askdo config check [--config PATH] [--live] | config install FILE [--config PATH] [--force]
  askdo gateway ...        askdo channel ...        askdo reviewer ...
  askdo review ...         askdo inspection ...     askdo logs ...
  askdo daemon [--config PATH]

Re-authorize Codex with no flags: sudo askdo auth login
Details: askdo auth --help
`)
}

func writeAuthHelp(w io.Writer) {
	fmt.Fprint(w, `usage: askdo auth login|status|logout [openai-codex] [--config PATH] [--credentials-dir DIR] [--token-file PATH]

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
  sudo askdo auth login
  sudo askdo auth login --config /etc/askdo-gateway/config.json
  sudo askdo auth login --token-file /etc/askdo-gateway/credentials/codex.json
  sudo askdo auth status
`)
}
