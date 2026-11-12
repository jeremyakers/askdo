package main

import (
	"fmt"
	"io"
)

// Help is resolved before dispatch: exploring any operator subcommand must
// never open private files, prompt, or submit an approval request.
func operatorHelp(args []string, out io.Writer) bool {
	help := false
	for _, arg := range args[1:] {
		if arg == "--" {
			break
		}
		if arg == "--help" || arg == "-h" {
			help = true
			break
		}
	}
	if !help {
		return false
	}
	switch args[0] {
	case "channel":
		fmt.Fprintln(out, channelUsage+"\nTelegram setup asks for a bot token, then can discover your chat and user IDs after you message the bot.\nFlags: --config PATH, --credentials-dir DIR, --token-file PATH, --chat-id ID, --operator-user-id ID, --yes")
	case "reviewer":
		fmt.Fprintln(out, reviewerUsage+"\nFlags: --config PATH, --credentials-dir DIR; add/edit: --provider PRESET, --name NAME (add only), --api DIALECT, --base-url URL, --model MODEL, --key-file PATH, --boundary local|external, --timeout DURATION, --force-login, --yes\nWithout --yes, add/edit prompts interactively; secrets are read from a file or a hidden prompt, never argv.")
	case "review":
		fmt.Fprintln(out, reviewUsage)
	case "fleet":
		fmt.Fprintln(out, fleetUsage)
	case "gateway":
		fmt.Fprintln(out, gatewayUsage)
		fmt.Fprintln(out, "Flags: --config PATH\n  init: --url URL --listen HOST:PORT --tls-cert PATH --tls-key PATH --bot-token-file PATH --chat-id ID --operator-user-id ID [--database PATH] [--credentials-dir DIR] [--force]\n  hosts add: --output PATH --channel ID [--profile ID] [--default-channel ID] [--uid-channel UID=CHANNEL] [--ca-file PATH]\n  hosts list: read non-secret status on the gateway host, without approval.\n  hosts rename HOST_ID NAME: set the name used in lists and Telegram notices.\n  hosts revoke HOST_ID: disable a host and its outstanding tickets.")
		fmt.Fprintln(out, "  upgrade-target [TAG|--clear]: [--host-config PATH]\n  connect: --enrollment PATH [--credentials-dir DIR] [--profile ID] [--approval-only] [--force]\n  check: [--live] (synthetic provider checks may consume quota)\n  serve: TLS gateway service mode (root only)")
	case "logs":
		fmt.Fprintln(out, "usage: askdo-config logs JOB_ID [--uid UID] [--all]\nReads root-only reviewer logs; requires approval and may contain secrets.")
	case "upgrade-fleet":
		fmt.Fprintln(out, upgradeFleetUsage)
		fmt.Fprintln(out, "Requires a configured gateway with enrolled hosts. --status reads non-secret broker status without approval. Changes request Telegram approval.\nFlags: --config PATH, --host-config PATH, --status, --stop")
	case "auth":
		writeAuthHelp(out)
	case "config":
		fmt.Fprintln(out, "usage: askdo-config config check [--config PATH] [--live] | install FILE [--config PATH] [--force]\nconfig check reads secret-bearing configuration; non-root access may require Telegram approval. --live runs synthetic provider checks and may consume quota.")
	case "inspection":
		fmt.Fprintln(out, "usage: askdo-config inspection check PATH [--config PATH]")
	case "upgrade":
		writeUpgradeHelp(out)
	default:
		writeConfigHelp(out)
	}
	return true
}

func statusView(args []string) string {
	if len(args) == 2 && args[0] == "upgrade-fleet" && args[1] == "--status" {
		return "fleet"
	}
	if len(args) == 3 && args[0] == "gateway" && args[1] == "hosts" && args[2] == "list" {
		return "hosts"
	}
	if len(args) == 2 && args[0] == "review" && args[1] == "mode" {
		return "review"
	}
	return ""
}
