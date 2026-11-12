# askdo

**Sudo, but the approval happens on your phone.**

askdo lets people and AI agents run privileged Linux commands after approval in
Telegram, instead of sharing a root password or granting blanket passwordless
sudo. Add an optional AI reviewer for a second opinion, or use approval-only
mode with no model or API key.

[Get started](#get-started) · [Everyday commands](#everyday-commands) ·
[Day-2 operations](#day-2-operations) · [Documentation](#documentation)

## Get started

### Prerequisites

- Linux on **amd64 (x86-64)** or **arm64**, with **systemd**, **sudo**
  (including `visudo`), and **curl**.
- A Telegram bot from [@BotFather](https://t.me/BotFather). The standalone
  steps below explain how to create and connect it.
- Optional: an AI model and its credentials for automated review. You do not
  need a model for approval-only mode.

### 1. Install

```sh
curl -fsSL https://github.com/jeremyakers/askdo/releases/latest/download/install.sh | sudo sh
```

The installer downloads and verifies the release and writes a starter config;
it does not enable or start the service. Use this command for a first install;
for later upgrades, use [`askdo-config upgrade`](#upgrade-this-host).

Check the installed versions (neither command asks for approval):

```sh
askdo --version
askdo-config --version
```

For asset verification and Synology DSM specifics, see
[installation details](docs/installation.md).

### 2A. Set up a standalone server

Use this path for one machine with its own Telegram bot.

1. **Add every human and agent account to the `askdo` group.**

   ```sh
   sudo usermod -aG askdo "$USER"
   # If an agent uses a separate account:
   sudo usermod -aG askdo AGENT_USER
   ```

   Log out and back in, or run `newgrp askdo` in your current shell. An agent
   account needs a fresh login too. Only add accounts you trust to request
   privileged commands.

2. **Connect Telegram.**

   a. Open [@BotFather](https://t.me/BotFather) in Telegram, send `/newbot`, and
   follow its prompts. Copy the bot token it gives you.

   b. Open a chat with your new bot and press **Start** or send it a message.

   c. Run the setup wizard:

   ```sh
   sudo askdo-config channel add telegram
   ```

   Paste the bot token when prompted. After your message, the wizard can
   discover both the **chat ID** (where approval cards arrive) and your numeric
   **Telegram user ID** (who may approve them). Accept those discovered IDs, or
   enter them manually if you already have them.

3. **Choose the review mode.** For phone-only approval with no AI model:

   ```sh
   sudo askdo-config review mode approval-only
   ```

   For AI review instead, add a hosted reviewer or your own local model:

   ```sh
   sudo askdo-config reviewer add my-reviewer
   ```

4. **Validate the configuration and enable the service.**

   ```sh
   sudo askdo-config config check
   sudo systemctl enable --now askdo
   ```

   A successful check prints `configuration valid`; resolve any reported error
   before enabling the service.

5. **Run a harmless first command.**

   ```sh
   askdo --reason 'Try my first Telegram approval' /usr/bin/id -u
   ```

   Telegram shows an **approval card** with the host and job, requester,
   command, reason, and expiry. AI-reviewed cards also show a risk verdict and
   warnings; approval-only cards prominently say **NO AI REVIEW — Risks NOT
   assessed**. Tap **Approve once** to run the command, **Deny** to stop it, or
   **Details** for more context. AI-reviewed cards also offer **Request
   changes**, which returns feedback without running anything.

   The terminal prints `0` after approval: that is root's user ID, so the
   command ran successfully as root.

### 2B. Add a machine to an existing fleet

Use this path only if you already have a fleet gateway. Skip it for a single
standalone machine.

1. **Add the human and agent accounts on this machine to the `askdo` group.**

   ```sh
   sudo usermod -aG askdo "$USER"
   sudo usermod -aG askdo AGENT_USER  # if you use a separate agent account
   ```

   Log out and back in, or run `newgrp askdo` in your current shell.

2. **Check the gateway prerequisites.** Before joining, complete
   [fleet gateway setup](docs/fleet-setup.md#prerequisites): its TLS
   certificate and key must have SANs matching the gateway DNS name or IP you
   use below, and it needs a **dedicated Telegram bot** (not a bot already used
   by a standalone server).

3. **Join from the new host.** Choose a display name with `--name`:

   ```sh
   sudo askdo-config fleet join --name web-01 https://gateway.example.com:8443
   ```

   The host prints a six-character request code. Approve the fleet enrollment
   card **only if its code matches the host terminal**. For a privately trusted
   CA, answer the host's `y/N` confirmation only after comparing the code and
   approving the card yourself. The code binds the request to the gateway's TLS
   certificate; a different code is unsafe. Join installs the fleet config and
   enables `askdo.service`.

   `--name` is optional. By default the gateway uses the machine hostname; if
   that hostname is already used, it assigns `hostname-<4 chars>` instead. On
   the gateway host, group members can list hosts without an approval card:

   ```sh
   askdo-config gateway hosts list
   askdo-config gateway hosts rename HOST_ID NAME
   ```

4. **Test the host.**

   ```sh
   askdo --reason 'Try my first fleet approval' /usr/bin/id -u
   ```

   Approve the card in Telegram as described in
   [standalone step 5](#2a-set-up-a-standalone-server). Output `0` means the
   command ran as root. See [fleet setup](docs/fleet-setup.md) for explicit CA
   trust, enrollment recovery, central AI review, and revocation.

### When do I need sudo?

| Task | Run as |
| --- | --- |
| First-time standalone setup (`channel add`, `reviewer add`, `review mode`, initial `config check`) | `sudo` |
| Fleet join (`askdo-config fleet join`) | `sudo` |
| Enable or disable the systemd service | `sudo systemctl …` |
| Everything else after setup | Your normal account in the `askdo` group; root-only operations ask for Telegram approval |

`askdo --help` and `askdo-config --help` are local help and never request
approval. Read-only views including `askdo -l`, `askdo status`,
`askdo-config upgrade-fleet --status`, and `askdo-config gateway hosts list`
also run without a card (in their default form; adding `--config PATH` reads
that file as root and asks for approval).

### If the first command cannot connect

Follow the remedy in the printed connection error. The usual checks are:

```sh
id -nG                         # must include askdo after a fresh login
sudo systemctl status askdo   # broker service state
sudo journalctl -u askdo      # broker logs
```

If `sudo` says `askdo-config` is not found, its `secure_path` may omit
`/usr/local/bin`; use `sudo /usr/local/bin/askdo-config …`. The starter
`/etc/askdo/config.json` is root-only (`0600`), so inspect or edit it with
administrator access rather than as an unprivileged user.

## Day-2 operations

### Upgrade this host

Run as an `askdo` group member, without `sudo`:

```sh
askdo-config upgrade
# Or choose an exact release:
askdo-config upgrade --release vX.Y.Z
```

The command asks for Telegram approval, downloads and verifies the release,
then activates it with automatic rollback if activation fails. See
[upgrading and recovery](docs/upgrade.md) for reconnecting, exact releases, and
backups.

### Upgrade a fleet from the gateway host

```sh
askdo-config upgrade-fleet          # newest stable release; one approval
askdo-config upgrade-fleet --status # releases, results, and rollout state; no card
askdo-config upgrade-fleet --stop   # stop offering the release
```

Hosts upgrade one at a time. A failure pauses the rollout; to resume, run the
exact `askdo-config upgrade-fleet TAG` command that `--status` prints (a bare
`upgrade-fleet` targets the newest release instead). See
[fleet upgrades](docs/upgrade.md#upgrade-a-fleet-from-the-gateway).

### Uninstall

Remove askdo while keeping configuration, credentials, and databases:

```sh
curl -fsSL https://github.com/jeremyakers/askdo/releases/latest/download/uninstall.sh | sudo sh
```

To remove the retained state too, download `uninstall.sh`, inspect it, and run
`sudo sh uninstall.sh --purge --yes`. It removes `/etc/askdo`, `/var/lib/askdo`,
`/var/lib/askdo-review` and the default gateway state. It does not remove a
gateway database at a custom path or upgrade backups (default
`/var/backups/askdo`); on Synology DSM it also keeps the askdo accounts and
`/var/lib/askdo-review`. Delete those yourself if you want them gone.

## Glossary

| Term | Meaning |
| --- | --- |
| **Broker** | The local root service that receives requests, enforces policy, and dispatches approved commands. |
| **Gateway** | The optional fleet service that centralizes Telegram approvals and AI credentials; it never runs host commands. |
| **Fleet host** | A machine enrolled with a gateway. It keeps its own broker, policy, jobs, and privileged execution. |
| **Reviewer** | The optional AI model that assesses a request and supplies risk findings before the human decision. |
| **Approval card** | The Telegram message showing a request and its Approve, Deny, and Details controls. |
| **Approval-only** | Mode with human Telegram approval but no AI review or model credentials. |
| **Bundle** | A captured folder of scripts and helper files reviewed and executed together. |
| **Auto-approval** | Opt-in automatic dispatch of qualifying requests under your risk policy; off by default. |

## Everyday commands

Use `askdo COMMAND [ARG...]` to run a command; use `askdo -- COMMAND` if its name
collides with an askdo subcommand or starts with `-`. Configuration and operator
commands live in `askdo-config --help`.

Ask for a second opinion on one command, even if your account is normally
exempt:

```sh
askdo --review=yes --reason 'Review the service restart' /usr/bin/systemctl restart nginx
```

Run a command as another account instead of root, like `sudo -u` (a login
name or `#UID` that exists on this host; the approval card shows
`you → tyme (uid 1001)` and the command gets that account's groups, `HOME`,
`USER` and `LOGNAME`):

```sh
askdo -u tyme --reason 'Rebuild the site as its owner' make -C /srv/site
askdo --user '#1001' --reason 'Check the service account' /usr/bin/id
askdo -u tyme --reason 'Run this script as tyme' bash < maintenance.sh
```

`--bundle` and `--script` always run as root (their staged copy is
root-private); pipe a script through stdin as above to run it as another user.

Sudo-style options (root remains the default target):

| Option | Meaning |
| --- | --- |
| `-k`, `--reset-timestamp` | Alone, invalidate this terminal's timestamp for all targets. With a command, ignore the timestamp without changing the saved window. |
| `-K`, `--remove-timestamp` | Remove your timestamps on all terminals; accepts no command. |
| `-v`, `--validate` | Refresh your terminal's timestamp, requesting approval if needed, without executing anything. Requires an enabled `timestamp_timeout`. |
| `-n`, `--non-interactive` | Never wait for a human: reuse a valid timestamp or eligible risk auto-approval, otherwise exit 1 with no pending approval card. |
| `-s`, `--shell` | Run the target account's passwd shell (or `/bin/sh` if empty), interactively without arguments, otherwise with `-c "arguments joined with spaces"`. |
| `-i`, `--login` | Run that shell with `-l`, target `HOME`/`USER`/`LOGNAME`, and target home as the working directory. |
| `-l`, `--list` | Show group membership, review policy, timestamp timeout/remaining time, and auto-approval status without approval. |

Shell invocations are ordinary reviewed/approved submissions: the actual shell
argv is visible to the reviewer. Neither shell mode preserves the caller's
environment. Unlike sudo's `-s`, askdo deliberately uses the **target** account's
shell, not the caller's `$SHELL`. Combined boolean short options such as `-kn`
work; value-taking combinations such as `-iu tyme` are not supported.

```sh
askdo -n /usr/bin/id                 # fail immediately if approval is needed
askdo -k                            # forget this terminal's approval
askdo -v                            # approve/refresh, without running a command
askdo -i -u tyme                     # target's login shell
askdo -s -u tyme -- 'echo "$HOME"'   # shell command string
askdo -l
```

Check a job or reconnect to its output:

```sh
askdo status '2026-09-28_#1' --json
askdo attach '2026-09-28_#1'
```

Keep AI review for agents but not for your own account:

```sh
askdo-config review exempt add "$USER"
```

Optionally reuse that approval for foreground unreviewed commands in the same
terminal, with a sliding five-minute window. The setting
`timestamp_timeout` follows sudo: plain numbers are minutes (decimals allowed),
or use a Go duration such as `90s`, `10m` or `1h` (30s–1h bounds).

```sh
askdo-config review timestamp_timeout set "$USER" 5
askdo-config review timestamp_timeout list
askdo-config review timestamp_timeout clear "$USER"  # disable reuse again
```

The first command still needs approval. Reuse is per resolved target UID: a name
and `#UID` for the same account share the window, but changing target (including
back to root by omitting `-u`) needs fresh approval and replaces the window on
successful handoff. Each successful handoff resets the window; detached jobs and
AI-required commands never use it. It is off by default.

Control that window with `-v` / `--validate` to approve or refresh without running
a command, `-k` / `--reset-timestamp` to forget this terminal's approval, or
`-K` / `--remove-timestamp` to forget approvals on all your terminals. With a
command, `-k` asks again for that request without changing the saved window.
Use `-n` / `--non-interactive` to fail with exit 1 instead of waiting for Telegram
when neither timestamp reuse nor eligible auto-approval can authorize the command.
The reset/remove operations need no approval and leave the timeout enabled.
See [timestamp_timeout and approval reuse](docs/configuration.md#sliding-foreground-approval-timestamps).

Headless agents get streamed output and a job ID they can return to later. If
the client disconnects before launch, the pending request is cancelled; after
launch, use `status` and `attach` rather than submitting the command again. See
[guidance for AI agents](docs/agents.md).

## Why askdo?

- **Give agents a checkpoint, not your root password.** Agents can request a
  package install or service restart while you keep the decision.
- **Approve from your phone.** Approval-only mode needs no AI model; optional
  AI review adds a second opinion and clearly labels unreviewed requests.
- **Review scripts and bundles before they run.** askdo captures the exact
  bytes or files for review. See [Review a script](#review-a-script-before-you-run-it).
- **Fit different people and agents.** Named Telegram channels, account
  exemptions, approval reuse windows, account notes, and inspection policies
  are covered in [configuration](docs/configuration.md).
- **Reconnect to long-running work.** Job IDs support `status` and `attach`
  without blindly running the command again.
- **Centralize several machines, not their root execution.** An optional fleet
  gateway shares Telegram and model credentials while each host executes
  locally. See [fleet setup](docs/fleet-setup.md).
- **Automate only what you choose.** Risk-based auto-approval is opt-in and off
  by default; [you choose the policy](docs/configuration.md).

## Review a script before you run it

Lots of projects start with `curl … | sh` — convenient, but what does that
script actually do? Put askdo in the middle of the pipe. It captures the script
before anything runs, lets the reviewer inspect it, and runs those exact bytes
only after you approve:

```sh
curl -fsSL https://example.com/install.sh | \
  askdo --review=yes --reason 'Review this installer' bash
```

A local script or a downloaded file works too:

```sh
askdo --review=yes --reason 'Review this maintenance script' \
  --script /tmp/maintenance.sh 'one script argument'
askdo --review=yes --reason 'Review this installer' bash < installer.sh
```

**Scripts captured from stdin always need a human tap**, regardless of your
auto-approval policy. Captured stdin can be up to 1 MiB; use a bundle for
larger installers.

For a folder of scripts that belong together, capture it as a bundle and use
`$ASKDO_BUNDLE` for helpers:

```sh
askdo --review=yes --reason 'Review this installer before running it' \
  --bundle ./installer --entry install.sh
```

## Documentation

- [Documentation map](docs/README.md)
- [Installation details and DSM notes](docs/installation.md)
- [Configuration](docs/configuration.md)
- [Fleet setup](docs/fleet-setup.md)
- [Upgrading and recovery](docs/upgrade.md)
- [Guidance for AI agents](docs/agents.md)
- [Review journal](docs/review-log.md)
- [Architecture](docs/architecture.md) and [review tools](docs/review-tools.md)
- [Client protocol](docs/protocol-client.md)
- [Clean installation and cutover](docs/clean-cutover.md)

## Developing

```sh
CGO_ENABLED=0 go build -trimpath -o askdo ./cmd/askdo
CGO_ENABLED=0 go build -trimpath -o askdo-launch ./cmd/askdo-launch
ln -s askdo askdo-config
```

Run `go vet ./...` and `go test -race ./...`; see [validation](docs/validation.md)
for the full list. `./askdo --help` lists client flags, `./askdo-config --help`
lists operator commands, and `./install.sh --help` lists installer options.

## License

Licensed under [GPLv3](LICENSE); dependency attribution in
[third-party notices](THIRD-PARTY-NOTICES).
