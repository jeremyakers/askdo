# askdo

**Sudo, but the approval happens on your phone.**

askdo lets humans and AI agents request privileged Linux commands and approve them through
Telegram. An AI reviewer can add a risk assessment before you decide — or skip the model and
just approve from your phone. By default, nothing runs until you approve; auto-approval is
opt-in.

On the server, you (or your agent) run:

```sh
askdo --reason 'restart nginx after config change' -- /usr/bin/systemctl restart nginx
```

Your phone gets an approval card leading with the AI's risk rating and verdict — or, with no
reviewer, a prominent **NO AI REVIEW — Risks NOT assessed**. Tap **Approve once** or **Deny**;
the output comes back to the terminal that asked.

## Install

One line, pinned to a published release tag:

```sh
curl -fsSL https://github.com/jeremyakers/askdo/releases/download/v1.0.0-rc.20/install.sh | sudo sh
```

You'll need a Linux host with systemd and sudo and a Telegram bot (create it with
[BotFather](https://t.me/BotFather)); a model is only needed if you want AI review. The
installer downloads release binaries and writes a starter config; it never starts the
service. To read the installer first, `curl -fsSL <same URL> -o install.sh` and run
`sudo sh install.sh`. Stop any running older askdo broker yourself before upgrading.
Installer internals and Synology DSM details are in [installation](docs/installation.md).

## Standalone setup

One bot per server, configured on that server — this is the default mode.

### 1. Connect Telegram

From your normal login account:

```sh
sudo askdo channel add telegram
```

The wizard asks for your bot token and can discover your Telegram IDs when you send the bot
a message. Use a separate bot for each server.

### 2. Choose how you want to approve

**With AI review:** add a reviewer with the setup wizard. Choose a hosted provider or your
own local model:

```sh
sudo askdo reviewer add my-reviewer
```

**Or, just Telegram approval:** skip the model entirely:

```sh
sudo askdo review mode approval-only
```

### 3. Add your account and start askdo

```sh
sudo usermod -aG askdo "$USER"
sudo askdo config check
sudo systemctl enable --now askdo
```

Add your agent's OS account to the `askdo` group too, if it uses a separate account. Log out
and back in so the group membership takes effect, then try a harmless first request:

```sh
askdo --reason 'Try my first Telegram approval' -- /usr/bin/id -u
```

Approve it in Telegram; seeing `0` in your terminal means it ran as root. For custom review
policies and inspection settings, see [configuration](docs/configuration.md).

## Several servers?

An optional shared gateway can hold the model credentials and one Telegram bot for a whole
fleet, while each machine keeps its own inspection rules, auto-approval policy and local
root execution. Standalone mode stays the default. See [fleet setup](docs/fleet-setup.md).

## Everyday commands

```sh
# Ask for AI review on a one-off request, even if your account is exempt
askdo --review=yes --reason 'Review the service restart' -- /usr/bin/systemctl restart nginx

# Follow up on a job (IDs look like 2026-09-28_#1, printed at submit time)
askdo status '2026-09-28_#1' --json
askdo attach '2026-09-28_#1'

# In AI-review mode, exempt your own account while keeping review for agents
sudo askdo review exempt add "$USER"
```

Headless agents get streamed output and a job ID they can return to later. The client waits
for both approval and the result, so give your agent's outer tool timeout enough room. If
the client disconnects before a command launches, the pending request is cancelled;
afterwards, use `status` and `attach` instead of submitting again.

## Review a script before you run it

Lots of projects start with `curl … | sh` — convenient, but what does that script actually
do? Put askdo in the middle of the pipe: it captures the script before anything runs, lets
the AI reviewer inspect it, and runs those exact captured bytes with `bash` only after you
approve:

```sh
curl -fsSL https://example.com/install.sh | \
  askdo --review=yes --reason 'Review this installer' -- bash
```

A downloaded file or a self-contained local script works the same way:

```sh
askdo --review=yes --reason 'Review this maintenance script' \
  --script /tmp/maintenance.sh -- 'one script argument'
askdo --review=yes --reason 'Review this installer' -- bash < installer.sh
```

**Scripts captured from stdin always need a human tap in Telegram** — askdo never
auto-approves one, regardless of your auto-approval policy. Captured stdin can be up to 1 MiB;
use a bundle for larger installers.

For a folder of scripts that belong together, capture the folder as a bundle and reference
helpers through `$ASKDO_BUNDLE` (for example, `source "$ASKDO_BUNDLE/helper.sh"`):

```sh
askdo --review=yes --reason 'Review this installer before running it' \
  --bundle ./installer --entry install.sh
```

## Documentation

- [Documentation map](docs/README.md) — links to everything else.
- [Configuration](docs/configuration.md) — full schema, review modes, credentials, exemptions, auto-approval.
- [Installation details](docs/installation.md) — installer internals, Synology DSM specifics.
- [Clean installation and cutover](docs/clean-cutover.md) — installing alongside another service.
- [Review journal](docs/review-log.md) — what `sudo askdo review log` shows.
- [Architecture](docs/architecture.md) and [review tools](docs/review-tools.md) — trust boundaries.
- [Fleet setup](docs/fleet-setup.md) — optional shared gateway.
- [Client protocol](docs/protocol-client.md) — job lifecycles, wire format.

## Developing

Build without installing:

```sh
CGO_ENABLED=0 go build -trimpath -o askdo ./cmd/askdo
CGO_ENABLED=0 go build -trimpath -o askdo-launch ./cmd/askdo-launch
```

Run `go vet ./...` and `go test -race ./...` for the unprivileged checks; see
[validation](docs/validation.md) for the full list. `./askdo --help` lists client flags,
`./install.sh --help` installer options.

## License

Licensed under [GPLv3](LICENSE); dependency attribution in
[third-party notices](THIRD-PARTY-NOTICES).