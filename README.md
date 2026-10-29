# askdo

**Sudo, but the approval happens on your phone.**

Your AI agent needs to install a package. Your server needs a service restarted.
You need to run a script you didn't write. None of those should mean handing
over a root password or blindly trusting a command.

**askdo lets humans and AI agents request privileged Linux commands, with
approval through Telegram.** Add an AI reviewer for a second opinion, or skip
the model and just approve from your phone.

[Why askdo?](#why-askdo) · [Get started](#get-started) ·
[Review a script](#review-a-script-before-you-run-it) · [Documentation](#documentation)

## See it work

On the server, you (or your agent) run:

```sh
askdo --reason 'restart nginx after config change' -- /usr/bin/systemctl restart nginx
```

Your phone buzzes once per request. The approval card leads with the AI's risk
rating and verdict, followed by the server/job identity, who's asking, expiry,
up to three ranked warnings, the command and the reason. **Details** expands
the full request, review, evidence and reviewer history. With no AI review, the
card instead prominently says **NO AI REVIEW — Risks NOT assessed**.
Tap **Approve once** to run it, **Deny** to stop it, or **Details** to
take a closer look. AI-reviewed cards also offer **Request changes**: run
nothing and return the review's uncertainties, warnings, and suggestions to
the submitting agent. The output comes back to the terminal that asked.

Suggestions identify what the submitter can address and what needs an
administrator. **Request changes** returns that feedback without running the
command. Nothing automatically resubmits: address it, then ask again when
you're ready.

## Why askdo?

### Let your agent work without handing it the keys

An agent can write the code and run the tests, then get stuck at the last step:
installing a system dependency, reloading nginx, or fixing a file's ownership.

Instead of giving it blanket passwordless sudo—or doing every privileged step
yourself—give it askdo. The agent asks, an AI reviewer can flag risky changes,
and you decide from Telegram. It gets a way to request root access, not your
password.

### Keep strong passwords. Stop typing them into every sudo prompt.

Long, unique passwords belong in your password manager, not your muscle memory.
With askdo, you can keep a different strong password for every server and use
a Telegram tap for day-to-day privileged commands.

Already know what you're doing? **Approval-only mode needs no AI model or API
key.** You still log in to your server as usual; askdo handles the approval
when it's time to run a privileged command.

### Get a second opinion before running unfamiliar code

That installer wants root. That maintenance script looks useful. Your own
cleanup command is a little more ambitious than usual.

Ask for an AI review before you run it. For a script arriving on stdin — the
classic `curl … | sh` — askdo can capture it, make it available to the
reviewer, and run those exact bytes with Bash after your approval; bundles
work the same way for local script folders. [Here's how](#review-a-script-before-you-run-it).

Reviewers can also inspect bounded files, executable hashes, service state and
sanitized sudo-policy metadata when you enable those tools. See
[review tools](docs/review-tools.md).

### Make the rest of the workflow easier, too

- **Approve homelab maintenance from the sofa.** Let an agent prepare the
  work and send you the decision instead of calling you back to the keyboard.
- **Put a human checkpoint in a deployment script.** Run the unprivileged
  steps normally, then use askdo for the service reload or system change.
- **Pick up long-running agent work later.** Once a headless command has
  launched, a client timeout needn't stop it. Check its status and reconnect
  to its output using the same job ID.
- **Use different review policies for people and agents.** Keep AI review
  for agent accounts while using phone-only approval for your own account.
- **Give reviewers account context.** Administrator-owned notes describe
  normal work for each user or group, without granting extra privileges.
  See [account notes](docs/configuration.md#reviewer-instruction-layers-and-account-notes).
- **Add more admins without sharing phones.** Each submitting account can
  reach its own bot, one request can reach several admins at once, and the
  first valid approve or deny decides it. Set up named channels in
  [configuration](docs/configuration.md#telegram).
- **Approve a whole fleet from one phone.** Running several servers? An
  optional shared gateway can hold the model credentials, Codex login and one
  Telegram bot for all of them, while each machine keeps its own inspection
  rules, auto-approval ceiling and local root execution. Standalone mode —
  one bot per server, configured on that server — stays the default and is
  unchanged. See [fleet setup](docs/fleet-setup.md).
- **Let routine work through automatically.** Opt-in risk-based auto-approval
  can run qualifying AI-reviewed headless jobs with a Telegram notice.
  It's off by default; [you choose the policy](docs/configuration.md).

## Get started

You'll need a Linux host with systemd and sudo, plus a Telegram bot. Create the
bot with [BotFather](https://t.me/BotFather). A model is optional: choose it
later if you want AI review.

### Install

One command, pinned to the published release:

```sh
curl -fsSL https://github.com/jeremyakers/askdo/releases/download/v1.0.0-rc.20/install.sh | sudo sh
```

The installer downloads the release binaries and writes a starter config; it
never starts the service. Stop an older askdo broker yourself before upgrading.
For the installer's verification model and Synology DSM specifics, see
[installation details](docs/installation.md).

### Set up a standalone server

Standalone mode uses one bot per server, configured on that server.

First, connect Telegram. The wizard asks for the bot token and can discover
your Telegram IDs after you message the bot:

```sh
sudo askdo channel add telegram
```

Then choose how you want to approve.

**With AI review:** add a hosted reviewer or your own local model:

```sh
sudo askdo reviewer add my-reviewer
```

**Or, just use your phone:** no model or API key is needed. Cards will clearly
say **NO AI REVIEW — Risks NOT assessed**; your tap is still required.

```sh
sudo askdo review mode approval-only
```

Finally, add your account to the `askdo` group, validate the config and start
the service:

```sh
sudo usermod -aG askdo "$USER"
sudo askdo config check
sudo systemctl enable --now askdo
```

Add a separate agent account too if you use one. Log out and back in, then try
something harmless:

```sh
askdo --reason 'Try my first Telegram approval' -- /usr/bin/id -u
```

Approve it in Telegram. Seeing `0` means it ran as root. For custom review
policies and inspection scope, see [configuration](docs/configuration.md).

### Join another machine to your fleet

Once your gateway is running, a fresh host can enroll itself:

```sh
sudo askdo fleet join https://your.gateway:8443
```

Match the request code in Telegram and tap **Approve**. The host installs its
fleet config, adds the invoking user to `askdo` and starts the service. Log out
and back in once, and it's ready. No bundle copying or server-side enrollment
command is needed.

## Everyday commands

Ask for a second opinion on one command, even if your account is normally
exempt:

```sh
askdo --review=yes --reason 'Review the service restart' -- /usr/bin/systemctl restart nginx
```

Check a job or reconnect to its output:

```sh
askdo status '2026-09-28_#1' --json
askdo attach '2026-09-28_#1'
```

Keep AI review for agents but not for your own account:

```sh
sudo askdo review exempt add "$USER"
```

Optionally reuse that approval for foreground unreviewed commands in the same
terminal, with a sliding five-minute window:

```sh
sudo askdo review timestamp set "$USER" 300
sudo askdo review timestamp list
sudo askdo review timestamp clear "$USER"  # disable reuse again
```

The first command still needs approval. Each successful handoff resets the
window; detached jobs and AI-required commands never use it. It is off by default.
See [approval timestamps](docs/configuration.md#sliding-foreground-approval-timestamps).

Headless agents get streamed output and a job ID they can return to later. If
the client disconnects before launch, the pending request is cancelled; after
launch, use `status` and `attach` rather than submitting the command again.

## Upgrade askdo

```sh
askdo upgrade
```

It downloads and verifies a release, asks for Telegram approval, then activates
and verifies it. No sudo password is needed. See [upgrading and recovery](docs/upgrade.md)
for exact releases, reconnecting after a restart and backup handling.

## Review a script before you run it

Lots of projects start with `curl … | sh` — convenient, but what does that
script actually do? Put askdo in the middle of the pipe. It captures the script
before anything runs, lets the reviewer inspect it, and runs those exact bytes
only after you approve:

```sh
curl -fsSL https://example.com/install.sh | \
  askdo --review=yes --reason 'Review this installer' -- bash
```

A local script or a downloaded file works too:

```sh
askdo --review=yes --reason 'Review this maintenance script' \
  --script /tmp/maintenance.sh -- 'one script argument'
askdo --review=yes --reason 'Review this installer' -- bash < installer.sh
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
- [Review journal](docs/review-log.md)
- [Architecture](docs/architecture.md) and [review tools](docs/review-tools.md)
- [Client protocol](docs/protocol-client.md)
- [Clean installation and cutover](docs/clean-cutover.md)

## Developing

```sh
CGO_ENABLED=0 go build -trimpath -o askdo ./cmd/askdo
CGO_ENABLED=0 go build -trimpath -o askdo-launch ./cmd/askdo-launch
```

Run `go vet ./...` and `go test -race ./...`; see [validation](docs/validation.md)
for the full list. `./askdo --help` lists client flags and `./install.sh --help`
lists installer options.

## License

Licensed under [GPLv3](LICENSE); dependency attribution in
[third-party notices](THIRD-PARTY-NOTICES).
