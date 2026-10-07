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

Your phone buzzes. You see the server, the command, and who's asking. With AI
review enabled, you also get a summary of the proposed changes and a risk
rating. Tap **Approve once** to run it, **Deny** to stop it, or **Details** to
take a closer look. The output comes back to the terminal that asked.

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

The source reviewer also exposes declared inspection scope, with optional
bounded executable hashes, service state and sanitized sudo-policy metadata.
These observations can reduce missing context, not guarantee safety or pin
later host execution. All three optional capabilities are off by default and
are not in published rc.2 binaries; see [review tools](docs/review-tools.md)
and [upgrade constraints](docs/configuration.md#optional-host-evidence-and-rollout).

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
- **Add more admins without sharing phones.** Each submitting account can
  reach its own bot, one request can reach several admins at once, and the
  first valid approve or deny decides it. Set up named channels in
  [configuration](docs/configuration.md#telegram).
- **Approve a whole fleet from one phone.** Running several servers? An
  optional shared gateway can hold the model credentials, Codex login and one
  Telegram bot for all of them, while each machine keeps its own inspection
  rules, auto-approval ceiling and local root execution. Standalone mode —
  one bot per server, configured on that server — stays the default and is
  unchanged. See [fleet setup](docs/fleet-setup.md) (implemented in source;
  not yet in a tagged release).
- **Let routine work through automatically.** Opt-in risk-based auto-approval
  can run qualifying AI-reviewed headless jobs with a Telegram notice.
  It's off by default; [you choose the policy](docs/configuration.md).

## Get started

You'll need a Linux host with systemd and sudo. The source implementation probes
the kernel features it needs rather than relying on a minimum kernel version:
`openat2` confinement and `STATX_MNT_ID`, or, when those primitives are absent,
an `os.Root` confined resolver and `name_to_handle_at` mount identity. It refuses
host inspection when no supported combination is available. The legacy paths
were exercised in an isolated, real **Linux 3.10.108** VM (x86_64, ext4); a vendor
or DSM installation still needs its own native broker, terminal and service
lifecycle acceptance. These compatibility additions are not in the published
rc.2 binaries. Release builders need [Go 1.27.1](go.mod), but installation does
not require Go or a destination compiler. Approval requires a
Telegram bot, which you can create with
[BotFather](https://t.me/BotFather). A model is only needed if you
want AI review.

### 1. Install a verified release

```sh
curl --proto '=https' --proto-redir '=https' -fsSL \
  https://github.com/jeremyakers/askdo/releases/latest/download/install.sh -o install.sh
sudo sh install.sh
```

The installer downloads release binaries for askdo and its terminal helper,
installs inert service units, and creates a starter config. It never compiles on
the destination or falls back to source. `--version TAG` selects a published
release tag (not a source branch); the default is `latest`. One closed
`install-manifest.v1` pins the tag, source commit, installer, both architecture
inventories and asset hashes/sizes. All subsequent assets use that exact tag.
The local installer must byte-match the selected release installer; a mismatch
refuses rather than silently executing different policy. `ASKDO_SOURCE_DIR` is
obsolete and rejected. Manifest/hash binding relies on the owner's HTTPS release
publication; it is not a signature or reproducible-build claim.

This new manifest-based bundle has not yet been published. Existing rc.2 assets
do not contain it or the DSM compatibility changes: this source installer fails
closed for those releases. Do not interpret local release fixtures as a published
upgrade. Publication and first native DSM installation require separate approval.

The same entry point automatically recognizes DSM metadata/native-tool paths
and uses native Synology role operations. DSM uses the existing vendor
`/usr/bin/python3` and `synoacltool`. A checked canonical native `visudo` may be
used when it matches the installed sudo version/grammar. Otherwise the verified
release validator runs temporarily from root-controlled executable staging, not
`/tmp`, and only for the exact supported sudo 1.9.5p2/grammar48 runtime. It never
replaces sudo, PAM or plugins or installs a compiler/package manager dependency. It
refuses unsupported bundled-parser configurations: custom plugins, plugin search
paths, alternate sudoers files and LDAP/SSSD sudoers sources are not treated as
stock local sudoers. Only bounded trusted default/standard configuration is
accepted; emitted parser warnings also fail closed. The real upstream amd64
checker rejects malformed policy and missing required include files. It accepts
an unrelated missing `@includedir` as empty, matching documented upstream
semantics; this is not a claim that every referenced directory exists. The
installer separately requires its own trusted `/etc/sudoers.d`. No native NAS
policy or authentication acceptance is claimed.
It accepts only native Linux-mode ACL metadata combined with absent/unsupported
POSIX extended ACLs, and refuses unknown, unsafe or inconsistent metadata.
Ordinary Linux installation needs no Python. Its role/sudo transaction is
preserved, while artifact delivery is now release-download-only on every host.

DSM reviewer creation uses `expired=1` on the first native call, privilege zero
and a **public, nonsecret placeholder password**. The installer verifies
`Expired=true`, native/NSS UID consistency and non-admin/non-submitter groups
before installing the grant. It never enables, resets the password of, or
repairs an existing reviewer. **Do not re-enable this service account:** its
placeholder is public. Disabled state is not a claim of share/application ACL
isolation. The fixed `askdo-review` execution group is independent of the native
NSS primary group (`users`, GID 100).

Native role creation/deletion, disabled-account authentication enforcement and
empty-group behavior still require approved first-install acceptance on DSM;
local native-command adapters test orchestration, not the NAS runtime. Ambiguous
native failures or changed rollback dependencies retain state and a private
staging journal for manual inspection; rollback never recursively erases a
native-created home. On DSM, `uninstall.sh --purge --yes` retains native identities
and `/var/lib/askdo-review` because name-only deletion cannot prove that a previous
installer created them. Neither install path enables or starts services.

### 2. Connect Telegram

From your normal login account, run:

```sh
sudo askdo channel add telegram
```

The wizard asks for your bot token and can discover your Telegram IDs when you
send the bot a message. Use a separate bot for each server.

### 3. Choose how you want to approve

**With AI review:** add a reviewer using the setup wizard.

```sh
sudo askdo reviewer add my-reviewer
```

Choose a hosted provider or your own local model. The Codex preset includes a
browser login; API-key providers prompt for your key.

**Or, just Telegram approval:** skip the reviewer and choose approval-only mode.

```sh
sudo askdo review mode approval-only
```

### 4. Add your account and start askdo

```sh
sudo usermod -aG askdo "$USER"
sudo askdo config check
sudo systemctl enable --now askdo
```

Add your agent's OS account to the `askdo` group too, if it uses a separate
account. Log out and back in so your new group membership takes effect, then
try a harmless first request:

```sh
askdo --reason 'Try my first Telegram approval' -- /usr/bin/id -u
```

Approve it in Telegram. Seeing `0` in your terminal means it ran as root.
For custom review policies and inspection settings, see
[configuration](docs/configuration.md).

## Everyday commands

```sh
# Ask for AI review on a one-off request, even if your account is exempt
askdo --review=yes --reason 'Review the service restart' -- /usr/bin/systemctl restart nginx

# Follow up on a job (IDs look like 2026-09-28_#1, printed at submit time)
askdo status '2026-09-28_#1' --json
askdo attach '2026-09-28_#1'
askdo cancel '2026-09-28_#1'      # only works before dispatch

# In AI-review mode, exempt your own account while keeping review for agents
sudo askdo review exempt add "$USER"
```

In an interactive terminal, approved commands run in the foreground with
normal terminal controls. Headless agents get streamed output and a job ID
they can return to later—no `--detach` flag needed. The client waits for approval
and the result, so give your agent's outer tool timeout enough room for both.

If the client disconnects before a command is launched, the pending request
is cancelled. After a headless command launches, use `status` and `attach` to
follow the existing job rather than submitting it again. See
[job lifecycles and recovery](docs/protocol-client.md) for the details.

## Review a script before you run it

Lots of projects start with `curl … | sh`. Convenient, but what does that
script actually do?

When a script would be piped into `bash`, put askdo in the middle of the pipe.
It captures the script before anything runs, lets the AI reviewer inspect it, and
runs those exact captured bytes with `bash` only after you approve:

```sh
curl -fsSL https://example.com/install.sh | \
  askdo --review=yes --reason 'Review this installer' -- bash
```

Everything after `--` is the command that runs, so `--review=yes` belongs on
the askdo side of the pipe. A downloaded file works the same way:

```sh
askdo --review=yes --reason 'Review this installer' -- bash < installer.sh
```

Captured scripts can be up to 1 MiB; use a bundle for larger installers.
Every captured script needs a human tap in Telegram; askdo never auto-approves
one. The reviewer reports on the script itself; if it mentions an installer
URL it didn't inspect, you can let it fetch and read those pages too with the
reviewer's separate `webfetch` tool (off by default; see
[configuration](docs/configuration.md)). If the approved script downloads more
code while running, those steps run as part of that same script.

Prefer keeping the script in a folder of your own — say, with helper scripts
it sources? Capture the folder as a bundle instead and reference the helpers
through `$ASKDO_BUNDLE` (for example, `source "$ASKDO_BUNDLE/helper.sh"`):

```sh
askdo --review=yes --reason 'Review this installer before running it' \
  --bundle ./installer --entry install.sh

# Or try bundles with a harmless example from this repository:
askdo --reason 'Try the bundled example' \
  --bundle ./examples/hello-bundle --entry run.sh
```

## Documentation

- [Documentation map](docs/README.md) — start here for everything else.
- [Configuration](docs/configuration.md) — full schema, both review modes,
  credentials, exemptions, auto-approval.
- [Clean installation and cutover](docs/clean-cutover.md) — installing
  alongside another service, Telegram token coordination, handoffs.
- [Architecture](docs/architecture.md) and [review tools](docs/review-tools.md)
  — trust boundaries and how model-led inspection works.
- [Fleet setup](docs/fleet-setup.md) — optional shared gateway for several
  hosts; [fleet gateway design](docs/fleet-gateway.md) records the objectives.
- [Client protocol](docs/protocol-client.md) and
  [worker protocol](docs/protocol-worker.md) — wire formats for integrators.

## Developing

Build without installing:

```sh
CGO_ENABLED=0 go build -trimpath -o askdo ./cmd/askdo
CGO_ENABLED=0 go build -trimpath -o askdo-launch ./cmd/askdo-launch
```

`./askdo --help` lists client flags, `./install.sh --help` installer options.
Run `go vet ./...` and `go test -race ./...` for the unprivileged checks;
`scripts/` contains container-based packaging, root, foreground-helper and
fleet-binary tests. See [validation](docs/validation.md) for the full list.

## License

Licensed under [GPLv3](LICENSE); dependency attribution in
[third-party notices](THIRD-PARTY-NOTICES).
