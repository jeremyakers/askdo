# askdo

askdo is a Linux approval gate for privileged operations requested by a
sandboxed coding agent or a human user. AI review is optional: when selected,
an unprivileged reviewer investigates using broker-mediated read-only tools.
By default, a human operator chooses **Approve once / Deny / Details** in
Telegram, including when there is **NO AI REVIEW**. An explicitly configured
risk-based grant can auto-approve a qualifying **detached** AI-reviewed request; it never
applies to **NO AI REVIEW**. Only an approved, frozen operation can be dispatched
as root, at most once. This is
an approval gate, **not** a sandbox for approved root programs or a guarantee
that a model's review is correct.

The client, root daemon and reviewer are modes of the `askdo` executable;
foreground execution additionally uses the root-owned, non-setuid
`askdo-launch` helper. At runtime it needs no provider SDK, model gateway,
Python or database server;
SQLite is embedded. Approval-only use needs no model endpoint; hosted models
work without a local inference server. Adapter/model compatibility is
deployment-specific and must be validated per installation.

## Requirements

- Linux with `openat2` `RESOLVE_*` and `statx` `STATX_MNT_ID` support (normally
  kernel 5.8 or newer; inspection fails closed if either is unavailable).
- A Telegram bot token, your numeric operator user ID and private chat ID.
- A configured reviewer model and its credentials (or a local inference server)
  when AI review is required; an explicit approval-only policy can use no model.
- For a source build (including the installer's fallback when no release asset
  is available), Go as declared in `go.mod`: `go 1.27.0`, `toolchain go1.27.1`.
  No public GitHub release asset is verified; do not assume a binary download.

## Install and onboard

To install from source, inspect `install.sh` and
run `./install.sh` only after reviewing the host and obtaining the machine
owner's approval. Installation can overlap another service without migrating its
state or forcing a systemd conflict. Before starting askdo, plan Telegram bot
token usage and any later service handoff with the operator; see the
[clean installation and cutover guide](docs/clean-cutover.md).

The installer builds both binaries from this checkout without downloading
source. It installs `/usr/local/bin/askdo` and the root-owned
`/usr/local/libexec/askdo-launch`, the single `askdo` submission/helper group,
the `askdo-review` account, example `/etc/askdo/config.json`, credential/state
directories, a validated narrow sudoers rule for the fixed no-argv helper,
and `askdo.service`. Membership in `askdo` grants socket submission and the
ability to invoke **only that fixed helper** for an approved, broker-verified
foreground TTY grant; it is **not general sudo access**. There is no second
submission/helper group to manage. Do not grant broad passwordless sudo.
The installer does **not** enable or start the service, and preserves an
existing config. `./install.sh --help` lists supported options.

When the repository is published, obtain a checkout of a reviewed revision or
release tag and inspect its installer before running it. If invoked outside a
checkout, `install.sh --version REF` fetches that ref's source tarball and builds
both binaries locally; it does **not** install prebuilt GitHub Release assets.
Release-asset SHA-256 files, if published separately, check integrity but are
**not** signatures or independent proof of origin. No binary release asset is
claimed available now.

After the machine owner's approval and installation, run these setup steps as
root (for example, in a root shell). The installed
example config needs Telegram IDs and a review policy; its default
`required` policy needs a reviewer before validation succeeds:

```sh
askdo reviewer add <reviewer-name> --provider codex
askdo channel add telegram
usermod -aG askdo <agent-user>
askdo config check
systemctl enable --now askdo
```

For approval-only use, run `askdo review mode approval-only` (config value
`approval_only`) and leave `review.models` as `[]` instead of adding a reviewer.
In `required` mode, `askdo review exempt add <username>` exempts an OS
login account; `review exempt remove <username>` and `review exempt list`
manage and display the exceptions. Run `askdo review mode required` to
switch back. In `required` mode,
`review.approval_only_users` can exempt named OS login accounts (including a
human and agents sharing that UID); other group members still require a model.
Telegram remains mandatory in both modes. See [configuration](docs/configuration.md)
for minimal examples. An empty model list does **not** guarantee the service
can handle every submitter: `--review=yes` fails closed without a model, as do
non-exempt submitters in `required` mode.

Risk-based auto-approval is opt-in and disabled by default. Root may configure
`review.auto_approve_grants` with login names and maximum risk scores for
detached jobs only; foreground always requires a human Telegram decision. A
submitting user can only set a lower personal preference over their own
SO_PEERCRED-verified UID. See [configuration](docs/configuration.md) for the
limits, eligibility rules, and security trade-off.

Choose another preset instead if appropriate: `askdo reviewer add`
offers provider, credentials, and a live model catalog (with manual model
entry if needed). Add more reviewers in fallback order. The Codex preset
uses askdo's **own OAuth device login**: follow its URL and code in a
browser; the Codex CLI is not required. It can reuse an existing login, or
`--force-login` can start a new one. The subscription backend and OAuth
client used by this implementation are subject to provider terms and may
change; this project does not claim provider authorization for third-party
client usage. API-key presets collect secrets at a hidden prompt or via
`--key-file`, not as command-line secret values. For scripted setup see
`askdo reviewer add <reviewer-name> --provider kimi --key-file FILE --yes`.

The Telegram wizard prompts for a bot token and numeric operator/private-chat
IDs; it can discover the IDs when the daemon is stopped and you message the
bot from your account. If the daemon or another process polls that bot,
provide the IDs manually. Enroll submitters in **`askdo`**, not a second group;
this does not grant credential access. Enroll each agent and human account
with the operator's explicit approval, and refresh each account's
session/group credentials before submitting. `config check --live` optionally
probes configured model endpoints with synthetic content only; it may consume
quota. With a Codex model, run
that live check as root so the broker-only OAuth token can be refreshed before
dropping privileges to the reviewer account.

For file-based host inspection policy (`inspection.*`, `limits.*`), edit
`/etc/askdo/config.json` as root or use
`askdo config install FILE [--force]` to validate and install a curated
config. There is **no socket access-policy CLI**; socket group membership controls
who can submit, while `review mode`/`review exempt` control whether they need
AI review. See the [configuration reference](docs/configuration.md).
To diagnose a path without reading its contents or changing permissions, run
`askdo inspection check /path/to/file [--config PATH]` as root. It reports
the decisive inspection rule and resolved name, or an explicit mount/filesystem
error; incomplete reviewer or Telegram onboarding does not prevent this check.
It reports an **inspection policy decision only**; run `askdo config check`
to validate the full service configuration before starting the daemon.

Common administration commands (as root):

```sh
askdo reviewer list
askdo reviewer edit <reviewer-name>
askdo reviewer delete <reviewer-name>
askdo reviewer moveup <reviewer-name>
askdo reviewer movedown <reviewer-name>
askdo review mode
askdo review mode required
askdo review mode approval-only
askdo review exempt add <username>
askdo review exempt remove <username>
askdo review exempt list
askdo channel list
askdo channel add telegram
askdo auth login openai-codex
askdo auth status
askdo auth logout
askdo config check
askdo config check --live
askdo config install FILE --force
```

`auth login` manages the Codex login without adding a reviewer; `auth status`
reports the account and token expiry without printing tokens; `auth logout`
removes the local token and attempts revocation. The broker-only Codex refresh
token is stored root:root `0600`; other reviewer-readable credentials use
root:askdo-review `0640`.

To remove the service/binary while preserving config, credentials, state and
accounts, run `./uninstall.sh` from the checkout as root. To **delete** config,
credentials, state and eligible accounts/groups too, use
`./uninstall.sh --purge --yes`; both flags are required and there is **no
interactive confirmation prompt**.
Review `./uninstall.sh --help` and back up any needed data before purging.

## Submit a request

Run as a submitting user with refreshed `askdo` group membership. Without a
controlling TTY (the normal sandboxed-agent/Bash-tool case), use the standard
sudo-like form: `askdo --reason ... -- /absolute/command`. The CLI selects
detached execution automatically but **waits synchronously** for the result,
streaming the command's captured stdout/stderr back to the caller. With a real
controlling TTY, the default is foreground on that original terminal; after
approval, the client invokes the fixed helper through
`/usr/bin/sudo -n /usr/local/libexec/askdo-launch`. `--detach` remains an
optional override for a TTY caller that wants no terminal for the root process.

```sh
askdo --reason 'Human foreground request (with a controlling TTY)' -- /usr/bin/id -u
askdo --reason 'Agent request (without a controlling TTY)' -- /usr/bin/id -u
askdo --review=yes --reason 'Request AI review even if exempt' -- /usr/bin/id -u
askdo --detach --reason 'TTY caller choosing detached execution' -- /usr/bin/id -u

# Capture a harmless script and its helper before review:
askdo --reason 'Try the bundled example' \
  --bundle ./examples/hello-bundle --entry run.sh
```

The foreground helper runs on the human's original TTY, not a daemon PTY.
Rootless/container tests cover Ctrl-C, stop/resume and resize. A disposable
sudo/container terminal-disconnect test observed honest `unknown` reporting
and the child exiting; real SSH-host disconnect behavior and cutover remain
unverified. Detached jobs continue to use the daemon's `SystemExecutor` with
no TTY, stdin from `/dev/null`, and spool-backed stdout/stderr: the two
lifecycles do **not** share one helper execution engine. There is **no stdin
passthrough** for headless/detached root commands; this is not full regular-sudo
parity. The helper accepts no caller-selected command or argument; the broker
verifies the original terminal,
identity, frozen manifest and one-use grant before sending the launch spec.

`--review=yes` adds a mandatory AI-review requirement; it cannot disable
review. Without it, an exhausted sequence of **typed provider availability**
failures can instead produce a **NO AI REVIEW** Telegram card with the reason
and sanitized failure history. The human may approve once or deny; fallback
never means automatic execution. Safety refusals, invalid final reviews,
broker/capture/changed-evidence errors, and elapsed deadlines do not take
that human-approval fallback. A no-review card does not claim assessed risk,
effects, reversibility or complete dependency discovery.

When model-led inspection encounters a credential-like host path (for example
`.env`, `.env.*`, `*.key`, or `*.pem` under the configured
`inspection.sensitive_masks`), the broker checks its access policy but
withholds its contents from the reviewer: the model receives a payload-free
`withheld` tool result and can still review the rest of the code and submit
a report that honestly names the gap. The reviewed Telegram summary
prominently lists the withheld path and states that
credential content was **not** reviewed. The human normally approves; an
explicit eligible auto-approval grant on a detached reviewed job can instead
execute without a human tap despite this gap. Do not enable such a grant if
that trade-off is unacceptable.
An `inspection check` result of `ALLOWED` describes the configured path policy,
not a promise that credential contents will be delivered to the model. The
masks match **names, not content**: a credential stored under an ordinary
filename, or a secret value placed in argv, the environment, or `--reason`,
can still leak. Keep read roots narrow. A sensitive bundle file deliberately
included by the submitter is staged root-only for execution but withheld from
the model regardless of the opt-in. A credential-like path submitted as the
executable is never content-read: the broker performs metadata-only
resolution and records the requested and resolved spellings as withheld
references, disclosed on a reviewed card. Reference runtime credentials from
reviewed code instead of naming them as the program.

In argv mode the broker resolves `argv[0]` with metadata only — no content
bytes, no hash, no shebang read — and host code is read only when the
reviewer model chooses to read it. An executable the reviewer never
inspected therefore has **no source-byte pin** in the frozen approval: the
manifest binds its resolved absolute path, and approving such a job is the
operator's explicit assumption. The Telegram card shows the model's report;
it does not add a judgment about which files the model should have read.

If the reviewer model asks to read a path that inspection policy denies —
`read_roots` may legitimately exclude a host file the operation will execute —
the job no longer fails. The model receives a denied tool result, is
instructed to submit anyway, and the broker freezes whatever schema-valid
report it produces; the human normally decides with the report's own stated
uncertainties and the broker-recorded withheld facts, but a configured eligible
detached auto-approval grant can bypass the human tap. A denied read is not
provider unavailability: a **NO AI REVIEW** fallback card requires typed
exhaustion of configured providers, not failed file access. If the reviewer
abandons
the job without submitting any report the job fails — a job with no model
report is never labeled reviewed. In that failure case the CLI reports a
generic broker-authored explanation; raw provider text remains in root-owned
logs, not in the submitter's
result. An operator can view the reviewer's last 16 KiB by job ID with
`sudo askdo logs JOB_ID` (or `--all` for the entire stat-time log). This
root-only output escapes terminal controls but **can contain provider text
and secret values**; do not paste it into an agent session. As root, use
`askdo inspection check /path/to/file` to diagnose the rule without
reading file contents. If policy genuinely needs changing, review that change
as an operator; do not broaden read roots solely to make a model review pass.
After resolving the denial, submit a **new** job rather than retrying an
ambiguous or already-dispatched operation.

Both modes **require the caller's current working directory**; the client
submits it and the broker binds its identity. Execution takes place there.
Bundle code is captured and the entry launches from its **absolute staged
path** with `/bin/bash --noprofile --norc`. `ASKDO_BUNDLE` points to the
staged dependency directory: use, for example,
`source "$ASKDO_BUNDLE/helper.sh"` in a captured script. Ordinary relative
paths resolve from the caller's cwd, not the bundle. Bundle capture excludes
credential-like and sensitive paths by default using the client's built-in
conventional name masks, and refuses symlinks, non-regular files, files with
multiple hard links (a second name could bypass the name filter), and
non-UTF-8 or NUL-containing content before reading any bytes; a separately
copied secret under an ordinary name is not detectable. A file explicitly
staged with
`--bundle-include-sensitive` is still withheld from the reviewer model (the
broker's masks always win for model egress) and disclosed to the operator as
a withheld reference on a reviewed card. Never put secrets in `--reason`.

The Telegram summary uses HTML with the authenticated kernel submitter UID
and account name, the daemon's actual host name, best-effort observed Docker
environment information (when available), and the exact cwd. The displayed
command is shell-quoted **for display only**; execution uses the frozen argv,
not the displayed shell text.

Interactive foreground TTY workflows are implemented for human users but are
not a complete replacement for sudo; supported host/SSH behavior still needs
operator testing. Model-free approval does not guarantee that every operation
or environment is supported.

The client first reserves one globally unique human job ID in the form
`YYYY-MM-DD_#N` (for example `2026-09-27_#1`) and prints it to stderr
**before submitting the command**. The same ID identifies the job in the CLI,
Telegram card, database and logs; a lost reservation acknowledgement may leave
an unused ID, never a second executable job. Progress on stderr is not
completion; detached stdout is streamed from the daemon, while foreground
command I/O uses the original TTY. Omit the CLI's `--timeout` to avoid a
separate client wait deadline; a calling shell/tool can still terminate first.
When supplied, `--timeout` limits **waiting**, not the
duration of a committed root command. Before dispatch an expired wait prevents
execution; after a detached dispatch the client can stop observing while the
command continues. A committed foreground handoff instead follows the
terminal; a missing completion is `unknown`. Never blindly resubmit an
ambiguous operation:

```sh
askdo status '2026-09-27_#1' --json
askdo attach '2026-09-27_#1'
askdo cancel '2026-09-27_#1'             # pre-dispatch only
```

The submitting account cannot read raw reviewer logs. Operators can use
`sudo askdo logs '2026-09-27_#1'` without locating spool files or querying
SQLite. `--uid UID` optionally checks ownership. Migrated historical 32-hex
IDs remain readable by root; when such an ID belongs to multiple UIDs,
`--uid UID` is required to select one.
The `queued: broker accepted; review/notification pending` CLI line confirms
submission, **not** Telegram delivery. A review can wait behind other jobs.

Only the submitting UID can inspect or cancel its jobs. A daemon restart
invalidates pending approvals; an interrupted `starting`/`running` job is
marked `unknown`, meaning **inspect host effects before considering a retry**.
Telegram delivery failures do not grant approval. The CLI returns the
command's exit code when known; wrapper statuses include `124` (wait timeout),
`125` (review/infrastructure failure or unknown outcome), `126` (denied,
expired or pre-dispatch cancelled), and `130` (interrupted wait). A command
can itself exit with one of those numbers; query its stored result to tell.

For a sandboxed-agent integration without a controlling TTY, submit
privileged work once with `askdo --reason ... -- /absolute/command` (no
`--detach` needed) and omit askdo's `--timeout` flag. Make sure the outer
tool-call or shell timeout that wraps the submission is longer than the
configured Telegram approval lifetime: an outer timeout shorter than that
lifetime can cancel the pending submission before any human has a chance to
decide, and an outer timeout that starts before review may still end before a
later-sent card's full lifetime. Bundle mutable dependencies and use
`ASKDO_BUNDLE` paths. Existing agent processes must have refreshed `askdo`
socket-group credentials; changing `/etc/group` alone does not refresh them.
The operator normally decides in Telegram; an opt-in, eligible detached
AI-reviewed risk grant can instead auto-approve, but **NO AI REVIEW** still
needs the operator. A timeout or disconnect **before dispatch** cancels the
pending request; there is no approval to resume. **After dispatch**, observation
can end while the broker-owned command continues: use the printed ID with
`status` and `attach` to replay retained output and follow later events while
the broker stays up. An attach to an actively writing job can miss bytes in the
replay-to-subscription gap; reattach after completion for the retained output.
Never silently bypass a denial or repeat an operation that may already have
executed.

## Documentation and development

- [Documentation map](docs/README.md) — user and integration references.
- [Clean installation and cutover](docs/clean-cutover.md) — overlap, Telegram
  token coordination, and separately approved host handoff.
- [Configuration](docs/configuration.md) — schema, defaults and credential rules.
- [Architecture](docs/architecture.md) and [review tools](docs/review-tools.md)
  — trust boundaries, model-chosen path inspection, and completeness
  limitations (dependency discovery is not exhaustive and not mechanically
  checked).
- [Client protocol](docs/protocol-client.md) and
  [worker protocol](docs/protocol-worker.md) — integration wire formats.

Deferred limits and behavior changes requiring an operator decision are
tracked outside this public documentation tree and are not part of the
published interface.

To build from this checkout locally (without installing):
`CGO_ENABLED=0 go build -trimpath -o askdo ./cmd/askdo` and
`CGO_ENABLED=0 go build -trimpath -o askdo-launch ./cmd/askdo-launch`.
`./askdo --help` lists the client flags; `./install.sh --help` describes
installer options. Run `go vet ./...` and `go test -race ./...` for static
and unprivileged checks. `scripts/test-packaging.sh` and
`scripts/run-root-tests.sh` use disposable containers;
`scripts/test-foreground-sudo-container.sh` tests the real helper in one too.
`scripts/test-build-release.sh` builds a release asset set into a disposable
temporary directory, checks the installer-facing file set, then removes its
test artifacts; it does not install a service.
These documentation changes do not install askdo on the host, and the checks
above do not evaluate the security of a particular requested command. See
[validation](docs/validation.md) for the full public check list.

Licensed under [GPLv3](LICENSE). See [third-party notices](THIRD-PARTY-NOTICES)
for dependency attribution. No claim of a completed security audit is made.
