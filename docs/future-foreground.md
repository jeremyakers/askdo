# Historical foreground design note (superseded)

This records the direction considered before the `askdo` foreground
implementation. It is **not** a proposed command syntax, a host install
instruction, or approval for a cutover. With a controlling TTY, the current
default is foreground on the caller's original terminal. Without one (the
normal sandboxed-agent case), `askdo --reason ... -- /absolute/command`
selects detached execution automatically while the CLI waits synchronously and
relays captured stdout/stderr. `--detach` is an optional override for a TTY
caller, not a mandatory agent flag. Detached root stdin is `/dev/null`, not
caller stdin: this is not full regular-sudo parity.

## What shipped in source

- Review, frozen manifests and Telegram approval remain broker-owned; optional
  AI review does not replace human approval unless an explicit eligible
  risk-based auto-approval grant is configured for a **detached** job.
  Foreground always requires a human decision. **NO AI REVIEW** never becomes
  an automatic execution grant.
- Foreground: the `askdo` client receives a short-lived one-use handoff after
  approval. A caller with an original controlling TTY in the single `askdo`
  group invokes the root-owned, non-setuid `/usr/local/libexec/askdo-launch`
  through `/usr/bin/sudo -n` with **no arguments**. The narrow rule covers only
  this helper and disables sudo's private PTY for it. No separate foreground
  group is needed. The helper measures the original terminal and asks the root
  broker for the verified, frozen launch; the broker consumes the grant before
  sending the executable and CWD fd.
  This is not general passwordless sudo for members of the `askdo` socket
  group. The approved root editor can still change files or run subprocesses
  beyond the initial argv: this approval gate is not a sandbox.
- Detached: no controlling TTY, or explicit `--detach`, selects the existing
  service-owned `SystemExecutor`, with no TTY and retained stdout/stderr. The
  earlier idea of one shared helper execution engine for both lifetimes **has
  not been implemented**.
  Foreground and detached must not be described as the same engine or as a
  no-runner architecture.
- Rootless/container tests cover Ctrl-C, stop/resume and terminal resize for
  the foreground helper. A disposable sudo/container test exercised abrupt
  terminal disconnect and observed honest `unknown` with the child exiting.
  Real SSH-host disconnect behavior under host sudo policies and manual
  cutover remain **unverified**. A missing completion after grant claim is
  `unknown`: inspect host effects and never blindly retry.

**This note makes no live-installation claim.** Any deployment needs a
separately approved install and service start; no live SSH-host TTY-disconnect
test is claimed by this documentation. Consult the
[clean installation guide](clean-cutover.md) before any handoff. See
[architecture](architecture.md) and [client protocol](protocol-client.md) for
the implemented lifecycles.
