# Clean installation alongside another service

This guide covers a **new askdo installation without migrating another
service's state**; an upgrade of an existing askdo installation preserves its
own database. No old service database or SQLite WAL copy is required. Installing
askdo need not stop another daemon: separate sockets and state directories
allow both installations to exist and even run at the same time, and askdo's
systemd unit does not force a conflict with another service.

**No live installation is claimed by this guide.** The v4
reserve-before-submit protocol, canonical `YYYY-MM-DD_#N` job IDs, no-TTY
synchronous client observation of broker-owned pipe execution, and single
`askdo` helper group describe the current source. The installer by itself does
not restart a running daemon. V2/v3 clients cannot submit new jobs to a v4
daemon; coordinate client and daemon versions.

**Telegram is the shared-resource exception to independent operation.** Never
run two active pollers or approval workflows against the same bot token at
once: updates or decisions may go to the wrong process. Use distinct bot
tokens for simultaneous operation, or arrange an operator-approved handoff
before starting askdo with a token another service already uses. With the
named multi-channel form, this holds per bot: each channel's token must be
unique among all running services, but the different bots of one askdo
installation each poll their own token independently (one bot serves a whole
job; a request is never fanned out across several bots).
During onboarding, the Telegram wizard can poll the bot to discover IDs; if
another process is polling that bot, supply the numeric operator and private
chat IDs manually instead. Separate bot tokens do not replace checking that
the two services have independent sockets and state.

## Prepare askdo without interrupting the other service

1. From the intended **source checkout** (verify it yourself; for a public
   release, prefer a verified upstream checkout or release), inspect
   `install.sh` and its `--help`, verify that the checkout is the intended
   source, and obtain the machine owner's approval before any host
   installation. Run `./install.sh`
   from that checkout as root only after approval. It builds from the local
   checkout, installs the askdo binary, helper, service, example configuration,
   accounts, groups, and directories; it does not enable or start the service.
   Do not stage from a remote script or an unverified copy of the checkout.
2. Configure askdo as root: add submitting users to the single `askdo` group
   and refresh their login/group credentials before submitting. Enroll each
   agent and human account with the operator's explicit approval. The narrow
   no-argv helper rule for approved original-TTY grants
   uses that same group; no second foreground membership is needed. Set up a
   reviewer with `askdo reviewer add` or explicitly choose
   `askdo review mode approval-only`;
   complete `askdo channel add telegram` with the intended bot token and IDs
   (`askdo channel add telegram NAME` for the named multi-channel form).
   Review `/etc/askdo/config.json`, credential file ownership/modes and
   inspection policy against [configuration](configuration.md). Telegram
   remains required even in approval-only mode; an empty model list alone does
   not enable approval-only behavior.
3. Run `askdo config check` as root. Resolve any validation errors before
   starting askdo. When ready, start/enable `askdo.service` from an independent
   root administration session (`systemctl enable --now askdo`); with a bot
   token another service already uses, first arrange the approved handoff so
   polling does not overlap.
   Installation alone does not prove a live cutover or authorize a test
   approval or root execution.

## Retire the other service only with separate approval

If a handoff requires downtime, obtain the machine owner's explicit
confirmation of the outage and timing **before** stopping the other service. Stop it only from
an independent root session, never through its own approval tool (which may
be waiting on the service being stopped). If retention is desired, after that
service is stopped make an optional backup of its state directory, including
the SQLite database and any `-wal` and `-shm` sidecars present. This is for
retention or independent recovery, **not** an input to askdo's new state.
Do not delete, purge, disable or remove the other installation without the
machine owner's separate explicit confirmation of exactly what may be lost.
None of these host actions are performed by this guide.
