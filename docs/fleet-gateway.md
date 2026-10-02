# Fleet gateway design

**Status: implemented in source; not present in the `v1.0.0-rc.1` release
binaries.** This document records the agreed objectives and boundaries the
implementation follows. For concrete setup and operations see
[fleet-setup.md](fleet-setup.md); for the wire contracts see
[configuration](configuration.md) and the protocol documents. Existing
standalone installations remain supported and unchanged.

## Goal

Configure model providers, Codex OAuth and Telegram approvals once, while each
server or workstation keeps its own inspection permissions, auto-approval
policy and privileged execution.

**Centralize credentials and approvals, not root execution.**

```text
RPi ──────────┐
Main server ──┼── askdo gateway ── Model providers
Workstations ─┘                 └─ Telegram
                  │
                  └─ Decision returns to the originating host
                     → its local askdo authorizes and runs the command
```

## Responsibilities

| Central gateway | Local askdo on each host |
|---|---|
| Provider endpoints, model choices and API keys | Kernel-authenticated submitting user |
| One authoritative Codex OAuth login/refresh path | Captured command, working directory and script input |
| Telegram bot tokens, admins and notification routing | Allowed read roots, deny paths and sensitive-file masks |
| Model API proxying | Reviewer loop and local inspection tools |
| Approval cards and one update listener per bot token | Auto-approval ceiling and submitter's local preference |
| Authenticated approval results and delivery receipts | Durable job state, one-use dispatch and retained output |

The gateway does not need fleet SSH keys, sudo access, a general remote-command
API or direct access to hosts' filesystems. It is nevertheless a trusted
approval authority: hosts accept its authenticated decision proof for pending
requests, subject to their own checks.

## Configuration

The gateway owns shared provider credentials and admin/bot configuration.
Static API keys and mutable OAuth tokens stay there rather than being copied
to every machine. A single owner refreshes the Codex session, avoiding hosts
independently rotating and overwriting copies of the same token file.

Each host needs a gateway address, a stable host identity, its own enrollment
credential, and its local policy. Enrollment credentials must be individually
revocable; one fleet-wide client key would lose host isolation.

Example policy intent, not a new configuration schema:

| Host | Highest automatically approvable security risk |
|---|---|
| Raspberry Pi | 4/5 |
| Main server | 2/5 |
| Workstation | Off until its owner opts in |

The host's root-owned ceiling remains authoritative. A submitter may choose a
stricter preference, not a higher ceiling. Changing a shared model profile
must not widen read roots, remove sensitive masks or enable auto-approval.
Existing always-human cases, including captured scripts and critical risk,
remain human decisions. Job databases and execution grants are not synced.

## Model review stays attached to the host

The local reviewer sends model conversations through the gateway. The gateway
handles provider authentication and proxies responses, including structured
tool calls, back to that reviewer.

Filesystem and webfetch tools still execute locally under that host's limits.
Only permitted evidence reaches the model; the gateway cannot ask for an
unrestricted directory dump or bypass the local broker's inspection policy.

A LAN gateway does not automatically make a cloud model local. Any local-only
review policy must be enforced against the actual upstream model route, not
merely the gateway's address.

## Request and approval flow

1. The local broker authenticates the caller and captures the requested
   operation using its existing lifecycle. The agent cannot supply a trusted
   submitting UID or choose another host's identity.
2. The local reviewer uses the model proxy and local tools, then produces its
   report. The broker freezes the command/input and report before requesting
   approval.
3. The host submits an approval ticket to its allowed gateway channel. The
   selected recipient set is frozen for that ticket; later routing changes do
   not retroactively change who can decide it.
4. The gateway sends the compact cards and runs **one Telegram update listener
   per bot token**, routing callbacks among pending tickets. Different hosts
   can wait concurrently; a long-lived card must not block the whole fleet.
   Each host's existing local queue behavior is otherwise unchanged.
5. The gateway validates the Telegram user/chat/message/nonce and returns an
   authenticated result. For multiple recipients, the first valid Approve or
   Deny wins and other cards are closed best-effort.
6. The originating broker verifies the result's authority and binding,
   revalidates its frozen operation, and atomically consumes the decision.
   Denial executes nothing. Approval uses the existing local broker executor
   or original-terminal helper; no command is executed by the gateway.

Automatic approval remains a **local** policy decision after review. The
gateway must provide a verified Telegram delivery receipt for the required
informational notice before the host commits automatic dispatch.

## Identity and decision binding

Local job IDs are installation-local, so the gateway identifies a ticket by
**stable host ID + local job ID**, not a job ID or hostname alone.

Approval proof must bind the host, job, one-use nonce, frozen manifest digest,
decision and expiry. The deciding admin identity and Telegram card/chat IDs
remain auditable. The root broker verifies the gateway's proof, not merely
fields claimed by a model or a submitter. The exact proof format is a protocol
design decision, not specified here.

One host's enrollment credential must not permit impersonating another host,
editing gateway admin routes or minting approvals. Replayed, expired,
wrong-host or changed-command decisions cannot authorize execution. Gateway
credentials and any decision-verification material join the existing local
credential masking rules.

## Failure and recovery

- Gateway unavailable: new reviews/approvals wait or fail closed according to
  their lifecycle. There is no silent direct-provider, raw-sudo or automatic
  approval fallback.
- Commands already dispatched keep running locally; status, output and
  reattachment do not depend on the gateway staying online.
- Reconnecting a host recovers the same ticket/job, not a new submission.
  Repeated delivery of a decision cannot cause a second dispatch.
- Gateway restart recovery needs only approval-ticket/delivery bookkeeping,
  not a copy of every host's execution database or raw reviewer logs.

## Keep the first version small

Use one optional gateway mode/service, the existing upstream provider adapters,
one Telegram listener per configured bot, and outbound authenticated HTTPS
from hosts. No inbound fleet SSH access is needed.

Do not add a distributed execution engine, job-database replication, voting
quorums, a plugin framework, a service mesh or high-availability cluster to
the first version. Standalone mode keeps its current direct-provider/direct-bot
configuration. The concrete command names, configuration fields, enrollment
and recovery wire formats that this design called for now live in
[configuration](configuration.md) and [fleet-setup.md](fleet-setup.md).

## Validation requirements

- Two hosts sharing a bot can receive decisions concurrently, including when
  their local job IDs collide. Cross-host decisions and replay are rejected.
- The same review score yields different permitted automatic behavior under
  different local ceilings; neither a gateway reply nor a shared profile can
  raise a host's ceiling or bypass its inspection restrictions.
- Concurrent model requests use one authoritative OAuth refresh path without
  stale-token overwrite; local-only routing does not escape to cloud models.
- One Telegram listener handles multiple tickets and recipient sets without
  consuming another ticket's callbacks. Partial notification delivery blocks
  dispatch, including automatic dispatch.
- Gateway loss/restart/reconnect never duplicates a root operation, and local
  monitoring of an already-running job continues during the outage.

Related: [existing architecture](architecture.md), [configuration](configuration.md),
[client protocol](protocol-client.md) and [reviewer tools](review-tools.md).
