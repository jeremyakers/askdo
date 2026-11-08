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
Main server ──┼── askdo-config gateway ── Model providers
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
| The release the fleet should run, who is offered it next, and when to pause | Downloading, verifying, activating and rolling back its own upgrade, and its opt-out |

The gateway does not need fleet SSH keys, sudo access, a general remote-command
API or direct access to hosts' filesystems. It is nevertheless a trusted
approval authority: hosts accept its authenticated decision proof for pending
requests, subject to their own checks. It can also name a release for hosts that
have not opted out to upgrade to (see [Gateway-pushed
upgrades](#gateway-pushed-upgrades)); that is data in its signed catalog, not a
command channel.

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
The gateway config may set `"reviewer_webfetch_enabled": true|false` (optional
top-level boolean) to control webfetch for all hosts; it is published in the
signed catalog and overrides each host's `review.webfetch_enabled`. If omitted,
each host's own setting applies (as it does with older gateways).
Hosts verify the catalog strictly, so hosts older than this release reject a
catalog that carries the field: upgrade every fleet host before setting it.
Hosts built with unknown-field tolerance (see
[unknown fields on the wire](architecture.md#unknown-fields-on-the-wire))
still verify the whole signed catalog but ignore optional catalog fields they
do not know, so a later optional catalog field no longer breaks them; such a
host simply does not apply a setting it does not understand.
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
   authenticated result. For multiple recipients, the first valid Approve,
   Deny, or Request changes wins and other cards are closed best-effort.
6. The originating broker verifies the result's authority and binding,
   revalidates its frozen operation, and atomically consumes the decision.
   Denial executes nothing. Approval uses the existing local broker executor
   or original-terminal helper; no command is executed by the gateway.

### Request changes wire compatibility

Reviewed cards add `r:<32-hex nonce>` beside existing `a:`/`d:`/`v:` callbacks.
The existing v1 signed decision/event shape gains only the action enum value
`request_changes`: binding, receipt hash, operator/chat/card, expiry, signature
domain and sequencing are unchanged. The gateway authenticates and consumes it
like Deny. The host verifies the same signed proof and denies without dispatch,
persisting feedback from its frozen report, not from callback text. Automatic
notice/approval behavior is unchanged.

Reports optionally include `suggestions` (see [worker protocol](protocol-worker.md)).
Empty/absent suggestions are omitted on the wire, preserving old display hashes
and signed fixtures. Older gateways use strict typed report decoding and reject
tickets **containing** the new field; tickets without it remain compatible.
Older hosts reject the new decision action rather than executing it. Upgrade
gateway and host/reviewer binaries before using Request changes. Client feedback
is separately negotiated with client protocol v6; older clients see plain denial.

Automatic approval remains a **local** policy decision after review. The
gateway must provide a verified Telegram delivery receipt for the required
informational notice before the host commits automatic dispatch.

## Gateway-pushed upgrades

The operator names one release for the fleet to run with `askdo-config gateway
upgrade-target TAG`, on the gateway host, through that host's usual Telegram
approval: one approval, not one per host (the operator guide is [upgrading a
fleet](upgrade.md#upgrade-a-fleet-from-the-gateway)). The gateway resolves the
release's `install-manifest.v1` from the official `jeremyakers/askdo` repository
when the target is set and keeps the release and the manifest's SHA-256 in its
database. The target is not a gateway configuration key and needs no restart.

**Trust.** The gateway names a release tag and a manifest digest. It never sends a
binary, a URL or a command. A host that applies pushed upgrades downloads the
release itself, only from the official repository, checks that the manifest has
the digest the gateway signed, installs only a release **newer** than the one it
runs, and then runs the same staged activation, with automatic rollback, as `askdo
upgrade`. A compromised gateway can at most make opted-in hosts install an
existing, newer official release, one at a time, or stall a rollout; it cannot
downgrade a host, install anything else, or touch a host that set
`fleet_upgrade.auto` to `false`. This is the one thing the gateway can cause a
host's root to do, and it is the reason a gateway should be as protected as the
approvals it already carries.

**Catalog.** The offer travels in the signed catalog as an optional member
addressed to the asking host:

```json
"fleet_upgrade": {"release": "v1.0.1", "manifest_sha256": "<64 hex digits>"}
```

It is omitted when there is no offer, so such a catalog is byte for byte what a
gateway without the member signs. Its members are optional on the wire as well: an
offer a host cannot act on is ignored and is never a reason to refuse the catalog,
and with it every review. The gateway sends it **only to a host that has reported
that it applies pushed upgrades**, so a host built before the member existed, which
never reports, never receives it and keeps working unchanged. Hosts built with
unknown-field tolerance (see [unknown fields on the
wire](architecture.md#unknown-fields-on-the-wire)) would ignore it in any case.

**Host status.** An enrolled host reports about itself with `PUT /v1/host-status`,
authenticated like every host request by its own credential; nothing in the body
can name another host.

```json
{"version":1,"hostname":"nas-01","release":"v1.0.0","auto_upgrade":true,
 "upgrade":{"operation":"up_…","release":"v1.0.1","state":"failed",
            "outcome":"rolled_back","detail":"…","updated_at":1783900000}}
```

`release` is the release the binary was built from (absent for any other build),
`auto_upgrade` whether the host will act on an offer, and `upgrade` the latest
upgrade receipt (or a `refused` result when the host declined an offer before it
made one). It reports something and asks for nothing, so it is a report under the
unknown-field rule: a field this gateway does not define is ignored. It is bounded
to 8 KiB, its text is reduced to bounded printable ASCII before it is kept or
shown, and the answer, `{"version":1}`, carries nothing a host acts on and is not
signed. A gateway from before the endpoint answers with an ordinary failure, which
the host ignores until its next report.

**Rollout.** The offer goes to one host at a time: the first to ask that applies
pushed upgrades and is older than the target, and it stays with that host until it
reports that it runs the target or how its upgrade failed. A result for the target
that is a failure, a rollback, unknown or a refusal pauses the rollout for every
host; so does a holder that reports no outcome within 45 minutes. A result counts
only when it differs from the one the gateway last saw from that host, so receipts
left from before the target was set, or carried in a host's first report, are never
mistaken for its outcome. Setting the target again starts afresh. The state lives in
four tables created beside the enrollments with `IF NOT EXISTS`; the database
version is unchanged, so a gateway from before them opens the same file and ignores
them.

**Notices.** Each concluded result is sent to the recipients of the reporting
host's default channel as an informational Telegram message with no buttons: no
card, no decision, nothing waits on it. It is delivered once per chat and retried
once a minute for up to thirty attempts.

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
- A gateway outage during a rollout fails hosts' reports and catalog reads, which
  they repeat at their next look. An upgrade already running does not depend on the
  gateway; its result is reported once the gateway is back.

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
