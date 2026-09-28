# Architecture

askdo has one Go executable with client, root daemon and unprivileged reviewer
modes, plus a separate root-owned, non-setuid foreground helper `askdo-launch`.
These are distinct processes with different trust levels. The client/broker
socket, broker/reviewer private pipe and broker/helper root-only handoff have
separate strictly validated protocols.

## Process roles

### Client (unprivileged, untrusted beyond authentication)

Any invocation without a mode word — and the `status`, `attach` and `cancel`
subcommands — runs client mode (`internal/client`). The client runs with the
calling user's privileges. It holds no authority of its own: Unix socket
permissions admit only root and members of the `askdo` group. The daemon
still obtains the kernel-verified peer UID (`SO_PEERCRED`) to record job
ownership and restrict status, attach, and cancel to that UID. The
executable is not setuid and carries no file capabilities. A caller with a
controlling TTY defaults to v4 `foreground` and, after approval, uses the
narrow fixed-helper sudoers rule available to `askdo` members. Without a
controlling TTY (as with a sandboxed agent's Bash-tool invocation), the client selects
v4 `detached` automatically; `--detach` is an optional TTY-caller override,
not a requirement for agents. No separate `askdo-foreground` membership is
required by the current helper rule. The client submits a job, then blocks
following events until a terminal outcome, a local `--timeout`, or an
interrupt. A detached client's lifetime never governs a
committed operation; foreground execution follows the original human terminal,
and loss of helper tracking after commit is `unknown`, not a retry signal.

### Daemon / broker (root, trusted)

`askdo daemon` requires effective UID 0 (anything else exits 125). It is
the only writer of job state and the only authority that commits a privileged
dispatch. Detached children launch through its executor; the foreground
helper launches only after claiming a broker-authenticated one-use grant.
At startup it:

1. Loads and validates `/etc/askdo/config.json` (or `--config`).
2. Probes `openat2` `RESOLVE_*` support and refuses to start without it
   (host content inspection would be unsafe). Inspection additionally
   requires `statx` `STATX_MNT_ID` and fails closed without it; in practice
   this means kernel 5.8 or newer.
3. Creates `/run/askdo/` (root:askdo 0750), the request socket
    `request.sock` (root:askdo 0660) and a separate root-only `launch.sock`.
4. Opens the durable store (`/var/lib/askdo/jobs.sqlite3`) and calls
   `MarkRestartAmbiguous` plus `SweepExpired`, so nothing from a previous
   daemon lifetime is ever revived (see *Restart semantics* below).
5. Serves at most 64 concurrent client connections and a FIFO job queue of
   depth 8. The queue worker serializes review and notification sessions, so
   at most one reviewer process is active. A foreground job leaves the queue
   when its approved handoff grant is ready; its subsequently launched terminal
   child can overlap another job's review or detached execution.

Before submitting an operation the client reserves a globally unique
`YYYY-MM-DD_#N` job ID over its own socket connection and prints that same
ID before sending the submit frame on a second connection. The store owns the
daily sequence and reservation tombstone; reservation alone neither stages a
command nor permits dispatch. The broker owns the spool tree
(`/var/lib/askdo/jobs/<id>/`, root-only
0700 per job), the descriptor-relative read-only inspection boundary
(`internal/inspection`, openat2-based), the approval-manifest freeze, and the
dispatch gate. Detached operations still use the daemon-owned
`SystemExecutor`; foreground operations use the separate root-only helper
after an approved one-use handoff. This is **not** a unified helper engine.

### Foreground helper (root, fixed entry point)

`/usr/local/libexec/askdo-launch` accepts no caller-selected argv or cwd and
requires root EUID. The TTY client invokes it via
`/usr/bin/sudo -n /usr/local/libexec/askdo-launch` under the narrow
`%askdo` sudoers rule, with no sudo PTY. The helper independently
opens the original controlling terminal, verifies the broker socket is root,
and presents a token/digest and measured terminal identity on the root-only
launch socket. The broker checks the originating UID, live terminal session,
frozen manifest and CWD, and atomically consumes the one-use grant before
sending the exact launch spec and CWD descriptor. The helper runs the child on
that original TTY and reports exit/signal; missing completion after commit is
`unknown`. It is not a general sudoers membership rule. Ctrl-C, stop/resume
and resize have rootless/container test coverage. A disposable sudo/container
test exercised abrupt terminal disconnect and observed honest `unknown` with
the child exiting. Real SSH-host disconnect behavior and host cutover remain
unverified.

### Reviewer / worker (`askdo-review`, unprivileged, code trusted / output untrusted)

`askdo reviewer` is the same binary re-executed by the broker as the
dedicated unprivileged `askdo-review` account (it refuses to run as root). It
reads no configuration file; everything it may know arrives in the one
immutable `bootstrap` message on its private pipe. It talks to the broker
over that pipe (its stdin/stdout), to configured model endpoints over HTTP(S),
and to the Telegram Bot API. The model receives no shell, process-execution,
file-write, browser, MCP or delegation tools. Three path tools
(`read_path`, `list_path`, `search_path`) request bounded filesystem work
through the broker for model-chosen paths; final-review submission runs in
trusted worker code. The model chooses which candidate files to inspect; the
broker enforces access policy, credential masking and read limits on every
call and discloses what it withheld to the operator; it does not choose or
score the files the model reads.
See [review-tools.md](review-tools.md) for tools and limitations. Model output
is treated as untrusted data: the reviewer's *code* validates the model's
report against a fixed schema, and the *broker* re-validates the report and
the model history before freezing. If AI review is skipped by policy or all
typed provider availability failures are exhausted (without `--review=yes`),
the same worker sends a **NO AI REVIEW** Telegram request without a model
report; it never substitutes invented risk, effects or reversibility.

## Trust boundaries

```text
  untrusted  agent/human ──(Unix socket, SO_PEERCRED)──▶ BROKER (root, trusted)
                                                   │ private pipe (stdin/stdout)
                                                   ▼
  untrusted model output ◀──(HTTPS, bounded)── REVIEWER (askdo-review, unpriv.)
                                                  │ Telegram Bot API (outbound only)
                                                  ▼
                                            OPERATOR (human unless eligible policy grant)

   approved original-TTY foreground: client ──sudo -n (narrow rule)──▶ askdo-launch
                           helper ──root-only launch.sock, one-use grant──▶ BROKER
  approved detached: BROKER ──SystemExecutor──▶ root process (no TTY)
```

- The submitting agent and everything it sends (argv, bundle bytes, reasons)
  are untrusted input.
- All model-generated content is untrusted advice, never authorization. By
  default authorization is the human's one-use Telegram decision; an explicit
  root grant can authorize only an eligible low-risk detached AI-reviewed request after
  dispatch checks and durable audit. Trusted
  reviewer code polls Telegram and validates the callback's operator ID, chat,
  card, nonce, expiry and first use. The root broker does **not** independently
  poll Telegram; it trusts that code's decision message, then verifies its
  digest, operator ID, card ID, pending state, expiry and one-use status under
  the dispatch lock. These broker checks do not independently authenticate a
  Telegram callback.
- The broker trusts: the host, the installed binary, the configuration, the
  reviewer code, and the operator's Telegram account.
- askdo is an approval gate, not confinement: an approved program runs
  as root and can make persistent changes to the host.

## Job state machine

States are the durable store states (`internal/store`); every transition is a
guarded compare-and-swap committed to SQLite.

```text
                 submit
                   │
                   ▼
               queued ──────────────────────────────┐
                 │                                  │
                 ▼ (queue worker starts)            │ cancel / client
             reviewing ───────────┐                 │ timeout / deadline
                 │                │ cancel/deadline │ / shutdown
   review_complete + freeze OK    ▼                 ▼
                 │            cancelled ◀───────────┘
                 ▼
           awaiting-human ─── deadline / approval TTL ──▶ expired
                 │   │
                 │   └── operator deny ────────────────▶ denied
                  │ operator approves: foreground → awaiting-handoff
                  │ operator approves: detached → starting
                  ▼
      awaiting-handoff (foreground only: one-use grant, pre-commit)
                  │ helper claims grant
                  ▼
              starting  (durable dispatch commit; detached auto grant also enters here from reviewing)
                 │
                  ▼ detached launch confirmed / foreground handoff sent
             running ── exit / signal ────────────────▶ finished
                 │
                 └── tracking lost after confirmed start ─▶ unknown
```

Terminal states: `finished`, `cancelled`, `expired`, `denied`, `failed`,
`unknown`. `failed` is not drawn above: any pre-dispatch review or
infrastructure failure (review rejected, worker error, capture failure, etc.)
transitions the job from `queued`/`reviewing`/`awaiting-human` to `failed`,
and a confirmed launch failure (the process never started) transitions
`starting` → `failed` for a confirmed detached launch failure. Foreground
handoff errors after grant claim are ambiguous (`unknown`). An unclaimed
foreground handoff can expire/cancel before execution.

`unknown` is terminal for transition purposes: an ambiguous dispatch must
never be retried.

### Restart semantics

At startup `MarkRestartAmbiguous` rewrites in-flight rows from the previous
lifetime, in one transaction:

| Previous state | Becomes |
|---|---|
| `starting`, `running` | `unknown` |
| `awaiting-human` | `expired` |
| `queued`, `reviewing`, `awaiting-handoff` | `cancelled` |

No in-memory queue entry, worker, deadline timer, or pending approval survives
a restart, and nothing is resumed. `SweepExpired` additionally backstops
pre-dispatch deadline expiry at startup and on each hourly retention pass.

## The capture → review → freeze → Telegram → dispatch pipeline

One pass through the pipeline per job (`internal/broker/job.go`):

1. **Reserve, submit & spool.** The client first receives and prints the
   canonical job ID; the broker then accepts a v4 submit for that UID's
   reserved ID, stores the byte-exact submit body and
   creates the job spool dir. In bundle mode the submitted files are staged
   into `bundle/` at submit time (`captureSubmittedBundle`).
2. **Capture.** On dequeue, `queued` → `reviewing`. In argv mode the broker
   performs **metadata-only** `argv[0]` resolution as execution preflight:
   it resolves symlinks and stats the target to prove a regular executable
   file, but never opens, hashes, or reads its content — including any
   shebang line. Host content reaches the reviewer only when the model
   chooses to read it through its path tools during review, as bounded
   per-call reads with no retained capture. In bundle mode the
   client-submitted files were already staged at submit time; a staged file
   matching `inspection.sensitive_masks` (or named in the client's
   `sensitive_inclusions`) is marked `masked`, stays root-only for execution,
   and is withheld from every reviewer path tool. The capture index records
   each staged bundle file with `path`, `size`, `sha256`, and `masked`.
 3. **Review.** The broker starts one reviewer process, sends the `bootstrap`
    (frozen operation — whose model-visible view includes mode, argv/entry/args,
    cwd, reason, target/submitter identity, host/container, and fixed non-secret
    launch variables — config projection, deadlines), then serves
   `inspect_request`/`inspect_result` exchanges until the worker sends
   `review_complete` or, for exhausted typed provider availability, a distinct
   `review_unavailable` outcome. Policy-exempt jobs bypass the model session.
   Interleaved `progress` frames are forwarded to client subscribers.
4. **Freeze.** For reviewed jobs the broker re-validates the report and model
   history against the wire schema (the final history entry must be a
   successful configured model), re-verifies the caller's working-directory
   identity, re-hashes every staged bundle file (re-opening the staged tree
   live to detect change-after-staging), collects the withheld references it
   observed during the job, writes exact approval-manifest bytes
   to `approval.json`, fsyncs, records the SHA-256 digest durably, and sends
   `frozen` with the digest, the report, and the withheld facts. Failure sends
   `review_rejected` (`invalid_report`, `evidence_changed`, `broker_error`)
   and fails the job. Approval-only jobs instead freeze
   broker-verified operation facts and a code-generated reason/history without
   a model report; cwd/staging failures still fail closed.
 5. **Telegram.** The worker sends all reviewed summary parts (chunked ≤ 4096
    runes), including factual credential-withholding notices. For manual
    approval it then sends the nonce-bound Approve once / Deny / Details card,
    reports `notification_sent`, and polls for the authenticated operator's
    one-use `decision`. The broker records `reviewing` → `awaiting-human` and
     binds the card ID, digest and expiry. Eligible detached auto-approved
     reviews instead send a button-free informational notice and
     `auto_notification_sent`; there
    is no callback, fabricated human operator or approval-card ID. A **NO AI
    REVIEW** job always takes the manual path and says the model did not assess
    consequences or risks.
  6. **Dispatch.** Manual approval re-checks the digest, operator/card IDs,
     pending state, expiry and deadline before consuming the decision. Detached
     manual approval durably commits `awaiting-human` → `starting`. Auto-approval requires
    acknowledged notice delivery, clean worker exit and the same prelaunch
    host/CWD/manifest/bundle checks; the store atomically rechecks the current
    UID preference, score, administrator cap, digest, deadline and reviewing
    state while recording an audit of kind `auto` and committing `reviewing`
    → `starting` for detached jobs. Foreground approval instead issues a
    short-lived one-use grant to the original client (`awaiting-handoff`);
    after sudo starts the helper, the broker verifies and atomically claims
    that grant to commit `starting`. Neither path retries an ambiguous start.
     Detached `SystemExecutor` then launches the frozen operation with a
     verbatim argv (no shell), an explicit minimal environment
   (`PATH=/usr/bin:/bin`, `HOME=/root`, `LANG=C.UTF-8`, plus
     `ASKDO_BUNDLE` in bundle mode), the caller-submitted cwd bound by
     directory identity at submission, stdin from
      `/dev/null`, and no inherited environment or TTY. Headless root stdin is
      not passed through from the client; synchronous stdout/stderr observation
      is not full regular-sudo parity. A confirmed launch marks
     `starting` → `running`; output drains into bounded per-stream logs from
     launch, independent of any subscriber. Foreground uses the same frozen
    argv/environment and bound CWD but inherits the verified original human
    TTY through `askdo-launch`; it is not captured into the daemon's detached
    stdout/stderr spool.

The client obtains `cwd` from its current working directory. Both argv and
bundle operations execute there; the broker holds and rechecks the submitted
directory identity through dispatch. In bundle mode the entry script is
launched by absolute path from the staged bundle, and `ASKDO_BUNDLE`
points to that staged dependency directory. Relative paths in scripts still
resolve from the caller's cwd, so captured dependencies should be referenced
explicitly, for example `"$ASKDO_BUNDLE/helper.sh"`.

Bootstrap also carries the authenticated submitter UID and a display name
looked up from that UID, the daemon's actual hostname, and best-effort observed
container metadata. The Telegram summary uses code-generated HTML bold section
 labels, the same canonical job ID, and a Bash `<pre>` block for the shell-quoted command display; quoting
is display-only and execution uses the original argv. The card shows the exact
cwd and submitter name plus UID. It does not infer or claim a physical hostname.

Denial commits `awaiting-human` → `denied` and executes nothing. A lapsed
approval commits `awaiting-human` → `expired`.

**Uninspected executables carry no source-byte pin.** Because argv-mode
preflight is metadata-only, a host executable the reviewer never
chose to read has no content hash in the frozen manifest: the manifest
binds the resolved absolute path, the exact argv, the authenticated submitter, the cwd
identity, and the SHA-256 of every staged bundle file. Approving such a job
is an explicit **operator assumption** that executing the metadata-resolved
path is acceptable without reviewed bytes. The model selects its own reads;
the approval gate does not require any file content at all.

## Model fallback model

Review uses whole-review fallback over the ordered `review.models` list
(`internal/reviewer/fallback.go`):

- Each job starts at the first choice; each choice gets one fresh, independent
  provider session (its own key material and continuation state — nothing is
  shared across vendors). Only one session runs at a time.
- **Typed availability failures** — quota/rate, transport, provider-request
  timeout, invalid key/model/endpoint, malformed provider response — are
  recorded and advance to the next choice.
- **Safety refusals** and **inspection/review failures** (broker errors,
  changed evidence, malformed-after-correction, exceeded turn bounds) stop
  the review entirely; there is no model shopping or approval-only fallback
  after a review failure.
- There are no retries, backoff, cooldowns, or health tables. Deadlines (the
  earlier of the client wait deadline and `review.total_timeout`) are computed
  once from the immutable bootstrap and never reset across choices.
- Each attempt is bounded by `max_model_calls_per_attempt` turns and
  `max_output_tokens` per response. Exhausting **all** choices through typed
  availability failures, with time still remaining and without `--review=yes`,
  offers an unreviewed human Telegram approval (never auto-execution). An
  elapsed deadline fails closed; forced AI review fails closed on exhaustion.

Under `review.mode: "approval_only"` any socket-group submitter bypasses the
model; under default `required`, only the configured OS login exemptions
(resolved to kernel UIDs) do. Agents running under an exempt UID share that
exemption. `--review=yes` always requires AI review, even for those submitters.

## Failure honesty

askdo distinguishes *failed* from *unknown* and never paper-covers an
ambiguity:

- **`failed`** is a known negative: review rejected, infrastructure error, or
  a *confirmed* launch failure (the executor's `Start` returned an error — the
  process never ran; recorded as result kind `launch_failure`). Pre-dispatch
  wrapper failures record result kind `wrapper`.
- **`unknown`** means the outcome is genuinely indeterminate: the broker
  confirmed the process started but lost tracking of it (a `Wait` outcome
  that is neither exit nor signal), or the daemon restarted while the job was
  `starting`/`running`. It means "inspect the host before deciding anything",
  never "safe to retry". `unknown` jobs are terminal, exempt from retention
  cleanup, and never auto-retried.
- **No auto-retry, anywhere.** The provider adapters perform one HTTP
  exchange per call (no retries); fallback advances rather than retries; a
  dispatched operation runs at most once.
- **At-most-once dispatch.** Detached `awaiting-human` → `starting` or
  foreground `awaiting-handoff` → `starting` is the durable launch gate.
  The one-use decision/grant is consumed before its dispatch commit;
  pre-launch revalidation re-hashes the frozen manifest,
  and a restart between commit and launch leaves a `starting` row that the
  next startup marks `unknown` — the child is reaped exactly once and never
  relaunched.
- **Telegram fails closed.** A summary part or card that cannot be delivered
  aborts the approval (no actionable card exists); Telegram unavailability
  never implies approval. Auto-approval's informational notice must be
  acknowledged by Telegram before dispatch; failure aborts rather than
  silently running. Button removal and callback acknowledgements on the manual
  path are best-effort cleanup only, never the authorization mechanism.

### Conditional risk-based auto-approval

Disabled by default and never applies to foreground. Root-owned login grants
resolve to UIDs and cap the
submitter's own preference; the effective threshold is `min(preference,
cap+1)`. Only a valid AI report score 1–4 strictly below the threshold is
eligible. Score 5, `unknown`, and **NO AI REVIEW** always use human approval.
Eligible requests send the reviewed summary and an informational
button-free Telegram notice; Bot API acknowledgement, worker clean exit,
prelaunch checks, unchanged digest, and atomic audit plus `StateStarting`
commit are required. Cancellation or revocation prevents execution. Scores are
self-reported: prompt injection and misclassification remain risks explicitly
accepted by an administrator who enables a grant. Credential masking remains
in force, but no machine completeness classifier is added.
