# Client ↔ daemon protocol

The client protocol runs over a Unix domain socket at
`/run/askdo/request.sock`. The daemon creates the socket on every
startup: directory `/run/askdo/` root:askdo 0750, socket
root:askdo 0660. Clients must additionally be in the `askdo` group
to connect at all. The same group also qualifies a TTY client for the narrow
fixed no-argv sudo helper *only* after an approved one-use handoff; it is not
general sudo access.

Current source submits protocol version `6` (`proto.FeedbackProtocolVersion`)
to opt into structured Request changes feedback. It retains explicit
`lifecycle` and a separate **v4 reservation** before submission, with optional
captured stdin under the v5 rules below. The daemon still accepts v4/v5
submissions and preserves their plain-denial result wire. Versions `2` and `3`
**cannot create new jobs** on this daemon. Historical jobs can still be queried by
their owning UID; v2's original lifecycle was implicitly detached, while v3
introduced explicit foreground/detached fields. **An older installed binary
is not changed by editing this source:** v6 feedback and automatic no-TTY selection
require a separately approved installation and service start/handoff.

## Framing

Every message in both directions is one frame:

```text
┌────────────────────────────┬──────────────────────────┐
│ length: uint32, big-endian │ body: UTF-8 JSON object  │
│ (4 bytes, network order)   │ (exactly `length` bytes) │
└────────────────────────────┴──────────────────────────┘
```

- Hard ceiling: 64 MiB (`proto.MaxFrameLength`). The daemon enforces an
  effective limit of `min(64 MiB, limits.max_inspected_bytes + 1 MiB)` and
  checks the advertised length *before* allocating the body.
- The body must be valid UTF-8 and valid JSON; writers enforce both.
- Decoding is strict: unknown fields are rejected (`proto.StrictUnmarshal`).
- The first frame on a connection must arrive within 10 seconds
  (`frameDeadline`); the deadline is cleared once the request frame is read,
  so long waits afterwards are unlimited.
- At most 64 concurrent connections; beyond that the daemon sends
  `{"op":"error","code":"too_many_connections",...}` and closes.

## Authentication

The kernel enforces submit access with Unix socket permissions: the socket is
`root:askdo 0660` under a `root:askdo 0750` directory. There is
**no second UID allowlist**; a non-member cannot connect. Review exemptions
are not socket access rules: under `review.mode: "required"`, configured OS
login names are resolved to peer UIDs at startup, and under `approval_only`
every socket-group member can submit for human approval. Before reading a
frame the daemon obtains `SO_PEERCRED` and fails closed if the peer's UID
cannot be determined. Nothing the client asserts (username, arguments,
environment) is used for authentication. All later operations on a job are
scoped to the owning UID: only the UID that submitted a job may
`status` or `attach` it. Cancellation of a new protected job additionally
requires its private creator capability, even before dispatch and on explicit
cancel frames within submit/attach connections. Disconnect/deadline cleanup
remains pre-dispatch-only; disconnect is never authority to kill a running job.

## Message types

### Client → daemon requests

All request bodies carry an `op` discriminator. New job IDs are canonical
`YYYY-MM-DD_#N` strings (real calendar day, positive unpadded int64 sequence)
allocated globally by the daemon. They are the **same** ID in the CLI,
Telegram, SQLite and reviewer logs; there is no hidden long job key.
Historical v2/v3 jobs may still have 32 lowercase hexadecimal IDs.

**`reserve`** — `{"op":"reserve","protocol_version":4}` on a separate
connection. The daemon binds a durable ID to the authenticated peer UID and
replies `{"op":"reserved","request_id":"2026-09-27_#1"}`. The client
must receive and print this ID **before** sending the command in a new v4
`submit` connection. Lost acknowledgements can leave unused reservations;
reservation creates no executable job, spool or Telegram approval. A reserved
ID is owner-scoped for status/cancel and cannot be submitted by another UID.

The current CLI opts in with `"cancel_capability":true` on `reserve`. Only
that private reply adds `"cancel_capability":"<64 lowercase hex>"`: 32 bytes
from the broker's cryptographic RNG. The allocation transaction binds its
SHA-256 hash to `(peer UID, job ID)`. The bearer is disclosed exactly once;
status, attach, accepted/progress/result streams, duplicate submits, spool,
manifest, reviewer and Telegram never return it. A legacy reserve without the
opt-in still receives exactly the old two-field reply, with no new grant.

Before sending any operation, the CLI durably writes an exclusive random-named
0600 receipt under `$XDG_STATE_HOME/askdo/cancel-handles` (default
`~/.local/state/askdo/cancel-handles`, directory 0700), syncing file and directory.
It contains only the bearer, job ID, absolute socket path and informative host
name. Only `JOB_ID=...` and `CANCEL_HANDLE_FILE=/...` are printed, never the
bearer. If the private file cannot be saved, nothing is submitted. The receipt
survives interruption, timeout, disconnect and client exit. Automatic removal
requires an observed terminal result on that submitting/cancelling client;
otherwise keep it, or explicitly remove it yourself after checking status.
No cancel command searches a shared-UID cache by public job ID.

This is a cooperative, guess-resistant capability, **not an OS boundary against
malicious same-UID agents** able to read each other's files/memory. Do not share
receipt contents. Host metadata helps identify the endpoint; renaming a host
does not revoke the grant. The authoritative binding is peer UID plus job
capability at the receipt's socket. A different broker/job will not match.

Roll out matching client, broker and `askdo-launch` binaries together, with
separately authorized installation/service actions. Old strict brokers reject
the extension; the new CLI does not silently fall back to unprotected submit.
Protected foreground claims require a helper advertising `cancel_control`
**before** claim consumption. Old helpers still serve legacy jobs. Jobs created
without a grant cannot acquire one retrospectively. The jobs DB migrates from
schema 4 to 5, preserving historical jobs/reservations; older brokers cannot
open the newer schema. No optional cancellation feature gates daemon startup.

**`submit`** — create or retrieve a job:

| Field | Type | Rule |
|---|---|---|
| `op` | string | must be `"submit"` |
| `protocol_version` | int | current CLI: `6`; also accepts `4` (no captured stdin) and `5` (captured stdin required); v2/v3 new submits receive `upgrade_required` |
| `request_id` | string | previously reserved canonical ID owned by peer UID |
| `wait_timeout_ms` | int64 or null | optional; if present must be positive. See below |
| `reason` | string | required, non-blank after trimming |
| `force_review` | boolean | optional (`false` when absent); CLI `--review=yes` requires AI review even if otherwise exempt. `--review=no` cannot disable policy. |
| `mode` | string | `"argv"` or `"bundle"` |
| `cwd` | string | required; clean absolute caller working directory |
| `argv` | string array | argv mode only; see below |
| `entry` | string | bundle mode only; see below |
| `args` | string array | bundle mode only |
| `files` | object array | bundle mode only |
| `sensitive_inclusions` | string array | optional; see below |
| `lifecycle` | string | required in v4–v6: `"foreground"` or `"detached"` |
| `terminal_type` | string | required only for foreground; validated TERM token (1–128 ASCII-safe bytes), forbidden for detached. Hint only, not authenticated identity |

The CLI chooses foreground when the caller has a controlling `/dev/tty`,
and detached automatically when it does not (for example a sandboxed
agent's Bash-tool invocation). `--detach` is an optional override for a TTY
caller. When the caller's stdin is a pipe or a regular redirected file with
content, the CLI submits a v6 detached argv request that carries the
captured bytes (`captured_stdin_base64`, below); capturing forces detached
lifecycle even for a TTY caller. The client waits synchronously for either
result; detached stdout/stderr are captured in the spool and streamed to the
caller. Detached execution uses the daemon-owned `SystemExecutor`, with no
TTY: root stdin is the sealed captured input for a v5/v6 request, or `/dev/null`
when nothing was captured (older v4 detached jobs are always `/dev/null`) —
no stdin passthrough either way, and this is not full regular-sudo parity.
Foreground uses the original TTY, not a daemon PTY, and the fixed helper
sudoers rule is limited to `askdo` members with an approved one-use grant.

**argv mode** (`"mode":"argv"`): `argv` is required and non-empty; every
element must be non-empty; `entry`, `args`, and `files` must all be absent.
The daemon resolves `argv[0]` to an absolute host executable as metadata-only
execution preflight: symlink resolution plus a stat proving a regular
executable file. It does **not** open, hash, or read content (including any
shebang line) at this stage; host code is read only when the reviewer model
chooses to read it through its path tools during review.

```json
{"op":"submit","protocol_version":6,"lifecycle":"detached","request_id":"2026-09-27_#1",
  "reason":"Install jq for this task","mode":"argv",
   "cwd":"/work/project",
  "argv":["/usr/bin/apt-get","install","-y","jq"]}
```

For a forced review without a controlling TTY, the CLI form is
`askdo --review=yes --reason 'Check this' -- /usr/bin/id -u`. Captured-stdin
requests look like
`curl -fsSL URL | askdo --review=yes -- bash` or
`askdo --review=yes -- bash < installer.sh`.
With no configured model the broker refuses a review-required submit before
creating a job. If all configured providers fail with typed availability
errors, `force_review: true` fails closed; without it the human can receive a
**NO AI REVIEW** Telegram card (reason and sanitized failure history). Human
approval is always necessary for this no-review path; it never auto-approves.
For valid detached AI-reviewed reports only, an explicitly enabled root grant
and submitter preference may authorize an eligible risk score; foreground
always requires human approval, and a captured-stdin job is never
auto-approved. See [configuration](configuration.md). Safety refusal,
invalid final review, broker/capture/changed evidence and elapsed deadlines
never trigger that fallback.

### Captured stdin (protocol versions 5 and 6)

Before reserving, the CLI captures its own stdin **only** when it is a real
pipe or a regular redirected file (a TTY and any other descriptor type are
left uncaptured) and the content is non-empty. The capture happens on the
client, before job submission:

- At most 1 MiB (`proto.MaxCapturedStdinBytes`); a larger stream fails the
  submit with an error and runs nothing.
- The bytes must be valid UTF-8 text without NUL bytes.
- There is no capture timeout. Pipe reads honor the caller's cancellation
  (including `--timeout` deadlines and SIGINT) and the 1 MiB ceiling; a
  regular-file read may wait as long as the underlying filesystem takes.
- Capture never reads TTY stdin: an interactive caller is unaffected.

A captured request bundles the bytes into the submit itself as
`captured_stdin_base64` (canonical standard base64 of the non-empty, UTF-8,
NUL-free payload). The current CLI uses `protocol_version: 6`; the legacy v5
shape below remains accepted. Whenever captured input is present the only
valid shape is a **detached argv submit**; it cannot be combined with `--bundle`.

```json
{"op":"submit","protocol_version":5,"lifecycle":"detached","request_id":"2026-09-27_#3",
  "reason":"Review the piped installer","mode":"argv",
   "cwd":"/work/project",
  "argv":["/usr/bin/bash"],
  "captured_stdin_base64":"IyEvYmluL2Jhc2gK"}
```

The broker validates the decoded content against the same bounds, stages it
root-only in the job spool, and records only metadata (path `stdin`, size,
SHA-256) in the operation description the reviewer sees. The launched process
reads the exact frozen bytes from a sealed, immutable descriptor. Captured-stdin
scripts always require human approval; auto-approval never applies. AI review
runs when required by policy or requested with `--review=yes`; approval-only
requests retain their **NO AI REVIEW** card.

**bundle mode** (`"mode":"bundle"`): `cwd` is required, just as in argv mode.
`entry` is required (relative path of
the entry script inside the bundle); `argv` must be absent; `args` (optional)
is passed to the entry at execution; `files` is the captured bundle. Each
element of `files` is `{"path": "...", "content_base64": "..."}` where `path`
is a relative path and `content_base64` is standard base64 of the file's
bytes. Paths must be relative (no leading `/`, no `\`, no empty/`.`/`..`
components) and unique within the bundle. Contents must be valid UTF-8 text
without NUL bytes — both the client capture and the broker's staging
validation reject anything else.

```json
{"op":"submit","protocol_version":6,"lifecycle":"detached","request_id":"2026-09-27_#2",
  "reason":"Run the prepared script","mode":"bundle",
   "cwd":"/work/project",
  "entry":"run.sh","args":["--apply"],
   "files":[{"path":"run.sh","content_base64":"IyEvYmluL2Jhc2gK"}]}
```

The source CLI's `--script PATH [--] [ARG...]` is a convenience producer of
this existing bundle message, not a new protocol mode or wire field. It captures
only the selected file under its basename, uses that as `entry`, and forwards
trailing arguments as `args`. CWD, sensitive-file rules, staging limits and
bundle approval policy are unchanged; neighboring files are not collected.

`sensitive_inclusions` lists bundle-relative paths the client deliberately
included although they match the client's built-in default sensitive-file
excludes (the compiled-in well-known name conventions, e.g. `.git`, `.env`,
`.env.*`, `.envrc`, `.netrc`, `.ssh`, `.aws`, `credentials`, `*.key`,
`*.pem`, `*.p12`, `*.pfx`, `*.kubeconfig`, `id_rsa*`, `id_ed25519*`,
`id_ecdsa*`, `id_dsa*`, and further well-known secret names; the CLI flag is
`--bundle-include-sensitive PATH`, repeatable). Each entry must be a valid
relative path of a captured bundle file, and it must name a path the default
excludes would otherwise drop. The CLI emits one stderr warning per
inclusion.

The opt-in only overrides the **client-side** default exclude filter. The
broker classifies every bundle file against the daemon's own
`inspection.sensitive_masks` policy regardless of `sensitive_inclusions`, and
that classification always wins for model egress: an included sensitive file
is still staged root-only for execution, but `read_path` against it returns a
payload-free `withheld` result, and `list_path`/`search_path` omit it while
reporting a `skipped_masked` count (a search scope that names it directly is
likewise `withheld`). The reviewer never receives its
contents; on a reviewed job the operator-facing Telegram summary discloses it
through the broker-recorded withheld references. These masks match names, not
content: a secret under an ordinary filename is not excluded or withheld by
them.
The client also refuses bundle files with multiple hard links (including a
hard-link alias of a masked file) before reading their bytes; it cannot detect
a separate **copy** of secret values under an ordinary filename.

The client obtains `cwd` from its current working directory. The broker binds
that clean absolute directory's identity at submission and both argv and bundle
operations execute there. Bundle mode launches the entry from its absolute
staged path and sets `ASKDO_BUNDLE` to the staged dependency directory;
plain relative paths remain relative to `cwd`, so scripts must explicitly
reference captured dependencies through that environment variable.

`wait_timeout_ms` is a **client waiting budget**, never an execution-kill
timer. When present, the daemon stores an absolute deadline at submit time.
While the job is pre-dispatch, expiry of the deadline transitions
`queued`/`reviewing` → `cancelled` or `awaiting-human`/`awaiting-handoff` → `expired`, stops the
worker, and publishes a `wait_timeout` event. It also caps the approval
lifetime: the Telegram approval expiry is
`min(approval_ttl, remaining client deadline)` measured from send-complete.
The deadline never resets between stages and never terminates a dispatched
command.

For a foreground request, include `"protocol_version":6`,
`"lifecycle":"foreground"` and a valid `"terminal_type"` (for example,
`"xterm-256color"`), with the remaining operation fields as above. The broker
also checks authenticated peer PID/UID and controlling terminal evidence;
TERM is not proof of identity. If a verified terminal is unavailable the
broker replies `foreground_unavailable` before creating a job.

**`status`** — one-shot state query: `{"op":"status","request_id":"2026-09-27_#1"}`.
The daemon replies with exactly one frame: an `accepted` event carrying the
current state if the job is live (including an unsubmitted `reserved` ID), a
`result` event if terminal, or `{"op":"error","code":"not_found",...}`.
Historical 32-hex IDs remain eligible for owner-scoped status lookup.
The current CLI adds `"protocol_version":6` to status and attach requests to
receive structured feedback. Omit it for the byte-compatible legacy result;
support is negotiated per connection, not inferred from the job's submit version.
Status, attach and cancel validate IDs strictly: only canonical syntax or
historical lowercase 32-hex syntax is accepted; a syntactically valid ID does
not bypass peer-UID ownership. A reserved ID cannot be attached before submit.

**`attach`** — replay and follow: `{"op":"attach","request_id":"2026-09-27_#1"}`.
For detached jobs the daemon first replays the retained `stdout.log` then
`stderr.log` as `stdout`/`stderr` events, then (for a live job) follows new
events like a submit connection. Foreground TTY output is not retained for
replay; attach can observe state/result but cannot reattach to the original
terminal or receive the handoff bearer. Only one attach subscriber per job:
a second concurrent attach gets `{"op":"error","code":"already_attached",...}`.
Attach never cancels the job on disconnect.

**`cancel`** — the creator uses:

```sh
askdo cancel --handle-file /path/printed/by/askdo/job-random.json
askdo cancel --handle-file /path/printed/by/askdo/job-random.json --force
```

The CLI reads only the explicitly provided private receipt. It sends the typed
`cancel_capability` wire credential with `op: "cancel"` and `request_id`; the
optional boolean `force: true` requests level 2 (`SIGKILL`) rather than level 1
(`SIGINT`, Ctrl-C). No raw-secret CLI flag/environment variable exists. The
capability cannot approve, modify, rerun or target a process ID/UID/signal.

Before dispatch, cancellation prevents launch and returns an honest `cancelled`
result (including revoking an unconsumed foreground handoff). Once committed,
the broker durably records monotonic desired level **before** notifying this
job's owned controller, independently of the execution queue. It promptly
returns only to the requester:

```json
{"op":"cancel_ack","request_id":"2026-09-27_#1","state":"running","desired_level":1,"delivery":"pending"}
```

`pending`, `succeeded`, `failed` or `unavailable` describe control delivery,
**not actual exit**. Repeat cancellation can observe its durable delivery;
repeating a level never resends a signal. Explicit force escalates once. There
is no automatic timeout, retry, escalation or new human approval. Early intent
survives the starting/controller-publication gap. A terminal job instead returns
its actual result. Continue with `status`/`attach`: a command may ignore SIGINT,
flush output then exit 0, or die by its actual signal. Nothing undoes already
performed side effects or erases the dispatch commit.

The legacy form `askdo cancel JOB_ID` / `{"op":"cancel","request_id":"..."}`
retains pre-dispatch-only, owning-UID behavior **only for jobs without a grant**.
After commit it still returns `starting`/`running`, not a false cancellation.
It cannot cancel a protected job at any stage: the broker refuses it with
`permission_denied` ("cancellation handle required"), and the CLI prints that
reason with the `--handle-file` remedy. With a handle, the CLI reports a refusal
without echoing broker text, so it cannot reveal the bearer. Explicit cancel frames on
submit/attach require the same credential but retain **pre-dispatch-only**
cleanup semantics (the client's view can lag dispatch). Running stop intent
uses a separate one-shot cancel exchange; acknowledgments are not broadcast
to other followers. Client disconnect/timeout still detaches after dispatch.

Execution groups include ordinary descendants and timeout wrappers, including
different-UID descendants when controlled by root. Signals are serialized with
final reap using Linux `waitid(WNOWAIT)`; a released/restarted/unknown controller
never signals a cached numeric PID/PGID. Detached execution owns its output-copy
pipes and joins them before final `cmd.Wait` reap and result publication,
preserving captured-input delivery. An exited leader remains unreaped as the
group's identity anchor while ordinary same-group descendants retain those
pipes. SIGINT and explicit force remain available during that drain; the real
leader exit status is preserved. Only after the drain is settled does final
reap disable group signaling.
Daemons escaping the job's process group/session are outside this authority;
there is no UID-wide descendant hunt.

**`auto_approval`** — the authenticated submitting UID's preference, not an
administrator grant. `{"op":"auto_approval","action":"get"}` reads it;
`{"op":"auto_approval","action":"set","threshold":2}` enables automatic
approval of detached score-1 jobs where the root grant permits it; foreground
jobs always require human approval. A threshold of `0`
disables the preference. SET accepts only `0` or `2`–`5`; GET forbids the
threshold field. Neither request contains a UID or administrator cap. The
broker binds it to `SO_PEERCRED` and rejects a positive threshold exceeding
the UID's root-configured cap. The response is
`{"op":"auto_approval_status","max_risk":1,"threshold":2,"effective_threshold":2}`;
`effective_threshold` is zero when disabled or ungranted, otherwise
`min(threshold,max_risk+1)`. The CLI exposes this as
`askdo auto-approve status|set N|off`. No preference request creates a job,
Telegram card or execution.

### Daemon → client events

**`accepted`** — submit accepted or deduplicated (or reserved status):

```json
{"op":"accepted","request_id":"2026-09-27_#1","state":"queued"}
```

`state` is the job's current state (`queued`, `reviewing`, `awaiting-human`,
`awaiting-handoff` (foreground), `starting`, `running`, or a terminal state for
a deduplicated resubmission).

**`handoff_ready`** — only on the original foreground submit connection (v4 or later)
after approval, never on `status`, `attach` or the general progress stream:

```json
{"op":"handoff_ready","request_id":"2026-09-27_#1","digest":"<64 lowercase hex>","token_hex":"<64 lowercase hex>","expiry_unix_ms":9999999999999}
```

This short-lived one-use bearer is not a launch command and must not be
logged or replayed. The client passes only token and digest through a pipe to
`/usr/bin/sudo -n /usr/local/libexec/askdo-launch`. The non-setuid helper
accepts **no** argv/cwd from the client; it obtains the original terminal and
claims the grant on root-only `/run/askdo/launch.sock`. The broker checks peer
root identity, original UID/terminal, frozen manifest and CWD and atomically
consumes the grant before sending the exact launch spec/CWD descriptor. The
helper reports exit/signal; after commit, lost completion is `unknown`, not
permission to resubmit. Only foreground completion/error/status travels on
the submit socket; stdout/stderr go directly to the original terminal, not
the base64 stream log. Rootless/container tests cover Ctrl-C, stop/resume and
resize; SSH-host behavior and host cutover remain unverified.

The matching helper re-execs only its fixed, no-argument root binary as a
per-job controller in a separate group of that **same original terminal
session**, using inherited root-parent/broker-authenticated sockets and the
original terminal descriptor. It is not a standalone daemon or an arbitrary
root-command interface. Bound cancel/ack frames use the existing consumed
claim's broker connection. Its receiver runs before child publication and
survives Ctrl-Z while the original wrapper group is suspended; only the owned
child group receives SIGINT/explicit SIGKILL (SIGCONT lets a stopped child
process its interrupt). Completion follows reap and terminal restoration.
Remote cancellation of a suspended job does not steal the foreground/modes
from a different terminal job. The deliberately suspended wrapper remains a
shell job until normal `fg` resumes it; status can already show the child's real
result. Native SSH/NAS acceptance is separate from rootless-fixture evidence.
If the original wrapper dies after handoff, its loss is not an implicit kill:
the owned controller can still receive explicit cancellation. It does not
fabricate a restored-terminal completion after losing that original wrapper;
the broker reports `unknown`, not permission to replay the command.
Broker-control loss alone also leaves a live original wrapper able to use
normal `fg`/Ctrl-C. Only when a command is stopped and **both** ownership paths
are unavailable does the helper report an unrecoverable controller error and
run its existing owned-child cleanup/reap. That is not a creator cancel request
or a fabricated completion: the broken helper connection remains `unknown`,
and cleanup does not take another terminal job's foreground or modes.

**`progress`** — non-terminal lifecycle progress:

```json
{"op":"progress","stage":"reviewing","detail":"review started"}
```

`stage` and `detail` are free-form within protocol bounds; stages seen in
practice include `reviewing`, `fallback`, `notifying`, `awaiting-human`,
`awaiting-handoff`, `starting`, `running`, `output`, `expired`, `failed`. The CLI
prints
`stage: detail` to stderr.
On a matching `accepted` event with state `queued`, the CLI also prints
`queued: broker accepted; review/notification pending`. That receipt does not
claim a Telegram card was sent; notification follows review, which may still
be waiting for the broker's review slot.

**`stdout` / `stderr`** — detached command output, base64:

```json
{"op":"stdout","stream":"stdout","data_base64":"MAo="}
```

`op` and `stream` always match (`stdout` or `stderr`). `data_base64` is
standard base64 of raw bytes — no sanitization on the wire (terminal-control
sanitization is a display concern). `truncated` is omitted unless true, once the
stream log reached `limits.max_log_bytes_per_stream` (a fixed marker is
appended to the retained log and excess bytes are discarded; the command's
pipe is always fully drained regardless).

**`result`** — terminal outcome:

```json
{"op":"result","state":"finished","exit_code":0}
```

`state` is a terminal state. `exit_code` (int) and `signal` (int) are
mutually exclusive and both optional: present only when the dispatched
command actually exited or died by a signal. `message` carries a human
explanation for wrapper outcomes (e.g. `"operation launch failed"`,
`"review or infrastructure failure"`, or the broker's failure detail).

**Request changes** uses terminal `state: "denied"`, never dispatches or
issues a foreground handoff, and has no command exit/signal. On v6 submit,
status and attach connections the result additionally carries:

```json
{"op":"result","request_id":"2026-09-27_#1","state":"denied",
 "decision":"request_changes",
 "feedback":{"uncertainties":["Backup not verified"],
   "warnings":[{"message":"Downtime possible","evidence":"Dependencies unverified"}],
   "suggestions":[{"issue":"Backup not verified","action":"Supply restore-test evidence","actor":"submitter"}]}}
```

The arrays come from the frozen report (`missing_context` becomes
`uncertainties`), with unsafe display controls stripped. Suggestion actors
are exactly `submitter` or `administrator`; all advice remains untrusted and
cannot change authorization. Missing suggestions are valid. The waiting CLI
and attach print this feedback to stderr; human status prints it to stdout,
and `status --json` exposes the structured result. The denial exit code stays
126. No automatic resubmission occurs: a correction needs a new reserved ID
and a full new review. Feedback is persisted atomically with denial in the
existing `result_json`, subject to normal retention; no DB schema migration.

Older strict clients cannot decode new result fields. The broker therefore
omits **both** `decision` and `feedback` for v4/v5 submits and status/attach
without v6, as well as legacy cancel exchanges: they see the unchanged plain
denial. Older brokers reject v6 requests; upgrade the matching binaries rather
than silently downgrading. Reservation and all other event shapes are unchanged.

**`wait_timeout`** — the client's waiting budget elapsed:

```json
{"op":"wait_timeout","request_id":"2026-09-27_#1"}
```

Sent after the pre-dispatch job has already been transitioned to `cancelled`
or `expired`; a terminal `result` follows. After a committed dispatch, a local
client timeout ends observation, not execution.

**`error`** — protocol or lifecycle error: `{"op":"error","code":"…","message":"…"}`.
Observed codes include `permission_denied`, `invalid_request`,
`foreground_unavailable`, `migration_in_progress`, `too_many_connections`,
`conflict`, `queue_full`, `broker_error`, `not_found`, `already_attached`,
`upgrade_required`, `not_submitted`.
The `migration_in_progress` wire code currently means the broker's admission
fence is active; it is not a required stage of a new installation.

## Submit dedup semantics

New IDs are globally unique and reserved by peer UID before submission;
historical rows remain keyed by `(peer UID, request_id)` and can have
cross-UID collisions. A v4/v5/v6 submit must use a reservation owned by its peer
UID. A captured-input submit body includes the captured stdin bytes, so any byte
difference is a conflict, not a dedup.

- Resubmitting with a **byte-identical** submit body is a no-op dedup: the
  daemon replies `accepted` with the current state and the connection follows
  the existing job. A concurrent first-submission race resolves the same way
   (`SubmitReservedJob`).
- Resubmitting the same `request_id` with **any** difference in the submit
  body is `{"op":"error","code":"conflict","message":"request ID has different contents"}`.
- Retention cleanup permanently retains compact identity rows for cleaned
  terminal jobs, so an old `request_id` can never become executable again —
  resubmission of a compacted ID is a conflict, not a new execution.

## Exit codes (CLI)

The blocking client maps outcomes to exit codes as follows; for foreground,
the helper's normal completion is reported via the broker and terminal I/O is
direct rather than streamed over this protocol:

| Code | Meaning |
|---|---|
| `0`–`255` (command's own) | `result` carried `exit_code`; the CLI exits with the command's verbatim status (including 0) |
| `128 + signal` | `result` carried `signal` (e.g. SIGKILL → 137) |
| `124` | client waiting timeout: `--timeout` expired (pre-dispatch the job is cancelled first; post-dispatch the CLI detaches and the operation keeps running) or a `wait_timeout` event was received |
| `125` | infrastructure/review failure, invalid config/usage, connection loss, terminal `failed`/`unknown`, rejected/unavailable cancellation, or legacy public-ID `cancel` against a committed job |
| `126` | terminal `denied`, `expired`, or `cancelled` before dispatch |
| `130` | SIGINT during the wait (pre-dispatch the job is cancelled first) |

A dispatched command may itself exit with 124/125/126/130; `status`/`attach`
output and the stored result (result kind `exit`/`signal` vs
`launch_failure`/`wrapper`/`decision`) distinguish the command's own codes from wrapper
codes.

`cancel --handle-file` exits 0 for a durable request with pending/successful
delivery, not proof of termination. A returned terminal result instead uses
the outcome codes above. Failed/unavailable delivery retains the receipt.
