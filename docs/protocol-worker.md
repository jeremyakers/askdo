# Broker ↔ reviewer private pipe protocol

The broker (root) and the reviewer worker (`askdo-review`) communicate over a
private pipe: the worker's stdin (broker → worker) and stdout (worker →
broker). Nothing else shares this channel. This document is the public
reference for the wire schema implemented in `internal/proto/worker.go` and
`internal/proto/inspection_metadata.go`. The host-evidence additions below
are source-only, not in published rc.2 binaries; old strict decoders do not
accept their new fields/operations. Upgrade the host broker and reviewer
together before enabling optional capabilities.

## Process launch contract

The broker launches the worker as
`exec.Command("/usr/local/bin/askdo", "reviewer")` with:

- **Credentials:** the process runs with `syscall.Credential` set to the
  UID of the fixed named `askdo-review` account and the GID of the fixed named
  `askdo-review` group, with an empty supplementary-group list. The execution
  group is independent of the account's NSS primary group; that primary group
  is not inherited. Missing, invalid or zero role IDs fail closed. Root-started
  `config check --live` resolves the same identity before provider preparation,
  then clears supplementary groups and drops GID before UID for live checks. The
  reviewer binary refuses to run as root (exit 1). Bare `askdo reviewer` is
  worker mode; subcommands such as `askdo reviewer add` are operator CLI, not
  worker invocations.
- **Environment:** exactly `PATH=/usr/bin:/bin`,
  `HOME=/var/lib/askdo-review`, `LANG=C.UTF-8`. Nothing is inherited
  from the daemon's environment.
- **Working directory:** the directory containing the binary
  (`/usr/local/bin`).
- **File descriptors:** stdin/stdout are the private pipe; stderr is
  redirected to the job's root-owned spool file (`0600`, append). No other
  file descriptors are handed to the worker.
- **Concurrency:** at most one reviewer process is active at a time. The job
  queue serializes jobs; `processWorker` additionally refuses to start a
  second process while one is active.
- **Configuration:** the worker reads no configuration file. Everything it
   may know — model projection (possibly empty for approval-only), limits,
   Telegram settings, the frozen operation, deadlines — arrives in the single
   `bootstrap` message.

This process boundary is not a full OS sandbox: normal filesystem permissions,
ACLs and network access still apply. Choosing a dedicated execution group does
not disable the account's login or remove UID-specific/default ACL grants.
On ordinary Linux the installer still requires the account's NSS primary group
to be `askdo-review`. The automatic DSM path instead verifies a disabled native
account with NSS primary `users` (GID 100) and independently resolves the named
`askdo-review` execution group. It does not inherit the account's primary or
supplementary groups at runtime. Native DSM deployment/authentication acceptance
is still separate from the local installer adapter tests; see the README.

## Framing and decoding

Frames are identical to the client protocol: a 4-byte big-endian (network
order) uint32 length followed by a UTF-8 JSON body, hard ceiling 64 MiB,
length checked before allocation. Every body is one JSON object with a `type`
discriminator, decoded strictly:

- Unknown fields are rejected; required fields must be present and non-null,
  recursively (required arrays must not be null). Optional `omitempty` fields
  may be absent.
- Every message is direction-validated: a type valid in one direction is
  rejected in the other. Directions below are **B→W** (broker to worker) and
  **W→B** (worker to broker).
- Strings are UTF-8; structural strings reject NUL, while the content-bearing
  messages (`review_complete`, `frozen`, `progress`, `inspect_result`
  payloads — report fields, progress details, path content and search
  excerpts) tolerate escaped controls, including NUL, as data. Bounds below
  are enforced at decode time. Integers are JSON numbers within the stated
  ranges. "64 hex" / "32 hex" mean lowercase hexadecimal of exactly that
  length (`^[0-9a-f]{64}$` / `^[0-9a-f]{32}$`).

## Message reference

### `bootstrap` (B→W)

The immutable job bootstrap; the first and only message of its kind.

| Field | Type — bounds |
|---|---|
| `type` | `"bootstrap"` |
| `host` | string ≤ 256 (trusted daemon hostname for the Telegram card) |
| `target_uid` | uint32 (execution identity of the dispatched process) |
| `submitter_uid` | uint32 (kernel-authenticated submitting peer UID) |
| `submitter_name` | string ≤ 256 (host account name looked up from that UID; display only) |
| `container` | string ≤ 128 (best-effort container label observed by the daemon; empty when unavailable) |
| `request_id` | canonical `YYYY-MM-DD_#N` job ID; legacy 32-hex IDs remain valid for historical status |
| `operation` | object, below |
| `config_projection` | object, below |
| `deadline_unix_ms` | int64 ≥ 0 (0 = no client deadline) |
| `review_deadline_unix_ms` | int64 > 0 (client-now + `review.total_timeout`) |
| `approval_only` | optional bool (policy bypass or all broker-preflight provider failures; never a forced review) |
| `preflight_failures` | optional array of typed broker-classified provider availability failures; omitted otherwise |

**`operation`:**

| Field | Type — bounds |
|---|---|
| `mode` | enum `"argv"` \| `"bundle"` |
| `captured_stdin` | optional argv-mode v5 metadata: logical bundle `path: "stdin"`, byte `size`, SHA-256 digest, and optional `delivery_kind` enum `"sealed_memfd"` (modern sealed seekable file, the historical default) | `"socket_stream"` (legacy non-seekable owner-approved stream, selected only on `memfd_create` `ENOSYS`); no script contents |
| `argv` | argv mode: array 1–64 of strings, each ≤ 4096; must be absent/empty in bundle mode |
| `entry` | bundle mode: string ≤ 1024; must be empty in argv mode |
| `args` | bundle mode: array ≤ 64 of strings, each ≤ 4096; must be empty in argv mode |
| `cwd` | clean absolute caller working directory used by both execution modes |
| `bundle_dir` | clean absolute staged bundle directory in bundle mode, ≤ 4096; omitted in argv mode |
| `reason` | string (no per-field bound; the frame ceiling applies) |

The bootstrap also carries `execution_environment`: exactly the non-secret
`PATH=/usr/bin:/bin`, `HOME=/root`, `LANG=C.UTF-8`, and `PWD=<operation.cwd>`
entries for reviewed jobs. The broker derives them from the actual launch
environment. Private `ASKDO_BUNDLE` staging paths are not projected.

The bootstrap carries no raw capture contents. For captured stdin it carries
only the logical path, byte size, SHA-256 digest and the selected delivery
kind — the kind is visible before approval and never changes afterwards; a
kind/bytes mismatch fails closed. In argv mode
the broker performs metadata-only `argv[0]` resolution as execution preflight
and reads no host content eagerly; host bytes cross to the model only through
model-chosen `inspect_request` exchanges. `bundle_dir` is broker-private
staging context for the worker's execution description; the **model-visible
view** includes `mode`, `argv`/`entry`/`args`, `cwd`, `reason`, broker-known
target and submitter identity, host/container, and the four allowlisted
environment entries — never the staging path or bundle hashes.

In bundle mode `entry` remains the bundle-relative entry name from the client
request; the broker launches the script from its absolute staged path and the
launched process sees `ASKDO_BUNDLE` pointing at the staged dependency
directory. The worker's operation description preserves the caller's `cwd`;
it does not use the bundle as the working directory. The Telegram
summary is code-rendered HTML with bold labels, exact cwd, submitter name and
UID, actual daemon hostname, and a Bash `<pre>` block containing shell-quoted
display text only (execution uses argv). The optional environment/container
label is shown only when observed; no physical hostname is inferred.

**`config_projection`:**

| Field | Type — bounds |
|---|---|
| `models` | array 0–16 of projected models; empty only in approval-only bootstrap |
| `limits` | object, below |
| `telegram` | object, below |

**projected model:** `name` ≤ 128; `api` enum `"openai_chat"` |
`"openai_responses"` | `"anthropic_messages"` | `"openai_codex"`; `base_url`
≤ 1024; `model` ≤ 256; `api_key_file` ≤ 1024, optional (omitted =
deliberately unauthenticated local service); `request_timeout_ms` int64 > 0;
`access_token` ≤ 4096 and `account_id` ≤ 256, both optional in the schema.
The projection carries credential *paths*, never
credential contents — with one exception: for `api: "openai_codex"` the
broker (the sole reader of the OAuth token file) refreshes at review start
and projects the fresh access token and account ID directly, so
`access_token` and `account_id` are **required at runtime** for that api
value and **forbidden** for every other api value, and the codex
`api_key_file` path is never projected. The OAuth refresh token and id_token
never appear in any worker message.

**`limits`:** `max_model_calls_per_attempt` 1–128; `max_output_tokens`
1–200000; optional `webfetch_enabled` bool (omitted/false unless the root-owned
`review.webfetch_enabled` setting is true); optional `inspection_caps` object
with required boolean fields `hash_path_enabled`, `service_status_enabled`,
`sudo_policy_enabled` (all false when the object is absent). The capability
object carries no roots, UID lists, credential paths or exclusion patterns.
The inspected-file/byte and hash budgets are enforced by the broker, not this
bootstrap projection. Their bounded values can be observed separately through
`inspection_scope`; do not confuse disclosure with worker-owned enforcement.

**`telegram`:** The broker projects the job's one selected channel. Two
shapes, mirroring the config's two forms:

- *Legacy projection* (legacy flat config): `token_file` ≤ 1024;
  `operator_user_id` int64; `chat_id` int64; `approval_ttl_ms` int64 > 0;
  `channel_name` and `recipients` absent.
- *Named projection* (named multi-channel config): `token_file` ≤ 1024;
  `approval_ttl_ms` int64 > 0; `channel_name` non-empty ≤ 128;
  `recipients` array 1–16 of {`chat_id` int64 ≠ 0;
  `operator_user_ids` array 1–16 of distinct positive int64}, unique per
  `chat_id`; `operator_user_id`/`chat_id` flat fields absent.

The projected `recipients` are the selected channel's configured recipients
(config allows 1–8 chats with 1–8 users each). The projection carries the
token *path*, never the token value.

### `inspect_request` (W→B)

One bounded broker inspection operation. `request_seq` is a per-job
monotonically increasing uint32 starting at 0, assigned by the worker's
`RequestTracker`; the broker additionally rejects out-of-order sequences.

| Field | Type — bounds |
|---|---|
| `type` | `"inspect_request"` |
| `request_seq` | uint32 |
| `op` | enum `"read_path"` \| `"list_path"` \| `"search_path"` \| `"stat_path"` \| `"find_path"` \| `"mount_info"` \| `"inspection_scope"` \| `"hash_path"` \| `"service_status"` \| `"sudo_policy"`; selects the payload shape |
| `payload` | object matching `op`, required |

There is no `required` or importance flag: the model chooses paths, and JSON
Schema `required` lists in the tool definitions describe argument shape only.

**Payloads by `op`:** the first five filesystem operations use `base`, enum
`"host"` \| `"bundle"`. A host `path` is a clean absolute path; a bundle `path` is a clean relative path
confined to the bundle root, with `"."` selecting the root. Every `path` is
≤ 4096.

| `op` | Payload fields |
|---|---|
| `read_path` | `base`; `path`; `offset` int64 ≥ 0; `max_bytes` 1–16384 |
| `list_path` | `base`; `path`; `cursor` ≤ 128 (empty = first page, opaque thereafter) |
| `search_path` | `base`; `path` (explicit scope, never empty/global); `pattern` ≤ 1024, non-empty, must compile as a Go regular expression; `cursor` ≤ 128 |
| `stat_path` | `base`; `path`; `resolve` bool (false inspects the final link itself; true resolves a host symlink under policy, forbidden for staged bundles) |
| `find_path` | `base`; `path` (explicit directory scope); `glob` non-empty basename glob ≤ 256, valid `path.Match` syntax, no `/` or `..`; `cursor` ≤ 128 |
| `mount_info` | `path` clean absolute host path, ≤ 4096; no `base` |
| `inspection_scope` | `cursor` string ≤ 128 (empty = first page); no path or `base` |
| `hash_path` | `path` clean absolute host path ≤ 4096; no `base` |
| `service_status` | `unit` literal `.service` name ≤ 128, matching `^[A-Za-z0-9_.@][A-Za-z0-9_.@-]*\.service$`; no `base`, properties, flags or action |
| `sudo_policy` | `uid` numeric uint32; no login name, executable or command arguments |

Every listed payload field is required and non-null. Unknown fields are
rejected. The worker offers `inspection_scope` unconditionally but does not
automatically call it; callers should use it early to discover declared scope.
The other three new operations are independently gated by both projected
capabilities and root-local configuration. UID authorization for `sudo_policy`
precedes account resolution and subprocess work: submitting UID plus explicitly
configured additional UIDs only, with no blanket UID 0 exception.

The host directory walker used by `find_path` and directory `search_path` is
bounded to depth 8 and 2048 raw entries; directory symlinks are not followed.
Host single-file and directory searches can scan up to
`min(limits.max_inspected_bytes, 1 MiB)` per call rather than a 16 KiB
whole-file ceiling. Paginated host directory observations use digest-bound
cursors, not an atomic filesystem snapshot.

### `inspect_result` (B→W)

Correlated answer to an outstanding `inspect_request`: `request_seq` must
match an outstanding request (the worker's `RequestTracker` validates and
consumes each result exactly once).

| Field | Type — bounds |
|---|---|
| `type` | `"inspect_result"` |
| `request_seq` | uint32 |
| `status` | enum `"ok"` \| `"withheld"` \| `"binary"` \| `"inspection_denied"` \| `"not_found"` \| `"changed_during_capture"` \| `"limit_exceeded"` \| `"unresolved"` \| `"unknown"` |
| `payload` | object matching the request's `op`; required iff `status` is `"ok"`, forbidden otherwise |
| `reason_code` | optional closed code; forbidden on success and on legacy operations, allowed only on a non-`ok` result for the four new operations |

Every non-`ok` status is payload-free; the model receives status and, for new
operations, an optional closed reason code, never raw command output or broker
internals. Valid reason/status pairs are:

| Status | `reason_code` values |
|---|---|
| `inspection_denied` | `disabled`, `outside_scope`, `unauthorized_uid` (sudo only), `not_executable` |
| `withheld` | `policy_withheld` |
| `not_found` | `object_not_found` |
| `changed_during_capture` | `observation_changed` |
| `limit_exceeded` | `hash_file_limit`, `hash_review_limit` (hash only), `file_count_limit`, `output_limit`, `request_limit` |
| `unresolved`, `unknown` | `timeout`, `unsupported_format`, `fragment_unresolved` (service only), `dependency_unavailable`, `inspection_failed` |

Malformed/unavailable new-tool exchanges are rendered by the worker as the
fixed `unresolved` / `inspection_failed` tool error, without raw diagnostics.
These ordinary tool failures do not veto a schema-valid final report; they do
not justify hiding material uncertainty from its warnings/missing context.

- `withheld` is the broker's payload-free answer at the credential boundary:
  the requested (or resolved) name matched the sensitive-mask policy, or a
  staged bundle file is masked. It is valid for all inspection ops. In `list_path`,
  `find_path`, and subtree `search_path` results, masked entries *below* the
  scope are instead omitted and counted in the payload's `skipped_masked`.
- `binary` is valid only for `read_path`: the target's bytes are not valid
  UTF-8 or contain NUL, so no content is returned.
- `inspection_denied` means policy refused the operation (for example a
  `find_path` scope that is a file). It is an ordinary tool result; the model
  can still complete its report.
- `not_found`, `changed_during_capture` (the object or path mapping changed
  around the bounded read, or staged bundle bytes no longer match the capture
  index), `limit_exceeded` (for example a host search exceeding its 1 MiB
  per-call ceiling, a walker exceeding depth/entry limits, or a search match
  whose path exceeds the 1024-byte result bound), `unresolved` (indeterminate, e.g. a malformed
  cursor or non-text search content), and `unknown` (a supported check ran
  but produced an indeterminate result) disclose uncertainty, never verified
  safety.

**Payloads by `op` (status `"ok"` only):**

- `read_path`: `content` string ≤ 16384 bytes, valid UTF-8; `offset` int64 ≥
  0; `next_offset` int64 ≥ `offset`; `eof` bool. `content` carries bytes and
  positions only — no capture IDs, hashes, or line accounting. A model-chosen
  byte offset that splits a trailing UTF-8 rune is trimmed to the rune
  boundary and `next_offset` advances only past delivered bytes.
- `list_path`: `entries` array ≤ 500 of {`name` ≤ 256; `type` enum
  `"file"` | `"dir"` | `"symlink"` | `"other"`}; `next_cursor` ≤ 128 (empty =
  last page); `skipped_masked` int ≥ 0.
- `search_path`: `matches` array ≤ 200 of {`path` ≤ 1024, non-empty; `line`
  int ≥ 0; `excerpt` ≤ 256}; `next_cursor` ≤ 128; `skipped_masked` int ≥ 0.
- `stat_path`: `source` enum `"host"` | `"bundle_staged"`; `type` enum
  `"file"` | `"dir"` | `"symlink"`; `mode` ≤ 07777 (including special bits),
  `uid`, `gid`, `nlink`, `size` ≥ 0, `atime_unix_ns`, `mtime_unix_ns`,
  `ctime_unix_ns`, `device`, `inode`; optional `target` ≤ 4096 for symlinks
  and `resolved_path` clean absolute path ≤ 4096. A bundle result is always
  `bundle_staged`/`file` without target or resolved path: it describes the
  staged object, not the original host metadata.
- `find_path`: `matches` array ≤ 200 of non-empty paths ≤ 1024;
  `next_cursor` ≤ 128; `skipped_masked` int ≥ 0. The glob matches basenames,
  not an unbounded recursive pattern.
- `mount_info`: `mount_id` positive integer; `mount_point` clean absolute
  host path; `fs_type` non-empty string ≤ 64; `read_only` bool. This reports
  one allowed object's mount, never the entire mount table or pseudo-paths;
  it is not evidence of container isolation.
- `inspection_scope`: `read_roots` array ≤ 128 of distinct clean absolute
  candidate paths ≤ 4096; `next_cursor` ≤ 128; `exclusions_remain: true`;
  `capabilities` with the three boolean flags; `max_read_bytes` 1–16384;
  `max_inspected_files` ≥ 1; `max_inspected_bytes` ≥ 1;
  `max_hash_file_bytes` 1–33554432; `max_hashed_bytes_per_review` between that
  per-file value and 67108864; `sudo_policy_uids` array ≤ 128 of distinct
  uint32s, empty when disabled. Optional `compatibility` object (omitted, never
  `null`): `path_resolver` enum `"openat2"` | `"os_root"`; booleans
  `terminal_link_follow_supported` and `absolute_path_follow_supported`;
  `mount_identity_policy` enum `"statx_or_file_handle"`. Unknown fields, other
  enum spellings and null inside the leaf are rejected at decode time. The
  leaf reports what the broker's one-time startup probe actually selected
  (`os_root` only where `openat2` answered `ENOSYS`; measured on Linux
  3.10.108, ext4 — not a universal vendor claim); the worker or caller cannot
  select a backend and the snapshot is identical on every page. When the field
  is absent, the historical scope JSON shape is preserved unchanged. Roots are
  descriptor-filtered configured
  spellings, not canonical aliases or blanket grants. Exclusion details remain
  private. An oversized effective UID list fails closed, not truncated.
- `hash_path`: `source: "host"`; `requested_path` exactly matching the request;
  `resolved_path` clean absolute ≤ 4096; `sha256` 64 lowercase hex;
  `size` 0–33554432; `mode` ≤ 07777; uint32 `uid`, `gid`; uint64 `device`,
  nonzero `inode`; int64 `mtime_ns`, `ctime_ns`; positive
  `observed_at_unix_ms`. Only allowed regular files with an execute bit are
  hashed, with descriptor/path revalidation; binary files need no text read.
- `service_status`: `id` exactly matching requested `unit`; `load_state`,
  `active_state`, `sub_state`, `unit_file_state` each matching
  `^[a-z0-9_-]{1,32}$` (`load_state` cannot be `not-found` on success);
  authorized `canonical_fragment_path` clean absolute ≤ 4096;
  `main_pid` int64 ≥ 0; `umask` four octal digits; positive
  `observed_at_unix_ms`. Alias ID mismatches and unsupported/empty fragments
  do not become successful results.
- `sudo_policy`: `uid` matching request; `rules` array ≤ 128; positive
  `observed_at_unix_ms`; `complete` bool; `withheld_rule_count` uint32 (zero
  when complete). Each rule: `run_as_users` array 1–128, `run_as_groups` array
  0–128 (safe account names or `ALL`); `command_scope` enum `all` | `path` |
  `restricted_withheld`; optional authorized canonical `path` only for `path`
  scope; `arg_constraint` enum `empty_only` | `unrestricted` |
  `restricted_withheld`; `auth` enum `required` | `not_required` | `unknown`.
  Partial sanitized listings are valid; raw Defaults and command argument bytes
  never cross the pipe.

New metadata payloads are ≤ 16 KiB each, with an additional 1024-byte hash
result ceiling. The root broker enforces 32 combined new-operation requests,
256 KiB aggregate payload bytes and 256 total inspection observations per job.
Hash defaults/hard maxima are 32 MiB per file and 64 MiB per review, separately
from the default 8 MiB content/staging budget; enabled attempts are bounded to
`min(2, limits.max_inspected_files)`, including denied attempts. Work includes
failed reads and one overflow probe; fallback never resets these counters.

The two metadata command adapters are fixed root-side `systemctl show` and
`sudo -n -ll -U` invocations, never arbitrary execution. Each has a two-second
timeout, a combined 16 KiB stdout/stderr cap and a pinned trusted executable.
Sudo first requires inspection access to the fixed sudoers sources and pinned
local `/etc/passwd`; configured plugins/NSS can cause audit/log writes or
network activity. See [review tools](review-tools.md) for exact argv and policy
checks. All returned facts are observations, not later process/file identity
guarantees or source-byte execution pins.

Sanitized observations are written to root-only `inspection-evidence.jsonl`.
When present, the manifest's `inspection` object freezes capability flags,
hash limits, counters and ordered observations into its digest before approval.
Scope cursors, raw responses, regexes, URLs and denied selectors are excluded;
this adds no independent signature or approval quorum.

`webfetch` is **not** an `inspect_request` operation: when enabled by the
projected flag, it executes in the unprivileged reviewer worker and returns
bounded public HTTP(S) text as a model tool result (or a fixed error category).
There is no `webfetch` pipe request/result; the tool does not execute code or
automatically follow remote dependencies. See [review tools](review-tools.md#optional-webfetch).

### `progress` (W→B)

Best-effort lifecycle progress; legal at any time on the W→B direction
(while awaiting `notification_sent` or the decision the broker tolerates at
most 64 interleaved progress frames).

| Field | Type — bounds |
|---|---|
| `type` | `"progress"` |
| `stage` | enum `"reviewing"` \| `"fallback"` \| `"notifying"` \| `"awaiting_human"` |
| `detail` | string ≤ 512 |
| `model_name` | string ≤ 128, optional |

### `review_complete` (W→B)

The single completion message of a review attempt. Delivered exactly once per
job by the `submit_review` tool path.

| Field | Type — bounds |
|---|---|
| `type` | `"review_complete"` |
| `report` | object, below |
| `model_history` | array ≤ 16 of history entries |

**`report`:** `risk` enum `"1"` | `"2"` | `"3"` | `"4"` | `"5"` | `"unknown"` (1 minimal through 5 critical);
`summary` ≤ 2048; `effects` array ≤ 32 of strings ≤ 512; `warnings` array ≤
32 of {`message` ≤ 512; `evidence` ≤ 512}; `missing_context` array ≤ 16 of
strings ≤ 512; `reversibility` ≤ 1024; `intent_match` enum `"consistent"` |
`"inconsistent"` | `"unverified"`. No additional fields are permitted —
notably no `approved`, no callback data, no provider identity, and no
coverage object.

**model history entry:** `name` ≤ 128; `outcome` enum `"ok"` | `"api_error"`
| `"refused"` | `"invalid"`; `error` ≤ 256 optional (a fixed label, never raw
provider text).

The broker re-validates the report and history at freeze time, requires the
final history entry to be a successful configured model, re-verifies the
caller's working-directory identity, and re-hashes every staged bundle file.
The broker does not score which files the model chose. The model is instructed
to put uncertainties in its own `warnings`/`missing_context`; broker-recorded
withheld credential references are a separate access-policy notice. A missing
file read never vetoes a schema-valid report.

### `review_unavailable` (W→B)

Distinct from `review_complete`: `type: "review_unavailable"`,
`code: "all_providers_unavailable"`, and `history` (1–16 ordered typed
availability failures). Only exhaustion of **all** configured provider choices
for typed availability errors permits an unreviewed approval when the submitter
did not request `--review=yes`; an elapsed deadline, safety refusal, malformed
final report or inspection/broker failure does not. Each history entry has a
bounded `name` and a fixed `code` (`quota_rate`, `transport`, `provider_timeout`,
`invalid_config`, `malformed_provider_wire`, or `codex_relogin`); raw provider
text is not sent to Telegram. The broker accepts the message only when the
history exactly covers the projected choices in order (with any broker-side
preflight failures re-inserted in configured order) and no review was forced.

### Worker exit without a report

There is no `review_failed` message. If the worker exits or errs without a
typed outcome — including a model that abandons the review without
`submit_review` — the job fails before freeze or notification. The
submitter's result carries only the generic broker-authored explanation
("reviewer did not complete; see the root-owned reviewer log"): worker stderr
and malformed pipe frames may contain provider text, including echoed
credentials, so they stay in the root-owned spool log and are never forwarded
to the submitter. An operator reads that log with the root-only
`askdo logs JOB_ID` command. A job with no model report is never labeled
reviewed.

### `approval_only_frozen` (B→W)

For policy bypass or validated total provider unavailability, the broker sends
`type: "approval_only_frozen"`, `manifest_digest` (64 hex), `reason` (≤ 512),
and `history` (0–16 typed availability failures; empty for policy bypass).
There is **no** model report or risk/effects/reversibility assessment. The
worker sends a **NO AI REVIEW** Telegram card with the reason/history and an
explicit unassessed warning before waiting for the same human approval.

### `frozen` (B→W)

The broker's acceptance of the review: the exact manifest digest the approval
will be bound to.

| Field | Type — bounds |
|---|---|
| `type` | `"frozen"` |
| `manifest_digest` | 64 hex (SHA-256 of the exact approval-manifest bytes) |
| `report` | the validated report object |
| `withheld_refs` | array ≤ 16 of distinct strings ≤ 1024 (sorted, capped) |
| `withheld_count` | int 0–1000000 (≥ `len(withheld_refs)`) |
| `auto_approval` | optional broker-authored `{score,max_risk,effective_threshold}`; score 1–4, score ≤ cap 1–4 and strictly below threshold 2–5; absent means manual approval |

`withheld_refs`/`withheld_count` are **broker-observed facts**: the host path
spellings and masked bundle paths the broker itself withheld during this job
(including a credential-like `argv[0]` whose executable resolution was
necessarily metadata-only). They are a factual access-policy signal, not a
completeness assessment. The worker renders any non-zero count as a prominent
code-constructed "credential content withheld" notice leading the reviewed
Telegram summary. The default is a human decision; only a reviewed report with
both a root-owned submitter UID cap and that UID's preference may receive an
auto plan, which requires a button-free Telegram notice before dispatch.
Unreviewed jobs never auto-approve.

There is deliberately **no expiry field** for manual approval: its lifetime
starts only when the complete Telegram request is sent. The worker computes
expiry as send-complete time + `min(approval_ttl_ms, remaining client deadline)`
and reports it in `notification_sent`. An auto plan produces reviewed summary
messages and a button-free policy notice, then `auto_notification_sent` with
their Bot API message IDs, manifest digest and send time. It never carries an
operator/card ID or a human `decision`.

### `review_rejected` (B→W)

The broker could not freeze the review; the job fails.

| Field | Type — bounds |
|---|---|
| `type` | `"review_rejected"` |
| `code` | enum `"invalid_report"` \| `"evidence_changed"` \| `"broker_error"` |
| `reason` | string ≤ 512 |

### `model_turn_request` (W→B) — fleet mode only

*Implemented in source; not in the `v1.0.0-rc.1` release binaries.*

In fleet mode the worker holds no provider, OAuth, enrollment, Telegram or
signing secrets, so its model traffic is mediated by the root broker through
correlated frames on this private pipe. One ordered turn per message; the
broker owns the network attempt/turn binding, enforces sequence, budget, the
selected model, the output bound and the fixed tool registry.

| Field | Type — bounds |
|---|---|
| `type` | `"model_turn_request"` |
| `request_seq` | uint64 ≥ 1, strictly increasing across all choices on this pipe |
| `choice_name` | string ≤ 128; immutable bootstrap choice name |
| `request` | typed model request: `model` (≤ 256), `max_output_tokens` 1–200000, 1–4096 typed `messages` (`system`/`user`/`assistant`/`tool`; tool messages carry `tool_call_id` ≤ 256), 1–32 tool definitions (name ≤ 128, description ≤ 16384, JSON schema ≤ 65536) |

### `model_turn_result` (B→W) — fleet mode only

Exactly one variant per request. A `failure` carries only a closed,
secret-free code (`auth`, `gateway_transport`, `signature`, `protocol`,
`session`, `revision`, `revoked`, `expired`, `delivery`, `safety`,
`upstream_quota_rate`, `upstream_transport`, `upstream_timeout`,
`upstream_invalid_config`, `upstream_malformed_wire`,
`upstream_codex_relogin`) so infrastructure failures can never masquerade as
ordinary provider exhaustion.

| Field | Type — bounds |
|---|---|
| `type` | `"model_turn_result"` |
| `request_seq` | uint64 matching an outstanding request |
| `response` | typed model response (exactly one of `response`/`failure`) |
| `failure` | `{ "code": <enum above> }` |

No pipe message can mint or substitute a fleet approval: these frames carry
model turns only, never notification or decision authority. Direct (non-fleet)
mode does not use them, and its frames remain unchanged.

### `notification_sent` (W→B)

Binds the completed Telegram approval card to the frozen manifest. Sent
before any polling begins.

| Field | Type — bounds |
|---|---|
| `type` | `"notification_sent"` |
| `message_ids` | array ≤ 32 of int64 (ordered summary-part message IDs) |
| `card_id` | int64 (approval-card message ID) |
| `digest` | 64 hex (must equal the `frozen` manifest digest) |
| `expiry_unix_ms` | int64 (absolute approval expiry) |
| `targets` | optional array 1–16; named projection only, below |

The broker rejects an expiry that is not in the future, exceeds
`approval_ttl` (+1 s slack), or exceeds the client deadline (+1 s slack).

The legacy projection reports only the flat `card_id`/`message_ids` shape
(`targets` must then be absent — `targets: null` is rejected, `message_ids`
is required). The named projection instead reports `targets`, one entry per
recipient chat, each: `chat_id`; `card_id` (positive — Telegram message IDs
are per-chat, so message IDs are *not* flattened across chats);
`message_ids` array 1–32 of positive int64 (that chat's summary parts);
`operator_user_ids` (the chat's authorized deciders). When `targets` is
present, `card_id` must be 0 and `message_ids` empty, the reported set must
exactly match the projected recipients (same count, same chats, same user
lists) — an incomplete or mismatched set is rejected. Delivering every
recipient happens before `notification_sent` at all: a partial send failure
removes the already-sent cards' keyboards best-effort and fails closed, so no
approval poll is opened and nothing executes.

### `auto_notification_sent` (W→B)

Only valid after a broker-authored `frozen.auto_approval` plan. The worker sends
all reviewed summary parts and then a **button-free** informational Telegram
notice. It emits this message only after the Bot API acknowledges every send;
it does not poll callbacks or create a human `decision`.

| Field | Type — bounds |
|---|---|
| `type` | `"auto_notification_sent"` |
| `digest` | 64 hex, equal to the frozen manifest digest |
| `message_ids` | 1–32 positive int64 summary-part IDs |
| `notice_id` | positive int64 Bot API message ID |
| `time_unix_ms` | positive int64 send time |
| `targets` | optional array 1–16; named projection only, below |

The named projection reports every recipient chat in `targets`, each:
`chat_id`; `notice_id` (positive, that chat's button-free notice ID);
`message_ids` array 1–32 of positive int64 (that chat's summary parts). The
set must exactly cover the projected recipients (every configured chat
delivered, each once); an incomplete fan-out fails closed like the human
path. The auto notice never polls callbacks and never carries an operator ID.

The broker validates the digest, IDs and recent send time, waits for clean
worker exit, repeats the normal prelaunch checks, and calls the store's atomic
auto-start commit. That transaction rechecks the current UID preference,
administrator cap, risk score, deadline and job state, and durably records
`kind:auto` without inventing an operator or approval-card ID. A failed or
ambiguous send never authorizes execution.

### `decision` (W→B)

The one-use authenticated human decision, code-constructed by the worker from
a validated Telegram callback.

| Field | Type — bounds |
|---|---|
| `type` | `"decision"` |
| `digest` | 64 hex (the bound manifest digest) |
| `operator_user_id` | int64 |
| `message_id` | int64 (the approval-card message the decision was made on) |
| `action` | enum `"approve"` \| `"deny"` |
| `time_unix_ms` | int64 |
| `channel_name` | optional string ≤ 128; non-empty exactly for the named projection (with non-empty `chat_id`; `channel_name`/`chat_id` must be set or empty together), and it must equal the projected channel |
| `chat_id` | optional int64 ≠ 0; the recipient chat the deciding card was made in |

Trusted reviewer code validates the Telegram callback's operator ID, chat,
card ID, nonce, expiry and first-use status — in the named form against every
projected `(chat, message, operator)` target, in the legacy form against the
single card. The **first valid decision wins**; once a decision is consumed
the poller rejects later presses on the pending request ("already decided"),
so a second admin's button cannot revoke an approved or denied job. The
broker does **not** poll
Telegram independently: it trusts the worker's `decision`, re-checks digest,
channel name, operator ID and message ID against the recorded card binding
(legacy: the single card ID; named: the deciding chat's recorded target),
pending state,
`time_unix_ms` ≤ expiry and the client deadline under its dispatch lock, and
consumes the decision exactly once. Its checks do not independently prove the
Telegram callback was authentic.

### `cancel` (B→W)

Ends review or approval before dispatch.

| Field | Type — bounds |
|---|---|
| `type` | `"cancel"` |
| `reason` | enum `"client_timeout"` \| `"operator_cancel"` \| `"deadline"` \| `"shutdown"` |

## Message lifecycle of one job

```text
B→W  bootstrap                     (immutable job definition)
W→B  inspect_request ─┐            (zero or more correlated exchanges;
B→W  inspect_result  ─┘             request_seq strictly increasing)
W→B  progress                      (any time; reviewing/fallback/notifying/awaiting_human)
W→B  review_complete ── or ── review_unavailable ── or ── worker exits without a report
B→W  frozen ── or ── approval_only_frozen ── or ── review_rejected
W→B  notification_sent             (Telegram card delivered; approval binding recorded)
W→B  decision                      (one-use approve/deny) ── job dispatches or is denied
B→W  cancel                        (any pre-dispatch point; terminates the worker)
```

After `decision`, the worker exits and must do so successfully: dispatch
re-validates that the worker exited cleanly (within 10 seconds) before the
durable `awaiting-human` → `starting` commit. A worker that exits at its
approval expiry without a decision leaves the pipe closed; the broker records
the honest `expired` state when the recorded expiry has passed.

## Invariants

- **Model text cannot become a control message.** The model never sees the
  private pipe. When present, its report text crosses the pipe only inside
  the validated fields of `review_complete` (report), each strictly bounded
  and schema-checked by trusted worker code and re-validated by the broker
  before freezing. Telegram callback data is parsed by fixed code
  (`<a|d|v>:<32 hex nonce>`); model-crafted text cannot become a decision.
- **One active worker.** The job queue runs one job at a time and
  `processWorker` refuses a second concurrent launch, so at most one reviewer
  process — and therefore at most one pending Telegram approval — exists.
  Only one long-poller runs per approval.
- **Serialized writes.** Both sides write frames under a mutex
  (`processWorkerSession.writeMu`, `asyncBroker.writeMu`), and inspection
  exchanges are serialized by `requestMu` plus the `RequestTracker`: one
  outstanding request per exchange, each result matched exactly once.
- **Directional validity.** A message that is well-formed but arrives in the
  wrong direction is a protocol error and terminates the exchange; there is
  no recovery or resync.
- **Correlation.** `inspect_result.request_seq` must match an outstanding
  request; `notification_sent.digest` and `decision.digest` must equal the
  digest the broker itself froze. Anything else fails the job closed.
- **Fleet mode carries no Telegram authority on this pipe.** A fleet worker
  never receives `frozen`-followed notification/decision exchanges: after the
  frozen review it exits cleanly and the root broker performs gateway ticket
  submission, signed-receipt/decision verification and dispatch itself. A
  worker claiming a fleet decision or receipt is rejected.
