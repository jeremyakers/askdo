# Review tools and report schema

When AI review is required, the reviewer model always has the six broker-mediated
filesystem inspection tools (`read_path`, `list_path`, `search_path`,
`stat_path`, `find_path`, `mount_info`), broker-mediated `inspection_scope`,
and worker-side `submit_review`: eight tools by default
(`internal/reviewer/tools.go`, `DefinitionsForCapabilities`). Three independent
root-owned inspection flags optionally add `hash_path`, `service_status`, and
`sudo_policy`; all default to false. Worker-side `webfetch` is separately
offered only with `review.webfetch_enabled: true` (also false by default).
The maximum registry is twelve tools. Configuration cannot redefine tools;
calls execute strictly sequentially. Broker operations use private-pipe
`inspect_request`/`inspect_result` exchanges with fixed, strictly typed shapes.

**Host-evidence additions are source-only, not in the published rc.2 binaries.**
They are separate from existing foreground-helper sudo hardening. See
[configuration and rollout](configuration.md#optional-host-evidence-and-rollout)
before adding fields to an installed host.

Under explicit `review.mode: "approval_only"`, or for an exempt OS login UID
under `required`, no model or tools are used unless `--review=yes` is given.
After **all** configured providers fail with typed availability errors without
that flag, the broker can instead freeze an unreviewed approval request. The
Telegram card identifies the job by the same canonical `YYYY-MM-DD_#N` ID
printed before submission and stored for operator log lookup. The callback
nonce is a separate one-use authorization value, not a second job ID. It says
**NO AI REVIEW**, gives the policy reason or sanitized
failure history, and never claims risk, effects, reversibility or dependency
completeness were assessed. Telegram approval is still required; this fallback
never authorizes execution by itself. Safety refusal, malformed final report,
inspection/broker/evidence failure, and expired deadlines fail closed. A job
from which **no model report exists** is never labeled reviewed.

## Tools and bounds

The model-visible operation description includes `mode`, `argv` (argv mode) or
`entry` plus `args` (bundle mode), the caller's exact `cwd` and `reason`, and
broker-known execution facts: `target_uid`, `submitter_uid`, submitter name,
host, observed container, and the fixed non-secret `PATH`, `HOME`, `LANG`, and
`PWD` variables (`internal/reviewer/loop.go`). The broker-private bundle
staging path and staged bundle hashes are **never** shown to the model. For
a captured-stdin job (`protocol_version` 5) the description also carries the
captured-input metadata `captured_stdin` — path `stdin`, size in bytes, and
SHA-256 — never the script bytes; the reviewer reads the content itself as a
bundle file (below). For bundle jobs the entry is staged and dependency files
are exposed to the executed process through `ASKDO_BUNDLE`; relative shell
paths otherwise resolve from `cwd`. Review instructions and dependency
references should use the explicit bundle path (for example
`"$ASKDO_BUNDLE/helper.sh"`) rather than assuming the bundle is the process
working directory.

The six filesystem tools except host-only `mount_info` take `base` (enum
`"host"` or `"bundle"`). A host path is a clean absolute path; a bundle path is a clean
relative path confined to the
staged bundle root, with `"."` selecting the root itself. The model chooses
every path; there is no broker-side dependency discovery, capture-ID list, or
importance flag.

### 1. `read_path`

Read up to `max_bytes` bytes of one file the model chooses, starting at byte
`offset`.

- **Arguments:** `base` (enum, required), `path` (string, required, ≤ 4096),
  `offset` (int64, required, ≥ 0), `max_bytes` (int, required, 1–16384 —
  `proto.MaxDirectReadBytes`; every call is bounded to at most 16 KiB).
- **Result:** `content` (string, valid UTF-8), `offset`, `next_offset`,
  `eof` (bool).
- **Pagination:** `offset` is a model-chosen **byte** offset, not a line
  number. If the chosen span would split the final UTF-8 rune of otherwise
  valid text, the broker trims to the last complete rune boundary and
  advances `next_offset` only past delivered bytes, so the next read can
  resume at that rune.
- **Binary:** content that is not valid UTF-8, or contains a NUL byte,
  returns the payload-free status `"binary"` instead of any bytes.
- **Host enforcement:** the broker opens the path descriptor-relative
  (openat2, `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS`) under
  `inspection.read_roots`, applies `deny_paths`, the hard-deny set and the
  `sensitive_masks` name policy against both the requested and resolved
  spellings on the authorized opened descriptor **before** reading, and
  revalidates the path and object identity **after** the bounded read; any
  change fails the call (`changed_during_capture`). A permitted path matching
  a sensitive name mask returns payload-free `withheld` — metadata policy is
  checked, but no content crosses to the model.
- **Bundle reads:** served from the root-only staged copy; the staged bytes
  are re-hashed against the capture index on every read. A staged file the
  broker classified as masked (admin `Masked` policy or a client
  `sensitive_inclusions` opt-in) returns payload-free `withheld` whatever the
  client opted into at submit time.
- **Captured stdin reads:** a captured-stdin job stages the submitted script
  bytes root-only as the bundle path `stdin`; the model reads them with
  `read_path` using `base:"bundle"`, `path:"stdin"`, paginating as usual. The
  broker hashes each read against the frozen capture just as for bundle
  files.

### 2. `list_path`

List one page of one directory the model chooses. `list_path` does not walk
recursively; `find_path` and directory `search_path` use a separate bounded
host walker under an explicit scope.

- **Arguments:** `base`, `path` (as above), `cursor` (string, required;
  empty = first page, opaque thereafter, ≤ 128).
- **Result:** `entries` (≤ 500 of {`name`, `type` ∈
  `file`|`dir`|`symlink`|`other`}), `next_cursor` (empty = last page),
  `skipped_masked` (count of masked entries omitted from the page, zero when
  nothing was skipped).
- **Host listing:** the directory is opened under the same descriptor policy
  as reads; entries whose requested or resolved names match a sensitive mask
  are skipped and counted in `skipped_masked`, and entries outside policy are
  omitted. A masked directory itself returns `withheld`.
- **Bundle listing:** derived from the staged capture index; masked staged
  files are omitted and counted in `skipped_masked`.

### 3. `search_path`

Search one explicit scope the model chooses with a Go regular expression.
The `path` argument is always an explicit scope; an empty path is never an
implicit global search.

- **Arguments:** `base`, `path` (as above), `pattern` (string, required,
  ≤ 1024, must compile as a Go regular expression — trusted worker code
  rejects invalid patterns before bothering the broker), `cursor` (string,
  required, ≤ 128).
- **Result:** `matches` (≤ 200 of {`path`, `line`, `excerpt` ≤ 256}),
  `next_cursor`, `skipped_masked`.
- **Path bound:** a path longer than the 1024-byte search-result path limit
  yields `limit_exceeded` for that tool call, not a failed review. The model
  can still choose `read_path` for the same file.
- **Host scope:** one explicit regular file or directory subtree. The broker
  reads whole files under the same host inspection policy, bounded by
  `min(limits.max_inspected_bytes, 1 MiB)` of content per search call; an
  over-budget file returns `limit_exceeded` and non-UTF-8/NUL text returns
  `unresolved`. Directory searches reuse the `find_path` walker (depth ≤ 8,
  ≤ 2048 raw entries); symlink directories are not followed. Host directory
  pagination checks a digest of the bounded observation on resumption; this
  is not an atomic snapshot of a changing host tree.
- **Bundle scope:** a staged file or subtree. Masked staged files are skipped
  and counted in `skipped_masked`; a scope that directly names masked content
  returns payload-free `withheld`. The whole bundle search is one bounded
  broker operation (at most 1 MiB of staged content, and within the
  configured per-job capture budgets).

### 4. `stat_path`

Inspect metadata without file contents. `base` and `path` use the path rules
above; required `resolve` (bool) explicitly follows the final symlink when
true. Host links are inspected as links by default. An inaccessible, masked,
or dangling target does not become a successful resolved link result.

- **Result:** `source` (`"host"` or `"bundle_staged"`), `type` (`file`, `dir`,
  `symlink`), `mode` (permission and special bits), `uid`, `gid`, `nlink`,
  `size`, `atime_unix_ns`, `mtime_unix_ns`, `ctime_unix_ns`, `device`, `inode`,
  and optional `target` (symlink text) and `resolved_path`. Host metadata and
  symlink targets remain subject to inspection policy and name masks.
- **Bundle:** only staged captured files are stat-able, with `resolve: false`.
  `source: "bundle_staged"` identifies staged-file metadata, **not** the
  original source host's ownership, mode, timestamps, or inode.

### 5. `find_path`

Find names beneath an explicit host or bundle directory. Arguments are
`base`, `path`, `glob` (nonempty basename glob ≤ 256 bytes; no `/` or `..`),
and `cursor` (empty on first page, ≤ 128 bytes). The result has `matches`
(≤ 200 paths, each ≤ 1024), `next_cursor`, and `skipped_masked`. The host
walker does not follow directory symlinks and is bounded to depth 8 and
2048 raw entries, including masked/omitted names. Bundle results come from
the staged capture index. A too-large traversal fails `limit_exceeded` rather
than silently claiming completeness; a continuation cursor checks the bounded
observation for changes. No host walk supplies an atomic snapshot.

### 6. `mount_info`

For one allowed clean absolute **host** `path` (no `base`), return only that
object's `mount_id`, `mount_point`, `fs_type`, and `read_only`. The broker
withholds or denies masked, excluded, or pseudo-filesystem paths; it does not
return raw mount-table contents. Mount type does not establish container or
host isolation.

### 7. `inspection_scope`

Call this tool early, preferably first, to discover the available declared host
scope rather than guessing roots. It is always offered; the current loop does
**not** automatically invoke it or mechanically require it before a report.

- **Arguments:** required `cursor` (string ≤ 128; `""` for the first page,
  returned `next_cursor` thereafter). No `base`, path or caller-selected policy.
- **Result:** `read_roots` (≤ 128 per page), `next_cursor`,
  `exclusions_remain: true`, `capabilities` (the three enabled booleans),
  `max_read_bytes`, `max_inspected_files`, `max_inspected_bytes`,
  `max_hash_file_bytes`, `max_hashed_bytes_per_review`, and `sudo_policy_uids`.
  The UID list is empty when sudo inspection is disabled; otherwise it is the
  sorted, deduplicated submitting UID plus configured additional UIDs.
- **Disclosure:** candidate configured root spellings only, filtered through
  descriptor authorization, masks, protected identities and revalidation.
  Denied/masked roots, private exclusion rules, mask patterns, credential paths
  and canonical aliases are not listed. A visible root is **not** blanket
  permission for its descendants. Pagination uses one per-job root snapshot,
  not a promise that the host remains unchanged.

### Optional `hash_path`

With `inspection.hash_path_enabled: true`, required `path` is one clean
absolute host path ≤ 4096 bytes (no `base`). The broker hashes only a
policy-authorized regular file with at least one execute bit; this is not an
execute-permission shortcut around inspection policy. Requested/resolved names,
mount aliases, masks, protected identities and multi-hardlink refusal apply.
The pinned descriptor and named path are revalidated after bounded hashing.

The result is metadata only: `source: "host"`, `requested_path`,
`resolved_path`, lowercase `sha256`, `size`, `mode`, `uid`, `gid`, `device`,
`inode`, `mtime_ns`, `ctime_ns`, and `observed_at_unix_ms`. No file bytes cross
to the model. Binary executables (for example a 20 MiB file) can be hashed
even when `read_path` returns `binary`. Default/hard ceilings are 32 MiB per
file and 64 MiB hashing work per review, independently of the default 8 MiB
content/staging budget. At most `min(2, limits.max_inspected_files)` enabled
hash attempts are allowed per job, including denied attempts; failed reads and
the single overflow-probe byte count as work. Fallback does not reset budgets.

A hash is a review-time observation, **not** a source-byte pin or proof that a
later privileged process executes the same inode or bytes. It does not attest
dependencies or establish that the binary is safe.

### Optional `service_status`

With `inspection.service_status_enabled: true`, required `unit` is one literal
`.service` name ≤ 128 bytes, matching
`^[A-Za-z0-9_.@][A-Za-z0-9_.@-]*\.service$`. Named instances such as
`foo@bar.service` are accepted; wildcard patterns and options are rejected.
The root adapter uses only:

```text
/usr/bin/systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,UMask -- <unit>
```

It returns only `id`, `load_state`, `active_state`, `sub_state`,
`unit_file_state`, `canonical_fragment_path`, `main_pid`, `umask`, and
`observed_at_unix_ms`. The observed `Id` must equal the requested unit exactly:
an alias returning another canonical ID is unresolved, not silently substituted.
The fragment and its resolved regular-file target must pass inspection policy;
empty/unresolvable fragments fail, denied fragments are withheld. No arbitrary
properties, environment, descriptions, `ExecStart`, command arguments or journal
are returned. No start/stop/reload action is available. State and PID are
observations, not guarantees about a later process or its executable identity.
Existing `stat_path` and `mount_info` can supply complementary file/mount facts.

### Optional `sudo_policy`

With `inspection.sudo_policy_enabled: true`, required `uid` is a numeric uint32.
The broker authorizes it **before** account resolution or invoking sudo: the
authenticated submitting UID is always eligible, plus explicit
`inspection.sudo_policy_uids`. There is no blanket root exception: UID 0 is
eligible only when it is the submitter or an explicitly listed additional UID.

Inspection policy must permit `/etc/sudoers`, `/etc/sudoers.d`, and
`/etc/passwd`. Local account resolution uses only the pinned, root-owned,
non-group/world-writable `/etc/passwd`, bounded to 64 KiB, with identity and
post-read checks; it does not use NSS to resolve the requested UID. The fixed
root adapter then lists policy with `/usr/bin/sudo -n -ll -U <local-account>`.
No administrative command is run and no new sudo privilege is granted.
Configured sudo plugins/NSS may nevertheless cause ancillary audit/log writes
or network activity: this is **not** a zero-side-effect or zero-network promise.

The metadata-only result has `uid`, `rules` (≤ 128), `observed_at_unix_ms`,
`complete`, and `withheld_rule_count`. Each rule has `run_as_users`,
`run_as_groups`, `command_scope` (`all`, `path`, `restricted_withheld`), optional
authorized canonical `path`, `arg_constraint` (`empty_only`, `unrestricted`,
`restricted_withheld`), and `auth` (`required`, `not_required`, `unknown`).
Unsupported restrictions can yield a partial result (`complete: false`);
unsafe rules are omitted or summarized as withheld. Raw Defaults, argument
bytes and raw sudo output are never returned. Unsupported listing formats fail
closed, not as evidence that the user lacks sudo rights.

Both command adapters pin the fixed root-owned executable and require
non-group/world-writable ancestors, use only `PATH=/usr/bin:/bin`, `LANG=C`,
`LC_ALL=C`, cwd `/`, and no inherited stdin. Each has a two-second timeout and
a combined stdout/stderr limit of 16 KiB; no caller-selected flags, executable
or environment are accepted.

### 8. `submit_review`

Submit the final report. This is the **sole completion path** and it cannot
approve, notify, or execute anything.

- **Arguments:** the report object itself — the seven report fields at the
  top level — validated against the fixed embedded JSON schema
  (`EmbeddedReportSchema`, mirroring the wire bounds in *Report schema*
  below; `additionalProperties: false`). The schema's `required` list is
  structural only; it describes argument shape, never file importance —
  there is no `required` flag on paths and no coverage object. Trusted worker
  code wraps the validated report into `review_complete.report` for the
  private pipe; the wire nesting is a protocol artifact, not part of the tool
  arguments.
- **No sufficiency gate:** trusted worker code validates the report against
  the schema, appends the ordered model history, re-validates the whole
    `review_complete` message against the wire bounds, and delivers it to the
  broker. A schema-valid report is **never vetoed for which files the model
  chose to read**, including withheld, denied, missing, over-limit or binary
  results, or no reads at all. The broker still validates the report, staged
  bundle integrity, and approval lifecycle before sending a card.
- **Correction:** a malformed first `submit_review` returns
  `{"status":"invalid","correction":"…"}` and the model may correct it once;
  a second malformed submission terminates the attempt.
- **Captured stdin turn boundary:** if the model read `bundle:stdin` in the
  same model turn that produced the report, `submit_review` is rejected with
  `{"status":"inspection_pending","correction":"Read the captured stdin tool
  results in the next model turn before submitting the review"}` — the model
  must receive the read results in a real model turn before finalizing.
  This costs no malformed-report allowance and never terminates the attempt.

### Optional `webfetch`

With `review.webfetch_enabled: true`, the reviewer worker can fetch one
model-chosen public HTTP(S) `url` (≤ 4096 bytes) per call. It returns
`status: "ok"`, `final_url`, `http_status`, and UTF-8 `content` (≤ 2 MiB
decompressed); fetch failures return only a fixed error category. The dedicated
client has a 15-second whole-fetch timeout, at most five redirects to the same
host, default HTTP(S) ports only, and no inherited proxy, cookies, URL
credentials, or provider tokens. URL, DNS results and dialed address are
checked against private, loopback, link-local and other non-public networks.
Fetched text is untrusted evidence: the tool does **not** execute code, follow
dependencies automatically, or verify that a remote script is safe to run.
The model chooses whether to follow another URL. The requested URL (including
its query) goes to the public server; the fetcher does not automatically attach
host files, but a model could include inspected data in a URL. An external
configured model provider may receive fetched content in its tool result.
`review.local_only` controls model selection separately from this opt-in.

## What the broker enforces

For every proxied path call the broker — running as root, on the broker side
of the trust boundary — enforces:

- **Protocol validity:** direction, `request_seq` order and correlation,
  argument bounds, and result shape (`internal/proto/worker.go`). Non-`ok`
  statuses (`withheld`, `binary`, `inspection_denied`, `not_found`,
  `changed_during_capture`, `limit_exceeded`, `unresolved`, `unknown`) carry
  no payload; legacy tools return only status, while the four new operations
  can also return a closed `reason_code` (see [wire reference](protocol-worker.md#inspect_result-bw)).
  Denial is an ordinary tool result, not proof that the guessed path exists;
  the model can still submit its report.
- **Inspection policy:** descriptor-relative, read-only, openat2-based access
  confined to `inspection.read_roots`, with `deny_paths` and the hard-deny
  set (`/etc/askdo`, `/var/lib/askdo`, `/var/lib/askdo-review`, `/run/askdo`, `/proc`,
  `/sys`, `/dev`) always denied. For configured allow and deny paths, the
  most-specific path rule wins and ties deny. Policy is evaluated on the
  authorized opened descriptor — object type, pseudo-filesystem rejection,
  protected identities, multi-hardlink regular file refusal, both path
  spellings and reachable same-object mount aliases — and the object and path
  are revalidated after each bounded read. `read_roots` may exclude a host
  file the operation will execute: the model then receives a denied tool
  result and can say so in its report.
- **Sensitive name masks:** a permitted host path or staged bundle path whose
  requested or resolved name matches `inspection.sensitive_masks` (or a
  client `sensitive_inclusions` opt-in) is answered `withheld` without
  content, or skipped with a `skipped_masked` count in list/search/find results.
  Masks match **names, not content**: a credential copied under an ordinary
  filename, or a secret value placed in argv, the environment, or `--reason`,
  can still leak. The broker records every reference it withheld (host
  spellings and masked bundle paths) as a factual access-policy signal — not
  a completeness assessment — and the reviewed Telegram card discloses the
  count and up to 16 references in a code-constructed warning.
- **Freeze-time validation** (`internal/broker/manifest.go`): the report and
  model history are re-validated against the wire schema; the caller's
  working directory identity is re-verified; every staged bundle file —
  including a captured-stdin script — is re-hashed (change-after-staging
  aborts `evidence_changed`); and the final successful model in the history
  must be a configured choice. The frozen manifest binds the report, the
  ordered model history, the exact command (mode, argv/environment, cwd), the
  caller's cwd identity, the staged bundle SHA-256 records, withheld
  references, and bounded inspection observations described below. Host file
  selection is never scored by the broker — the
  model cannot reference broker captures for host paths, it only ever
  received bounded bytes or observational metadata for paths it chose — but a
  captured-stdin script is
  the one broker-captured artifact with broker-verified read coverage (see
  *Completeness honesty model*).

### Inspection budgets and audit evidence

The root broker limits the four new operations together to 32 requests and
256 KiB of successful payloads per job (≤ 16 KiB each; hash results ≤ 1024
bytes). A separate 256-observation cap spans all broker inspection tools.
Disabled/denied requests consume the metadata request budget when dispatched;
review fallback never resets job accounting. Limits, withheld information and
adapter failures remain ordinary uncertain tool results: a schema-valid report
can still complete, but should retain material warnings and missing context.

Each recorded exchange appends a sanitized record to
`inspection-evidence.jsonl` in the protected root-only job spool, mode `0600`.
The writer refuses symlinks, multiply linked files and unsafe ownership/mode.
Records contain `sequence`, `operation`, `status`, closed `reason`,
`observed_at_unix_ms`, `selector_redacted`, and optional typed `metadata` or
`selector` (`source`, `path`, optional `resolved_path`). Successful new metadata
is strictly decoded and re-encoded; scope cursors are stripped. Successful legacy operations may retain
only a whitelisted, reauthorized path selector, never content. No raw responses,
search regexes, URLs, cursors or denied selectors enter this evidence file.
Audit write failure is a broker failure, not a successful observation.

When observations exist, the frozen manifest's `inspection` object binds their
ordered `observations`, `capabilities`, `max_hash_file_bytes`,
`max_hashed_bytes_per_review`, `metadata_requests`, `metadata_response_bytes`,
`hash_attempts` and `hashed_work_bytes` into the manifest SHA-256 **before
approval**. It does not add independent evidence
signatures or a quorum. Existing fleet gateway Ed25519-signed approvals cover
that manifest digest; the gateway stores approval display/ticket data, not the
entire raw model conversation. Evidence fields are data, not model instructions
or additional approval authority.

## Report schema

`submit_review` arguments (wrapped by trusted code into
`review_complete.report` on the wire):

| Field | Type — bounds | Meaning |
|---|---|---|
| `risk` | string enum `"1"` \| `"2"` \| `"3"` \| `"4"` \| `"5"` \| `"unknown"` | Security risk: 1 minimal, 2 low, 3 moderate, 4 high, 5 critical; unknown means not assessed and is never eligible for auto-approval |
| `summary` | string ≤ 2048 | Concrete consequences of running the operation |
| `effects` | array ≤ 32 of strings ≤ 512 | Expected effects |
| `warnings` | array ≤ 32 of {`message` ≤ 512, `evidence` ≤ 512} | Material risks, each with evidence reference |
| `missing_context` | array ≤ 16 of strings ≤ 512 | Uncertainties and context the reviewer could not obtain |
| `reversibility` | string ≤ 1024 | How the operation can be undone, honestly ("do not invent backups or rollback procedures") |
| `intent_match` | enum `consistent` \| `inconsistent` \| `unverified` | Whether the operation matches the client's stated `reason` |

All seven fields are required; no additional fields are permitted (notably no
`approved`, callback data, or provider identity). Embedded reviewer
instructions additionally forbid reproducing secret **values** in any field —
affected credentials are referenced by redacted description or path only —
forbid claiming to have reviewed withheld credential contents, and direct the
model to list every withheld path as uncertainty in `missing_context`.

## Completeness honesty model

There is deliberately **no coverage scoring for host files**: nothing tracks
which bytes the model saw from host paths, no tool marks a path required, and
no mechanical check decides whether that side of the review was complete.
Honesty is structural instead:

- The model alone decides which files, in any language, are relevant and
  reads them with the path tools. Following `source ./helper` is a model
  choice, not a mechanically verified dependency edge. This is reviewer
  judgment, not an exhaustive dependency analysis or a hermetic guarantee.
- The embedded instructions ask for effects, material risks, and uncertainties
  relevant to the assessment. Failed or withheld reads are mentioned only
  when they affect that assessment, not as automatic boilerplate.
- The reviewed Telegram summary shows the model's report. If the broker
  withheld credential content, a code-constructed notice with the count and
  withheld references leads the summary. Neither file selection nor command
  syntax causes an additional machine-authored review judgment.
- Host reads and optional hashes provide observations, **not source-byte pins**
  for dispatch. Even a hash in the manifest does not guarantee later executable
  identity; approving a metadata-resolved host path remains an operator assumption.
- A job with no model report — provider exhaustion handled as
  `review_unavailable`, or a reviewer that ended without `submit_review` —
  is never labeled reviewed. The unreviewed lane is the distinct **NO AI
  REVIEW** Telegram card, which still requires the human decision.

Captured stdin is the exception: it is a broker-captured, broker-staged
artifact with exact known bytes, so the broker does verify read coverage for
it.

- While the review runs, the broker records which bytes of `bundle:stdin` it
  actually delivered to the final model (successful `read_path` results
  only, tracked per byte; model assertions, failed and withheld reads add
  nothing).
- At freeze time, coverage counts only if history has exactly one entry —
  a successful final model — with an end-of-file read. Coverage is never
  combined across fallback models.
- If the captured script was not fully read, the broker appends its own
  operator-visible warning to the report before freezing: a `warnings` entry
  ("Broker cannot verify that the AI read all captured stdin script bytes;
  inspect before approval.", with broker-observed coverage evidence) plus a
  `missing_context` entry — and fails closed if the report has no room left
  for them. The reviewed Telegram card shows the warning in its Warnings
  section plus an `Input: captured script input (N bytes); review via
  bundle:stdin` line: size and location only, never the script body. This is
  a broker-authored notice, not model-authored, and it does not change the
  model's score.
- A captured-stdin job is also **never auto-approved**, regardless of an
  otherwise eligible score, grant and preference.

## What the reviewer cannot do

- **No shell or arbitrary process-execution tool.** The reviewer runs as the
  unprivileged `askdo-review` user with an empty supplementary-group list and
  refuses to run as root. Optional service/sudo inspection uses the root
  broker's fixed bounded metadata adapters, never a model-selected command.
- **No unrestricted network tool for the model.** The optional `webfetch`
  is limited to public HTTP(S) targets under the bounds above; with the flag
  off it is neither offered nor executable. Trusted reviewer code also calls
  configured model endpoints and the Telegram Bot API through bounded HTTP
  clients (the Codex subscription endpoint uses bounded SSE). This is an
  application/tool boundary, **not an OS-enforced network sandbox** around
  the `askdo-review` process; a compromised reviewer binary could open other
  connections. Normal redirects to credential-forwarding targets and hidden
  retries are not allowed.
- **No host-content reads outside broker mediation, no file-write tool.**
  The reviewer reads its authorized model API keys and Telegram bot token
  from credential files; the broker alone reads the Codex refresh token.
  Its tool-accessible view of host content is broker-mediated path
  inspection.
- **No browser, MCP, delegation, or sub-agent tools.**
- **No authorization.** `submit_review` only submits a report. The approval
  card, its nonce, and its buttons are constructed by fixed code; the
  decision is validated against operator user ID, chat, card message,
  nonce, expiry and one-use status by trusted worker code's poller. The broker
  checks the reported decision's digest, operator ID, card ID, expiry and
  one-use state under its dispatch lock; it does **not** independently poll
  Telegram or authenticate the original callback. Model output can never
  become a decision.
