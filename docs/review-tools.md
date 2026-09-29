# Review tools and report schema

When AI review is required, the reviewer model always has the six broker-mediated
filesystem inspection tools (`read_path`, `list_path`, `search_path`,
`stat_path`, `find_path`, `mount_info`) plus the worker-side `submit_review`
(`internal/reviewer/tools.go`, `Definitions()`); the six inspection tools use
private-pipe `inspect_request`/`inspect_result` exchanges. One additional,
worker-side `webfetch` tool is offered only when the root-owned
`review.webfetch_enabled` setting is true (false by default). Configuration
cannot redefine the tools. Tool calls execute strictly sequentially.

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

Every path tool except host-only `mount_info` takes `base` (enum `"host"` or
`"bundle"`). A host path is a clean absolute path; a bundle path is a clean
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

### 7. `submit_review`

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
  no payload; the model receives only the fixed status string. A denied read
  is an ordinary tool result: the model learns that the path exists outside
  what policy permits it to see, and it can still submit its report.
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
  caller's cwd identity, the staged bundle SHA-256 records, and the withheld
  references. Host file selection is never cross-checked by the broker — the
  model cannot reference broker captures for host paths, it only ever
  received bounded bytes for paths it chose — but a captured-stdin script is
  the one broker-captured artifact with broker-verified read coverage (see
  *Completeness honesty model*).

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
- A host executable the model never chose to read has **no source-byte pin**
  in the frozen manifest; approving such a job is the operator's explicit
  assumption (see the README).
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

- **No shell, no process execution.** There is no exec tool; the reviewer
  binary itself is the only process the broker starts, and it runs as the
  unprivileged `askdo-review` user with an empty supplementary-group list.
  The reviewer refuses to run as root.
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
