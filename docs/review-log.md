# Review journal

Each host broker appends its own root-owned, mode `0600` journal at
`/var/lib/askdo/reviews.jsonl` (beside its jobs database). The path follows the
broker's state/database directory; fleet gateways do not collect these files.
The file is created lazily. Journal errors produce `slog` warnings but do not
reject approvals, execution, terminal transitions, or daemon startup.

Read it locally as root:

```sh
askdo review log                         # jobs active in the last 24 hours
askdo review log --since 7d               # equivalently, --since 168h
askdo review log --job '2026-10-22_#1' --since 0
askdo review log --since 0 --json         # all original JSONL records
```

The compact view joins by (`job_id`, `submitter_uid`), sorts newest activity first
(job ID, then UID, breaks ties), and includes the command, identity, risk or `NO AI`,
final decision, result kind, exit code or signal,
summary, warnings, and uncertainties. `--since` selects jobs with any recent
activity, retaining older review context for their outcomes. With `--json`, it
filters individual records instead and preserves their original bytes and file
order. `--job` matches the ID exactly and shows each submitting UID separately;
`--since` accepts Go durations (such as `1h30m`) or a number of days (such as
`7d` or `0.5d`); `--since 0` disables the time filter. Output write failures return
nonzero. Malformed lines are reported by line number on stderr and skipped. A missing journal is
empty history. A missing outcome means **not recorded**, not necessarily pending.
For a recent compact view, two passes select active keys before retaining their
records, so unrelated old jobs do not accumulate in memory. `--since 0` explicitly
retains all history; `--job` limits retention to that ID.

## JSONL schema (version 1)

Every record has `version`, `event`, UTC `time`, `job_id`, and `submitter_uid`.

* `review`: emitted once after the AI approval manifest successfully freezes.
  Contains host, submitter UID/name, target UID, mode, approval-display `argv`
  (or bundle `entry` plus `args`), cwd, reason, captured-file path/size/SHA-256/
  masked metadata, model names/outcomes, successful model, the structured report
  (risk, summary, effects, warnings, missing context, optional suggestions, reversibility, intent
  match), withheld references/count, optional auto-approval plan, inspection
  counts grouped by operation/status/reason, and `manifest_digest`.
* `unreviewed`: the same operation metadata without an AI report, plus
  `approval_reason` and typed `availability_history` failures when applicable.
* `outcome`: final `state`, optional `result_kind` (the stored result kind),
  `exit_code` for an exit result or `signal` for a signal result, `approval_kind`
  (`human`/`auto`/`none`), and `decision` (`approved`, `denied`, `request_changes`, `expired`,
  `cancelled`, or `none` when no decision occurred). Covers terminal transitions,
  expiry sweeps, and restart invalidation. `unknown` records lost execution
  tracking honestly; it does not invent an exit code. Older version-1 records may
  lack `result_kind`/`signal`. Outcome fields are captured atomically with the
  terminal state mutation before retention can compact the row, then appended
  after commit. A human decision registered while the job is live stays recorded as `human`
  with `approved`, `denied`, or `request_changes` whichever terminal state the job reaches before
  dispatch commits: a pre-launch failure, a client deadline that lapses during
  pre-launch checks, cancellation, or an expiry sweep yields `failed`, `expired`
  or `cancelled` beside that decision. Approval did not imply execution, and no
  dispatch/authorization checks are bypassed. Registration and terminal snapshots
  serialize on the store's single connection. If a terminal mutation wins before
  registration, the already-ended job keeps its no-decision outcome and no late
  decision is retained. This record of a consumed decision
  is held in broker memory only until the outcome is appended, and is never
  written early to the approval record. If the broker dies after consuming a
  decision and before dispatch (or foreground handoff) commits, restart recovery
  can only report `expired` with `approval_kind: "none"`.
  Broker wrapper failures atomically store and journal `result_kind: "wrapper"`.
  Request changes normally records `state: "denied"`, `result_kind: "decision"`,
  and `decision: "request_changes"`, never execution. The compact viewer shows
  that decision; the correlated review retains its suggestions. If cancellation
  or a deadline wins after consumption, the accepted choice remains recorded
  beside the actual terminal state, without inventing a decision result payload.
  If an approved foreground handoff later expires, is cancelled, or is
  invalidated by restart, its decision remains `human`/`approved`; the final
  state conveys what happened to the handoff. `expired`/`cancelled` decisions
  are synthesized only when no human or auto decision has been recorded.

The journal never copies captured file contents, environment values, credentials,
provider response bodies, raw reviewer logs, or inspection selectors/payloads.
Model-history error text is omitted. Command arguments, reasons, report text,
and paths are already approval-card material and can still be sensitive; do not
put secrets in arguments/reasons or share this root-only journal indiscriminately.
This is a best-effort scrutiny log, not a transactional or tamper-proof audit
ledger: a crash or write failure can leave missing records.
Cooperating appenders use an inode lock and inspect the final byte while holding
it. If a failed write left a partial record, the next append first delimits that
fragment with a newline. The CLI skips the malformed fragment without losing
the later complete record; existing history is not truncated or rewritten.

## Growth and rotation

There is no size cap or automatic rotation. The append-only JSONL file grows
until an administrator rotates or archives it with standard tools. Rename the
file and retain the archive root-only; the next append creates a new `0600`
file without a daemon restart. The CLI reads only the current file. Database
retention does not delete journal records. Review and outcome records may span
archives, so keep archives together when analyzing older jobs.
