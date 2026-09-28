# Configuration reference

One file: `/etc/askdo/config.json` (override with `--config`), schema
`config_version: 4`, plus the credential files it references. Decoding is
strict: unknown fields are rejected at every nesting level, and
durations are quoted Go duration strings (`"2m"`, `"30s"`). The daemon and
`askdo config check` run the identical validation
(`internal/config/config.go`).

**You rarely edit this file by hand.** For a fresh installation, inspect the
checkout's `install.sh` and run `./install.sh` only with the machine owner's
approval;
it does not enable or start the service (see the README "Install and onboard"
section and [clean installation guide](clean-cutover.md)). The onboarding
wizards own the common writes and apply the credential ownership/mode rules for
you:
`askdo reviewer add|edit|delete|moveup|movedown` manage `review.models` and
the model credential files, while
`askdo channel add telegram` writes the bot token file and the
`telegram` section. To authorize a submitting user, add it to the single
`askdo` group (`usermod -aG askdo <user>`). That group admits socket requests
and the fixed no-argv sudo helper only for an approved, verified original-TTY
foreground grant; it does not confer general sudo rights. Enroll each
agent and human account with the operator's explicit approval, and refresh
login credentials before submitting. No controlling TTY means
automatic detached execution, without requiring `--detach`; a TTY caller can
choose `--detach` explicitly. What remains file-based by design is the one-time
host-trust policy — `inspection.*` and
`limits.*` — edited directly or installed from a curated file with
`askdo config install FILE` (which validates before anything lands).
This document is the reference for every field the wizards write and for
those file-based sections.

As root, `askdo review mode required` or `askdo review mode approval-only`
sets the policy (`approval-only` on the CLI becomes
`approval_only` in JSON). `askdo review exempt add <username>` and
`askdo review exempt remove <username>` manage OS login exemptions in
`required` mode; `askdo review mode` and `askdo review exempt list`
display current settings. These commands do not grant socket access or replace
Telegram.

Validate with:

```sh
askdo config check         # offline validation + warnings + openat2 probe
askdo config check --live  # additionally probes each model endpoint
                           # with a synthetic fixture (never host files)
```

## Field reference

"Required" means the key must be present in the file. Defaults apply only
when the key is absent.

### Top level

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `config_version` | yes | — | Must equal `4`. |
| `inspection` | yes | — | Object, below. |
| `review` | yes | — | Object, below. |
| `limits` | yes (object) | all fields defaulted | Object, below. |
| `telegram` | yes | — | Object, below. |

### `inspection`

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `read_roots` | yes | — | Absolute, cleaned allow paths (files or directory trees). Empty disables host-content inspection. Requested spellings are retained; no current-working-directory access is implied. |
| `deny_paths` | no | `[]` | Absolute, cleaned exclusions. The most-specific component-wise match wins across allow and deny rules; ties deny, and no match denies. Allow `/`, deny `/home/user`, allow `/home/user/bin` reopens only the `bin` subtree. |
| `trusted_executable_roots` | no | — | **Deprecated and ignored.** Still accepted by the strict decoder so existing version 4 files that carry it keep loading, but the value has no effect: no validation, no warning, no policy decision, and no record in the frozen approval manifest. There is no trusted-code category that substitutes for the model reading code, and the reviewer does not automatically discover dependencies. Omit this field in new configurations. |
| `sensitive_masks` | no | built-in default list | Credential-like path **name** masks. Omitting the field compiles the built-in list of 31 well-known secret-name conventions; an explicit **non-empty** array **replaces** the defaults entirely (it does not extend them), so tuning out one false positive without re-listing the others silently unprotects them. An explicit empty or `null` array is invalid — never a silent disable. At most 256 masks, each ≤ 256 bytes, valid UTF-8, no backslashes, control characters, or empty/`.`/`..` components. Mask syntax and matching semantics are defined below. |

A mask is a slash-separated glob over Linux path components, matched purely
lexically and **case-sensitively** (Linux semantics):

- A mask **without** a slash matches **any single path component**; matching a
  directory component makes that whole subtree sensitive (`.ssh` covers
  `/home/u/.ssh/id_rsa`).
- A mask **with** slashes matches a **contiguous run** of components ending at
  any position, so `.config/gcloud` covers `/home/u/.config/gcloud` and
  everything beneath it.
- Within one component, `*`, `?`, and `[...]` follow `path.Match` syntax and
  never cross a slash. There is **no `**` recursive operator**.

Both the **requested spelling** and the **symlink-resolved** host path are
evaluated, so an alias cannot launder a sensitive target name.

Masks are a **name convention, not content scanning**: a secret stored under
an ordinary filename, or a value carried in argv, environment, or the submit
`--reason`, can still leak. Masks also do not grant or deny access by
themselves: `read_roots`, `deny_paths`, and the hard-deny set below still
decide whether a host path may be opened at all. A masked path that policy
permits is metadata-checked and its contents withheld from the reviewer
model; a masked path outside policy is denied like any other.

The shipped `askdo-config.example.json` lists every built-in default
mask explicitly. Because an explicit array replaces the defaults, that file
**pins the default set until edited**: removing or renaming an entry
narrows protection, and adding entries extends it.

Requested and opened names and reachable same-object mount aliases must pass
the same policy. Regular files with multiple hardlinks are conservatively
refused because their other names cannot be proved safe without a tree walk.
Client-side bundle capture likewise refuses multiply linked files before
reading them; a separately copied secret under an ordinary name is not
detectable by name masks.
Mountinfo coordinates unreachable in the current namespace are not aliases.
Regardless of these lists, the broker hard-denies host inspection of
`/etc/askdo`, `/var/lib/askdo`, `/var/lib/askdo-review`,
`/run/askdo`, configured credential files (even outside `/etc`), and the
pseudo-filesystems `/proc`, `/sys`, `/dev`. Hard
denies apply to host inspection only, never to submitted bundle content.

`askdo inspection check <path> [--config PATH]` runs as root and prints
ALLOWED or DENIED with the decisive rule and resolved path where available.
It opens metadata only; it does not print contents or change configuration.
It reports an **inspection policy decision only**; incomplete reviewer or
Telegram sections are intentionally permitted during onboarding. Run
`askdo config check` for complete service configuration validation.
Inspection requires `STATX_MNT_ID` (normally Linux 5.8+), in addition to
`openat2`; missing kernel support fails closed.

### `review`

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `local_only` | no | `false` | If true, every entry in `models` must declare `data_boundary: "local"`; entries declared external or unspecified are rejected. This checks the operator's inference-location declarations, not network isolation. A LAN inference server is valid; a proxy can still forward data elsewhere. Telegram delivery is unaffected. |
| `mode` | no | `"required"` | `required` reviews all submitters except exempt UIDs; `approval_only` skips AI review for every submitting socket-group member. A human Telegram decision remains mandatory for **NO AI REVIEW**; eligible detached AI-reviewed jobs can use an explicitly configured risk auto-approval grant. Set `approval_only` explicitly for model-free use. |
| `approval_only_users` | no | `[]` | OS login names exempt from AI review in `required` mode only; no UID or client-supplied username strings. Names resolve to UIDs at config load; missing or duplicate accounts fail validation. An agent sharing an exempt UID is exempt too. `--review=yes` overrides an exemption. |
| `auto_approve_grants` | no | `[]` | Root-owned opt-in grants, each naming an OS login and `max_risk` from `1` through `4`. The login resolves to a UID at config load; invalid/missing accounts fail validation. A grant sets the administrator cap; the submitter's local preference cannot raise it. Empty means disabled. |
| `models` | yes | — | Ordered fallback list. May be empty only with explicit `approval_only` or `required` plus nonempty `approval_only_users`; non-exempt/forced-review submitters then fail closed. Adding a model does not itself change `approval_only` policy. |
| `request_timeout` | no | `"2m"` | Per-request provider timeout; Go duration > 0. |
| `total_timeout` | no | `"20m"` | Whole-review budget across all fallback choices; > 0 and ≥ `request_timeout`. Becomes the worker's `review_deadline_unix_ms`. |
| `max_model_calls_per_attempt` | no | `32` | 1–128; bound on model turns per attempt. |
| `max_output_tokens` | no | `8192` | 1–200000; bound on tokens per model response. |

Auto-approval requires an administrator grant and a submitter preference. The
submitter can inspect/set/disable their preference without root via
`askdo auto-approve status`, `askdo auto-approve set N` (N is 2–5), and
`askdo auto-approve off`; peer credentials bind this setting to the caller's
UID. Only a reviewed job with both a root-owned UID grant and that UID's
preference is eligible. The administrator's `max_risk` cap is authoritative.
Effective threshold is `min(preference, cap + 1)`: only a valid AI report
scored 1–4 and strictly below that threshold is eligible. Score 5, `unknown`,
and **NO AI REVIEW**
always require the ordinary human decision.

Example grant (add to the `review` object; retain other existing fields):

```json
"auto_approve_grants": [{"user": "alice", "max_risk": 2}]
```

An administrator grant is an explicit acceptance of model self-reporting,
prompt-injection, and misclassification risk; the score is not independently
verified. Credential masks still withhold matching credential contents, but
there is no new machine completeness classifier. Telegram still receives the
reviewed summary, followed by a button-free informational notice for eligible
jobs. Dispatch requires Telegram Bot API acknowledgement, clean worker exit,
prelaunch checks, and an atomic audit write (`kind:auto`) with the
`StateStarting` transition. Delivery failure, cancellation/revocation, or a
digest change fails closed; this is not silent auto-execution. No human
operator or approval-card ID is fabricated.

### `review.models[]`

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `name` | yes | — | Non-empty, unique across the list. |
| `api` | yes | — | Wire adapter: `openai_chat`, `openai_responses`, `anthropic_messages`, or `openai_codex`. The first three append their fixed suffix (`/chat/completions`, `/responses`, `/messages`) to `base_url` exactly once; a root may already carry a version prefix such as `/v1`. `openai_codex` is the ChatGPT-subscription Codex backend (OAuth via `askdo auth login openai-codex`, see below): it ignores the adapter-suffix rule and always uses the fixed backend URL `https://chatgpt.com/backend-api/codex`, and its `data_boundary` must be `external`. |
| `base_url` | yes | — | Absolute `http` or `https` URL. Plaintext `http` to a non-loopback host is **accepted with a config warning** — LAN-hosted inference (Ollama on a Spark/GB10, SGLang on a cluster node) is a normal deployment — but reviewed content and any API key then cross the network unencrypted. Other schemes are rejected. For `openai_codex` the field stays required for schema uniformity but is overridden by the fixed Codex backend URL. |
| `model` | yes | — | Non-empty opaque model identifier. |
| `api_key_file` | conditional | — | Required unless `data_boundary` is `"local"`. Absolute path to a credential file (requirements below). When omitted, requests carry no authorization header at all — intended only for deliberately unauthenticated local services. **For `api: "openai_codex"`** it names the OAuth token JSON written by `askdo auth login openai-codex`: it is always required, is **broker-only** (the reviewer never opens it — the broker projects the refreshed access token into the worker bootstrap), and follows the stricter root:root `0600` rule below instead of the `askdo-review` key rule. |
| `data_boundary` | no | `"external"` | `local` or `external`. Declares whether inspected content may leave the host through this provider. An explicitly present but empty value is rejected. |
| `request_timeout` | no | `review.request_timeout` | Per-model override; Go duration > 0. |

Every configured model is authorized to receive the operation and all
inspectable content — there are no per-file or per-provider permissions. The
list order is the fallback order. Without `--review=yes`, only exhaustion
of typed provider availability failures can offer a **NO AI REVIEW** Telegram
approval instead of a report; safety refusal, malformed final review,
broker/capture/changed-evidence failures, and elapsed deadlines fail closed.
`--review=yes` requires a completed AI review and fails if no model is
configured or every choice is unavailable. **NO AI REVIEW** never qualifies
for auto-approval.

For all group members to submit without models, use this `review` excerpt
alongside valid `inspection`, `limits`, and `telegram` sections:

```json
{"review": {"mode": "approval_only", "models": []}}
```

For a mixed setup, only the OS login `alice` is exempt (including agents
running under her UID); other members require the model. Replace the model ID
and add the other required top-level sections as in the full example below:

```json
{"review": {
  "mode": "required",
  "approval_only_users": ["alice"],
  "models": [{
    "name": "local", "api": "openai_chat",
    "base_url": "http://127.0.0.1:11434/v1",
    "model": "<your-local-model-id>", "data_boundary": "local"
  }]
}}
```

With `required`, `approval_only_users` and `models: []`, exempt UIDs can
request approval but other group members (and any `--review=yes` request)
cannot; this is not a general model-free completeness guarantee. Telegram
configuration is always required.

### `limits`

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `max_inspected_files` | no | `256` | ≥ 1. Bound on staged bundle files per job; also bounds the file set of one bundle-scope `search_path` call. |
| `max_inspected_bytes` | no | `8388608` (8 MiB) | ≥ 1 and ≤ 66060288 (fits under the 64 MiB frame ceiling). Total staged bundle byte budget per job; also sets the daemon's effective client frame limit to `max_inspected_bytes + 1 MiB` and caps the content one broker-side bundle search will scan (further bounded to 1 MiB per search call). |
| `max_log_bytes_per_stream` | no | `33554432` (32 MiB) | ≥ 4096. Retained-output cap per stream (stdout/stderr); a fixed truncation marker is appended at the cap and further bytes discarded while the pipe keeps draining. |

### `telegram`

Telegram is the mandatory decision interface; there is no approval path
without it.

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `token_file` | yes | — | Absolute path to a file containing only the bot token; same credential-file requirements as `api_key_file`, plus ≤ 4096 bytes, non-empty after trimming, no `/` or NUL. |
| `operator_user_id` | yes | — | Integer > 0. The sole numeric Telegram user ID allowed to decide; `0` (the shipped placeholder) is invalid. Usernames and group membership are never authentication. |
| `chat_id` | yes | — | Integer ≠ 0. The private chat the approval card is sent to; callbacks from any other chat are rejected. |
| `approval_ttl` | no | `"10m"` | At least 30 s; no one-hour upper limit. Approval lifetime, measured from the moment the complete Telegram request is sent, and additionally capped by the client's remaining pre-dispatch deadline. The 30 s minimum remains to allow a usable decision window; `review.request_timeout` and `review.total_timeout` are separate review budgets. |

## Credential file requirements

Every credential file referenced by `telegram.token_file` or
`review.models[].api_key_file` must, at validation time (daemon startup and
`config check`):

- be an absolute path to an existing **regular file**;
- be owned by **root** (UID 0);
- have group **`askdo-review`** (the group must exist);
- have mode **no more permissive than `0640`**.

**Exception — `openai_codex` OAuth token file:** `review.models[]` entries
with `api: "openai_codex"` point `api_key_file` at the token JSON written by
`askdo auth login openai-codex`. That file holds the OAuth refresh
token, so it must be readable by the broker alone: owner **root**, group
**root**, mode **exactly `0600`**. The reviewer never opens it — at review
start the broker loads it, refreshes the access token when it is inside the
5-minute expiry window (persisting the rotated refresh token atomically;
refresh tokens are one-time), and projects only the fresh access token and
account ID into the worker bootstrap. A revoked/expired/already-used refresh
token fails the model as an invalid-config availability failure (the
fallback advances to the next configured model; if none remain the job fails
before any review) until you re-run `askdo auth login openai-codex`.

Rationale: the broker (root) validates them; the reviewer (running as
`askdo-review`) reads them through group membership; the submitting agent can
read neither. The recommended layout is:

```sh
install -d -m 0750 -o root -g askdo-review /etc/askdo/credentials
install -m 0640 -o root -g askdo-review /dev/stdin \
  /etc/askdo/credentials/telegram.token
install -m 0640 -o root -g askdo-review /dev/stdin \
  /etc/askdo/credentials/openai.key
```

The Codex OAuth token file is not installed by hand — `sudo askdo auth
login openai-codex` writes `/etc/askdo/credentials/openai-codex.json`
as root:root `0600` itself.

Contents are read exactly once (the Telegram token at client construction,
each API key at provider-session construction), held in memory, and attached
only to requests against the configured endpoint. Configured provider API key
and Codex access-token values are redacted from error diagnostics. Already-bounded
HTTP and SSE error payloads are retained in the root-only reviewer log; arbitrary
secret detection in provider responses is not guaranteed. Treat the reviewer
log as sensitive even though socket clients cannot read it.

## Worked example

The shipped `askdo-config.example.json` is structurally valid but
deliberately fails validation until populated: its default required policy has
an empty `review.models`, and `telegram.operator_user_id`/`chat_id` are zero.
It demonstrates inspection roots, limits, and review scalars with usual values,
and it lists `inspection.sensitive_masks` explicitly — pinning the built-in
default mask set until you edit that array (see the field reference above).
Choose the explicit approval-only policy above if no reviewer is needed, or run
`askdo reviewer add` once per model (each entry lands in
`review.models` with its credential file installed under
`/etc/askdo/credentials/`), `askdo channel add telegram` for the
bot token and IDs. Add each submitting user to the `askdo` socket group.
If your agent's scripts live outside the shipped
`inspection.read_roots`, add that directory to the file directly. Then run
`askdo config check`.

### Minimal local-only test config

The smallest useful configuration: one local, unauthenticated inference
server, `local_only: true`, no API key files. Only the Telegram token file is
a credential.

```json
{
  "config_version": 4,
  "inspection": {
    "read_roots": ["/usr/bin", "/usr/local/bin"],
    "deny_paths": []
  },
  "review": {
    "mode": "required",
    "local_only": true,
    "models": [
      {
        "name": "ollama-local",
        "api": "openai_chat",
        "base_url": "http://127.0.0.1:11434/v1",
        "model": "<your-local-model-id>",
        "data_boundary": "local",
        "request_timeout": "5m"
      }
    ],
    "request_timeout": "2m",
    "total_timeout": "20m",
    "max_model_calls_per_attempt": 32,
    "max_output_tokens": 8192
  },
  "limits": {
    "max_inspected_files": 256,
    "max_inspected_bytes": 8388608,
    "max_log_bytes_per_stream": 33554432
  },
  "telegram": {
    "token_file": "/etc/askdo/credentials/telegram.token",
    "operator_user_id": 0,
    "chat_id": 0,
    "approval_ttl": "10m"
  }
}
```

This excerpt omits `inspection.sensitive_masks`, so the built-in default mask
list applies; add the field only to replace that list wholesale.

Replace the model ID and both zero Telegram IDs with your own values before
validation; add the submitting user to the `askdo` socket group and
create the token file with the ownership and mode above. Plaintext
`http` to a non-loopback host (e.g. a LAN inference server) is accepted with
a validation warning; use `https` whenever the content may leave a trusted
network segment.
