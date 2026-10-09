# Configuration reference

One file: `/etc/askdo/config.json` (override with `--config`), schema
`config_version: 4`, plus the credential files it references. (Fleet hosts
instead use `config_version: 5` — see [below](#fleet-host-config-version-5);
the optional central gateway has its own separate
[version 1 file](#gateway-server-config-version-1).) Decoding is
strict: unknown fields are rejected at every nesting level, and
durations are quoted Go duration strings (`"2m"`, `"30s"`). The daemon and
`askdo config check` run the identical validation
(`internal/config/config.go`).

**You rarely edit this file by hand.** For a fresh installation, inspect the
checkout's `install.sh` and run `./install.sh` only with the machine owner's
approval;
it does not enable or start the service (see [Get started](../README.md#get-started)
and the [clean installation guide](clean-cutover.md)). The onboarding
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
askdo config check         # offline validation + warnings + kernel feature
                           # probe (prints the actually selected backend)
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
| `read_roots` | yes | — | Absolute, cleaned allow paths (files or directory trees). Empty disables host-content inspection. Requested spellings are retained; no current-working-directory access is implied. A root need not exist yet (for example a temporary directory created after boot): it stays in scope as spelled, requests under it report `not_found` until it exists, and a path that appears later is inspected under the same per-request policy without a restart. Only the spelling is allowed — a root that later appears as a link to a protected, denied or out-of-scope target is still refused where it resolves. |
| `deny_paths` | no | `[]` | Absolute, cleaned exclusions. The most-specific component-wise match wins across allow and deny rules; ties deny, and no match denies. Allow `/`, deny `/home/user`, allow `/home/user/bin` reopens only the `bin` subtree. |
| `trusted_executable_roots` | no | — | **Deprecated and ignored.** Still accepted by the strict decoder so existing version 4 files that carry it keep loading, but the value has no effect: no validation, no warning, no policy decision, and no record in the frozen approval manifest. There is no trusted-code category that substitutes for the model reading code, and the reviewer does not automatically discover dependencies. Omit this field in new configurations. |
| `sensitive_masks` | no | built-in default list | Credential-like path **name** masks. Omitting the field compiles the built-in list of 31 well-known secret-name conventions; an explicit **non-empty** array **replaces** the defaults entirely (it does not extend them), so tuning out one false positive without re-listing the others silently unprotects them. An explicit empty or `null` array is invalid — never a silent disable. At most 256 masks, each ≤ 256 bytes, valid UTF-8, no backslashes, control characters, or empty/`.`/`..` components. Mask syntax and matching semantics are defined below. |
| `hash_path_enabled` | no | `false` | Source-only opt-in to bounded executable SHA-256 metadata. Does not bypass path policy, return bytes or pin a later execution. |
| `service_status_enabled` | no | `false` | Source-only opt-in to fixed observational metadata for one literal `.service` unit. No arbitrary properties or service actions. |
| `sudo_policy_enabled` | no | `false` | Source-only opt-in to sanitized policy listings for the submitting UID and explicitly authorized additional UIDs. Does not grant sudo rights. |
| `sudo_policy_uids` | no | `[]` | At most 127 additional numeric uint32 UIDs, not login names; unique integers 0–4294967295. Null array/elements, duplicates, strings, fractions and out-of-range numbers are rejected. The caller is always eligible when enabled; UID 0 has no special exemption. |

The three capability flags accept JSON booleans, never `null`. These fields
apply equally to direct v4 and fleet v5 hosts, not the separate gateway-server
v1 configuration. An unchanged old host configuration keeps all three off.

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
Inspection is selected by actual kernel feature probes, not a blind version
check: `openat2` is preferred, and only its absence
(`ENOSYS`) selects the legacy `os.Root` confined fallback with exact
`name_to_handle_at` mount IDs (statx `STATX_MNT_ID` preferred when present).
Permission and resource errors on either path fail closed, and filesystems
without descriptor mount identity are denied per object — there is no
blanket-filesystem support flag, no uname-based guessing, and no
configuration override for the backend the probe selected. Legacy paths were
tested on real Linux 3.10.108 (x86_64, ext4); native daemon and service-lifecycle
acceptance remains deployment-specific. `askdo config check` prints which
backend the same probe selected.

Go 1.27.1's Unix `os.Root` implementation opens intermediate directories
read-only while walking a confined path. Search-only ancestor access can
therefore be insufficient even when the final acquisition is metadata-only
(`O_PATH`). Such permission failures remain fail-closed; no broader read root,
ACL bypass, or alternate path walker is selected to compensate.

These source-only compatibility changes require compatible fleet gateway and
joining host broker/reviewer builds. Older strict peers can reject
`display.captured_stdin_kind`, `operation.captured_stdin.delivery_kind`, or
inspection-scope `compatibility`. Modern sealed-memfd jobs also emit the new
kind metadata; it is not enabled only on legacy kernels. Current-version
fixtures do not establish older-peer interoperability. Coordinate an
owner-approved rollout before joining the new flow; this does not require
upgrading every existing host or authorize a fleet upgrade/restart. Native
host installation and acceptance remain separate from source publication.

#### Optional host evidence and rollout

These additions are implemented on the `feat/reviewer-host-evidence` source branch,
**not in published rc.2 binaries** and not implied by the separate existing
foreground-helper sudo hardening. Old strict config parsers reject unknown
new fields, even if a new flag is set to false. Do not add them to an old
installation before upgrading its parser, root broker and reviewer together.
The broker must understand the new operations, bootstrap capability projection
and fixed tool registry; upgrading only the reader/reviewer is insufficient.

The fleet wire already relays typed tool-definition arrays (up to 32), so an
existing compatible gateway can relay the new maximum twelve-tool registry
without a gateway-side tool-name allowlist change. Host-local root code still
enforces the exact offered definitions and inspection policy. No new gateway
config flags or signing keys are needed; verify deployed version compatibility
before rollout rather than assuming that an arbitrary old gateway works.

After owner review and merge, obtain approval **per host** for the binary
upgrade, specific flag/UID/path values, queue drain and askdo restart. This is
not authorization to change running configuration or restart shared services;
OpenCode/GPU services are outside this rollout. Retain existing denies,
protected paths and all 31 default masks (plus any operator additions).
Do not replace narrow roots with all of `/etc` merely to use sudo metadata:
the required **additions** to existing `read_roots` are `/etc/sudoers`,
`/etc/sudoers.d`, and `/etc/passwd`. Other configured sudo source paths and
returned command paths remain subject to their own policy checks. Keep flags
off until their owner-approved policy is installed and checked.

If the operator chooses to inspect an additional account, an illustrative
field is `"sudo_policy_uids": [1000]` inside the existing inspection object.
UID 1000 is a common example, **not a deployment value**: the owner must select
the actual numeric account. Listing UID 0 is not needed for ordinary caller
inspection and should not be added by default. Sudo metadata queries do not
alter the narrow foreground-helper sudoers rule or other root execution policy.

The 127-entry configuration cap leaves room for the caller in the scope tool's
128 effective authorized UID limit. Prefer only the additional accounts actually
needed for a review; this list is authorization to observe their sudo policy,
not a grant of their execution privileges.

Use [review tools](review-tools.md) for the exact metadata contracts and
side-effect caveats, and [validation](validation.md#host-evidence-validation)
for the distinction between fixture checks and deployment evidence.

### `review`

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `local_only` | no | `false` | If true, every entry in `models` must declare `data_boundary: "local"`; entries declared external or unspecified are rejected. This checks the operator's inference-location declarations, not network isolation. A LAN inference server is valid; a proxy can still forward data elsewhere. Telegram delivery is unaffected. |
| `mode` | no | `"required"` | `required` reviews all submitters except exempt UIDs; `approval_only` skips AI review for every submitting socket-group member. A human Telegram decision remains mandatory for **NO AI REVIEW**; eligible detached AI-reviewed jobs can use an explicitly configured risk auto-approval grant. Set `approval_only` explicitly for model-free use. |
| `approval_only_users` | no | `[]` | OS login names exempt from AI review in `required` mode only; no UID or client-supplied username strings. Names resolve to UIDs at config load; missing or duplicate accounts fail validation. An agent sharing an exempt UID is exempt too. `--review=yes` overrides an exemption. |
| `auto_approve_grants` | no | `[]` | Root-owned opt-in grants, each naming an OS login and `max_risk` from `1` through `4`. The login resolves to a UID at config load; invalid/missing accounts fail validation. A grant sets the administrator cap; the submitter's local preference cannot raise it. Empty means disabled. A job with captured stdin (a piped or redirected script submitted for review) is never eligible: it always requires the human decision. |
| `webfetch_enabled` | no | `false` | Root-owned opt-in to the reviewer worker's bounded public HTTP(S) `webfetch` tool. When false the model is not offered the tool and cannot execute it; true does not change host inspection policy or grant shell/network execution. See [review tools](review-tools.md#optional-webfetch). |
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
**NO AI REVIEW**, and any job with captured stdin (a piped or redirected
script submitted for review) always require the ordinary human decision.

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

To permit public-page inspection for a reviewed job, add this field inside the
existing version 4 `review` object (retain its `models` and other fields):

```json
"webfetch_enabled": true
```

Omitting it leaves web fetching off. `review.local_only` still governs the
configured **model** inference location; it does not disable this independent
public-web opt-in. Fetched text becomes model-visible evidence, and an external
model provider may receive it. Fetched pages are untrusted data, not verified
instructions or proof that a remote script is safe to execute. This is a
configuration reference, not an instruction to install from source or restart
an installed service.

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
| `max_inspected_files` | no | `256` | ≥ 1. Bound on staged bundle files per job; also bounds the file set of one bundle-scope `search_path` call and caps enabled hash attempts at `min(2, max_inspected_files)` per job. |
| `max_inspected_bytes` | no | `8388608` (8 MiB) | ≥ 1 and ≤ 66060288 (fits under the 64 MiB frame ceiling). Total staged bundle byte budget per job; also sets the daemon's effective client frame limit to `max_inspected_bytes + 1 MiB` and caps the content one broker-side bundle search will scan (further bounded to 1 MiB per search call). |
| `max_hash_file_bytes` | no | `33554432` (32 MiB) | Source-only integer 1–33554432. Independent per-file executable hashing budget, not the content/staging budget. Zero/null are invalid when explicitly present. |
| `max_hashed_bytes_per_review` | no | `67108864` (64 MiB) | Source-only integer ≥ `max_hash_file_bytes` and ≤ 67108864. Aggregate hashing-work budget across the job, including failed reads and an overflow-probe byte; fallback does not reset it. Zero/null are invalid when explicitly present. |
| `max_log_bytes_per_stream` | no | `33554432` (32 MiB) | ≥ 4096. Retained-output cap per stream (stdout/stderr); a fixed truncation marker is appended at the cap and further bytes discarded while the pipe keeps draining. |

Fixed broker ceilings (not additional configurable fields): 32 combined new
metadata requests, 256 KiB aggregate successful metadata payloads, 16 KiB per
metadata payload (1024 bytes for hashes), and 256 inspection observations per
job across all broker tools. Hash byte ceilings may be lowered, not raised.

### `telegram`

Telegram is the mandatory decision interface; there is no approval path
without it. One configuration uses exactly one of two forms:

- **Legacy single-bot form** (the original shape): the flat
  `token_file`/`operator_user_id`/`chat_id` fields below. Still fully
  supported, unchanged. Every submitting UID reaches that one bot in its one
  chat.
- **Named multi-channel form**: `default_channel`, `channels[]`, and the
  optional `routes{}` map, described after the shared fields. It supports
  several bots, several recipient chats per bot, and per-login routing. The
  two forms never mix: a config that carries both fails validation
  (`telegram mixed legacy and named fields`).

Shared field:

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `approval_ttl` | no | `"10m"` | At least 30 s. Approval lifetime, measured from the moment the complete Telegram request is sent, and additionally capped by the client's remaining pre-dispatch deadline. The 30 s minimum remains to allow a usable decision window; `review.request_timeout` and `review.total_timeout` are separate review budgets. With a per-channel `approval_ttl` set, that value overrides this one for the channel's jobs. |

Each daemon handles review and approval one request at a time. While a card
waits for a decision, later requests stay queued; a longer approval lifetime
also means they may wait longer.

#### Legacy single-bot form

| Field | Required (in this form) | Default | Rules and meaning |
|---|---|---|---|
| `token_file` | yes | — | Absolute path to a file containing only the bot token; same credential-file requirements as `api_key_file`, plus ≤ 4096 bytes, non-empty after trimming, no `/` or NUL. |
| `operator_user_id` | yes | — | Integer > 0. The sole numeric Telegram user ID allowed to decide; `0` (the shipped placeholder) is invalid. Usernames and group membership are never authentication. |
| `chat_id` | yes | — | Integer ≠ 0. The private chat the approval card is sent to; callbacks from any other chat are rejected. |

#### Named multi-channel form

A **channel** is one bot token plus one or more **recipients**. A
**recipient** is one chat (private or group) plus the numeric Telegram user
IDs allowed to decide in that chat — one shared group chat with several
authorized admins, or several private chats, both work. A job uses exactly
one channel (its bot); the channel's recipients all receive the request card,
and **the first valid Approve or Deny from any authorized user in any
recipient chat wins** — there is no quorum, and a later decision cannot
revoke an already launched command. Remaining cards are closed best-effort
and their buttons become inert.

Route selection is made by the root daemon from the **authenticated
submitting OS UID** — never a client-supplied name. `routes` keys are OS
login names, resolved to UIDs at config load; unknown accounts fail
validation and a numeric UID is rejected as a key. Unlisted submitters use
`default_channel`. The submitting user cannot choose a route.

| Field | Required (in this form) | Default | Rules and meaning |
|---|---|---|---|
| `default_channel` | yes | — | Must name an entry in `channels`. The route for every submitting UID without a `routes` entry. |
| `channels` | yes | — | Array of 1–8 objects, each: `name` (non-empty, unique, ≤ 128 bytes, no surrounding whitespace), `token_file` (absolute path, distinct per channel, same credential-file requirements as above), `recipients` (1–8 objects of `chat_id` ≠ 0 plus 1–8 distinct positive `operator_user_ids`), and optional `approval_ttl` (≥ 30 s, overrides the shared value). A chat ID may appear once per channel. |
| `routes` | no | — | Map of OS login → channel name for per-user routing, at most 128 entries. Keys must be login names, not numeric UIDs; each must resolve to an existing account at load, and two logins resolving to one UID are rejected. |

The daemon enforces the same bounds at load, so a config that passes
`askdo config check` behaves identically at service start.

CLI ownership of these fields:

```sh
# Add one bot + one recipient chat as a named channel (never touches a
# legacy config; on a fresh config it becomes the default channel).
# With flags, --operator-user-id takes one ID; interactively (omit the
# flag) you can enter the list of authorized IDs comma-separated:
sudo askdo channel add telegram ops \
  --token-file /root/ops-bot.token --chat-id 123456789 \
  --operator-user-id 100111

# List channels, chats, operator users and routes (token values are never printed):
sudo askdo channel list

# Pin a submitting login to a channel; everything else uses default_channel:
sudo askdo channel route set alice ops
sudo askdo channel route set deploy-agent ops
```

`channel add telegram NAME` writes one recipient with one chat ID; to give a
channel further chats or more operators, edit `channels` (and back up the
file first). `channel route set` requires a named-form config and refuses a
login that would collide with another login on the same UID.

The **untouched installer template** has a placeholder token path but zero
operator/chat IDs, so adding the first named channel replaces that unusable
placeholder without deleting any credential file. There is **no automatic
migration of a configured legacy bot**: `askdo channel add telegram NAME`
refuses that case rather than dropping a working channel. To convert one by
hand, back up `/etc/askdo/config.json`; create one token file per bot; move
the legacy flat fields into a `channels` entry; set `default_channel`; then
run `askdo config check` and restart the service when the new config is ready.

The CLI also refuses a channel name that could not file a token: one
path-safe component (no `/` or `\`, not `.` or `..`), because the wizard
derives the token path `…/credentials/telegram-<name>.token` from it.

##### Example

```json
"telegram": {
  "approval_ttl": "10m",
  "default_channel": "ops",
  "channels": [
    {
      "name": "ops",
      "token_file": "/etc/askdo/credentials/telegram-ops.token",
      "recipients": [
        { "chat_id": 111111111, "operator_user_ids": [100111, 100222] },
        { "chat_id": -100200333, "operator_user_ids": [100111, 100222, 100333] }
      ]
    },
    {
      "name": "alice",
      "token_file": "/etc/askdo/credentials/telegram-alice.token",
      "recipients": [
        { "chat_id": -100444555, "operator_user_ids": [100111] }
      ]
    }
  ],
  "routes": {
    "alice": "alice",
    "deploy-agent": "ops"
  }
}
```

Read as: submissions from the OS account `alice` go to her bot; the account
`deploy-agent` (and any other submitter, via `default_channel`) goes to the
operations bot, which cards both `recipients` — the private chat `111111111`
and the group `-100200333` (the negative ID marks a group). The token paths
and IDs are placeholders: replace them with your own tokens and IDs. A private
recipient must start a chat with that bot; for a group recipient, add the bot
to the group with permission to send messages. The CLI flags above take one
recipient; the additional group-chat recipient in this example is a manual
`channels` edit. Each chat's list of `operator_user_ids` is exactly who may
decide there.

## Credential file requirements

Every credential file referenced by `telegram.token_file`,
`telegram.channels[].token_file`, or `review.models[].api_key_file` must, at
validation time (daemon startup and `config check`):

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

`askdo auth login|status|logout` resolve the token file the same way, with
the highest-priority applicable rule winning:

1. `--token-file PATH` — explicit path (first provisioning); no config is read.
2. `--credentials-dir DIR` — `DIR/openai-codex.json`; no config is read.
3. `--config PATH` — the `openai_codex` `api_key_file` in that host
   (`review.models[]`) or gateway (`profiles[]`) document.
4. Neither — the installed `/etc/askdo/config.json` and
   `/etc/askdo-gateway/config.json` (absent ones are skipped). Entries
   sharing one path count once; more than one distinct path is refused before
   any network call or write — choose with `--config` or `--token-file`. A
   fleet (`config_version` 5) host with no gateway config is directed to run
   auth on the gateway. With nothing configured, the provisioning default
   `/etc/askdo/credentials/openai-codex.json` is used.

The config is only read, by its `config_version` and structure; unrelated
sections (missing TLS or credential files, placeholders) do not block re-auth,
so a missing or corrupt token can be repaired. An unreadable or malformed
document is an error, never skipped. `askdo auth --help` shows this summary.

Use `sudo` for configuration-driven `auth login`, `auth status`, and `auth
logout`: the installed config and OAuth file are root-private. Explicit
credential-path workflows retain their existing permission rules. Repeated
slashes and `.` components can share a target, but authentication does not
bypass its trusted-directory checks for `..` traversal or symlink ancestors.

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

A named channel's token file follows the same ownership and mode: owner
**root** (the broker/daemon reads it), group **`askdo-review`** readable at
most `0640` — never group- or world-writable, never owned by a submitting
account.

The Codex OAuth token file is not installed by hand — `sudo askdo auth
login openai-codex` writes `/etc/askdo/credentials/openai-codex.json`
as root:root `0600` itself.

Contents are read exactly once (each Telegram token at client construction,
each API key at provider-session construction), held in memory, and attached
only to requests against the configured endpoint. Configured provider API key
and Codex access-token values are redacted from error diagnostics. Already-bounded
HTTP and SSE error payloads are retained in the root-only reviewer log; arbitrary
secret detection in provider responses is not guaranteed. Treat the reviewer
log as sensitive even though socket clients cannot read it.

**One bot token per running service.** Never reuse a bot token in another
running host or service while askdo polls it: Telegram's `getUpdates` is a
polling API, so two active pollers on one token steal each other's updates
and a decision may reach the wrong process (see
[clean installation and cutover](clean-cutover.md)). With named channels this
applies per bot: each channel needs its own token, distinct from every other
running service's tokens. The recommended per-channel layout keeps root
ownership and the `askdo-review` group read:

```sh
install -m 0640 -o root -g askdo-review /dev/stdin \
  /etc/askdo/credentials/telegram-ops.token
install -m 0640 -o root -g askdo-review /dev/stdin \
  /etc/askdo/credentials/telegram-alice.token
```

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
bot token and IDs (or `askdo channel add telegram NAME` for the named
multi-channel form with several bots and admins). Add each submitting user to
the `askdo` socket group.
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

The example above uses the legacy single-bot form. If several admins should
decide, or different submitters should reach different bots, use the
[named multi-channel form](#named-multi-channel-form) instead — the rest of
this example is unchanged.

## Fleet host config (version 5)

**Fleet mode is implemented in source; it is not in the `v1.0.0-rc.1` release
binaries.** A host that uses the optional shared gateway sets
`config_version: 5` and a `fleet` object. `askdo gateway connect` writes this
document; the rules below are what it and the daemon enforce. Mixed mode is
rejected: a v5 file must **not** contain `telegram` or `review.models` (no
local provider credentials or bots on a fleet host), and fleet fields are
forbidden in a v4 file. `inspection`, `limits`, review mode/exemptions,
auto-approval grants and preferences keep exactly their version 4 meanings
and remain local — the gateway cannot widen them.

### `fleet`

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `url` | yes | — | Gateway base URL. Absolute `https` only, no userinfo, query or fragment; normal hostname/certificate verification. No insecure or trust-on-first-use mode exists. |
| `host_id` | yes | — | This host's individual enrollment identity, issued by `askdo gateway hosts add`. |
| `enrollment_file` | yes | — | Bearer credential file for this host only. **Broker-only**: root:root, exactly `0600`. |
| `verification_key_file` | yes | — | The gateway's **public** Ed25519 verification key (base64). Root-owned, non-writable trust file. |
| `ca_file` | no | system roots | Additional CA for the gateway connection, explicitly supplied by the operator; same root-owned non-writable trust rule. |
| `enrollment_bundle_files` | no | omitted | Up to 128 unique absolute clean paths of retained enrollment imports. `connect` records each source and preserves earlier paths. These are hard-protected inspection paths, not files needed for TLS or authentication; a recorded file may have been deleted. |
| `approval_ttl` | no | `600` | **Integer seconds** (≥ 30), matching the gateway's ticket lifetime units. Note this differs from version 4 `telegram.approval_ttl`, which is a quoted Go duration string. |

`enrollment_file`, `verification_key_file`, `ca_file` and every recorded
`enrollment_bundle_files` path join the protected credential/trust paths: the
broker hard-denies host inspection of them, including original private bundles
outside a `credentials` directory. Other backups/copies must be explicitly
protected by the operator; importing one file does not discover every copy.

### `review.gateway_profiles`

Replaces `review.models` in fleet mode: an explicit ordered selection of
gateway profile IDs (at most 16; the gateway catalog itself is bounded at
128). An empty array is valid with explicitly configured human-only mode or
the existing required-mode approval-only exemptions; forced AI review still
requires a selected model. `review.local_only`
keeps its meaning but is enforced against the **actual upstream** each
selected profile routes to, as declared in the signed catalog snapshot — not
against the gateway's address: a LAN gateway fronting a cloud model is not
local. As in version 4, `data_boundary` declarations are operator trust
statements; askdo does not detect hidden forwarding by an upstream.

The normal reviewer uses an effective output-token ceiling no higher than
either the host's `review.max_output_tokens` or any frozen selected upstream
limit. A host ceiling above the gateway limit does not rewrite local policy
and does not make a legitimate review request over-budget.

Example: [`examples/fleet/host-config.example.json`](../examples/fleet/host-config.example.json)
(installed read-only at `/etc/askdo/examples/host-config.example.json`).

## Gateway server config (version 1)

The optional central gateway reads a separate server-only file — default
`/etc/askdo-gateway/config.json` as written by `askdo gateway init`. It
contains **no execution policy**. Decoding is strict (unknown/duplicate
fields rejected at every depth). Example:
[`examples/fleet/gateway-config.example.json`](../examples/fleet/gateway-config.example.json).

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `config_version` | yes | — | Must equal `1`. |
| `listen` | yes | — | `host:port`, port 1–65535. |
| `public_url` | yes | — | Absolute `https` URL hosts dial; no userinfo/query/fragment. |
| `tls_cert_file` | yes | — | Operator-provisioned certificate. Root-owned, non-writable. |
| `tls_key_file` | yes | — | Operator-provisioned key. Root:root, exactly `0600`. |
| `signing_key_file` | yes | — | Gateway Ed25519 signing key, distinct from every host enrollment credential. Created by `gateway init` at `<config parent>/credentials/signing.seed` (the matching public key lands in `verification.pub` beside it). Root:root `0600`. |
| `database` | yes | — | Absolute clean path of the gateway SQLite store (enrollments, ticket/delivery bookkeeping only — never host job databases or raw model conversations). `askdo gateway init` defaults it to `/var/lib/askdo-gateway/gateway.db`; an explicitly chosen custom path is the operator's own responsibility (uninstall never deletes custom paths). |
| `profiles` | yes | — | Explicit array (empty means approval-only: human Telegram decisions, no model). At most 128 entries; each entry uses the standalone [`review.models[]`](#reviewmodels) schema. Provider credential files are root:root `0600`. |
| `bots` | yes | — | 1–128 entries: `name` plus `token_file` (root:root `0600`). One update listener per actual bot-token identity. |
| `channels` | yes | — | 1–128 entries: `name`, `bot`, `approval_ttl` in **integer seconds** (≥ 30), and 1–8 `recipients` of `chat_id` plus 1–8 `operator_user_ids` — the same routing model as the standalone [named channels](#named-multi-channel-form). |

Gateway credential and key files are validated at load with the same
root-ownership rules as host fleet files. Provider configuration is manual
server-side JSON only; there is no host-side provider upload and no new admin
UI.
