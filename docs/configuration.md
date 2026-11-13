# Configuration reference

One file: `/etc/askdo/config.json` (override with `--config`), schema
`config_version: 4`, plus the credential files it references. (Fleet hosts
instead use `config_version: 5` — see [below](#fleet-host-config-version-5);
the optional central gateway has its own separate
[version 1 file](#gateway-server-config-version-1).) Decoding is
strict: unknown fields are rejected at every nesting level, and
durations are quoted Go duration strings (`"2m"`, `"30s"`). The daemon and
`askdo-config config check` run the identical validation
(`internal/config/config.go`).

**You rarely edit this file by hand.** For a fresh installation, inspect the
checkout's `install.sh` and run `./install.sh` only with the machine owner's
approval;
it does not enable or start the service (see [Get started](../README.md#get-started)
and the [clean installation guide](clean-cutover.md)). The onboarding
wizards own the common writes and apply the credential ownership/mode rules for
you:
`askdo-config reviewer add|edit|delete|moveup|movedown` manage `review.models` and
the model credential files, while
`askdo-config channel add telegram` writes the bot token file and the
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
`askdo-config config install FILE` (which validates before anything lands).
This document is the reference for every field the wizards write and for
those file-based sections.

`askdo-config` is the configuration/operator entrypoint. A root caller runs
directly; an askdo member's root-only operation submits
`/usr/local/bin/askdo-config` with the same arguments through normal Telegram
approval, foreground output and TTY prompts. Read-only operations that already
work without root do not request approval. Initial provisioning without a running
broker still needs administrator access. `fleet join` has its own enrollment
approval and, like `daemon` and `gateway serve`, must be started as root.

`askdo-config review mode required` or `askdo-config review mode approval-only`
sets the policy (`approval-only` on the CLI becomes
`approval_only` in JSON). `askdo-config review exempt add <username>` and
`askdo-config review exempt remove <username>` manage OS login exemptions in
`required` mode; `askdo-config review mode` and `askdo-config review exempt list`
display current settings. These commands do not grant socket access.

For sudo-like approval reuse on your own account, opt in with
`askdo-config review timestamp_timeout set <username> <value>`.
Like sudo's `timestamp_timeout`, a plain value is **minutes**, including decimals
(`10` or `2.5`); Go durations such as `90s`, `10m` and `1h` also work. The range
is 30 seconds through one hour, stored internally as whole seconds, or exactly
`0` for off. `askdo-config review timestamp_timeout clear <username>` removes the
entry and `askdo-config review timestamp_timeout list` displays the configured
timeouts. On a standalone host `0` and `clear` both leave reuse off. On a fleet
host they differ: `clear` leaves the login to the gateway's default window, if
any, while `0` is an explicit off that overrides a window the gateway offers
(see [fleet policy defaults](#fleet-policy-defaults)). Either erases the user's
stored approvals.
This controls how long one approval is reused on the same terminal, per target
user. All three require root and request normal Telegram approval for non-root
askdo members. They accept `--config PATH` with direct v4 and fleet v5 configs.
The legacy `review timestamp` alias still accepts plain integer **seconds**
(30–3600; it cannot set `0`) and prints a rename notice. The old
`approval_timestamp_users` JSON key also means seconds (30–3600, or `0` for off);
the new `timestamp_timeout_users` key uses numeric minutes. Either key
is accepted, but specifying both is an error. Saves write only the new key.
They use the same atomic, section-validated config mutation as the other review
policy commands; adding a timestamp does not itself exempt an account from AI review.

Validate with:

```sh
askdo-config config check         # offline validation + warnings + kernel feature
                           # probe (prints the actually selected backend)
askdo-config config check --live  # additionally probes each model endpoint
                           # with a synthetic fixture (never host files)
```

The host broker reloads and validates the selected config for each **new
submission**. Reviewer, channel, review-policy, inspection and limit changes
apply without `systemctl restart askdo`, a signal or a file watcher. Each admitted
job keeps its own config, inspection policy and fleet connection through review
and execution; queued and pending jobs are not reassigned to new reviewers or
approval routes. Auto-approval grants are re-read at the final no-human dispatch
gate, so a revocation still blocks an already-reviewed job. Keep referenced
credential files available until admitted jobs end.
Invalid config or unusable inspection/fleet initialization rejects new submissions
with a generic broker error rather than using stale policy. Existing jobs,
status and cancellation continue; auto-approval preference requests also validate
the current config and grant.

The selected config pathname, socket, store and spool locations remain
startup-only. The incoming frame ceiling is also fixed at startup:
`min(limits.max_inspected_bytes + 1 MiB, protocol maximum)`. Job inspection and
capture limits reload, but raising that byte limit does not enlarge the running
broker's frame ceiling. Frame parsing precedes config loading so invalid config
cannot block cancellation or status. These reload semantics concern the host
broker, not the separate gateway service.

## Field reference

"Required" means the key must be present in the file. Defaults apply only
when the key is absent.

### Top level

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `config_version` | yes | — | Must equal `4`. |
| `upgrade_backup_dir` | no | `/var/backups/askdo` | Absolute clean path (no `..`, redundant separators or trailing slash), outside `/var/lib/askdo-upgrade` and its descendants (the receipt/bootstrap namespace). Applies to direct v4 and fleet v5 hosts. The root upgrade helper reads it only when scheduling; its directory and ancestors must pass the existing root-owned, nonsymlink, non-writable-by-group/others trust checks. Missing directories are created by root, with the backup directory at `0700`. |
| `inspection` | yes | — | Object, below. |
| `review` | yes | — | Object, below. |
| `limits` | yes (object) | all fields defaulted | Object, below. |
| `telegram` | yes | — | Object, below. |

### `inspection`

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `read_roots` | no | `[]` (implicit `/` always applies) | Absolute, cleaned **additive** read paths (files or directory trees), not an allow-list limiting metadata inspection. A configured entry **other than `/`** grants content access even to private files in that tree. With only the implicit `/`, content requires file other-read and ancestor-directory other-search permissions (see below). Configured spellings remain in manifests and trust assumptions and may re-open a more-specific part of `deny_paths`; they never override hard exclusions or masks. A path need not exist yet: requests report `not_found` until it appears, then use the same per-request checks without a restart. Symlink targets are checked independently. |
| `deny_paths` | no | `[]` | Absolute, cleaned exclusions. The most-specific component-wise match wins across the implicit `/`, configured read paths and deny rules; ties deny. Deny `/home/user`, allow `/home/user/bin` reopens only the `bin` subtree. Hard exclusions always win. |
| `trusted_executable_roots` | no | — | **Deprecated and ignored.** Still accepted by the strict decoder so existing version 4 files that carry it keep loading, but the value has no effect: no validation, no warning, no policy decision, and no record in the frozen approval manifest. There is no trusted-code category that substitutes for the model reading code, and the reviewer does not automatically discover dependencies. Omit this field in new configurations. |
| `sensitive_masks` | no | built-in default list | Credential-like path **name** masks. Omitting the field compiles the built-in well-known secret-name conventions; an explicit **non-empty** array **replaces** those configurable defaults (it does not extend them), so tuning out one false positive without re-listing the others silently unprotects them. The always-on system-secret protections below apply **in addition** and cannot be replaced. An explicit empty or `null` array is invalid — never a silent disable. At most 256 configured masks, each ≤ 256 bytes, valid UTF-8, no backslashes, control characters, or empty/`.`/`..` components. Mask syntax and matching semantics are defined below. |
| `hash_path_enabled` | no | `false` | Opt-in to bounded executable SHA-256 metadata. Does not bypass path policy, return bytes or pin a later execution. |
| `service_status_enabled` | no | `false` | Opt-in to fixed observational metadata for one literal `.service` unit. No arbitrary properties or service actions. |
| `sudo_policy_enabled` | no | `false` | Opt-in to sanitized policy listings for the submitting UID and explicitly authorized additional UIDs. Does not grant sudo rights. |
| `sudo_policy_uids` | no | `[]` | At most 127 additional numeric uint32 UIDs, not login names; unique integers 0–4294967295. Null array/elements, duplicates, strings, fractions and out-of-range numbers are rejected. The caller is always eligible when enabled; UID 0 has no special exemption. |

The three capability flags accept JSON booleans, never `null`. These fields
apply equally to direct v4 and fleet v5 hosts, not the separate gateway-server
v1 configuration. An unchanged old host configuration keeps all three off.

Inspection scope is not execution permission. The reviewer can inspect live
host context throughout `/`, including `/var/lib`, `/etc`, `/opt`, `/srv` and
temporary maintenance scripts, subject to exclusions, sensitive masks and
descriptor/mount checks. Narrow legacy `read_roots` do not restrict that scope.
Use `deny_paths` for administrator exclusions. `inspection_scope` reports `/`
alongside any safe configured roots; it is not a promise that every descendant
is readable. Existing budgets and optional capability flags are unchanged.

**Metadata and content have different access rules.** `list_path`, `stat_path`,
`find_path`, `mount_info` and enabled executable `hash_path` remain available
on private objects, subject to the existing hard denies, masks and exclusions.
Directory listings remain names-only and do not require world-readable or
world-searchable permissions.

For `read_path` and file contents matched by `search_path`, a file allowed
only by the implicit `/` must have the **other-read** bit (`0004`) set and
**every traversed ancestor directory** must have **other-search** (`0001`)
set. A `0600`/`0640` file, or a `0644` file behind a `0700` directory, returns
payload-free `inspection_denied` with reason `not_world_readable`. Directory
searches skip such files and include them in `skipped_masked`; they never
match or return private lines. Permissions and path identity are rechecked
after reading; a change discards the content.

Administrators can grant content access to a private file or tree by adding
that path to `inspection.read_roots`, for example `/etc/sudoers` or
`/srv/application/config`. An explicit `/` does **not** grant this exception.
Named secret paths, configured `deny_paths`, masks and hard identity/mount
protections still apply: a read root cannot release an always-hidden secret.
Submitted bundle content keeps its existing capture/mask policy rather than
inheriting this live-host permission rule.

For a generated Bash script, `askdo --script PATH` captures only that selected
file using the existing bundle mechanism. Its captured copy is reviewable
without requiring host read-root changes. Related live host files use the same
filesystem-wide inspection policy. Capturing a script does not remove genuine
missing context or bypass host exclusions.

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

Masks are a **name convention, not content scanning**: a secret stored in a
world-readable file under an ordinary filename (or explicitly granted private
tree), or a value carried in argv, environment, or the submit `--reason`, can
still leak. Masks also do not grant or deny access by
themselves: `read_roots`, `deny_paths`, and the hard-deny set below still
decide whether a host path may be opened at all. A masked path that policy
permits is metadata-checked and its contents withheld from the reviewer
model; a masked path outside policy is denied like any other.

The shipped `askdo-config.example.json` lists every built-in default
mask explicitly. Because an explicit array replaces the defaults, that file
**pins the default set until edited**: removing or renaming an entry
narrows the configurable protection, and adding entries extends it. Neither
operation changes the always-on protections below.

Requested and opened names and reachable same-object mount aliases must pass
the same policy. Regular files with multiple hardlinks are conservatively
refused because their other names cannot be proved safe without a tree walk.
Client-side bundle capture likewise refuses multiply linked files before
reading them; a separately copied secret under an ordinary name is not
detectable by name masks.
Mountinfo coordinates unreachable in the current namespace are not aliases.
Regardless of configured lists, these paths and their descendants are always
hard-denied (`inspection_denied`, reason `protected_path`):

- askdo state: `/etc/askdo`, `/var/lib/askdo`, `/var/lib/askdo-review`,
  `/run/askdo`, `/etc/askdo-gateway`, `/var/lib/askdo-gateway`;
- kernel interfaces: `/proc`, `/sys`, `/dev`;
- password databases: `/etc/shadow`, `/etc/shadow-`, `/etc/gshadow`,
  `/etc/gshadow-`, `/etc/security/opasswd`;
- private TLS keys: `/etc/ssl/private`, `/etc/pki/tls/private`;
- network credentials: `/etc/wireguard`,
  `/etc/NetworkManager/system-connections`, `/var/lib/iwd`,
  `/etc/ppp/chap-secrets`, `/etc/ppp/pap-secrets`;
- Kerberos host credentials: `/etc/krb5.keytab`;
- runtime and systemd credential stores: `/run/secrets`, `/run/credentials`,
  `/etc/credstore`, `/etc/credstore.encrypted`,
  `/var/lib/systemd/credential.secret`;
- Kubernetes node credentials: `/var/lib/kubelet/pods` (secret and projected
  volumes), `/var/lib/kubelet/pki`, `/etc/kubernetes`, `/etc/rancher`,
  `/var/lib/rancher/k3s/server`, `/var/lib/rancher/rke2/server`;
- the selected configuration and configured credential/protected files,
  including external paths and retained fleet enrollment bundles.

Always-on masks additionally withhold `ssh_host_*_key` (SSH private host keys),
`*.keytab`, `.gnupg`, `.password-store`, `auth.json`, `.git-credentials`,
`.config/gh` and browser profiles (`.mozilla`, `.config/google-chrome`,
`.config/chromium`, `.config/BraveSoftware`) and their subtrees, even
with an explicit `sensitive_masks` override. They use the existing `withheld`
status and are omitted from listings; `ssh_host_*_key.pub` stays visible unless
an administrator mask or exclusion hides it. The configurable defaults still
cover `.ssh` (including `/root/.ssh`) and the other conventions listed in the
example config. No generic `shadow` mask hides unrelated files by that name.

Hard denies apply to host inspection only, never to submitted bundle content.
The always-on masks also apply wherever the policy's sensitive matcher is used.

`askdo-config inspection check <path> [--config PATH]` runs as root and prints
ALLOWED or DENIED with the decisive rule and resolved path where available.
It checks metadata/path policy without reading content: ALLOWED does not
override `not_world_readable` on a later implicit-root content request.
It opens metadata only; it does not print contents or change configuration.
It reports an **inspection policy decision only**; incomplete reviewer or
Telegram sections are intentionally permitted during onboarding. Run
`askdo-config config check` for complete service configuration validation.
Inspection is selected by actual kernel feature probes, not a blind version
check: `openat2` is preferred, and only its absence
(`ENOSYS`) selects the legacy `os.Root` confined fallback with exact
`name_to_handle_at` mount IDs (statx `STATX_MNT_ID` preferred when present).
Permission and resource errors on either path fail closed, and filesystems
without descriptor mount identity are denied per object — there is no
blanket-filesystem support flag, no uname-based guessing, and no
configuration override for the backend the probe selected. Legacy paths were
tested on real Linux 3.10.108 (x86_64, ext4); native daemon and service-lifecycle
acceptance remains deployment-specific. `askdo-config config check` prints which
backend the same probe selected.

Go 1.27.1's Unix `os.Root` implementation opens intermediate directories
read-only while walking a confined path. Search-only ancestor access can
therefore be insufficient even when the final acquisition is metadata-only
(`O_PATH`). Such permission failures remain fail-closed; no broader read root,
ACL bypass, or alternate path walker is selected to compensate.

These compatibility changes require compatible fleet gateway and
joining host broker/reviewer builds. Older strict peers can reject
`display.captured_stdin_kind`, `operation.captured_stdin.delivery_kind`, or
inspection-scope `compatibility`. Modern sealed-memfd jobs also emit the new
kind metadata; it is not enabled only on legacy kernels. Current-version
fixtures do not establish older-peer interoperability. Coordinate an
owner-approved rollout before joining the new flow; this does not require
upgrading every existing host or authorize a fleet upgrade/restart. Native
host installation and acceptance remain separate from source publication.

#### Optional host evidence and rollout

These additions are not implied by the separate existing foreground-helper
sudo hardening. Old strict config parsers reject unknown new fields, even if a
new flag is set to false. Do not add them to an old installation before
upgrading its parser, root broker and reviewer together.
The broker must understand the new operations, bootstrap capability projection
and fixed tool registry; upgrading only the reader/reviewer is insufficient.

The fleet wire already relays typed tool-definition arrays (up to 32), so an
existing compatible gateway can relay the new maximum twelve-tool registry
without a gateway-side tool-name allowlist change. Host-local root code still
enforces the exact offered definitions and inspection policy. No new gateway
config flags or signing keys are needed; verify deployed version compatibility
before rollout rather than assuming that an arbitrary old gateway works.

Obtain approval **per host** for the binary
upgrade, specific flag/UID/path values, queue drain and askdo restart. This is
not authorization to change running configuration or restart shared services;
OpenCode/GPU services are outside this rollout. Retain existing denies,
protected paths and default masks (plus any operator additions).
No `read_roots` additions are needed for `/etc/sudoers`, `/etc/sudoers.d` or
`/etc/passwd`: the implicit `/` already covers them. Administrator exclusions,
other configured sudo source paths and returned command paths remain subject
to their own policy checks. Keep flags off until their owner-approved policy
is installed and checked.

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
| `mode` | no | `"required"` | `required` reviews all submitters except exempt UIDs; `approval_only` skips AI review for every submitting socket-group member. **NO AI REVIEW** requires a human Telegram decision unless an explicitly enabled foreground approval timestamp is valid; eligible detached AI-reviewed jobs can use an explicitly configured risk auto-approval grant. Set `approval_only` explicitly for model-free use. |
| `approval_only_users` | no | `[]` | OS login names exempt from AI review in `required` mode only; no UID or client-supplied username strings. Names resolve to UIDs at config load; missing or duplicate accounts fail validation. An agent sharing an exempt UID is exempt too. `--review=yes` overrides an exemption. On a fleet host the logins in the gateway's `review_defaults.approval_only_users` are exempt as well ([fleet policy defaults](#fleet-policy-defaults)). |
| `timestamp_timeout_users` | no | `{}` (off) | Map of OS login names to numeric **minutes**, matching sudo's `timestamp_timeout` (decimals allowed, 0.5–60, or exactly `0` for off). Controls how long one approval is reused on the same terminal, per target user. Names resolve to kernel peer UIDs at load; missing accounts or duplicate resolved UIDs are invalid. Only foreground commands already exempt from AI review can reuse it. Omit or clear a login to disable it. Legacy `approval_timestamp_users` accepts integer **seconds** (30–3600, or `0` for off); do not specify both keys. On a fleet host a login listed here keeps this setting whatever the gateway says, and `0` is an explicit off that the gateway's window cannot turn back on; a login not listed (or cleared) takes the gateway's default. |
| `account_notes` | no | absent | Additive administrator Markdown context: optional `users` and `groups` maps from OS login / Unix group names to absolute clean file paths. Names resolve at config load; files and membership are read per review. See [reviewer instruction layers and account notes](#reviewer-instruction-layers-and-account-notes). On a fleet host the gateway's notes for the same account come first and these follow. |
| `auto_approve_grants` | no | `[]` | Root-owned opt-in grants, each naming an OS login and `max_risk` from `1` through `4`, or `0`, which grants nothing and turns off the fleet gateway's grant for that login on this host. The login resolves to a UID at config load; invalid/missing accounts fail validation. A grant sets the administrator cap; the submitter's local preference cannot raise it. Empty means disabled. Where a fleet gateway also grants the login, the **lower** of the two caps applies. A job with captured stdin (a piped or redirected script submitted for review) is never eligible: it always requires the human decision. |
| `webfetch_enabled` | no | unset (off) | Root-owned opt-in to the reviewer worker's bounded public HTTP(S) `webfetch` tool. When false the model is not offered the tool and cannot execute it; true does not change host inspection policy or grant shell/network execution. Setting it, to `true` **or** `false`, is this host's own decision and always wins. Leaving it out lets a fleet gateway's `reviewer_webfetch_enabled` apply, and means off where there is none. See [review tools](review-tools.md#optional-webfetch). |
| `models` | yes | — | Ordered fallback list. May be empty only with explicit `approval_only` or `required` plus nonempty `approval_only_users`; non-exempt/forced-review submitters then fail closed. Adding a model does not itself change `approval_only` policy. |
| `request_timeout` | no | `"2m"` | Per-request provider timeout; Go duration > 0. |
| `total_timeout` | no | `"20m"` | Whole-review budget across all fallback choices; > 0 and ≥ `request_timeout`. Becomes the worker's `review_deadline_unix_ms`. |
| `max_model_calls_per_attempt` | no | `32` | 1–128; bound on physical model calls per choice, including failed calls and retries, not just successful conversation turns. |
| `max_output_tokens` | no | `8192` | 1–200000; bound on tokens per model response. |

#### Sliding foreground approval timestamps

The first foreground unreviewed command still needs Telegram approval. Only a
successful handoff to the original client starts the window. Later unreviewed
commands from the same authenticated UID and controlling terminal, for the same
resolved execution target UID, skip the tap while the timestamp is valid. A login
name and `#UID` for the same account share the window. Changing target (including
omitting `-u` to run as root) requires fresh approval; its successful handoff
replaces the window with the new target. Each successful handoff resets expiry to
the dispatch time plus the configured timeout. `askdo -v` (`--validate`) can also
create or refresh a window without executing a command: a valid window is
refreshed immediately; otherwise the caller approves a no-op validation in Telegram.
This requires an enabled `timestamp_timeout` for the caller. Validation itself
does not run an AI review or a command; AI-required commands remain AI-required.

`askdo -k` (`--reset-timestamp`) alone invalidates this terminal's timestamp,
irrespective of target.
With a command, `-k` ignores the saved timestamp for that request and leaves the
saved window unchanged, even after fresh approval. `askdo -K`
(`--remove-timestamp`) removes all of the caller's timestamps on all terminals
and accepts no command. Neither removal needs approval or changes the configured
timeout. `askdo -l` shows the timeout
and remaining time on this terminal for the selected target (`-u`, root by
default), alongside group membership, review/exemption and auto-approval policy.

`askdo -n` (`--non-interactive`) never waits for a human: valid foreground timestamp
reuse or eligible detached risk-based auto-approval can proceed. Otherwise it
exits 1 with
`askdo: a Telegram approval is required`; the broker never creates a pending
Telegram card for that request. Automated AI review may still run to determine
eligibility for risk-based auto-approval. Combining `-n -v` only refreshes an
already valid window, and combining `-n -k COMMAND` cannot reuse a timestamp.

The identity includes the kernel TTY session, device and inode, not the command's
PID or process start time. A different UID or terminal cannot reuse it. Like
sudo's timestamp, it is not protection against other processes sharing that UID
and terminal; keep agents on a distinct OS account.

Detached jobs, captured-stdin scripts (which remain detached), AI-required jobs
(including `--review=yes`) and risk-based auto-approval neither use nor refresh
this timestamp. Denial, expiry, failed evidence checks or failed handoff do not
extend it. Reuse still freezes the exact manifest and applies the existing
pre-launch and one-use foreground grant checks; it does not invent a Telegram
decision. Timestamp records live in the local jobs database. Config changes apply
to the next submission without a restart; already admitted jobs keep their policy.
`askdo-config review timestamp_timeout clear USER` removes the host's entry and
erases that user's stored records, and `set USER 0` erases them while keeping an
explicit off; on a fleet host the difference is whose window then applies (see
[fleet policy defaults](#fleet-policy-defaults)). `telegram.approval_ttl` is a
separate deadline for an individual approval card and never starts a timestamp
by itself.

#### Reviewer instruction layers and account notes

Each review has three layers, in this order:

1. **Built-in protocol:** compiled role, rating scale, effects guidance,
   reviewer duties, report schema and tool contract. Administrators cannot edit it.
2. **Host risk guidance:** the compiled calibration paragraph and resource clause,
   unless `risk-policy.md` beside the selected daemon config exists
   (`/etc/askdo/risk-policy.md` by default). That file replaces **only** this
   calibration, not layer 1. An absent file keeps the built-in calibration; a
   present empty file is an empty replacement, not an absent file. On a fleet
   host whose gateway publishes default guidance
   ([`review_defaults.risk_policy`](#fleet-policy-defaults)), that text takes the
   absent file's place; a present file, even an empty one, always replaces it.
3. **Account notes:** additive Markdown context describing normal work. All
   applicable group notes are appended in **group-name order**, followed by the
   submitter's own user note. They never replace or remove layer 2. With no host
   file and no applicable notes, the compiled instructions are byte-for-byte
   unchanged. On a fleet host the gateway's notes add to these and come first:
   its group notes, then the host's group notes, then the gateway's note for the
   submitter, then the host's own user note, so the host has the last word on an
   account.

Add `account_notes` inside the existing `review` object, keeping other settings:

```json
"account_notes": {
  "groups": {
    "database-operators": "/etc/askdo/notes/database-operator.md",
    "web-deployers": "/etc/askdo/notes/web-deployer.md"
  },
  "users": {
    "db-agent": "/etc/askdo/notes/db-agent.md"
  }
}
```

Both maps are optional. These names are examples, not accounts or groups askdo
creates. Unknown logins/groups, two names resolving to the same UID/GID, and
non-absolute or unclean paths fail configuration validation. Operator saves
preserve both maps. Changing mappings follows the existing config-load lifecycle.

The broker selects from the **kernel-authenticated submitting UID**, not the
target UID (usually root), reason, display name or client-supplied group list.
At each AI review start, when group notes are configured, it looks up that UID's
primary and supplementary groups in the account database, never the submitting
process's credentials. Membership changes take effect on later reviews without
a restart. Processes sharing a UID share user notes; group-only members receive
their group notes too. A submitting UID with no account entry has no groups: it
is still reviewed, without group notes. Release binaries are static, so the
account database is `/etc/passwd` and `/etc/group` (not LDAP/SSSD via NSS), and
the broker's own account (root) has its primary group read once per start.

Notes are **account context only**, not risk calibration, a command allowlist,
or approval/denial. Expected work is not proof that a command is that work:
the reviewer must assess actual effects and rate departures accordingly. Notes
do not change the rating scale, schema or tools. See the short
[database-operator](../examples/risk-policies/database-operator.md) and
[web-deployer](../examples/risk-policies/web-deployer.md) examples; adapt them to
the machine. They are not installed automatically.

All administrator files use the same trust rules: root-owned regular files,
no symlink components, and no group/other write permission on the file or any
ancestor from `/`. Modes such as `0644` and `0600` are accepted. Keep files in a
root-controlled directory, not a submitter's home or checkout. A missing,
unreadable, unsafe or invalid configured note, an unusable present host file,
or a membership lookup failure fails **only that AI review**, with the existing
classified risk-policy failure; there is no fallback to fewer notes. An absent
optional host file still imposes no trust requirement on its ancestors. Files
and membership are not new startup dependencies; approval-only jobs consult neither.

Before starting the worker, the broker freezes the applied layers. Retries,
fallback models and pending approvals keep that snapshot; file edits affect only
later reviews. The digest-bound approval manifest has an ordered
`administrator_layers` list: `scope` (`host_default`, `group`, `user`), `name`
(empty for the host default), authenticated `subject_uid`, `source` path,
`sha256`, and exact `text`; `source` is `gateway` instead of a path for text the
fleet gateway supplied. It replaces rc.15's single `risk_policy` record.
The review journal is unchanged. The worker receives text only, not source paths
or authority to select files.

In fleet mode the host composes and pins the exact first system message, refusing
substitution, reordered notes or extra system messages. The gateway relays the
existing model-message shape, with conversation isolation. It can publish default
text in its signed catalog, but the host alone selects what applies to the
authenticated submitter and composes the message; the gateway never chooses
account context for a review. Administrator text is visible to reviewer
providers: do not put credentials in it.

Files must be UTF-8 without NUL. **Combined** host guidance and notes (and any
text from the fleet gateway, which counts like a file) must fit the
existing 64 MiB encoded bootstrap frame limit (checked before worker start; the
broker stops reading files once their combined size exceeds it) and
the 1 MiB foreground manifest handoff limit (checked before approval). Detached
manifests have no handoff-size limit. The complete fleet system message must
also fit 262144 bytes, allowing only newline and tab among control characters;
use LF, not CRLF. Direct providers retain their own request/context limits.

Existing human approval, explicit risk auto-approval grants/preferences,
inspection permissions and dispatch checks remain authoritative. Because model
scores can qualify for opt-in auto-approval, review guidance and note edits with
the same care as those grants; prose does not create or raise a grant.

**Migrating from v1.0.0-rc.15:** `review.risk_policy_files` was prerelease-only
and is removed, not aliased. Move descriptions of normal work to
`review.account_notes.users` (and/or `.groups`); move actual replacement scoring
calibration to `risk-policy.md` beside the daemon config
(`/etc/askdo/risk-policy.md` by default). Do not copy an old replacement rubric
unchanged into additive notes. Strict decoding explains this migration when the
old key is encountered, naming the file beside the config being loaded. Configs
without either mapping continue to load unchanged.

Upgrade the host broker and reviewer **together**, then migrate/add the config
key. The private bootstrap is unversioned; the new optional `account_notes` array
is rejected by older strict workers, while old bootstraps remain accepted by
new workers. Client protocol versions, manifest version 1, and fleet/gateway
wire versions are unchanged. A gateway upgrade is not required for these layers;
update external manifest readers if they need the new audit list. Publication
does not authorize installation, policy edits or service restarts.

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
| `api` | yes | — | Wire adapter: `openai_chat`, `openai_responses`, `anthropic_messages`, or `openai_codex`. The first three append their fixed suffix (`/chat/completions`, `/responses`, `/messages`) to `base_url` exactly once; a root may already carry a version prefix such as `/v1`. `openai_codex` is the ChatGPT-subscription Codex backend (OAuth via `askdo-config auth login openai-codex`, see below): it ignores the adapter-suffix rule and always uses the fixed backend URL `https://chatgpt.com/backend-api/codex`, and its `data_boundary` must be `external`. |
| `base_url` | yes | — | Absolute `http` or `https` URL. Plaintext `http` to a non-loopback host is **accepted with a config warning** — LAN-hosted inference (Ollama on a Spark/GB10, SGLang on a cluster node) is a normal deployment — but reviewed content and any API key then cross the network unencrypted. Other schemes are rejected. For `openai_codex` the field stays required for schema uniformity but is overridden by the fixed Codex backend URL. |
| `model` | yes | — | Non-empty opaque model identifier. |
| `api_key_file` | conditional | — | Required unless `data_boundary` is `"local"`. Absolute path to a credential file (requirements below). When omitted, requests carry no authorization header at all — intended only for deliberately unauthenticated local services. **For `api: "openai_codex"`** it names the OAuth token JSON written by `askdo-config auth login openai-codex`: it is always required, is **broker-only** (the reviewer never opens it — the broker projects the refreshed access token into the worker bootstrap), and follows the stricter root:root `0600` rule below instead of the `askdo-review` key rule. |
| `data_boundary` | no | `"external"` | `local` or `external`. Declares whether inspected content may leave the host through this provider. An explicitly present but empty value is rejected. |
| `request_timeout` | no | `review.request_timeout` | Per-model override; Go duration > 0. |

Every configured model is authorized to receive the operation and all
inspectable content — there are no per-file or per-provider permissions. The
list order is the fallback order. Without `--review=yes`, only exhaustion
of typed provider availability failures can offer a **NO AI REVIEW** Telegram
approval instead of a report; safety refusal, malformed final review,
broker/capture/changed-evidence failures, and elapsed deadlines without a complete
typed availability history fail closed. An actual final provider timeout retains
its availability type even when the review budget expires; client cancellation
and the client's pre-dispatch deadline still take precedence.
`--review=yes` requires a completed AI review and fails if no model is
configured or every choice is unavailable. **NO AI REVIEW** never qualifies
for auto-approval.

Transient provider network/read failures, per-request timeouts, HTTP 408/5xx,
and temporary HTTP 429 rate limits retry the **same failed conversation** before
advancing the ordered fallback list. Backoff starts at 250 ms and doubles up to
one second; a provider's `Retry-After` minimum (seconds or HTTP date) is never
shortened. Retries use remaining call slots and the original whole-review/client
deadline, with the existing timeout on each physical request. There is no new
retry-count setting or hidden adapter retry. Completed tool results are reused;
tools and privileged operations are not replayed. Explicit hard quota codes,
invalid credentials/configuration, and Codex re-login requirements do not retry;
safety refusal still stops without shopping for another model.

Fleet retries use optional `retry_transient` requests and signed, secret-free
`retry.after_ms` results, with a new sequence for each counted upstream attempt.
Requests without the extension retain the original terminal-on-error behavior.
Older strict peers reject the new extension: update the gateway before deploying
the matching broker/reviewer binaries. This adds no startup negotiation or new
configuration prerequisite. Root still enforces the frozen per-request HTTPS cap;
the fleet reviewer waits on the unchanged whole-review/job deadline rather than
racing root with a duplicate per-request timer. Direct reviewers retain their
per-request timer.

If **root's own request timer** expires before it verifies an outcome, its private
pipe reports `request_timeout` (unknown outcome, **not** provider unavailability).
Only an identical, charged next sequence can request `recover_previous`. The
gateway cancels and joins any active predecessor before another upstream call;
if the predecessor already completed successfully, it returns that cached response
under the new sequence without re-running the provider or tools. Every recovery
sequence conservatively consumes a call slot even when it only reconciles a cached
outcome. A known provider `Retry-After` remains in force across recovery.

Generic network, TLS, authentication, signature and protocol errors do not grant
this recovery. Unknown-outcome exhaustion cannot authorize fallback models or
**NO AI REVIEW** approval. Recovery cannot reconstruct a missing/restarted session
or bypass its profile/binding, original expiry, cancellation, capacity, DropSession
or terminal-failure tombstone. No new attempt, timeout margin or grace period is
introduced.

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
| `max_hash_file_bytes` | no | `33554432` (32 MiB) | Optional integer 1–33554432. Independent per-file executable hashing budget, not the content/staging budget. Zero/null are invalid when explicitly present. |
| `max_hashed_bytes_per_review` | no | `67108864` (64 MiB) | Optional integer ≥ `max_hash_file_bytes` and ≤ 67108864. Aggregate hashing-work budget across the job, including failed reads and an overflow-probe byte; fallback does not reset it. Zero/null are invalid when explicitly present. |
| `max_log_bytes_per_stream` | no | `33554432` (32 MiB) | ≥ 4096. Retained-output cap per stream (stdout/stderr); a fixed truncation marker is appended at the cap and further bytes discarded while the pipe keeps draining. |

Fixed broker ceilings (not additional configurable fields): 32 combined new
metadata requests, 256 KiB aggregate successful metadata payloads, 16 KiB per
metadata payload (1024 bytes for hashes), and 256 inspection observations per
job across all broker tools. Hash byte ceilings may be lowered, not raised.

### `telegram`

Telegram supplies human decisions, including the first approval that starts an
opt-in foreground timestamp. Its configuration remains required. One
configuration uses exactly one of two forms:

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
| `approval_ttl` | no | `"2h"` | At least 30 s. Approval lifetime, measured from the moment the complete Telegram request is sent, and additionally capped by the client's remaining pre-dispatch deadline. The 30 s minimum remains to allow a usable decision window; `review.request_timeout` and `review.total_timeout` are separate review budgets. With a per-channel `approval_ttl` set, that value overrides this one for the channel's jobs. |

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
`askdo-config config check` behaves identically at service start.

CLI ownership of these fields:

```sh
# Add one bot + one recipient chat as a named channel (never touches a
# legacy config; on a fresh config it becomes the default channel).
# With flags, --operator-user-id takes one ID; interactively (omit the
# flag) you can enter the list of authorized IDs comma-separated:
askdo-config channel add telegram ops \
  --token-file /root/ops-bot.token --chat-id 123456789 \
  --operator-user-id 100111

# List channels, chats, operator users and routes (token values are never printed):
askdo-config channel list

# Pin a submitting login to a channel; everything else uses default_channel:
askdo-config channel route set alice ops
askdo-config channel route set deploy-agent ops
```

`channel add telegram NAME` writes one recipient with one chat ID; to give a
channel further chats or more operators, edit `channels` (and back up the
file first). `channel route set` requires a named-form config and refuses a
login that would collide with another login on the same UID.

The **untouched installer template** has a placeholder token path but zero
operator/chat IDs, so adding the first named channel replaces that unusable
placeholder without deleting any credential file. There is **no automatic
migration of a configured legacy bot**: `askdo-config channel add telegram NAME`
refuses that case rather than dropping a working channel. To convert one by
hand, back up `/etc/askdo/config.json`; create one token file per bot; move
the legacy flat fields into a `channels` entry; set `default_channel`; then
run `askdo-config config check`. New submissions use the new channels automatically;
already-admitted jobs keep their original routes.

The CLI also refuses a channel name that could not file a token: one
path-safe component (no `/` or `\`, not `.` or `..`), because the wizard
derives the token path `…/credentials/telegram-<name>.token` from it.

##### Example

```json
"telegram": {
  "approval_ttl": "2h",
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
`askdo-config auth login openai-codex`. That file holds the OAuth refresh
token, so it must be readable by the broker alone: owner **root**, group
**root**, mode **exactly `0600`**. The reviewer never opens it — at review
start the broker loads it, refreshes the access token when it is inside the
5-minute expiry window (persisting the rotated refresh token atomically;
refresh tokens are one-time), and projects only the fresh access token and
account ID into the worker bootstrap. A revoked/expired/already-used refresh
token fails the model as an invalid-config availability failure (the
fallback advances to the next configured model; if none remain the job fails
before any review) until you re-run `askdo-config auth login openai-codex`.

`askdo-config auth login|status|logout` resolve the token file the same way, with
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
document is an error, never skipped. `askdo-config auth --help` shows this summary.

`askdo-config auth login` requests Telegram approval when not root. Configuration-
driven `auth status` and `auth logout` also request approval if the installed
root-private config or OAuth file denies access; readable user-owned targets
remain unprivileged. Explicit
credential-path workflows retain their existing permission rules. Repeated
slashes and `.` components can share a target, but authentication does not
bypass its trusted-directory checks for `..` traversal or symlink ancestors.

Rationale: the broker (root) validates them; the reviewer (running as
`askdo-review`) reads them through group membership; the submitting agent can
read neither. The recommended layout is below; each `install … /dev/stdin`
reads the secret you paste: paste it, press Enter, then press Ctrl-D.

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

The Codex OAuth token file is not installed by hand — `askdo-config auth
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
`askdo-config reviewer add` once per model (each entry lands in
`review.models` with its credential file installed under
`/etc/askdo/credentials/`), `askdo-config channel add telegram` for the
bot token and IDs (or `askdo-config channel add telegram NAME` for the named
multi-channel form with several bots and admins). Add each submitting user to
the `askdo` socket group.
No script-directory additions to `inspection.read_roots` are needed: `/` is
always in scope. Configure `deny_paths` for exclusions, then run
`askdo-config config check`.

### Minimal local-only test config

The smallest useful configuration: one local, unauthenticated inference
server, `local_only: true`, no API key files. Only the Telegram token file is
a credential.

```json
{
  "config_version": 4,
  "inspection": {
    "read_roots": [],
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
    "approval_ttl": "2h"
  }
}
```

This excerpt omits `inspection.sensitive_masks`, so the built-in default mask
list applies; add the field only to replace that configurable list. Always-on
system-secret protections remain in either case.

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

A host that uses the optional shared gateway sets
`config_version: 5` and a `fleet` object. `askdo-config gateway connect` writes this
document; the rules below are what it and the daemon enforce. Mixed mode is
rejected: a v5 file must **not** contain `telegram` or `review.models` (no
local provider credentials or bots on a fleet host), and fleet fields are
forbidden in a v4 file. `inspection`, `limits`, the global review `mode`,
`review.gateway_profiles` and `upgrade_backup_dir` keep exactly their version 4
meanings and remain local. The gateway can only offer **defaults** for the review
policy listed under [fleet policy defaults](#fleet-policy-defaults), and a host's
own setting always takes precedence over them.

### `fleet`

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `url` | yes | — | Gateway base URL. Absolute `https` only, no userinfo, query or fragment; normal hostname/certificate verification. No insecure or trust-on-first-use mode exists. |
| `host_id` | yes | — | This host's individual enrollment identity, issued by `askdo-config gateway hosts add`. |
| `enrollment_file` | yes | — | Bearer credential file for this host only. **Broker-only**: root:root, exactly `0600`. |
| `verification_key_file` | yes | — | The gateway's **public** Ed25519 verification key (base64). Root-owned, non-writable trust file. |
| `ca_file` | no | system roots | Additional CA for the gateway connection, explicitly supplied by the operator; same root-owned non-writable trust rule. |
| `enrollment_bundle_files` | no | omitted | Up to 128 unique absolute clean paths of retained enrollment imports. `connect` records each source and preserves earlier paths. These are hard-protected inspection paths, not files needed for TLS or authentication; a recorded file may have been deleted. |
| `approval_ttl` | no | omitted | **Deprecated and ignored.** Existing integer values remain accepted (with the legacy ≥ 30 s validation when present), but approval lifetime comes only from the gateway channel's `channels[].approval_ttl`. New fleet joins/conversions omit this field. Change the gateway config and restart `askdo-gateway` to change fleet approval lifetime. |

`enrollment_file`, `verification_key_file`, `ca_file` and every recorded
`enrollment_bundle_files` path join the protected credential/trust paths: the
broker hard-denies host inspection of them, including original private bundles
outside a `credentials` directory. Other backups/copies must be explicitly
protected by the operator; importing one file does not discover every copy.

### `fleet_upgrade`

A top-level object beside `fleet`, optional. It is the host's own say in the
upgrades its gateway pushes (see [upgrading a
fleet](upgrade.md#upgrade-a-fleet-from-the-gateway)).

| Field | Required | Default | Rules and meaning |
|---|---|---|---|
| `auto` | no | `true` | Boolean. `false` opts this host out: it keeps reporting to its gateway with `auto_upgrade=false`, and the gateway never offers it an upgrade. Absent, `null` or `true` means the host upgrades itself when its gateway names a release newer than the one it runs. |

Without a `fleet` object there is no gateway to push anything and the section has no
effect. Like every administrator file key it is strict: a misspelled key or a
non-boolean `auto` stops the file loading rather than leaving a host that you
believe is opted out still upgrading. It sits outside `fleet` so that enrolling the
host again, which replaces `fleet`, does not turn it back on. Example:

```json
"fleet_upgrade": {"auto": false}
```

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

### Fleet policy defaults

The gateway can publish default review policy once, in its signed catalog, instead
of it being repeated in every host's config. **A host's own setting always
decides: where the host sets a value, that value is used (for an auto-approval
cap, the lower of the two); where it sets nothing, it inherits the gateway's
default; with no gateway value (an older gateway, a gateway that sets none, or a
standalone host) behavior is exactly as it was.** The one additive setting is the
exemption list: the gateway can exempt a login from AI review, and a host cannot
take that back, only add its own exemptions.

| Setting | Gateway key | Host key | Effective value |
|---|---|---|---|
| Reviewer `webfetch` | `reviewer_webfetch_enabled` | `review.webfetch_enabled` | The host's value if the host sets it, `true` or `false`; otherwise the gateway's; otherwise off. |
| Exempt from AI review (human approval only) | `review_defaults.approval_only_users` | `review.approval_only_users`, `review.mode` | A login is exempt if the host exempts it (its list, or global `approval_only`) **or** the gateway lists it. A host cannot un-exempt a login the gateway lists. `--review=yes` still forces a review. |
| Approval reuse window | `review_defaults.timestamp_timeout_users` | `review.timestamp_timeout_users` | Per login: the host's entry if it has one, otherwise the gateway's. A host entry of `0` is an explicit off: that login gets no reuse on that host whatever the gateway offers, where an omitted (or cleared) login takes the gateway's window. Same limits (0.5–60 minutes); `0` is host-only, so a gateway cannot publish it. |
| Auto-approval cap | `review_defaults.auto_approve_grants` | `review.auto_approve_grants` | Per login: the **lower** of the host's and the gateway's cap where both grant it; the gateway's where the host has no grant; the host's where the gateway has none. A host `max_risk` of `0` turns the gateway's grant off. The submitter's own preference still cannot exceed the effective cap. |
| Risk-scoring guidance | `review_defaults.risk_policy` | `risk-policy.md` beside the daemon config | The host file if it exists (even empty); otherwise the gateway's text; otherwise the compiled default. |
| Account notes | `review_defaults.account_notes` | `review.account_notes` | Both apply: the gateway's note first, then the host's own for the same account (see [reviewer instruction layers](#reviewer-instruction-layers-and-account-notes)). |

Gateway `review_defaults` example (see the [gateway keys](#gateway-server-config-version-1)
for the rules; every key is optional, and the names below are examples):

```json
"reviewer_webfetch_enabled": true,
"review_defaults": {
  "approval_only_users": ["alice"],
  "timestamp_timeout_users": {"alice": 10},
  "auto_approve_grants": [{"user": "alice", "max_risk": 2}],
  "risk_policy": {"file": "/etc/askdo-gateway/risk-policy.md"},
  "account_notes": {
    "users": {"alice": {"text": "Alice administers the fleet; routine package upgrades are expected."}},
    "groups": {"deployers": {"file": "/etc/askdo-gateway/notes/deployers.md"}}
  }
}
```

How a host applies them:

- **People are named by login or group name**, and each host resolves the name
  against its own accounts. A name with no account on a host is ignored there,
  never an error. Where two names are one account, the shorter window and the
  lower cap apply, and both names' notes are used.
- **Values a host could not set itself are ignored**, not applied: a window
  outside 30–3600 seconds, a cap outside 1–4. Nothing in the defaults can make a
  review fail on a host except gateway text that the fleet message limits refuse
  (the same classified risk-policy failure a host's own file would give).
- **Frozen per review.** The host reads the defaults from the signed catalog it
  fetched for that review and keeps them for it: reviewer tools, exemption
  decision, auto-approval cap, timestamp window and the risk-policy and notes
  snapshot all come from that one catalog. A gateway change reaches the next
  review, not one already prepared. The final no-human dispatch gate still
  re-reads the **host's** own grant, so lowering or revoking it at the host
  blocks an already-reviewed job; the gateway's part of the cap is the one frozen
  with the review.
- **Submissions** consult the host's own policy first and ask the gateway only
  when that would refuse (`askdo -n` without a usable window or grant, `askdo -v`
  for a login the host has no timestamp entry for, a submitter who needs a review
  the host cannot run), so a decision the host makes alone never waits on the
  gateway. A host entry of `0` is such a decision: `askdo -v` is refused without
  asking. `askdo -l` and
  `askdo auto-approve` always ask, because they report or bound the effective
  values. A gateway that cannot be reached within the frame deadline leaves
  the host's own answer, or a
  timeout if the request's own budget ran out, never a grant.
- **`askdo -l`** shows the effective values and, on a fleet host, whose they are:
  `(source: host)`, `(source: gateway)`, or `(source: host+gateway)` for an
  auto-approval cap both grant. It says so when the gateway could not be asked,
  in which case it shows the host's own settings only.
- **Authority is unchanged.** The gateway is already the fleet's approval
  authority, and these defaults only change which submitters skip AI review, how
  long an approval can be reused and which risk scores can skip a human tap;
  inspection policy, sensitive masks, dispatch checks, captured-stdin and
  risk-5 human decisions stay with the host. A host that wants none of a default
  sets its own value (a lower grant or `max_risk: 0`, its own window or `0` for
  none, `webfetch_enabled: false`); only an exemption cannot be taken back.

Deploy order: hosts built before unknown-field tolerance
([unknown fields on the wire](architecture.md#unknown-fields-on-the-wire)) reject
a signed catalog carrying a field they do not know, so upgrade every fleet host
before adding `review_defaults` (or `reviewer_webfetch_enabled`) to the gateway.
Newer hosts ignore what they do not understand and keep working with an older
gateway.

## Gateway server config (version 1)

The optional central gateway reads a separate server-only file — default
`/etc/askdo-gateway/config.json` as written by `askdo-config gateway init`. It
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
| `database` | yes | — | Absolute clean path of the gateway SQLite store (enrollments, ticket/delivery bookkeeping only — never host job databases or raw model conversations). `askdo-config gateway init` defaults it to `/var/lib/askdo-gateway/gateway.db`; an explicitly chosen custom path is the operator's own responsibility (uninstall never deletes custom paths). |
| `profiles` | yes | — | Explicit array (empty means approval-only: human Telegram decisions, no model). At most 128 entries; each entry uses the standalone [`review.models[]`](#reviewmodels) schema. Provider credential files are root:root `0600`. |
| `bots` | yes | — | 1–128 entries: `name` plus `token_file` (root:root `0600`). One update listener per actual bot-token identity. |
| `channels` | yes | — | 1–128 entries: `name`, `bot`, `approval_ttl` in **integer seconds** (≥ 30), and 1–8 `recipients` of `chat_id` plus 1–8 `operator_user_ids` — the same routing model as the standalone [named channels](#named-multi-channel-form). `gateway init` writes `approval_ttl: 7200` (2h); this gateway value alone controls fleet approval-card lifetime. Edit it and restart `askdo-gateway` to apply a change. |
| `reviewer_webfetch_enabled` | no | absent | Boolean default for the reviewer's `webfetch` tool on every host that does not set `review.webfetch_enabled` itself. Absent leaves it to each host. |
| `review_defaults` | no | absent | Object of review-policy defaults published to every host, applied where a host sets nothing ([precedence table](#fleet-policy-defaults)). Keys mirror a host's `review` section and use its units and limits; every key is optional: `approval_only_users` (array of logins, no blanks or duplicates), `timestamp_timeout_users` (login → **minutes**, 0.5–60), `auto_approve_grants` (array of `{"user","max_risk"}`, `max_risk` 1–4, at most 128, no duplicate logins), `risk_policy` and `account_notes` (`{"users":{login: TEXT},"groups":{group: TEXT}}`). Each TEXT is exactly one of `{"text": "..."}` or `{"file": "/abs/clean/path"}`. A file must be a root-owned regular file with no write bits (for example mode `0444`) in root-controlled directories, like the TLS certificate; it is read **once, when the gateway starts**, so edit it and restart the gateway. Text must be UTF-8 of at most 262144 bytes with no control characters other than newline and tab (use LF, not CRLF), and the whole section may publish at most 512 KiB so the signed catalog always stays inside the 1 MiB payload limit hosts enforce. Anything a host would refuse stops the gateway from starting and fails `askdo-config gateway check`. |

Gateway credential and key files are validated at load with the same
root-ownership rules as host fleet files. Provider configuration is manual
server-side JSON only; there is no host-side provider upload and no new admin
UI. `reviewer_webfetch_enabled` and `review_defaults` are edited in this file
directly; no `askdo-config gateway` subcommand sets them.
