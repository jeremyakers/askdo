# Fleet setup and operations

This is the operator guide for the optional fleet gateway. The
design objectives and trust boundaries are in [fleet-gateway.md](fleet-gateway.md);
field-level schemas are in [configuration.md](configuration.md). Standalone
installations (one bot per server, configured on that server) remain the
default and are fully supported.

A gateway centralizes **model credentials, Codex OAuth and Telegram
approvals** — never execution. Each host keeps its own inspection policy,
job database and privileged dispatch, and applies the review policy the
gateway offers as defaults (exempt logins, approval reuse windows,
auto-approval ceilings, `webfetch`, risk guidance) only where its own
configuration sets nothing; see
[fleet policy defaults](configuration.md#fleet-policy-defaults). The gateway
never connects to hosts, never runs commands, and holds no host sudo or SSH
access.

## Prerequisites

- A Linux host for the gateway (it needs inbound HTTPS from the fleet hosts
  and outbound HTTPS to providers and Telegram).
- A TLS certificate and key for the gateway's public name, provisioned by
  you, with matching DNS/IP SANs and valid dates. There is no self-signed
  auto-generation or insecure mode. Publicly trusted certificates and private
  LAN certificates are supported; joining hosts confirm gateway identity by
  comparing a certificate-bound request code with the Telegram card below.
- A Telegram bot **dedicated to the gateway**. One running poller per bot
  token, ever (see [cutover](#exclusive-bot-cutover-and-rollback)).
- Optional: provider API keys or a Codex subscription for central AI review.

The installer ships read-only examples in `/etc/askdo/examples/`
(`gateway-config.example.json`, `host-config.example.json`) and an inert
`/etc/systemd/system/askdo-gateway.service`. It does not create gateway
signing keys, certificates, credentials or databases, and it never enables
or starts any service. If you edit or replace `askdo-gateway.service`,
`uninstall.sh` refuses to remove anything (including with `--purge --yes`)
until you restore the shipped unit or remove the unit yourself, because the
unit's `ExecStart` shares `/usr/local/bin/askdo` with the main install.

## 1. Initialize the gateway (approval-only by default)

On the gateway host, as root. Provision the TLS certificate/key and the bot
token first — the certificate is a non-writable root-owned trust file, the
key and token are root-private secrets:

```sh
sudo install -d -m 0700 /etc/askdo-gateway /etc/askdo-gateway/credentials
sudo install -m 0444 -o root -g root tls.crt /etc/askdo-gateway/tls.crt   # your cert (0400 also fine)
sudo install -m 0600 -o root -g root tls.key /etc/askdo-gateway/tls.key   # your key
sudo install -m 0600 -o root -g root /dev/stdin /etc/askdo-gateway/credentials/telegram.token  # paste the bot token
sudo askdo-config gateway init \
  --url https://gateway.example.com:8443 \
  --listen 0.0.0.0:8443 \
  --tls-cert /etc/askdo-gateway/tls.crt \
  --tls-key /etc/askdo-gateway/tls.key \
  --bot-token-file /etc/askdo-gateway/credentials/telegram.token \
  --chat-id 111111111 --operator-user-id 100111
```

`init` generates the signing identity and writes a valid **approval-only**
server configuration: `profiles: []` and one bot and one channel, both named
`default`. Defaults: config `/etc/askdo-gateway/config.json`, database
`/var/lib/askdo-gateway/gateway.db`, credentials in
`/etc/askdo-gateway/credentials/` (`signing.seed` root:root `0600`,
`verification.pub` non-writable); `--database` and `--credentials-dir`
override them. Secrets come from files, never argv, and all outputs are
written atomically with restrictive ownership. Re-running refuses to
overwrite the config without `--force`; with `--force` the existing signing
identity is preserved (and verified against `verification.pub`), not rotated.
Changing its credentials directory or supplying missing/mismatched identity
files is refused; `--force` is not a signing-key rotation command.

Start the service explicitly when ready:

```sh
sudo askdo-config gateway check --config /etc/askdo-gateway/config.json
sudo systemctl enable --now askdo-gateway
```

`gateway check` validates offline; `--live` additionally probes the
configured provider endpoints with a synthetic fixture (never host files).

## 2. Join a host (recommended)

With askdo installed, run **on the joining host**:

```sh
sudo askdo-config fleet join --name web-01 https://gateway.example.com:8443
# Optional explicit trust: --ca-file /path/to/root-owned-read-only-ca.pem
```

`--name` sets the host's gateway display name and is optional. By default the
gateway uses the machine hostname; a duplicate hostname gets a generated
`hostname-<4 chars>` name instead. On the gateway host, `askdo-config gateway
hosts list` shows host IDs, names, releases, and rollout state without an
approval card for askdo-group members. Rename a host with:

```sh
askdo-config gateway hosts rename HOST_ID NAME
```

Approve the dedicated **fleet enrollment** card in Telegram **ONLY if its
six-character request code matches the host terminal**. No server-side host
command, bundle copy, profile flag or channel flag is needed. Join automatically allows/selects the
gateway's configured profiles (up to the existing 16-profile selection limit)
and uses the channel literally named `default`; no profiles means approval-only.
The host generates its bearer locally; the gateway stores only its hash.
For a provisionally trusted private CA, keep the host terminal open: after the
gateway reports approval, it asks `Did the Telegram card show code XXXXXX, and
did you approve it? [y/N] `. Answer `y` or `yes` only after comparing the code
and approving that card yourself. A gateway's approval claim alone is not proof
that a Telegram card existed.

### Gateway trust and the request code

On a private LAN, no CA copying or fingerprint pasting is needed. Without
`--ca-file`, an **unknown certificate authority only** permits
provisional trust of the certificate on the first TLS connection. The host pins
the top-most certificate the gateway presented (a root/intermediate when sent,
otherwise the leaf). Normal Go TLS verification still checks the chain,
DNS/IP SANs, validity and server-auth usage; an expired, not-yet-valid or
wrong-name certificate is refused, not provisionally trusted.

The host's first leaf certificate and top-most anchor cannot change during that
join, even to another valid leaf from the same CA. A change aborts enrollment;
rerun `fleet join` and compare the new code. Only after approval and terminal
confirmation (when trust is provisional) is the anchor
saved as the existing `<host_id>.ca.pem` credential for later fleet connections.
An explicit `--ca-file` retains normal system-plus-supplied-CA verification and
is saved unchanged; it never falls back to provisional trust. System-trusted
gateways and `--ca-file` joins do not ask the terminal confirmation question.
For provisional trust, the answer is read from `/dev/tty`, never piped stdin.
Anything other than `y`/`yes` (case-insensitive), EOF, or an unavailable terminal
aborts with `enrollment not confirmed; local configuration unchanged`: no local
config, bearer, verification key or CA is installed, and setup does not run.

The version-2 join first commits to a fresh host nonce without disclosing it.
The gateway durably fixes its own random nonce and the request's hashes before
returning that challenge. Only then does the host reveal its nonce, authenticated
with its join secret. The gateway verifies the commitment before making the
Telegram card available; the host prints its code only after reveal acceptance.
Replayed POSTs cannot replace the fixed hashes, commitment or gateway nonce, and
a second reveal is rejected (a lost response is recovered through status).

The request code binds the host ID, bearer hash, join-secret hash, commitment,
both nonces and SHA-256 of the gateway's **leaf certificate**. This commit/reveal
exchange prevents a TLS relay from adaptively grinding substitute join hashes
after learning the host nonce. The host uses the leaf it actually received;
the gateway uses its own serving leaf, including when system trust or
`--ca-file` is used. A TLS relay with a different certificate normally produces
different codes on the host and the genuine gateway's Telegram card. The
six-hex-digit comparison provides 24-bit authentication per fixed exchange,
not an absolute collision guarantee.
**Approving a card whose code differs from the terminal is unsafe: do not approve
it.** The code is not a credential or automatic approval. It is printed only
after the gateway accepts the reveal, with the remaining enrollment wait time.
Older join-wire versions are rejected; upgrade the host and gateway together.

Join preflights local policy before sending a card, installs the root-private
v5 config and credentials, validates them offline, adds the invoking non-root
`SUDO_USER` to `askdo` if needed (Linux or DSM), and enables/starts `askdo`.
Log out and back in **once**, then test askdo. Direct root invocations skip
the group add with an explanation. A setup failure keeps a valid enrollment
and reports which local step is incomplete; it does not undo the config.

Requests expire after ten minutes. Denial/expiry never creates an enrollment.
Pending cards expire fail-closed when the gateway restarts; request a fresh
card by rerunning join. An approved status response can be retried until its
expiry, so a lost reply does not lose enrollment. Already-fleet hosts refuse
join without sending another card. Older gateways must be upgraded first.

### Manual bundle enrollment (advanced/compatibility)

On the gateway, mint one enrollment per host against the channel `init`
created (individual credentials; one fleet-wide key would lose isolation and
revocation):

```sh
askdo-config gateway hosts add --config /etc/askdo-gateway/config.json \
  --output /root/host-pi-bundle.json \
  --channel default --default-channel default
# optional extras:  --uid-channel 1000=default   --ca-file /etc/askdo-gateway/ca.pem
askdo-config gateway hosts list --config /etc/askdo-gateway/config.json
```

The bundle is written root-only `0600` and contains the individual host ID,
its bearer credential, the gateway's **public** verification key, the CA (if
given) and the allowed profiles. Only bearer hashes persist in the gateway
database. Treat the bundle as a secret until it is imported on the host;
copy it over a trusted channel, then on the host:

```sh
sudo askdo-config gateway connect --enrollment /root/host-pi-bundle.json --approval-only
sudo askdo-config config check
```

A running host broker uses the new connection for its next submitted job;
no local broker restart is needed. Already-admitted jobs retain their original
config, inspection policy and connection; automatic dispatch still re-reads the
current auto-approval grant. Keep credentials needed by those jobs until they
finish. The gateway's own config remains startup-loaded.

`connect` strictly imports the bundle into a `config_version: 5` document
([schema](configuration.md#fleet-host-config-version-5)) and **preserves all
local policy**: inspection roots/masks, limits, review mode, exemptions,
auto-approval grants and preferences are carried over unchanged unless you
explicitly supply `--approval-only`, which selects human-only review. Selecting
a model profile alone does not change the existing review mode. The approval
TTL is inherited from the host's previous Telegram/fleet setting.
The enrollment files land in `<config parent>/credentials/`: the bearer as
`<host_id>.bearer` (`0600`), the public verification key as `<host_id>.pub`
(`0400`), and the CA as `<host_id>.ca.pem` (`0400`) when present. Re-running
`connect` for the same host refuses unless `--force`, and `--force` permits
only an exact byte-identical reapplication of existing enrollment files — a
conflicting secret is never overwritten.

`connect` also records each original import file in
`fleet.enrollment_bundle_files`. These exact paths join the broker's hard
credential protections, so a reviewer cannot read the retained bundle through
host inspection—even with broad read roots and a custom credentials directory.
Re-enrollment retains earlier import paths. Deleting a bundle does not remove
its protected-path binding or make future files at that path inspectable.
Other copies/backups are not discovered automatically: keep them in protected
credential directories or add their exact paths to this root-owned list.

Enrollment is enabled only after its private bundle is durably written. If
`hosts add` reports that the bundle was written but activation is **not ready**,
that enrollment remains disabled and cannot authenticate. Resolve the database
problem and create a replacement enrollment with a fresh output filename;
do not treat the failed export as ready to connect. A disabled administrative
record may remain after an interrupted or failed provisioning operation.

## 3. Add central AI review (optional, explicit)

Profiles execute **on the gateway**: a `base_url` such as
`http://127.0.0.1:11434/v1` names a model server reachable *from the
gateway*, not from the fleet hosts, and provider keys live only on the
gateway — nothing is copied to hosts. As root on the gateway, add a
`profiles` entry to `/etc/askdo-gateway/config.json` (same schema as
standalone `review.models`), install its credential file root:root `0600`,
then validate and restart:

```json
"profiles": [
  {
    "name": "local",
    "api": "openai_chat",
    "base_url": "http://127.0.0.1:11434/v1",
    "model": "<your-local-model-id>",
    "data_boundary": "local",
    "request_timeout": "5m"
  }
]
```

```sh
askdo-config gateway check --config /etc/askdo-gateway/config.json
sudo systemctl restart askdo-gateway
```

For the ChatGPT-subscription Codex backend, log in centrally — exactly once,
on the gateway:

```sh
askdo-config auth login openai-codex --token-file /etc/askdo-gateway/credentials/openai-codex.json
```

and use a profile with `"api": "openai_codex"`, `"api_key_file"` pointing at
that token JSON, and `"data_boundary": "external"` (forced: the Codex
backend is OpenAI-hosted). Its `base_url` stays required for schema
uniformity but is overridden at runtime by the fixed Codex backend URL. The
token file is root:root `0600`, and every writer — login, refresh,
replacement, removal — holds the same canonical sidecar lock. A refresh
whose outcome is uncertain (`refresh_pending`) requires re-login; an old
refresh token is never retried. Hosts never hold OAuth copies.

Once the profile is configured, re-authorize with no path:
`askdo-config auth login` (also `auth status` / `auth logout`) reads
`/etc/askdo-gateway/config.json` and `/etc/askdo/config.json`, and uses the
one configured `openai_codex` token file. If both name different files the
command stops and asks for `--config PATH` (or `--token-file`). On a
fleet-only host with no gateway config it directs you to the gateway host
instead of creating an unused local copy.

Then enroll (or re-enroll) hosts with the profile allowed and selected:

```sh
askdo-config gateway hosts add --config /etc/askdo-gateway/config.json \
  --output /root/host-pi-ai-bundle.json \
  --profile local --channel default --default-channel default
```

Use a fresh bundle filename: `hosts add` does not overwrite the approval-only
bundle from step 2. Transfer the new bundle to the host, then:

```sh
askdo-config gateway connect --enrollment /root/host-pi-ai-bundle.json --profile local
```

If the host used step 2's `--approval-only`, edit its root-owned
`/etc/askdo/config.json` and set `review.mode` to `"required"` to enable AI
review. Keep the other local policy fields unchanged; selecting `local` does
not itself change the mode. Validate the new configuration:

```sh
askdo-config config check
askdo-config config check --live
```

New submissions use that policy without restarting the local broker; queued,
reviewing and pending jobs keep their original policy and routes. Automatic
dispatch still re-reads the current auto-approval grant.

Omitting `--profile` uses the bundle's default profile selection recorded by
`hosts add`. An empty selection requires an explicitly permitted human-only
configuration; it never silently changes a required-review policy. When
re-enrolling, revoke the old host ID on the gateway after the replacement is
working; creating a new enrollment does not revoke the old credential.

## Upgrading the fleet

Instead of running `askdo-config upgrade` on every host, name the release once on the
gateway host:

```sh
askdo-config upgrade-fleet            # newest stable; or: askdo-config upgrade-fleet v1.0.1
```

It asks for the usual Telegram approval (one, for the whole rollout), stores the
release and the digest of its install manifest in the gateway database (no
restart), and each enrolled host then upgrades itself, one at a time, with the
same staged activation and automatic rollback as `askdo-config upgrade`. A failure pauses
the rollout; you get a Telegram notice for every host's result; run the command
again to resume. `askdo-config upgrade-fleet --status` shows each host's release,
last upgrade result and rollout state without an approval card for askdo-group
members (`--stop` stops offering; disabled or opted-out hosts show
`rollout=excluded`). The gateway host takes the push only if it is
enrolled with this gateway; if not, the command tells you to run
`askdo-config upgrade` on it. `askdo-config gateway hosts list` shows the
raw columns (`name`, `release`, `auto_upgrade`, `upgrade`,
`seen`). A host opts out with `"fleet_upgrade": {"auto": false}` in its own
configuration. Hosts and gateway must first be upgraded by hand to the first
release that contains this feature. The full behavior and the trust boundary are in
[upgrade.md](upgrade.md#upgrade-a-fleet-from-the-gateway) and
[fleet-gateway.md](fleet-gateway.md#gateway-pushed-upgrades).

## Revocation and its limits

```sh
askdo-config gateway hosts revoke HOST_ID --config /etc/askdo-gateway/config.json
```

Revocation takes effect live in the gateway database: the host's
authenticated requests and pending tickets are refused. The command fails the
host's pending tickets itself, in the same transaction; a running gateway
notices the change by itself within about a second and removes the approval
buttons from the affected Telegram cards (best effort, as for other card
cleanup). It **cannot undo an
already-issued proof or recall already-dispatched work** — those remain
bounded by proof expiry and the host's own local state. There is no claim of
instant offline revocation.

## Failure and recovery semantics (all fail closed)

- **Gateway restart** loses in-memory model sessions, so an interrupted
  review fails closed on the host rather than reconstructing provider
  continuation. Fully recorded tickets/decisions replay idempotently.
- A ticket whose Telegram send state is **unknown** after a restart fails
  closed; the gateway never resends a card it cannot account for.
- Transient Telegram **polling** failures resume in the existing single listener
  from the last committed update offset. Backoff grows from 1 to 30 seconds;
  a valid rate-limit `retry_after` can require a longer wait. Cancellation stops
  the wait, and a successful poll plus inbox/cursor commit resets the backoff.
  Network/read transport errors retry the same way even when their cause is
  not individually recognized. Existing ticket expiries are never extended.
- Invalid credentials, a competing-poller conflict, trust/protocol failures and
  unexpected cursor/inbox database failures remain terminal and require operator
  attention. Categorical outage/recovery/failure events are logged without bot
  tokens, URLs, descriptions, update bodies or token hashes.
- Poll recovery never retries an uncertain `sendMessage` or revives a failed
  ticket. Host ticket transport reconciliation remains separate and retains the
  original expiry.
- Authenticated gateway failure events are retained as evidence and reported as
  `fleet gateway failure: <code>` rather than being mislabeled invalid proofs.
  They cannot authorize execution. Invalid signatures, bindings, sequences and
  incomplete receipts are still rejected.
- Card cleanup and callback acknowledgements are cosmetic, bounded,
  lossy and best effort; they never affect authorization.
- The dispatcher waits for work rather than polling. About once a second it
  looks for another process's commits, retries a database operation that failed,
  and re-reads the wall clock for ticket expiry; authentication and every
  authorization check read the database directly and are not delayed.
- Model sessions have a global capacity of 256, not per-host quotas. Capacity
  exhaustion fails new reviews closed; a noisy enrolled host can affect other
  hosts' availability until sessions are released or expire. Enrollment
  credentials therefore belong only to trusted local root brokers.
- **Gateway outage ≠ local broker restart.** During a gateway outage, an
  already-dispatched local command keeps running and its local
  `status`/`attach`/output keep working. A **local broker restart** is the
  existing standalone baseline: pending work (`queued`/`reviewing`) cancels,
  `awaiting-human` expires, and `starting`/`running` jobs become `unknown` —
  the broker-owned process may have been killed or orphaned, so only the
  retained output bytes are readable. An `unknown` job is not permission to
  relaunch it blindly: verify whether the operation ran (or its effects
  landed) before resubmitting.

## Exclusive bot cutover and rollback

Telegram `getUpdates` polling tolerates exactly one active poller per bot
token. To move a bot from a standalone host to the gateway: stop the
standalone `askdo.service` first, configure the gateway, start it, then
connect hosts. Never run a standalone bot and the gateway on one token, even
briefly. To roll a host back to standalone, restore its `config_version: 4`
configuration with its own bot (a **separate** token from the gateway's).
New submissions use it without a local broker restart. In-flight fleet jobs
keep their original connection and routes; let them finish or cancel them before
revoking their enrollment or removing needed credentials. Never revive old jobs.

## What the gateway never does

No inbound SSH/command channel to hosts, no execution policy, no job
replication, no admin web UI, no HA/cluster machinery. It never installs
software: it names a release and each host upgrades itself. Hosts authenticate
outbound over verified HTTPS with individual enrollment credentials; the
gateway signs catalog, receipts and decisions with its own key, and each
host's root broker verifies those proofs against its own frozen snapshots
before any dispatch.
