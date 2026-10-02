# Fleet setup and operations

**Status: implemented in source; not present in the `v1.0.0-rc.1` release
binaries.** This is the operator guide for the optional fleet gateway. The
design objectives and trust boundaries are in [fleet-gateway.md](fleet-gateway.md);
field-level schemas are in [configuration.md](configuration.md). Standalone
installations (one bot per server, configured on that server) remain the
default and are fully supported.

A gateway centralizes **model credentials, Codex OAuth and Telegram
approvals** — never execution. Each host keeps its own inspection policy,
auto-approval ceiling, job database and privileged dispatch. The gateway
never connects to hosts, never runs commands, and holds no host sudo or SSH
access.

## Prerequisites

- A Linux host for the gateway (it needs inbound HTTPS from the fleet hosts
  and outbound HTTPS to providers and Telegram).
- A TLS certificate and key for the gateway's public name, provisioned by
  you. There is no self-signed auto-generation, insecure mode, or
  trust-on-first-use: hosts verify the certificate chain with normal
  hostname checks, optionally against an explicitly supplied additional CA.
- A Telegram bot **dedicated to the gateway**. One running poller per bot
  token, ever (see [cutover](#exclusive-bot-cutover-and-rollback)).
- Optional: provider API keys or a Codex subscription for central AI review.

The installer ships read-only examples in `/etc/askdo/examples/`
(`gateway-config.example.json`, `host-config.example.json`) and an inert
`/etc/systemd/system/askdo-gateway.service`. It does not create gateway
signing keys, certificates, credentials or databases, and it never enables
or starts any service.

## 1. Initialize the gateway (approval-only by default)

On the gateway host, as root. Provision the TLS certificate/key and the bot
token first — the certificate is a non-writable root-owned trust file, the
key and token are root-private secrets:

```sh
sudo install -d -m 0700 /etc/askdo-gateway /etc/askdo-gateway/credentials
sudo install -m 0444 -o root -g root tls.crt /etc/askdo-gateway/tls.crt   # your cert (0400 also fine)
sudo install -m 0600 -o root -g root tls.key /etc/askdo-gateway/tls.key   # your key
sudo install -m 0600 -o root -g root /dev/stdin /etc/askdo-gateway/credentials/telegram.token  # paste the bot token
sudo askdo gateway init \
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
sudo askdo gateway check --config /etc/askdo-gateway/config.json
sudo systemctl enable --now askdo-gateway
```

`gateway check` validates offline; `--live` additionally probes the
configured provider endpoints with a synthetic fixture (never host files).

## 2. Enroll and connect a host (human approvals, no model)

On the gateway, mint one enrollment per host against the channel `init`
created (individual credentials; one fleet-wide key would lose isolation and
revocation):

```sh
sudo askdo gateway hosts add --config /etc/askdo-gateway/config.json \
  --output /root/host-pi-bundle.json \
  --channel default --default-channel default
# optional extras:  --uid-channel 1000=default   --ca-file /etc/askdo-gateway/ca.pem
sudo askdo gateway hosts list --config /etc/askdo-gateway/config.json
```

The bundle is written root-only `0600` and contains the individual host ID,
its bearer credential, the gateway's **public** verification key, the CA (if
given) and the allowed profiles. Only bearer hashes persist in the gateway
database. Treat the bundle as a secret until it is imported on the host;
copy it over a trusted channel, then on the host:

```sh
sudo askdo gateway connect --enrollment /root/host-pi-bundle.json --approval-only
sudo askdo config check
sudo systemctl restart askdo      # pick up the new config
```

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
sudo askdo gateway check --config /etc/askdo-gateway/config.json
sudo systemctl restart askdo-gateway
```

For the ChatGPT-subscription Codex backend, log in centrally — exactly once,
on the gateway:

```sh
sudo askdo auth login openai-codex --token-file /etc/askdo-gateway/credentials/openai-codex.json
```

and use a profile with `"api": "openai_codex"`, `"api_key_file"` pointing at
that token JSON, and `"data_boundary": "external"` (forced: the Codex
backend is OpenAI-hosted). Its `base_url` stays required for schema
uniformity but is overridden at runtime by the fixed Codex backend URL. The
token file is root:root `0600`, and every writer — login, refresh,
replacement, removal — holds the same canonical sidecar lock. A refresh
whose outcome is uncertain (`refresh_pending`) requires re-login; an old
refresh token is never retried. Hosts never hold OAuth copies.

Then enroll (or re-enroll) hosts with the profile allowed and selected:

```sh
sudo askdo gateway hosts add --config /etc/askdo-gateway/config.json \
  --output /root/host-pi-ai-bundle.json \
  --profile local --channel default --default-channel default
```

Use a fresh bundle filename: `hosts add` does not overwrite the approval-only
bundle from step 2. Transfer the new bundle to the host, then:

```sh
sudo askdo gateway connect --enrollment /root/host-pi-ai-bundle.json --profile local
```

If the host used step 2's `--approval-only`, edit its root-owned
`/etc/askdo/config.json` and set `review.mode` to `"required"` to enable AI
review. Keep the other local policy fields unchanged; selecting `local` does
not itself change the mode. Validate before loading the new configuration:

```sh
sudo askdo config check
sudo askdo config check --live
# Finish or cancel pending work before this local broker restart:
sudo systemctl restart askdo
```

Omitting `--profile` uses the bundle's default profile selection recorded by
`hosts add`. An empty selection requires an explicitly permitted human-only
configuration; it never silently changes a required-review policy. When
re-enrolling, revoke the old host ID on the gateway after the replacement is
working; creating a new enrollment does not revoke the old credential.

## Revocation and its limits

```sh
sudo askdo gateway hosts revoke HOST_ID --config /etc/askdo-gateway/config.json
```

Revocation takes effect live in the gateway database: the host's
authenticated requests and pending tickets are refused. It **cannot undo an
already-issued proof or recall already-dispatched work** — those remain
bounded by proof expiry and the host's own local state. There is no claim of
instant offline revocation.

## Failure and recovery semantics (all fail closed)

- **Gateway restart** loses in-memory model sessions, so an interrupted
  review fails closed on the host rather than reconstructing provider
  continuation. Fully recorded tickets/decisions replay idempotently.
- A ticket whose Telegram send state is **unknown** after a restart fails
  closed; the gateway never resends a card it cannot account for.
- If the Telegram **poller** fails, the gateway needs an operator
  restart/repair; the failed poller is not automatically retried. Host ticket
  transport reconciliation is separate and retains the original expiry.
- Card cleanup and callback acknowledgements are cosmetic, bounded,
  lossy and best effort; they never affect authorization.
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
briefly. To roll a host back to standalone: let in-flight fleet jobs finish
(or accept their cancel/expire/unknown outcome) **before** restarting the
broker — no job is promised to finish across a broker restart — then restore
its `config_version: 4` configuration with its own bot (a **separate** token
from the gateway's), restart `askdo.service`, and never revive old jobs.

## What the gateway never does

No inbound SSH/command channel to hosts, no execution policy, no job
replication, no admin web UI, no HA/cluster machinery. Hosts authenticate
outbound over verified HTTPS with individual enrollment credentials; the
gateway signs catalog, receipts and decisions with its own key, and each
host's root broker verifies those proofs against its own frozen snapshots
before any dispatch.
