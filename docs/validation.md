# Validation checks

Checks you can run yourself against a source checkout or an installed askdo
service. None of them send host file contents anywhere, and none of them prove
a security audit; they confirm buildability, configuration validity, and
service reachability only.

## From a source checkout

With the Go version declared in `go.mod`:

```sh
go vet ./...
go test -race ./...
CGO_ENABLED=0 go build -trimpath -o askdo ./cmd/askdo
CGO_ENABLED=0 go build -trimpath -o askdo-launch ./cmd/askdo-launch
./askdo --help
```

- `go vet ./...` and `go test -race ./...` include unit tests for the
  client-side stdin capture (pipes and redirected files, 1 MiB ceiling,
  UTF-8/NUL rejection), the broker's captured-stdin staging, review
  coverage tracking and no-auto-approval rule, and the named Telegram
  channels: config validation and login→UID route resolution, per-channel
  wire projections, first-valid-decision and per-chat message-ID handling,
  and fail-closed behavior when one recipient's delivery fails. Those checks
  run against test fixtures and fake bots; they do not operate a Telegram
  bot or run real scripts.
- Optional, container-based suites (require Docker; they do not install a
  service on the host):

```sh
scripts/build-release.sh dist    # refuses to overwrite an existing dist/
scripts/test-packaging.sh
scripts/run-root-tests.sh
scripts/test-foreground-sudo-container.sh
scripts/test-fleet-binary.sh
```

`scripts/build-release.sh` writes Linux amd64/arm64 assets and SHA-256 files
to `dist/`; `scripts/test-build-release.sh` wraps it in a disposable
temporary directory and asserts the installer-facing file set (and that the
test-only `askdo_fleet_fixture` build tag never leaks into release assets).

### Fleet fixtures (implemented in source; not in the rc.1 release binaries)

The default root and foreground container runners
(`scripts/run-root-tests.sh`, `scripts/test-foreground-sudo-container.sh`)
already compile the test-only `askdo_fleet_fixture` tag, which enables a
strict loopback HTTP Telegram wire override (`gateway.NewFixtureServer`) and
includes every `TestRootFleet*` case: an in-process production gateway,
reviewer and broker over real TLS and real SQLite.

`scripts/test-fleet-binary.sh` goes one step further: it builds a disposable
fixture-tagged binary (`go build -tags askdo_fleet_fixture ./cmd/askdo`; a
normal build has **no** Telegram endpoint override) and runs an actual
compiled `askdo gateway serve` subprocess serving verified TLS, while two
isolated in-process root brokers (separate spool, socket and SQLite store)
approve **colliding local job IDs** concurrently — proving one waiting host
does not block another and that signed proofs stay bound to separate host
enrollments. The binary is also built once without the tag to prove release
builds lack the override.

Everything the fleet suites talk to is a **synthetic wire fixture**: a fake
Telegram Bot API and a fake provider on loopback HTTP. External Telegram and
real provider/cloud endpoints are **not** tested by these suites; live
provider behavior is your own deployment check (`config check --live`).
Native ARM execution is likewise not rerun here — release ARM64 assets are
cross-built and checksum-verified only.

### Performed fleet validation (2026-10-02)

Separate, owner-approved validation of the current fleet implementation included:

- **Real providers and Telegram:** isolated gateways and two disposable hosts
  exercised Kimi and a fresh independent Codex OAuth login. Real provider tool
  checks, human-approved commands and captured-input reviews completed through
  verified gateway TLS. The Kimi run also exercised real human denial, different
  local auto-approval policies, pending-ticket gateway restart and host revocation.
- **Native ARM64:** two AArch64 systems executed normal and fixture-tagged race
  suites and vet, real bind/tmpfs namespace cases, root dispatch and protection,
  the compiled two-host gateway lifecycle, original-PTY foreground tests,
  packaging, static build/checksum checks and native CLI smoke tests. Namespace
  fixtures used container-only security settings; no host security policy or
  service configuration was changed.

These were disposable test environments, not production deployments. They do
not make the source-checkout suites contact external services automatically,
cover every provider/model, or prove model risk calibration. Real issuer refresh
rotation after natural token expiry was not forced during the short Codex smoke;
refresh locking and uncertain-outcome handling remain covered by automated tests.
The previously published rc.1 binaries still do not contain the fleet gateway.

## Against an installed service

Run these as root after a reviewed installation:

```sh
askdo config check         # offline validation + warnings + openat2 probe
askdo config check --live  # additionally probes each model endpoint
                           # with a synthetic fixture (never host files)
askdo inspection check /path/to/file   # diagnose a rule without reading content
systemctl status askdo
journalctl -u askdo
```

A fleet host runs the same `config check [--live]` (it validates the v5 fleet
connection and exercises the signed gateway catalog). On a gateway server,
`askdo gateway check --config /etc/askdo-gateway/config.json [--live]`
validates the server config and probes its provider endpoints the same way.

`config check --live` sends a synthetic multi-turn tool fixture to each
configured endpoint, not host files, and may consume provider quota. It does
not prove the model will safely review a real operation. A real Telegram
approval needs a configured bot and a human operator; it cannot be exercised
by an offline check.

## Scope

These checks cover build health, schema validation, and service liveness.
Model risk calibration, prompt-injection resistance, real SSH-host terminal
behavior, and any particular operation's safety are deployment-specific
responsibilities and are **not** validated by these commands.
