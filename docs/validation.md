# Validation checks

Checks you can run yourself against a source checkout or an installed askdo
service. Automated fixtures and `config check --live` do not send inspected
host content to real model providers. Real reviewed operations may do so under
the configured provider policy. None of these checks proves a security audit
or an operation's safety.

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

### Host-evidence validation

`inspection_scope`, optional executable hashing, service metadata, sudo-policy
metadata and inspection audit/manifest binding are new source additions, **not
in the published rc.2 binaries**. The earlier fleet validation above and existing
foreground-helper sudo hardening do not establish that these additions were
tested or deployed.

Targeted fixture checks from the current checkout:

```sh
go test -race ./internal/config ./internal/proto ./internal/inspection ./internal/hostmeta ./internal/reviewer ./internal/broker ./internal/providers
go vet ./...
```

These packages contain checks for false/default capability flags and strict
UID/hash-limit decoding; request/result correlation and closed reasons;
descriptor-filtered scope, binary executable hashing and mutation/policy
refusal; exact adapter argv and bounded parser output; independent worker/root
gates, report completion after metadata failure, per-job accounting, redacted
audit output and digest-bound manifest evidence. Unprivileged runs can skip
root-only cases: success there is not proof that every root case executed.
The default content/staging limit remains 8 MiB, independently of the 32 MiB
file / 64 MiB review hash ceilings, two-attempt cap, 32 metadata requests,
256 KiB aggregate metadata responses and 256 audit observations.

Use `scripts/run-root-tests.sh` for the existing disposable root/container
runner, which currently selects broker/inspection root cases, **not** the new
hostmeta integration fixture. The separate
`internal/hostmeta/testdata/root-fixture.sh` provisions disposable accounts and
policy and exercises a real sudo listing with `ASKDO_HOSTMETA_ROOT_FIXTURE=1`
and a prebuilt `/hostmeta.test`. Never set that switch or run the provisioning
script directly on a production host. These fixtures are not a production-policy
audit.

Run the dedicated metadata lane separately:

```sh
sh scripts/test-inspection-metadata.sh
```

It uses a disposable container and a loopback-only runtime network namespace;
never run its account/policy setup directly on a production host. The recorded
run passed with an actual root broker, reviewer UID995, submitter UID1001
authenticated by kernel peer credentials, private pipe, TLS gateway, SQLite,
GNU sudo and a 21 MiB executable hash under the independent 8 MiB content limit.
The provider fixture received the inspection results before report completion.
Human approval then produced root UID0; tampering with the frozen service-PID
observation changed the digest and prevented dispatch. A long/JSON-escaped hash
result is reported as a bounded tool failure, allowing report completion rather
than terminating the review. Privileged alias/ownership/cancellation cases run
in the same lane.

Provider and Telegram responses are wire fixtures. Service observations use a
synthetic fixed-argv systemctl adapter, not a real systemd manager. This proves
the new broker/tool/approval flow, not native ARM, live-model behavior, or actual
deployed manager observations. Those remain post-merge/approved-rollout checks.

### Legacy-kernel compatibility validation (honest scope)

The legacy inspection path was exercised on a **real isolated Linux
3.10.108 VM** (x86_64, ext4): confined
`os.Root` lookups, exact descriptor mount IDs via the `name_to_handle_at`
fallback, credential masking, terminal-symlink and absolute-link denial,
mount-alias handling and captured-stdin review via the legacy socket-stream
delivery. The `inspection_scope` `compatibility` leaf and the
`config check` backend note report exactly what such a kernel selects. This
proves those units and a separate fixture-backed broker runtime matrix:

- The VM runtime matrix exercised actual kernel peer credentials, an
  unprivileged reviewer, private IPC, SQLite, TLS, root execution, literal argv,
  a real Bash staged bundle, sequential captured stdin, approval/denial,
  once-only decisions, cancellation, mutation refusal and status/output replay.
  Model and Telegram responses were loopback wire fixtures; graceful restart
  does not establish SIGKILL/crash recovery.
- No successful **native DSM broker acceptance** or compatibility deployment
  has been completed. Native account/SSH restrictions, original terminal/helper
  behavior, real service-manager integration, installation persistence and
  rollback remain separate owner-approved acceptance lanes.
- The old-kernel test VM stages its temporary `HOME` outside `/tmp` because
  that environment reports `/tmp` as `noexec`; this is an environment
  accommodation, not advice to remount production filesystems.
- Docker-based suites do not prove old-kernel behavior; only the real 3.10
  VM run does.

Deployment still needs owner-approved per-host upgrade/configuration, queue
drain and askdo restart after review/merge. `config check` cannot prove that an
enabled sudo adapter has no plugin/NSS network or audit effects, that service
state will persist, or that an observed executable hash pins later execution.
No new capability is enabled by these instructions or shipped example defaults.

## Against an installed service

Run these as root after a reviewed installation:

```sh
askdo config check         # offline validation + warnings + kernel feature
                           # probe (prints the actually selected backend)
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
