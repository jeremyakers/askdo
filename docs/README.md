# Documentation map

**Start here:**

- [`../README.md`](../README.md) — requirements, install, onboarding and
  synchronous submissions (automatic no-TTY detached execution or original-TTY
  foreground execution).
- [`clean-cutover.md`](clean-cutover.md) — install alongside another service,
  coordinate Telegram bot use, and plan an operator-approved handoff; no live
  cutover is claimed.
- [`configuration.md`](configuration.md) — the complete `config.json`
  reference: every field, defaults, validation rules, credential-file
  requirements, worked examples.
- [`validation.md`](validation.md) — public, host-independent checks for a
  source checkout and an installed service.

**Internals reference (contributors / integrators):**

- [`architecture.md`](architecture.md) — client, broker, reviewer and
  foreground helper trust boundaries, lifecycles, dispatch and failure honesty.
- [`protocol-client.md`](protocol-client.md) — client ↔ daemon socket
  protocol (v4 reservation and lifecycle, historical v2/v3 reads, framing,
  authentication, exit codes).
- [`protocol-worker.md`](protocol-worker.md) — broker ↔ reviewer private
  pipe (process contract, full message reference, invariants).
- [`review-tools.md`](review-tools.md) — six filesystem inspection tools,
  optional webfetch, the report schema, inspection boundaries, and the
  `compatibility` snapshot of the host's actual inspection backend.

**Optional fleet mode (implemented in source; not in the `v1.0.0-rc.1` release binaries):**

- [`fleet-setup.md`](fleet-setup.md) — concrete gateway/host operations:
  TLS, enrollment, revocation, checks, cutover and rollback.
- [`fleet-gateway.md`](fleet-gateway.md) — the agreed design objectives and
  boundaries the implementation follows.

**Historical design context:**

- [`future-foreground.md`](future-foreground.md) — superseded foreground
  proposal and current implementation differences; not deployment approval.

Adapter/model compatibility and live validation are deployment-specific:
exercise `askdo config check --live` and non-disruptive checks against your
own installation. None of this documentation is a security audit.
