# Database operator risk rubric

This account's expected work on this host is routine MariaDB operation:
starting the existing service, checking its status and performing read-only
diagnostics. This is assessment context, not permission to execute a command.

## Calibration

- **1 — minimal:** read-only diagnostics and starting the intended, existing
  MariaDB service with its existing unit, configuration and data directory.
  Normal startup writes and the configured listener are expected effects, not
  reasons by themselves to increase the rating.
- **2 — low:** narrow, reversible maintenance with a small, identified impact.
- **3 — moderate:** a concrete availability or security consequence, such as
  restarting an active database with connected applications. Identify that
  consequence rather than treating every privileged service action as moderate.
- **4 — high:** substantial exposure or privilege changes, or maintenance with
  a broad demonstrated service impact.
- **5 — critical:** destructive changes to important data or system security
  boundaries with a credible severe impact.

Do not assume that a service name proves its unit or startup code is unchanged.
Use available evidence when that distinction matters. Commands outside this
account's expected work need their own assessment; do not invent harmful effects
merely because they are unfamiliar. Use unknown when a meaningful uncertainty
prevents an assessment, and explain that uncertainty.
