# askdo for AI agents

Use askdo instead of `sudo` for privileged commands. Your account must be in the
host's `askdo` group; ask the administrator to enroll it if necessary.

## Submit and track a request

```sh
askdo --reason 'Restart nginx so the validated site config takes effect' -- \
  /usr/bin/systemctl restart nginx
```

- Put what and why in a specific `--reason`; it is shown to the reviewer and
  human approver.
- Keep the printed `JOB_ID`. It identifies this request even if your client
  disconnects.
- Do not add `--timeout` to accommodate a slow human approval. Let askdo wait.
  If you cannot wait, use `-n`: it runs only with reusable or eligible
  auto-approval and otherwise exits 1 without leaving a pending card.
- Check the existing job before doing anything else after a disconnect,
  timeout, or uncertain result:

  ```sh
  askdo status '2026-09-28_#1' --json
  askdo attach '2026-09-28_#1'       # reconnect to retained/streamed output
  ```

- **Never resubmit blindly.** A command may already be running or may have run.
  Inspect its status and effects first. After denial or **Request changes**,
  nothing ran: read the returned warnings and suggestions, address them or ask
  the administrator, and do not retry the denied command unchanged.
- `askdo --help`, `askdo-config --help`, `askdo --version`, and
  `askdo-config --version` do not request approval.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0`–`255` | After dispatch, the command's own exit status is preserved; `0` means it succeeded. |
| `128 + signal` | The dispatched command died from that signal (for example, `137` for SIGKILL). |
| `124` | The client waiting timeout expired. Before dispatch the request is cancelled; after dispatch only observation stops and the command continues. |
| `2` | `askdo` was run with no command; nothing was submitted. |
| `125` | askdo usage, connection, review, or infrastructure failure, or a failed/unknown job. Check status and the error; do not assume nothing ran. |
| `126` | Denied, expired, or cancelled before dispatch; the command did not run. |
| `130` | Interrupted with SIGINT while waiting; before dispatch the request is cancelled. |

A command can itself return `124`, `125`, `126`, or `130`. Use `askdo status` and
its recorded result kind to distinguish the command's status from an askdo
wrapper outcome.

## Paste into AGENTS.md or a system prompt

```md
### Privileged commands
- Use `askdo --reason 'what and why' -- CMD [ARG...]`, never `sudo`.
- Keep the printed JOB_ID. After any disconnect, timeout, or uncertain result,
  run `askdo status JOB_ID --json`; use `askdo attach JOB_ID` for output.
- Never resubmit blindly: first determine whether the existing job ran and
  whether its effects landed. Never retry a denied command unchanged.
- Do not set `--timeout` to wait for human approval. Use `-n` only when a
  non-blocking attempt is required; it never leaves a pending approval card.
- Exit 126 means denied/expired/cancelled before execution; 125 means an askdo
  or job failure needing inspection; 124 is a waiting timeout, not proof that
  a dispatched command stopped. Other dispatched command exit codes are
  preserved. Check `askdo status` when the distinction matters.
- `askdo --help`, `askdo-config --help`, and both `--version` commands are safe
  to read and never ask for approval.
```
