# Upgrade askdo

Run this as an askdo user; no sudo password is needed:

```sh
askdo upgrade
```

The command selects the newest stable release by publication date, or the newest
published prerelease when no stable release exists. To choose an exact release:

```sh
askdo upgrade --release v1.0.0-rc.21
```

It downloads and verifies the release, shows its operation, source commit and
manifest digest, and asks for Telegram approval. Approval is mandatory for every
upgrade; automatic approval is not used for this operation.

After approval, a captured root bootstrap verifies a root-owned candidate copy
and executes it through a pinned file descriptor with the frozen plan, so path
replacement cannot change the verified inode. The new helper stages and verifies the
release again before activation. It drains new work while existing jobs finish,
backs up the broker and gateway data,
installs the release, and verifies the restarted services and gateway catalog.
On hosts without `systemd-run`, a detached activation starts a new session and
moves to the root of each cgroup hierarchy before stopping the broker. The
result is not called successful until those checks pass.

## Supported topology and timing

A standalone broker without a local gateway can self-upgrade. If a local gateway
config exists, the host broker must have a usable local fleet enrollment for that
gateway. A standalone gateway with an unenrolled broker (`cfg.Fleet == nil`) is
not supported: preflight rejects it before staging, receipts, manager acceptance,
service stops or installation. Enrollment remains necessary to verify the local
gateway's authenticated catalog after restart.

Download, review and human approval use their normal workflow time limits; the
upgrade observation budget does not cancel them. After the scheduling client
returns, receipt observation has the activation deadline plus two minutes. If it
times out, use `--operation` to reconnect without submitting another upgrade.

## Reconnect to an upgrade

The operation ID is printed before approval. If the client disconnects or the
broker restarts, resume observation without submitting another upgrade:

```sh
askdo upgrade --operation up_0123456789abcdef0123456789abcdef
```

Receipts in `/var/lib/askdo-upgrade` contain only the operation, release, source
commit, state, stage and timestamps. They contain no credentials.

## Backup location and retention

The root helper reads the optional top-level `upgrade_backup_dir` from
`/etc/askdo/config.json` (direct v4 or fleet v5). It defaults to
`/var/backups/askdo`. Each operation stages its release at
`<upgrade_backup_dir>/up_<32 hex digits>` and, before installation, preserves
the old binaries, configuration and stopped database snapshots in that stage's
`backup/` subdirectory. The directory and its ancestors must be trusted,
root-owned, nonsymlink paths without group/other write access; a missing backup
directory is created `0700` by root.

On Synology DSM, use a data volume rather than the small system partition:
set `"upgrade_backup_dir": "/volume1/@askdo/upgrade-backups"` in the root config.
Fresh DSM installations write this setting and create root-private directories
on `/volume1`. Existing installations are **not** rewritten, and existing backups
are not moved: an administrator must set the value once. A different data-volume
location is fine if it meets the same trust checks. Keep the data volume mounted
and allow space for staged binaries and database snapshots.

The unprivileged client never needs to read this setting. Its captured shell uses
the fixed, transient `/var/lib/askdo-upgrade/bootstrap-<operation>` directory for
the pinned candidate, with exclusive `0700` creation, parent trust checks,
descriptor pinning, digest verification and EXIT-trap cleanup. A missing parent
is created `0700` by root. This executable-filesystem location deliberately avoids
`/run` and `/tmp`, which may be mounted `noexec`. The receipt scanner recognizes
only private, nonsymlink `bootstrap-up_<32 lowercase hex digits>` directories as
bootstrap artifacts; other unexpected entries still block scheduling.

When a failure is known to have made no live changes (including manager rejection,
scheduling cancellation before manager acceptance, or a pre-activation failure),
the helper removes its stage and records `stage removed` in the receipt detail.
Failed operations after a stop/install, interrupted manager acceptance, unknown
outcomes, or incomplete admission recovery retain their stages for inspection.
After successful activation, the helper keeps the newest **two successful stages**,
ordered by successful receipt timestamps, and removes older successful stages.
It only removes trusted `up_<32 lowercase hex digits>` directories whose matching
receipts identify them as successful stages under this backup root. Other entries,
including legacy `rc22-nas.*` maintenance backups, are left untouched. Receipts
remain available even after a stage is removed; historical failed stages are not
retroactively swept.

## Failure and recovery

- Denial or an expired approval does not schedule activation.
- A duplicate active operation is refused; a completed release can be upgraded
  again later with a new operation ID.
- Failed or uncertain results include the stage and backup path. If the receipt
  says `stage removed`, no recovery backup was needed. Otherwise, use the receipt's
  actual `stage` path, not an assumed `/var/backups/askdo` location. No automatic
  rollback is attempted. On detached hosts, inspect `<stage>/activation.log` for
  retained activation errors. Inspect `<stage>/backup/` before restoring compatible
  binaries and databases together.
- The backup directory is root-private. Use normal administrator access to
  inspect it; public receipts never expose its contents.
- A legacy service that does not support cooperative draining is frozen while
  admission and quietness are checked. If the helper is interrupted, it may need
  `kill -CONT <pid>` after checking that no stop was issued.
- Legacy stop uses a temporary systemd drop-in with `KillSignal=SIGKILL` and
  `SuccessExitStatus=SIGKILL`. It is restored or removed afterward. If a failure
  message names a drop-in, verify that file and run `systemctl daemon-reload`.

Do not resubmit an operation whose activation state is uncertain. Read its
receipt and backup first. Future upgrades can resume observation only; they do
not replay an ambiguous activation.

For manual recovery, run a downloaded `askdo` from a home directory, not `/tmp`,
because `/tmp` is often mounted `noexec`.
