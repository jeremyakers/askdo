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
manifest digest, and submits a small root bootstrap script as a one-file bundle.
That request follows the host's normal approval policy: AI review (when
required) and Telegram approval, or risk-based auto-approval at the level you
have enabled. The script begins with a provenance header naming the release,
source commit, the official published checksum URL for the exact binary it will
run, and this document at that commit, so the reviewer can check those facts
independently (with `webfetch` enabled) instead of trusting the request.

After approval, the root bootstrap verifies a root-owned candidate copy
and executes it through a pinned file descriptor with the frozen plan, so path
replacement cannot change the verified inode. The new helper stages and verifies the
release again before activation. It drains new work while existing jobs finish,
backs up the broker and gateway data,
installs the release, and verifies the restarted services and gateway catalog.
After installing the binaries, activation creates or repairs the root-owned
`/usr/local/bin/askdo-config -> askdo` multicall symlink on existing hosts. It
refuses to replace a non-symlink at that path; a foreign file is never opened,
followed or overwritten.
On hosts without `systemd-run`, a detached activation starts a new session and
moves to the root of each cgroup hierarchy before stopping the broker. The
result is not called successful until those checks pass. If activation fails
after the services were stopped, the helper rolls back automatically; see
[failure and recovery](#failure-and-recovery).

## Supported topology and timing

A standalone broker without a local gateway can self-upgrade. If a local gateway
config exists, the host broker must have a usable local fleet enrollment for that
gateway. A standalone gateway with an unenrolled broker (`cfg.Fleet == nil`) is
not supported: preflight rejects it before staging, receipts, manager acceptance,
service stops or installation. Enrollment remains necessary to verify the local
gateway's authenticated catalog after restart.

Download, review and human approval use their normal workflow time limits; the
upgrade observation budget does not cancel them. After the scheduling client
returns, receipt observation has the 10 minute activation deadline, the 5 minute
rollback allowance and two more minutes. If it times out, use `--operation` to
reconnect without submitting another upgrade.

## Reconnect to an upgrade

The operation ID is printed before approval. If the client disconnects or the
broker restarts, resume observation without submitting another upgrade:

```sh
askdo upgrade --operation up_0123456789abcdef0123456789abcdef
```

Receipts in `/var/lib/askdo-upgrade` contain only the operation, release, source
commit, state, stage and timestamps. They contain no credentials.

## Backup location and retention

When scheduling, the root helper reads the optional top-level `upgrade_backup_dir` from
`/etc/askdo/config.json` (direct v4 or fleet v5). It defaults to
`/var/backups/askdo`. Each operation stages its release at
`<upgrade_backup_dir>/up_<32 hex digits>` and, before installation, preserves
the old binaries, configuration and stopped database snapshots in that stage's
`backup/` subdirectory. The directory and its ancestors must be trusted,
root-owned, nonsymlink paths without group/other write access; a missing backup
directory is created `0700` by root.

The backup root must be outside `/var/lib/askdo-upgrade` and all its descendants,
which are reserved for receipts and bootstraps. Activation and failure
reconciliation use the recorded stage's parent directory, not a later config
value, so a config edit cannot strand an already-scheduled operation.

On Synology DSM, use a data volume rather than the small system partition:
set `"upgrade_backup_dir": "/volume1/@askdo/upgrade-backups"` in the root config.
Fresh DSM installations write this setting and create root-private directories
on `/volume1` when it is present and trusted; otherwise they print a WARNING and
keep the `/var/backups/askdo` default, which an administrator should change. Existing installations are **not** rewritten, and existing backups
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
Failed operations after a stop/install, whether or not they were rolled back,
interrupted manager acceptance, unknown outcomes, or incomplete admission
recovery retain their stages: the stage holds the backup a rollback restores
from, and the evidence for one that failed.
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
- A failure before any service was stopped changes nothing: admission is
  reopened, the stage is removed and the receipt says `no live changes; stage
  removed`.
- A failure once the helper has begun stopping services (a stop, the stopped
  backups, installation, a start, the post-install verification, or the operation
  deadline) is rolled back automatically; see
  [automatic rollback](#automatic-rollback).
- Failed or uncertain results include the stage and backup path. If the receipt
  says `stage removed`, no recovery backup was needed. Otherwise, use the receipt's
  actual `stage` path, not an assumed `/var/backups/askdo` location. On detached
  hosts, inspect `<stage>/activation.log` for retained activation errors. Inspect
  `<stage>/backup/` before restoring compatible binaries and databases together.
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

### Automatic rollback

The root helper that activated the release reverses a failed activation from the
stage's `backup/`, in the same process and under the same operation lock:

1. **Check first.** Without changing anything, it confirms the rollback can
   finish: the backup directory is still trusted, each saved copy it would restore
   still matches the SHA-256 recorded when it was made, each binary it would
   replace is still the one the upgrade installed (or untouched), and
   `askdo-config` is still what the upgrade made. If a check fails, the services
   and files are left as they were and the rollback is recorded as failed.
2. **Stop what must not run during the restore.** The services of the release
   being abandoned are stopped, including a crash-looping or failed unit, whose
   start limit is cleared. A service that is still the pre-upgrade process, or was
   restarted by systemd from unchanged files, is left running, and its drained
   admission is reopened.
3. **Restore, atomically and in this order.** Each file is written to a hashed
   temporary file beside its destination and renamed into place. First the data,
   but only if a service of the new release was started: the databases, and any
   configuration file that differs from the backup. Then `askdo` and
   `askdo-launch`, with their original permissions and ownership. Last, the
   `askdo-config` link as it was found: absent, or its previous target.
4. **Start and verify.** The services that were running are started in their
   original order and verified as a successful activation verifies a release:
   each runs the restored executable (by hash), the broker and gateway answer
   their probes, and every service is observed again afterward.

Restoring a database moves its `-wal`, `-shm` and `-journal` files aside instead
of deleting them, because replaying them over the older image would corrupt it.
They are deleted only after the snapshot is in place. If the snapshot cannot be
put in place they are moved back, leaving the database and the committed
transactions in its write-ahead log as they were. One that cannot be moved back is
kept in a `.askdo-rollback-*` directory beside the database, and the activation
log says where.

Never restored: anything the backup did not capture; a binary that is neither
the original nor the one the upgrade installed, and a foreign file at
`askdo-config`, which are never overwritten; a gateway database that did not exist
before the upgrade, which stays as the new release created it; and database
changes made after the new release started. The restored database is the
snapshot taken while the services were stopped, so jobs recorded in that window
are lost.

The rollback has its own five minute allowance, which begins when it does: the
deadline expiring is itself a reason to roll back, and a termination signal does
not cancel it. It is never retried. A step that fails stops it there.

The receipt state is `failed` in both outcomes, and the stage and its backup are
kept. The detail is one of:

- `<phase> failed; rolled back to previous release; services verified; backup retained at stage/backup`
- `<phase> failed; rollback failed: <step>; manual recovery required; backup retained at stage/backup`

`<phase>` is the activation step that failed, such as `start askdo.service` or
`verify responsiveness`; `<step>` is the rollback step, such as `restore askdo`
or `stop askdo.service`. Receipts carry no error text; the cause is in the
activation log. After `rollback failed`, recover manually from `<stage>/backup/`.

Rollback applies only while the helper that observed the failure is alive. If the
helper itself dies (killed, or the host loses power), nothing is rolled back from
disk: a later run finds the receipt in an active state, records `unknown` and
replays nothing, and the stage's `backup/` is the recovery source.
