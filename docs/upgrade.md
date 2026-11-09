# Upgrade askdo

Run this as an askdo user; no sudo password is needed. (`askdo upgrade` is the
deprecated old spelling: it still works and prints a notice.)

```sh
askdo-config upgrade
```

The command selects the newest stable release by publication date, or the newest
published prerelease when no stable release exists. To choose an exact release:

```sh
askdo-config upgrade --release v1.0.0-rc.21
```

To upgrade every host of a fleet from one decision instead of one approval per
host, see [Upgrade a fleet from the gateway](#upgrade-a-fleet-from-the-gateway).

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
askdo-config upgrade --operation up_0123456789abcdef0123456789abcdef
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

What step 3 restores is decided after the services stop, not before. The release
being abandoned can write until it exits, so the checks of step 1 are made again
once nothing is running, and the restore follows what they find then: a
configuration file or database it rewrote on its way out is put back, and a
binary that was replaced in the meantime by something the upgrade did not
install is refused (step `recheck <file>`) before any file is touched, leaving
the services stopped. A file is left alone only while its bytes and its recorded
permissions (and, as root, its owner and group) match the backup, so a release
whose bytes are identical but that was installed with other permissions is
restored too.

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
`verify responsiveness`; `<step>` is the rollback step, such as `restore askdo`,
`recheck askdo` (a file changed after the services stopped) or
`stop askdo.service`. Receipts carry no error text; the cause is in the
activation log. After `rollback failed`, recover manually from `<stage>/backup/`.

Rollback applies only while the helper that observed the failure is alive. If the
helper itself dies (killed, or the host loses power), nothing is rolled back from
disk: a later run finds the receipt in an active state, records `unknown` and
replays nothing, and the stage's `backup/` is the recovery source.

## Upgrade a fleet from the gateway

`askdo-config upgrade` asks for one approval per host per release. In a fleet you can
instead name the release **once**, on the gateway host, and each enrolled host
upgrades itself, one at a time, with the same staged activation and
[automatic rollback](#automatic-rollback) as above.

```sh
askdo-config upgrade-fleet                     # newest stable release, one approval
askdo-config upgrade-fleet v1.0.1              # or an exact release
askdo-config upgrade-fleet --status            # each host's release, last result, rollout state
askdo-config upgrade-fleet --stop              # stop offering the release
```

`upgrade-fleet` only sets the gateway's upgrade target (below). The gateway host
takes the push like any other host if its own broker is enrolled with this gateway
(its `/etc/askdo/config.json` names a host ID this gateway has enabled, and it has
not opted out of pushed upgrades). If it is not, the command says so after setting
the target, and you run `askdo-config upgrade` on this host yourself. While a
rollout is paused, `--status` prints the exact `askdo-config upgrade-fleet TAG` that
resumes it, and shows hosts that are disabled or opted out as `rollout=excluded`.
The underlying admin form stays available:

```sh
askdo-config gateway upgrade-target v1.0.1     # set the target (the one approval)
askdo-config gateway upgrade-target            # show the target and where the rollout stands
askdo-config gateway upgrade-target --clear    # stop offering any release
askdo-config gateway hosts list                # each host's release and last upgrade result
```

### Before the first push

A host can only be upgraded by push if it runs a release that contains this
feature **and** was produced by the release build, which embeds the release tag in
the binary. A binary built any other way does not know which release it is, so it
cannot tell newer from older and never upgrades by push (`hosts list` shows
`release=unknown`). Upgrade each host and the gateway once by hand with
`askdo-config upgrade` to the first such release; after that, set the target. (A binary
you build from source reports a release only if you embed one:
`go build -ldflags '-X github.com/jeremyakers/askdo/internal/version.Release=v1.0.1' ./cmd/askdo`.)

Hosts from before this feature keep working unchanged against a gateway that has
it. They never report, so the gateway never offers them anything and never sends
them a catalog field they do not know. Upgrade those by hand.

### Setting the target

Run `askdo-config upgrade-fleet [TAG]` (or `askdo-config gateway upgrade-target TAG`) on the gateway host as yourself, like
the other root-only `askdo-config` commands: it asks for the usual Telegram
approval, and that one approval covers the whole rollout. (As root it runs
directly.) `TAG` must be a release tag of the form `vMAJOR.MINOR.PATCH` with an
optional `-PRERELEASE`, such as `v1.0.1` or `v1.0.0-rc.35`.

The command fetches that release's `install-manifest.v1` from the official
`jeremyakers/askdo` repository, once, and stores the manifest's SHA-256 as the
target in the gateway database. The gateway publishes the release and that digest
in its signed catalog to the host whose turn it is. The target is not in the
gateway configuration file, so setting it needs no gateway restart; it reaches the
next catalog a host fetches. A tag the repository cannot resolve, or one hosts
could not order against the releases they run, is refused and leaves the current
target in place.

Setting the target also **starts the rollout afresh**: any pause is cleared, so
running the command again with the same tag is how you resume after a failure.
Hosts that already run the target (or something newer) are left alone.

### What each host does

About fifteen seconds after its broker starts, and then about every five minutes
(a little spread, so hosts that started together do not report together; every
thirty seconds while one of its own upgrades is running, so the result reaches the
gateway soon after the receipt records it), an enrolled host reports to the
gateway: the release it was built from, whether it applies pushed upgrades, whether
it is **ready** for one right now (it applies them and none is running on it), and
its latest upgrade receipt, whoever started that upgrade. That report is how a host
takes its turn ([below](#one-host-at-a-time-and-a-pause-on-failure)). If it applies
pushed upgrades and none is running it then reads the signed catalog, which carries
an offer only if the gateway has assigned it to this host. It upgrades itself only
when **all** of these hold:

- it has not opted out ([below](#opting-a-host-out)) and its binary knows its release;
- no upgrade of its own is in progress on the host;
- the offered release is **newer** than the one it runs. It never downgrades:
  `v1.0.0` is newer than every `v1.0.0-rc.N`, `rc.9` is older than `rc.34`, and an
  offer of the same or an older release, or of a tag it cannot order, is ignored.

It then does what `askdo-config upgrade` does after approval, with the same code:

1. It fetches the release's manifest alone and compares its SHA-256 with the digest
   in the gateway's signed offer. A mismatch installs nothing and downloads no
   binary: the host refuses, reports `refused` to the gateway, and the rollout pauses.
2. It downloads the release with the same repository-, host- and redirect-restricted
   download as `askdo-config upgrade`, and compares the manifest it actually downloaded
   with the same digest again, because a release can be republished in between.
3. It freezes a plan, writes the same root bootstrap script and runs it. The script
   verifies a root-owned copy of the new binary against the plan and runs that
   binary's `upgrade-helper`, which stages and re-verifies every asset and starts
   the activation detached from the broker: a transient `systemd-run` unit, or the
   detached process on hosts without `systemd-run` such as Synology DSM.
4. The activation drains the broker (and a local gateway), waits for existing work,
   backs up, installs, restarts and verifies, and rolls back automatically on any
   failure, exactly as described [above](#automatic-rollback). The broker never
   replaces itself: it only schedules, and the activation stops it.

The only thing that replaces a human's approval of this host is the operator's one
approval of the target. The host still verifies the signed offer, the manifest
digest and the release's own digests, never downgrades, and runs the unchanged
activation checks. A refusal, or a failure before activation starts (a failed
download, or another upgrade operation being active), is not tried again for ten
minutes rather than at every look, which is well inside the gateway's one-hour lease
on the offer, so a dropped download is retried before the rollout gives up on the
host; only the refusal is reported as a result, the other is logged.
The release is downloaded into a private temporary directory (under `$TMPDIR`, else
`/tmp`, as `askdo-config upgrade` does; on DSM that is RAM-backed, not the small system
partition) and removed once the helper has staged its own copy under
`upgrade_backup_dir`; a leftover from a crashed broker is removed at the next start.

### One host at a time, and a pause on failure

The gateway offers the target to **one host at a time**, and a host takes its turn
by **reporting**: the first host whose report says it is ready, and that runs an
older release, is assigned the offer, and only that host's catalog carries it. The
offer stays with that host until it reports how its upgrade ended (or that it now
runs the target with nothing running, which is what a host upgraded by hand
reports, or that it has opted out). A host whose new release is already up but
whose upgrade is still being verified keeps the offer: that verdict can still be a
rollback, and the next host must not start before it. Then the next ready host to
report has its turn, which is at most a few minutes later. Within a rollout the
order is therefore the order hosts happen to report in; to have a particular host
go first (the gateway host, say), upgrade it by hand before setting the target. The
gateway host is otherwise an ordinary host: its upgrade restarts the gateway, and
other hosts' reports and catalog reads fail and are retried meanwhile.

Reading the catalog never assigns the offer. A host's broker reads it for every job
it reviews, and the activation's own post-upgrade probe and `askdo-config gateway
check` read it too, none of which can act on an offer; only the upgrade agent's
report takes a turn.

The rollout **pauses for every host** as soon as any host reports an upgrade to the
target that ended in a failure, a rollback, an unknown outcome or a refusal. A bad
release therefore stops at the first host it fails on. It also pauses if the host
holding the offer reports no outcome for an hour: that host may be the one a bad
release took down, so the offer is not passed on. In both cases `askdo-config
gateway upgrade-target` shows why, and running it with the tag again resumes.

Changing the target while a host holds the offer does not stop that host's upgrade,
and the next host may then start before it finishes; the command warns you. The
outcome of an upgrade to a release that is no longer the target is not announced and
pauses nothing, though `hosts list` still shows it.

### What you are told

Each host result reaches the operator as an informational Telegram message, with no
buttons, to the recipients of the host's default channel:

- **succeeded**: the host now runs the target;
- **rolled back**: the upgrade failed and the previous release was restored and
  verified; the rollout is paused;
- **rollback failed**: the host needs [manual recovery](#automatic-rollback); the
  rollout is paused;
- **failed before changing anything**, **outcome unknown** (the helper was
  interrupted), **refused** (the manifest digest differed) or any other **failure**
  (the receipt's own sentence is shown beneath, for example that admission recovery
  failed and the host needs manual recovery): the rollout is paused;
- **not reported**: the host holding the offer reported no outcome for an hour; the
  rollout is paused.

A notice is delivered once per chat and retried once a minute for up to thirty
attempts; nothing else waits on it, and `askdo-config gateway hosts list` shows the
same results:

```text
host_… enabled=true … name=nas-01 release=v1.0.1 auto_upgrade=true upgrade=succeeded(v1.0.1) seen=2026-11-08T16:05:11-06:00
host_… enabled=true … name=- release=unknown auto_upgrade=unknown upgrade=none seen=never
```

`release` is what the host reported it runs, `auto_upgrade` whether it applies
pushed upgrades, `upgrade` its last result (`state/outcome(release)`), and `seen`
when it last reported, in the gateway host's local time zone. A host that never
reported says `unknown` and `never`.

### Opting a host out

Set `fleet_upgrade.auto` to `false` in the host's root-owned `/etc/askdo/config.json`
(see [configuration](configuration.md#fleet_upgrade)). The host keeps reporting, with
`auto_upgrade=false`, and the gateway never offers it anything. Without the
section, an enrolled host applies pushed upgrades. The section survives enrolling
the host again.

### What the gateway can and cannot do

The gateway was already the approval authority its hosts accept Telegram decisions
from. Pushed upgrades add one thing it can cause: that hosts which apply them
upgrade themselves, as root, to an official release. It can name only a release
tag, never a URL, a file or a command; hosts download only from the official
repository; a host installs only a release **newer** than the one it runs and only
if its manifest has the digest the gateway published; and the host's own activation
checks and rollback are unchanged. A compromised gateway can therefore, at most,
make opted-in hosts install an existing, newer official release, one at a time, or
stall a rollout. It cannot downgrade a host or install anything else, and a host
that opted out is unaffected. A host is trusted to report on itself: it can pause
a rollout by reporting a failure, or hand the offer on by reporting that it has
finished, and it affects nothing else.
