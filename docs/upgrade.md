# Upgrade askdo

Run this as an askdo user; no sudo password is needed:

```sh
askdo upgrade
```

The command selects the newest stable release, or the newest prerelease when no
stable release exists. To choose an exact release:

```sh
askdo upgrade --release v1.0.0-rc.21
```

It downloads and verifies the release, shows its operation, source commit and
manifest digest, and asks for Telegram approval. Approval is mandatory for every
upgrade; automatic approval is not used for this operation.

After approval, askdo stages the verified files, drains new work while existing
jobs finish, backs up the broker and gateway data, installs the release, and
verifies the restarted services and gateway catalog. The result is not called
successful until those checks pass.

## Reconnect to an upgrade

The operation ID is printed before approval. If the client disconnects or the
broker restarts, resume observation without submitting another upgrade:

```sh
askdo upgrade --operation up_0123456789abcdef0123456789abcdef
```

Receipts in `/var/lib/askdo-upgrade` contain only the operation, release, source
commit, state, stage and timestamps. They contain no credentials.

## Failure and recovery

- Denial or an expired approval does not schedule activation.
- A duplicate active operation is refused; a completed release can be upgraded
  again later with a new operation ID.
- Failed or uncertain results include the stage and backup path. No automatic
  rollback is attempted. Inspect the backup before restoring compatible
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
