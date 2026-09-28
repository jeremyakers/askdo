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

Optional, container-based suites (require Docker; they do not install a
service on the host):

```sh
scripts/build-release.sh dist    # refuses to overwrite an existing dist/
scripts/test-packaging.sh
scripts/run-root-tests.sh
scripts/test-foreground-sudo-container.sh
```

`scripts/build-release.sh` writes Linux amd64/arm64 assets and SHA-256 files
to `dist/`; `scripts/test-build-release.sh` wraps it in a disposable
temporary directory and asserts the installer-facing file set.

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