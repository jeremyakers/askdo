#!/bin/sh
# test-fleet-binary.sh — binary-level fleet QA in a disposable privileged
# container. Builds the test-only fixture binary
# (`go build -tags askdo_fleet_fixture ./cmd/askdo`, which wires
# ASKDO_FLEET_TELEGRAM_URL to gateway.NewFixtureServer's strict loopback HTTP
# override; normal builds have no such override), then runs the real-binary
# test: a compiled `askdo gateway serve` process serving verified TLS against
# fake Telegram/provider HTTP fixtures, with two isolated in-process root
# brokers approving colliding local job IDs concurrently.
# The source tree is mounted read-only; all builds, databases, spools and
# credentials live in the container's disposable filesystem. Nothing is
# installed on the host and no external Telegram or provider is contacted.
#
# Usage: scripts/test-fleet-binary.sh [extra go test args...]
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

exec docker run --rm \
	-v "$ROOT:/src:ro" -w /src \
	-e ASKDO_ROOT_TEST=1 \
	golang:1.27 bash -c '
		set -e
		# Reviewer identity for the worker process boundary; no host accounts change.
		groupadd askdo
		groupadd askdo-review
		useradd -r -g askdo-review -s /usr/sbin/nologin askdo-review
		export GOCACHE=/tmp/fleet-gocache GOMODCACHE=/tmp/fleet-gomodcache
		mkdir -p /tmp/fleet-bin
		# Normal release-style build must not carry the fixture override.
		CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /tmp/fleet-bin/askdo-normal ./cmd/askdo
		if go version -m /tmp/fleet-bin/askdo-normal | grep -q askdo_fleet_fixture; then
			echo "normal build unexpectedly carries the fixture tag" >&2
			exit 1
		fi
		# Test-only artifact with the fixture override compiled in.
		CGO_ENABLED=0 go build -tags askdo_fleet_fixture -buildvcs=false -o /tmp/fleet-bin/askdo ./cmd/askdo
		chmod 0755 /tmp/fleet-bin /tmp/fleet-bin/askdo
		export ASKDO_FLEET_BINARY=/tmp/fleet-bin/askdo ASKDO_FLEET_BINARY_TEST=1
		go test -race -tags askdo_fleet_fixture -shuffle=on -count=1 -timeout=300s -run "TestBinaryFleet" -v ./internal/broker "$@"
	' -- "$@"
