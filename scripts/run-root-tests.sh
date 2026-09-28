#!/bin/sh
# run-root-tests.sh — execute the root-gated dispatch suite in a disposable
# privileged container.
#
# The broker and inspection root tests skip unless ASKDO_ROOT_TEST=1 and euid 0.
# The reviewer process boundary test also runs under the provisioned reviewer
# identity. Only the source tree is mounted from the host, read-only; the bind
# mount inspection test requires CAP_SYS_ADMIN and an unrestricted mount syscall.
# Nothing is installed on the host.
#
# Usage: scripts/run-root-tests.sh [extra go test args...]
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

exec docker run --rm --cap-add SYS_ADMIN --security-opt seccomp=unconfined \
	-v "$ROOT:/src:ro" -w /src \
	-e ASKDO_ROOT_TEST=1 \
	golang:1.27 bash -c '
		set -e
		# The daemon resolves askdo for socket ownership and the reviewer
		# account with its separate primary group for the process boundary.
		groupadd askdo
		groupadd askdo-review
		useradd -r -g askdo-review -s /usr/sbin/nologin askdo-review
		# Disposable login for UID-bound auto-approval grants; no host accounts change.
		useradd -u 1000 -g askdo -M -s /usr/sbin/nologin askdo-grantee
		go test -race -count=1 -run "TestRoot|TestProcessWorkerBoundary" -v ./internal/broker ./internal/inspection "$@"
	' -- "$@"
