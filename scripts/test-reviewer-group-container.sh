#!/bin/sh
# Disposable mismatch-identity lane. Never provisions accounts on the host.
# Usage: sh scripts/test-reviewer-group-container.sh PREBUILT_ARTIFACT_DIRECTORY
# Prebuild broker.test and cli.test with go test -race -c for their packages,
# and identity-probe from internal/reviewidentity/testdata/probe.go.
# Only explicit synthetic test binaries are copied; source is read-only.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARTIFACTS=${1:?prebuilt artifact directory required}
for name in broker.test cli.test identity-probe; do
    test -f "$ARTIFACTS/$name"
done
tar -C "$ARTIFACTS" -cf - broker.test cli.test identity-probe |
docker run --rm -i --network none -v "$ROOT:/src:ro" -w /src \
    -e ASKDO_ROOT_TEST=1 -e ASKDO_REVIEWER_GROUP_FIXTURE=1 \
    golang:1.27 bash -c '
        set -eu
        mkdir /artifacts /fixture
        tar -xf - -C /artifacts
        chmod 755 /artifacts/* /fixture
        # users is deliberately broad; membership does not grant execution GID.
        test "$(getent group users | cut -d: -f3)" = 100
        groupadd -g 995 askdo-review
        groupadd -g 996 askdo
        useradd -u 2007 -g users -G askdo-review -M -s /usr/sbin/nologin askdo-review
        useradd -u 2008 -g users -G askdo -M -s /usr/sbin/nologin askdo-client
        printf synthetic > /fixture/credential
        printf broad > /fixture/broad-canary
        chown root:askdo-review /fixture/credential
        chown root:users /fixture/broad-canary
        chmod 640 /fixture/credential /fixture/broad-canary
        /artifacts/broker.test -test.shuffle=on -test.count=1 -test.timeout=300s -test.v \
            -test.run="^(TestRootReviewerExecutionGroup|TestRootDACSocketGate|TestRootApprovalConsumedOnceBeforeLaunch|TestRootExitCodesAndSignals|TestProcessWorkerBoundaryAndSingleActive)$"
        /artifacts/cli.test -test.shuffle=on -test.count=1 -test.timeout=120s -test.v \
            -test.run="^TestRootReviewerCLIExecutionGroup$"
    '
