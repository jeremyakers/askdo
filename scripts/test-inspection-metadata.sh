#!/bin/sh
# Ephemeral root QA only. No host account, package, key or service changes.
# Source is streamed into a unique Docker volume; no writable host mount.
# systemctl below is explicitly a synthetic manager adapter, not systemd.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VOLUME="askdo-metadata-qa-$(date +%s)-$$"
cleanup() { docker volume rm "$VOLUME" >/dev/null; }
docker volume create "$VOLUME" >/dev/null
trap cleanup EXIT HUP INT TERM
tar -C "$ROOT" --exclude=.git --exclude=.codegraph -cf - . | docker run --rm -i \
  -v "$VOLUME:/qa" golang:1.27 bash -c 'mkdir /qa/src; tar -xf - -C /qa/src'
docker run --rm --cap-add SYS_ADMIN --cap-add NET_ADMIN --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined -v "$VOLUME:/qa" -w /qa/src \
  -e ASKDO_ROOT_TEST=1 -e ASKDO_METADATA_CONTAINER=1 -e TMPDIR=/root/tmp \
  golang:1.27 bash -ec '
  apt-get update -qq
  apt-get install -y -qq sudo iproute2
  groupadd askdo
  groupadd -g 995 askdo-review
  useradd -u 995 -g askdo-review -M -s /usr/sbin/nologin askdo-review
  groupadd -g 1001 opencode
  useradd -u 1001 -g opencode -M -s /usr/sbin/nologin opencode
  useradd -u 1000 -g sudo -M -s /usr/sbin/nologin jeremy
  mkdir -p /qa/submit /root/tmp /etc/systemd/system
  chmod 0700 /root/tmp
  chown 1001:1001 /qa/submit
  printf "%s\n" "#!/bin/sh" "exit 125" > /usr/local/bin/askdo-helper
  chmod 0755 /usr/local/bin/askdo-helper
  printf "%s\n" "root ALL=(ALL:ALL) ALL" "%sudo ALL=(ALL:ALL) ALL" "opencode ALL=(root) NOPASSWD: /usr/local/bin/askdo-helper" > /etc/sudoers
  chmod 0440 /etc/sudoers
  visudo -c
  printf "%s\n" "[Service]" "ExecStart=/usr/bin/true" "UMask=0077" > /etc/systemd/system/askdo-metadata-fixture.service
  # Fixed real executable: production runner validates ownership, pins its FD,
  # supplies clean env/argv, captures output, and reaps this process.
  printf "%s\n" "#!/bin/sh" \
    '\''[ "$#" = 5 ] && [ "$1" = show ] && [ "$2" = --no-pager ] && [ "$3" = --property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,UMask ] && [ "$4" = -- ] && [ "$5" = askdo-metadata-fixture.service ] || exit 1'\'' \
    '\''printf "%s\n" "Id=askdo-metadata-fixture.service" "LoadState=loaded" "ActiveState=active" "SubState=running" "UnitFileState=enabled" "MainPID=11001" "FragmentPath=/etc/systemd/system/askdo-metadata-fixture.service" "UMask=0077"'\'' > /usr/bin/systemctl
  chmod 0755 /usr/bin/systemctl
  go test -c -race -tags askdo_fleet_fixture -o /qa/broker.test ./internal/broker
  go test -c -race -o /qa/inspection.test ./internal/inspection
  chmod 0755 /qa/broker.test /qa/inspection.test
  mount --bind /qa/src /qa/src
  mount -o remount,bind,ro /qa/src
  # New network namespace has only loopback: runtime cannot reach the network
  # used above for container-only apt/modules. No host namespace is modified.
  unshare --net bash -ec '\''
    ip link set lo up
    cd /qa/src/internal/broker
    /qa/broker.test -test.v -test.count=1 -test.timeout=3m -test.run="^TestRootInspectionMetadata(FullFlow|RejectsBeforeReader|HashPayloadLimitContinues)$"
    cd /qa/src/internal/inspection
    /qa/inspection.test -test.v -test.count=1 -test.timeout=3m -test.run="TestRoot|TestHashExecutable"
  '\''
'
