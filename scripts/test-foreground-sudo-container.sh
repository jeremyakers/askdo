#!/bin/sh
set -eu
if [ "$(df -Pk /var | awk 'NR==2 {print $4}')" -lt 20971520 ]; then
  printf '%s\n' 'Refusing container run: /var has less than 20 GiB free' >&2
  exit 1
fi
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
docker run --rm --cap-add=SYS_PTRACE --network bridge --mount "type=bind,src=$repo,dst=/src,readonly" -e ASKDO_FOREGROUND_CONTAINER_TEST=1 -w /src golang:1.27 sh -eu -c '
  check_space() { [ "$(df -Pk /var | awk '\''NR==2 {print $4}'\'')" -ge 20971520 ] || { printf "%s\n" "container /var below 20 GiB" >&2; exit 1; }; }
  check_space
  export GOFLAGS=-buildvcs=false
  apt-get update >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sudo util-linux >/dev/null
  groupadd askdo
  useradd -m -u 1001 -G askdo askdo-human
  useradd -m -u 1002 askdo-outsider
  install -d -m 0750 /usr/local/libexec
  check_space
  go build -o /usr/local/bin/askdo ./cmd/askdo
  check_space
  go build -o /usr/local/libexec/askdo-launch ./cmd/askdo-launch
  check_space
  printf "Defaults use_pty\n" > /etc/sudoers.d/askdo-defaults
  cp /src/contrib/askdo.sudoers /etc/sudoers.d/askdo
  chmod 0440 /etc/sudoers.d/askdo /etc/sudoers.d/askdo-defaults
  visudo -cf /etc/sudoers
  go test ./internal/broker -run "^TestForegroundSudoContainer$" -count=1 -v -timeout=120s
'
if [ "$(df -Pk /var | awk 'NR==2 {print $4}')" -lt 20971520 ]; then
  printf '%s\n' 'WARNING: /var fell below 20 GiB free' >&2
  exit 1
fi
