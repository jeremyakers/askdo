#!/bin/sh
# Install from source or upgrade only the precisely recognized legacy policy.
set -eu
REPO=jeremyakers/askdo
VERSION=${ASKDO_VERSION:-main}
SOURCE_DIR=${ASKDO_SOURCE_DIR:-}
EXPLICIT_REF=${ASKDO_EXPLICIT_REF:-0}
if [ "${ASKDO_VERSION:-main}" != main ]; then EXPLICIT_REF=1; fi
die() { printf 'install.sh: error: %s\n' "$*" >&2; exit 1; }
case "${1:-}" in
  --help|-h) printf 'usage: sh install.sh [--version REF|TAG]\nNon-root local or piped use re-executes with sudo; root installs never start the service.\n'; exit 0 ;;
esac
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) [ "$#" -ge 2 ] || die 'missing ref'; VERSION=$2; EXPLICIT_REF=1; shift 2 ;;
    --version=*) VERSION=${1#--version=}; EXPLICIT_REF=1; shift ;;
    *) die "unknown option: $1" ;;
  esac
done
[ -z "$SOURCE_DIR" ] || [ "$EXPLICIT_REF" = 0 ] || die 'explicit ref conflicts with local source; use a remote ref without ASKDO_SOURCE_DIR'
if [ "$(id -u)" != 0 ]; then
  command -v sudo >/dev/null 2>&1 || die 'run as root or install sudo'
  if [ -f "$0" ] && [ -r "$0" ]; then
    exec sudo env ASKDO_VERSION="$VERSION" ASKDO_SOURCE_DIR="$SOURCE_DIR" ASKDO_EXPLICIT_REF="$EXPLICIT_REF" sh "$0" "$@"
  fi
  # stdin is already buffered by sh: never execute a partial copy of stdin.
  SELF_URL=${ASKDO_INSTALL_URL:-https://raw.githubusercontent.com/$REPO/$VERSION/install.sh}
  SELF=$(mktemp "${TMPDIR:-/tmp}/askdo-self.XXXXXX") || die 'could not stage installer'
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$SELF_URL" -o "$SELF" || { rm -f "$SELF"; die 'could not re-fetch installer'; }
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$SELF" "$SELF_URL" || { rm -f "$SELF"; die 'could not re-fetch installer'; }
  else
    rm -f "$SELF"
    die 'curl or wget required for piped sudo re-exec'
  fi
  if ! awk 'END {if (NR == 0 || $0 != "# askdo install.sh end-of-file") exit 1}' "$SELF"; then
    rm -f "$SELF"
    die 're-fetched installer is truncated'
  fi
  if sudo env ASKDO_VERSION="$VERSION" ASKDO_SOURCE_DIR="$SOURCE_DIR" ASKDO_EXPLICIT_REF="$EXPLICIT_REF" sh "$SELF" "$@"; then
    rm -f "$SELF"
    exit 0
  else
    RESULT=$?
    rm -f "$SELF"
    exit "$RESULT"
  fi
fi
[ "$(uname -s)" = Linux ] || die 'Linux required'
case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) die 'unsupported architecture' ;; esac

# Existing operator state is trusted input; never follow a symlink or repair
# an unsafe config/credential path behind the operator's back.
[ ! -L /etc/askdo ] && [ ! -L /etc/askdo/config.json ] &&
  [ ! -L /etc/askdo/credentials ] || die 'askdo configuration path is a symlink'
if [ -e /etc/askdo ]; then
  [ -d /etc/askdo ] && [ "$(stat -c %u /etc/askdo)" = 0 ] || die 'unsafe config directory'
  CONFIG_MODE=$(stat -c %a /etc/askdo)
  [ $((0$CONFIG_MODE & 0022)) -eq 0 ] || die 'writable config directory'
fi
if [ -e /etc/askdo/config.json ]; then
  [ -f /etc/askdo/config.json ] &&
    [ "$(stat -c %a:%u:%g /etc/askdo/config.json)" = 600:0:0 ] || die 'existing config must be root:root 0600'
fi
if [ -e /etc/askdo/credentials ]; then
  [ -d /etc/askdo/credentials ] &&
    [ "$(stat -c %a:%u /etc/askdo/credentials)" = 750:0 ] &&
    getent group askdo-review >/dev/null 2>&1 &&
    [ "$(stat -c %g /etc/askdo/credentials)" = "$(getent group askdo-review | cut -d: -f3)" ] ||
    die 'existing credentials directory must be root:askdo-review 0750'
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/askdo-install.XXXXXX") || die 'staging failed'
trap 'rm -rf "$TMP"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else return 1; fi
}
repo_file() {
  if [ -n "$SRC" ]; then cp "$SRC/$1" "$2"
  else fetch "https://raw.githubusercontent.com/$REPO/$RAW_REF/$1" "$2"; fi
}
SRC=
RAW_REF=$VERSION
if [ "$EXPLICIT_REF" = 0 ] && [ -z "$SOURCE_DIR" ] && [ -f "$0" ]; then
  SELF_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
  if [ -f "$SELF_DIR/go.mod" ] && [ -f "$SELF_DIR/cmd/askdo/main.go" ]; then SOURCE_DIR=$SELF_DIR; fi
fi
ASSET=askdo-linux-$ARCH
HELPER=askdo-launch-linux-$ARCH
if [ -z "$SOURCE_DIR" ]; then
  fetch "https://codeload.github.com/$REPO/tar.gz/$RAW_REF" "$TMP/src.tar.gz" || die 'source download failed'
  mkdir "$TMP/src"
  tar -xzf "$TMP/src.tar.gz" -C "$TMP/src" --strip-components=1 || die 'source extraction failed'
  SRC=$TMP/src
else
  SRC=$SOURCE_DIR
fi
[ -f "$SRC/cmd/askdo/main.go" ] && [ -f "$SRC/cmd/askdo-launch/main.go" ] || die 'source does not contain both commands'
if ! command -v go >/dev/null 2>&1 && [ -x /usr/local/go/bin/go ]; then PATH=$PATH:/usr/local/go/bin; fi
command -v go >/dev/null 2>&1 || die 'Go toolchain required'
(cd "$SRC" && CGO_ENABLED=0 go build -buildvcs=false -trimpath -o "$TMP/$ASSET" ./cmd/askdo && CGO_ENABLED=0 go build -buildvcs=false -trimpath -o "$TMP/$HELPER" ./cmd/askdo-launch) || die 'source build failed'
for FILE in askdo-config.example.json contrib/askdo.service contrib/askdo.sudoers contrib/askdo-gateway.service examples/fleet/gateway-config.example.json examples/fleet/host-config.example.json; do
  repo_file "$FILE" "$TMP/$(basename "$FILE")" || die "missing $FILE"
done
command -v visudo >/dev/null 2>&1 || die 'visudo required to verify effective sudoers policy'
SUDOERS=/etc/sudoers.d/askdo
OLD_SUDOERS=/etc/sudoers.d/askdo-foreground
printf '%%askdo-foreground ALL=(root) NOPASSWD: /usr/local/libexec/askdo-launch ""\nDefaults!/usr/local/libexec/askdo-launch !use_pty\n' > "$TMP/legacy-policy"
[ -d /etc/sudoers.d ] && [ ! -L /etc/sudoers.d ] &&
  [ "$(stat -c %u:%g /etc/sudoers.d)" = 0:0 ] || die 'unsafe sudoers directory'
SUDOERS_MODE=$(stat -c %a /etc/sudoers.d)
[ $((0$SUDOERS_MODE & 0022)) -eq 0 ] || die 'writable sudoers directory'
for POLICY_PATH in "$SUDOERS" "$OLD_SUDOERS"; do
  [ ! -L "$POLICY_PATH" ] || die 'existing sudoers policy is a symlink'
  if [ -e "$POLICY_PATH" ]; then
    [ -f "$POLICY_PATH" ] && [ "$(stat -c %a:%u:%g "$POLICY_PATH")" = 440:0:0 ] || die 'unsafe sudoers policy metadata'
  fi
done
if [ -e "$SUDOERS" ] && ! cmp -s "$SUDOERS" "$TMP/askdo.sudoers"; then die 'existing sudoers policy differs; refusing to overwrite'; fi
if [ -e "$OLD_SUDOERS" ] && ! cmp -s "$OLD_SUDOERS" "$TMP/legacy-policy"; then die 'existing legacy policy differs; refusing to overwrite'; fi
if [ -e "$OLD_SUDOERS" ]; then
  for PATH_PART in /usr/local /usr/local/libexec; do
    [ -d "$PATH_PART" ] && [ ! -L "$PATH_PART" ] && [ "$(stat -c %u:%g "$PATH_PART")" = 0:0 ] || die 'unsafe existing helper parent'
    MODE=$(stat -c %a "$PATH_PART")
    [ $((0$MODE & 0022)) -eq 0 ] || die 'writable existing helper parent'
  done
  [ -f /usr/local/libexec/askdo-launch ] && [ ! -L /usr/local/libexec/askdo-launch ] &&
    [ "$(stat -c %a:%u:%g /usr/local/libexec/askdo-launch)" = 755:0:0 ] || die 'unsafe existing helper during upgrade'
fi
install -m 0440 -o root -g root "$TMP/askdo.sudoers" "$TMP/staged-policy"
visudo -cf "$TMP/staged-policy" >/dev/null 2>&1 || die 'staged sudoers validation failed'
# The pre-existing effective policy must already be valid, too.
visudo -c >/dev/null 2>&1 || die 'existing effective sudoers validation failed'

# Preserve the running installation before any binary changes. Never back up
# a symlink, non-root binary or unexpectedly writable executable.
for NAME in askdo askdo-launch; do
  case "$NAME" in askdo) DEST=/usr/local/bin/askdo ;; *) DEST=/usr/local/libexec/askdo-launch ;; esac
  [ ! -L "$DEST" ] || die "existing $NAME binary is a symlink"
  if [ -e "$DEST" ]; then
    [ -f "$DEST" ] && [ "$(stat -c %a:%u:%g "$DEST")" = 755:0:0 ] || die "unsafe existing $NAME binary"
    install -m 0600 -o root -g root "$DEST" "$TMP/original-$NAME" || die "could not back up $NAME"
    cmp -s "$DEST" "$TMP/original-$NAME" || die "$NAME changed while backing up"
  fi
done
# A service failure must never replace the old unit before the policy commit.
if [ -e /etc/systemd/system/askdo.service ] || [ -L /etc/systemd/system/askdo.service ]; then
  [ ! -L /etc/systemd/system/askdo.service ] && [ -f /etc/systemd/system/askdo.service ] &&
    [ "$(stat -c %a:%u:%g /etc/systemd/system/askdo.service)" = 644:0:0 ] || die 'unsafe existing service unit'
  install -m 0600 -o root -g root /etc/systemd/system/askdo.service "$TMP/original-service" || die 'could not back up service unit'
  cmp -s /etc/systemd/system/askdo.service "$TMP/original-service" || die 'service unit changed during backup'
fi

NEW_SUDOERS=
MIGRATING=
INSTALL_DONE=
ROLLBACK_BINARIES=1
SERVICE_UPDATED=
GATEWAY_UNIT_NEW=
EXAMPLES_NEW=
if [ -e "$OLD_SUDOERS" ]; then
  MIGRATING=1
  install -m 0600 -o root -g root "$OLD_SUDOERS" "$TMP/rollback-policy" || die 'could not protect legacy policy'
  cmp -s "$OLD_SUDOERS" "$TMP/rollback-policy" || die 'legacy policy changed during backup'
fi
rollback_policy() {
  if [ "$MIGRATING" = 1 ]; then
    if [ ! -e "$OLD_SUDOERS" ] && [ ! -L "$OLD_SUDOERS" ]; then
      [ -f "$TMP/rollback-policy" ] && cmp -s "$TMP/rollback-policy" "$TMP/legacy-policy" &&
        install -m 0440 -o root -g root "$TMP/rollback-policy" "$OLD_SUDOERS" || return 1
    fi
    [ -f "$OLD_SUDOERS" ] && [ ! -L "$OLD_SUDOERS" ] &&
      [ "$(stat -c %a:%u:%g "$OLD_SUDOERS")" = 440:0:0 ] &&
      cmp -s "$OLD_SUDOERS" "$TMP/legacy-policy" || return 1
  fi
  if [ "$NEW_SUDOERS" = 1 ]; then
    if [ -e "$SUDOERS" ] || [ -L "$SUDOERS" ]; then
      [ -f "$SUDOERS" ] && [ ! -L "$SUDOERS" ] &&
        cmp -s "$SUDOERS" "$TMP/staged-policy" && rm -f "$SUDOERS" || return 1
    fi
  fi
}
rollback_binaries() {
  [ "$ROLLBACK_BINARIES" = 1 ] || return 0
  for NAME in askdo askdo-launch; do
    case "$NAME" in askdo) DEST=/usr/local/bin/askdo ;; *) DEST=/usr/local/libexec/askdo-launch ;; esac
    [ ! -L "$DEST" ] || return 1
    if [ -f "$TMP/original-$NAME" ]; then
      install -m 0755 -o root -g root "$TMP/original-$NAME" "$DEST" &&
        cmp -s "$TMP/original-$NAME" "$DEST" &&
        [ "$(stat -c %a:%u:%g "$DEST")" = 755:0:0 ] || return 1
    elif [ -e "$DEST" ]; then
      [ -f "$DEST" ] && rm -f "$DEST" || return 1
    fi
  done
}
rollback_service() {
  [ "$SERVICE_UPDATED" = 1 ] || return 0
  [ ! -L /etc/systemd/system/askdo.service ] || return 1
  if [ -f "$TMP/original-service" ]; then
    install -m 0644 -o root -g root "$TMP/original-service" /etc/systemd/system/askdo.service &&
      cmp -s "$TMP/original-service" /etc/systemd/system/askdo.service &&
      [ "$(stat -c %a:%u:%g /etc/systemd/system/askdo.service)" = 644:0:0 ] || return 1
  elif [ -e /etc/systemd/system/askdo.service ]; then
    [ -f /etc/systemd/system/askdo.service ] && rm -f /etc/systemd/system/askdo.service || return 1
  fi
}
# Only assets this run installed are rolled back, and only while they still
# byte-match the staged copies; operator edits survive a failed install.
rollback_gateway_unit() {
  [ "$GATEWAY_UNIT_NEW" = 1 ] || return 0
  GW=/etc/systemd/system/askdo-gateway.service
  [ ! -L "$GW" ] || return 1
  if [ -e "$GW" ]; then
    [ -f "$GW" ] && cmp -s "$GW" "$TMP/askdo-gateway.service" && rm -f "$GW" || return 1
  fi
}
rollback_examples() {
  for NAME in $EXAMPLES_NEW; do
    F=/etc/askdo/examples/$NAME
    [ ! -L "$F" ] || return 1
    if [ -e "$F" ]; then
      [ -f "$F" ] && cmp -s "$F" "$TMP/$NAME" && rm -f "$F" || return 1
    fi
  done
  rmdir /etc/askdo/examples 2>/dev/null || :
}
finish_install() {
  RESULT=$?
  trap - EXIT
  if [ "$INSTALL_DONE" != 1 ]; then
    POLICY_OK=1
    rollback_policy || POLICY_OK=0
    BINARIES_OK=1
    rollback_binaries || BINARIES_OK=0
    SERVICE_OK=1
    rollback_service || SERVICE_OK=0
    GATEWAY_OK=1
    rollback_gateway_unit || GATEWAY_OK=0
    EXAMPLES_OK=1
    rollback_examples || EXAMPLES_OK=0
    if [ "$POLICY_OK" != 1 ] || [ "$BINARIES_OK" != 1 ] || [ "$SERVICE_OK" != 1 ] || [ "$GATEWAY_OK" != 1 ] || [ "$EXAMPLES_OK" != 1 ]; then
      printf 'install.sh: ERROR: rollback incomplete; protected originals retained in %s; inspect policy and binaries manually\n' "$TMP" >&2
      exit 1
    fi
  fi
  rm -rf "$TMP"
  exit "$RESULT"
}
trap 'finish_install' EXIT

getent group askdo >/dev/null || groupadd --system askdo
getent group askdo-review >/dev/null || groupadd --system askdo-review
if id askdo-review >/dev/null 2>&1; then
  [ "$(id -gn askdo-review)" = askdo-review ] || die 'existing reviewer has wrong primary group'
else
  useradd --system --gid askdo-review --shell /usr/sbin/nologin --home-dir /var/lib/askdo-review askdo-review
fi
[ ! -L /usr/local ] && [ ! -L /usr/local/libexec ] && [ ! -L /usr/local/libexec/askdo-launch ] || die 'helper path contains a symlink'
install -d -m 0755 -o root -g root /usr/local/bin /usr/local/libexec
install -m 0755 -o root -g root "$TMP/$ASSET" /usr/local/bin/askdo
install -m 0755 -o root -g root "$TMP/$HELPER" /usr/local/libexec/askdo-launch
install -d -m 0755 -o root -g root /etc/askdo
if [ ! -e /etc/askdo/config.json ]; then install -m 0600 -o root -g root "$TMP/askdo-config.example.json" /etc/askdo/config.json; fi
install -d -m 0750 -o root -g askdo-review /etc/askdo/credentials
install -d -m 0700 -o root -g root /var/lib/askdo
install -d -m 0700 -o askdo-review -g askdo-review /var/lib/askdo-review
install -d -m 0750 -o root -g askdo /run/askdo
# Last privilege-enabling step: all paths and identities are now installed.
for PATH_PART in /usr/local /usr/local/libexec; do
  [ -d "$PATH_PART" ] && [ ! -L "$PATH_PART" ] && [ "$(stat -c %u:%g "$PATH_PART")" = 0:0 ] || die 'unsafe helper parent'
  MODE=$(stat -c %a "$PATH_PART")
  [ $((0$MODE & 0022)) -eq 0 ] || die 'writable helper parent'
done
[ -f /usr/local/libexec/askdo-launch ] && [ ! -L /usr/local/libexec/askdo-launch ] &&
  [ "$(stat -c %a:%u:%g /usr/local/libexec/askdo-launch)" = 755:0:0 ] || die 'unsafe helper binary'
if [ ! -e "$SUDOERS" ] && [ ! -L "$SUDOERS" ]; then
  NEW_SUDOERS=1
  install -m 0440 -o root -g root "$TMP/staged-policy" "$SUDOERS" || die 'sudoers install failed'
fi
if ! visudo -c >/dev/null 2>&1; then
  die 'effective sudoers validation failed'
fi
if [ -e "$OLD_SUDOERS" ]; then
  cmp -s "$OLD_SUDOERS" "$TMP/legacy-policy" || die 'legacy policy changed during upgrade; inspect both grants'
  rm "$OLD_SUDOERS" || die 'could not remove legacy policy; inspect both grants'
  if ! visudo -c >/dev/null 2>&1; then
    die 'effective sudoers validation failed after legacy removal'
  fi
fi
SERVICE_UPDATED=1
install -m 0644 -o root -g root "$TMP/askdo.service" /etc/systemd/system/askdo.service || die 'service unit installation failed'
# Optional fleet gateway unit: installed inert like askdo.service (never
# enabled or started), but never overwrites a differing operator unit.
GWUNIT=/etc/systemd/system/askdo-gateway.service
if [ -e "$GWUNIT" ] || [ -L "$GWUNIT" ]; then
  [ ! -L "$GWUNIT" ] && [ -f "$GWUNIT" ] &&
    [ "$(stat -c %a:%u:%g "$GWUNIT")" = 644:0:0 ] || die 'unsafe existing gateway unit'
  cmp -s "$GWUNIT" "$TMP/askdo-gateway.service" || die 'existing askdo-gateway.service differs; refusing to overwrite'
else
  install -m 0644 -o root -g root "$TMP/askdo-gateway.service" "$GWUNIT" || die 'gateway unit installation failed'
  GATEWAY_UNIT_NEW=1
fi
# Read-only fleet configuration examples; a differing operator copy is kept.
install -d -m 0755 -o root -g root /etc/askdo/examples
for NAME in gateway-config.example.json host-config.example.json; do
  F=/etc/askdo/examples/$NAME
  if [ -e "$F" ] || [ -L "$F" ]; then
    if [ -f "$F" ] && [ ! -L "$F" ] && cmp -s "$F" "$TMP/$NAME"; then continue; fi
    printf 'install.sh: WARNING: preserving existing %s (differs from shipped example)\n' "$F" >&2
    continue
  fi
  install -m 0444 -o root -g root "$TMP/$NAME" "$F" || die "example install failed: $NAME"
  EXAMPLES_NEW="$EXAMPLES_NEW $NAME"
done
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload >/dev/null 2>&1 || :; fi
INSTALL_DONE=1
if [ "$MIGRATING" = 1 ]; then
  # A populated or unenumerable NSS group is never deleted. It has no grant.
  if getent group askdo-foreground > "$TMP/old-group"; then
    OLD_GID=$(cut -d: -f3 "$TMP/old-group")
    if [ -z "$(cut -d: -f4 "$TMP/old-group")" ] &&
       getent passwd > "$TMP/passwd" &&
       ! cut -d: -f4 "$TMP/passwd" | grep -qx "$OLD_GID"; then
      groupdel askdo-foreground || printf 'WARNING: could not remove unused askdo-foreground group\n' >&2
    else
      printf 'WARNING: askdo-foreground group retained (members or NSS uncertainty); its sudo grant was removed\n' >&2
    fi
  else
    printf 'WARNING: could not enumerate askdo-foreground group; no group deletion attempted\n' >&2
  fi
fi
printf 'askdo installed; service was NOT enabled or started. Configure /etc/askdo/config.json, then explicitly enable askdo.service. Optional fleet gateway: read-only examples in /etc/askdo/examples; askdo-gateway.service installed but NOT enabled or started; no gateway keys or credentials were created.\n'

# askdo install.sh end-of-file
