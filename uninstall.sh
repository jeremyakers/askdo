#!/bin/sh
# Remove askdo only; leave all unrelated services and state untouched.
set -eu
die() { printf 'uninstall.sh: error: %s\n' "$*" >&2; exit 1; }
PURGE=0
YES=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) printf 'usage: sh uninstall.sh [--purge --yes]\n'; exit 0 ;;
    --purge) PURGE=1 ;;
    --yes) YES=1 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done
[ "$(id -u)" = 0 ] || die 'run as root'
if [ "$PURGE" = 1 ] && [ "$YES" != 1 ]; then die 'purge requires --yes'; fi

# Stop first. Never remove the sudo handoff or its policy while the daemon is
# still active (nor after a failed stop of an active service).
if command -v systemctl >/dev/null 2>&1; then
  ACTIVE=0
  if systemctl is-active --quiet askdo.service; then ACTIVE=1; fi
  if ! systemctl disable --now askdo.service >/dev/null 2>&1 && [ "$ACTIVE" = 1 ]; then
    die 'could not stop active askdo.service; nothing removed'
  fi
  if systemctl is-active --quiet askdo.service; then
    die 'askdo.service remains active; nothing removed'
  fi
fi

# Remove only byte-for-byte recognized, root-owned regular policy fragments.
for ENTRY in askdo askdo-foreground; do
  FILE=/etc/sudoers.d/$ENTRY
  [ ! -e "$FILE" ] && [ ! -L "$FILE" ] && continue
  case "$ENTRY" in askdo) GROUP=askdo ;; *) GROUP=askdo-foreground ;; esac
  if [ -f "$FILE" ] && [ ! -L "$FILE" ] &&
     [ "$(stat -c %a:%u:%g "$FILE")" = 440:0:0 ] &&
     printf '%%%s ALL=(root) NOPASSWD: /usr/local/libexec/askdo-launch ""\nDefaults!/usr/local/libexec/askdo-launch !use_pty\n' "$GROUP" | cmp -s - "$FILE"; then
    rm -f "$FILE"
  else
    printf 'WARNING: preserving unrecognized %s and helper; inspect manually\n' "$FILE" >&2
    KEEP_HELPER=1
  fi
done
rm -f /etc/systemd/system/askdo.service /usr/local/bin/askdo
if [ "${KEEP_HELPER:-0}" != 1 ]; then rm -f /usr/local/libexec/askdo-launch; fi
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload >/dev/null 2>&1 || :; fi
rm -rf /run/askdo
if [ "$PURGE" = 1 ]; then
  rm -rf /etc/askdo /var/lib/askdo /var/lib/askdo-review
  if id askdo-review >/dev/null 2>&1; then userdel askdo-review || die 'reviewer account still in use'; fi
  PASSWD_SNAPSHOT=$(mktemp) || die 'could not stage NSS enumeration'
  # groupdel refuses a primary group in use; also retain supplementary groups
  # with any member (including the optional human foreground group).
  for GROUP in askdo-review askdo askdo-foreground; do
    if getent group "$GROUP" >/dev/null 2>&1; then
      MEMBERS=$(getent group "$GROUP" | cut -d: -f4)
       if getent passwd > "$PASSWD_SNAPSHOT" && [ -z "$MEMBERS" ] &&
          ! cut -d: -f4 "$PASSWD_SNAPSHOT" | grep -qx "$(getent group "$GROUP" | cut -d: -f3)" &&
          { [ "$GROUP" != askdo-foreground ] || { [ ! -e /etc/sudoers.d/askdo-foreground ] && [ ! -L /etc/sudoers.d/askdo-foreground ]; }; }; then
         groupdel "$GROUP" || die "could not remove unused group $GROUP"
       else
         printf 'WARNING: retaining group %s (members, policy or NSS uncertainty)\n' "$GROUP" >&2
       fi
    fi
  done
  rm -f "$PASSWD_SNAPSHOT"
fi
printf 'askdo removed%s; unrelated services and state untouched.\n' "$( [ "$PURGE" = 1 ] && printf ' and purged' || : )"
