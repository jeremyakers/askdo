#!/bin/sh
# Remove askdo only; leave all unrelated services and state untouched.
set -eu
die() { printf 'uninstall.sh: error: %s\n' "$*" >&2; exit 1; }
PURGE=0
YES=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) printf 'usage: sh uninstall.sh [--purge --yes]\nDefault keeps all configuration, credentials and databases. --purge also removes /etc/askdo, /var/lib/askdo, /var/lib/askdo-review and the default fleet gateway state (/etc/askdo-gateway and /var/lib/askdo-gateway); a custom gateway database path is never deleted. On DSM, native identities and /var/lib/askdo-review are retained because creation ownership cannot be proved across runs.\n'; exit 0 ;;
    --purge) PURGE=1 ;;
    --yes) YES=1 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done
[ "$(id -u)" = 0 ] || die 'run as root'
if [ "$PURGE" = 1 ] && [ "$YES" != 1 ]; then die 'purge requires --yes'; fi
DSM_NATIVE=0
# Even incomplete DSM evidence forbids generic name-only identity deletion.
# This is retention, not proof of identity ownership or trusted native tools.
if [ -e /etc.defaults/VERSION ] || [ -L /etc.defaults/VERSION ] ||
   [ -e /usr/syno/sbin/synouser ] || [ -L /usr/syno/sbin/synouser ] ||
   [ -e /usr/syno/sbin/synogroup ] || [ -L /usr/syno/sbin/synogroup ]; then
  DSM_NATIVE=1
fi

# Recognize the optional fleet gateway unit BEFORE any service control: only
# a byte-for-byte shipped, root-owned, non-symlink unit may be stopped,
# disabled or removed. An edited or foreign unit still points its ExecStart at
# the shared /usr/local/bin/askdo binary, so removing anything would strand a
# unit the owner chose to keep; refuse before any service control or removal.
GWUNIT=/etc/systemd/system/askdo-gateway.service
GW_UNIT_CONTENT='[Unit]
Description=askdo fleet gateway (optional central model and Telegram approval authority)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/askdo gateway serve --config /etc/askdo-gateway/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target'
GW_RECOGNIZED=0
if [ -e "$GWUNIT" ] || [ -L "$GWUNIT" ]; then
  if [ -f "$GWUNIT" ] && [ ! -L "$GWUNIT" ] &&
     [ "$(stat -c %a:%u:%g "$GWUNIT")" = 644:0:0 ] &&
     printf '%s\n' "$GW_UNIT_CONTENT" | cmp -s - "$GWUNIT"; then
    GW_RECOGNIZED=1
  else
    die "unsafe or custom $GWUNIT prevents uninstall; remove the unit or restore the shipped one, then rerun (its ExecStart uses the shared askdo binary)"
  fi
fi

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
  if [ "$GW_RECOGNIZED" = 1 ]; then
    GW_ACTIVE=0
    if systemctl is-active --quiet askdo-gateway.service; then GW_ACTIVE=1; fi
    if ! systemctl disable --now askdo-gateway.service >/dev/null 2>&1 && [ "$GW_ACTIVE" = 1 ]; then
      die 'could not stop active askdo-gateway.service; nothing removed'
    fi
    if systemctl is-active --quiet askdo-gateway.service; then
      die 'askdo-gateway.service remains active; nothing removed'
    fi
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
# Removal follows the same recognition computed above; an unrecognized unit
# already aborted the uninstall before any service control or removal.
if [ "$GW_RECOGNIZED" = 1 ]; then rm -f "$GWUNIT"; fi
if [ "${KEEP_HELPER:-0}" != 1 ]; then rm -f /usr/local/libexec/askdo-launch; fi
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload >/dev/null 2>&1 || :; fi
rm -rf /run/askdo
if [ "$PURGE" = 1 ]; then
  rm -rf /etc/askdo /var/lib/askdo
  if [ "$DSM_NATIVE" = 0 ]; then rm -rf /var/lib/askdo-review; fi
  # Default fleet gateway state holds operator-provisioned signing keys, the
  # enrollment database and server credentials. Remove the two default
  # directories only on explicit purge, and only when each is a root-owned,
  # non-symlink directory; a custom gateway database path is never deleted.
  for GSTATE in /etc/askdo-gateway /var/lib/askdo-gateway; do
    if [ -e "$GSTATE" ] || [ -L "$GSTATE" ]; then
      [ -d "$GSTATE" ] && [ ! -L "$GSTATE" ] &&
        [ "$(stat -c %u "$GSTATE")" = 0 ] || die "unsafe $GSTATE; not purged"
      rm -rf "$GSTATE"
    fi
  done
  if [ "$DSM_NATIVE" = 1 ]; then
    printf 'WARNING: retaining DSM identities and /var/lib/askdo-review; no durable native creation provenance exists; no generic userdel/groupdel attempted\n' >&2
  else
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
fi
if [ "$PURGE" != 1 ]; then
  for GSTATE in /etc/askdo-gateway /var/lib/askdo-gateway; do
    if [ -e "$GSTATE" ]; then
      printf 'Note: kept %s (fleet gateway configuration, credentials or database); rerun with --purge --yes to remove it.\n' "$GSTATE"
    fi
  done
fi
printf 'askdo removed%s; unrelated services and state untouched.\n' "$( [ "$PURGE" = 1 ] && printf ' and purged' || : )"
