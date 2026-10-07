#!/bin/sh
# Install verified release assets; upgrade only precisely recognized policy.
set -eu
REPO=jeremyakers/askdo
VERSION=${ASKDO_VERSION:-latest}
die() { printf 'install.sh: error: %s\n' "$*" >&2; exit 1; }
case "${1:-}" in
  --help|-h) printf 'usage: sh install.sh [--version TAG]\nDownloads verified release assets; no destination compiler. Non-root local or piped use re-executes with sudo; root installs never start the service.\n'; exit 0 ;;
esac
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) [ "$#" -ge 2 ] || die 'missing release tag'; VERSION=$2; shift 2 ;;
    --version=*) VERSION=${1#--version=}; shift ;;
    *) die "unknown option: $1" ;;
  esac
done
[ -z "${ASKDO_SOURCE_DIR:-}" ] || die 'ASKDO_SOURCE_DIR is obsolete; normal installs download releases and never compile source'
case "$VERSION" in ''|*[!A-Za-z0-9._-]*|.*|-*) die 'invalid release tag' ;; main|master) die 'select a published release tag, not a branch' ;; esac
if [ "$(id -u)" != 0 ]; then
  command -v sudo >/dev/null 2>&1 || die 'run as root or install sudo'
  if [ -f "$0" ] && [ -r "$0" ]; then
    exec sudo env ASKDO_VERSION="$VERSION" sh "$0" "$@"
  fi
  # stdin is already buffered by sh: never execute a partial copy of stdin.
  case "$VERSION" in latest) SELF_URL=https://github.com/$REPO/releases/latest/download/install.sh ;;
    *) SELF_URL=https://github.com/$REPO/releases/download/$VERSION/install.sh ;; esac
  SELF=$(mktemp "${TMPDIR:-/tmp}/askdo-self.XXXXXX") || die 'could not stage installer'
  if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --proto-redir '=https' -fsSL "$SELF_URL" -o "$SELF" || { rm -f "$SELF"; die 'could not re-fetch installer'; }
  elif command -v wget >/dev/null 2>&1; then
    wget --https-only -qO "$SELF" "$SELF_URL" || { rm -f "$SELF"; die 'could not re-fetch installer'; }
  else
    rm -f "$SELF"
    die 'curl or wget required for piped sudo re-exec'
  fi
  if ! awk 'END {if (NR == 0 || $0 != "# askdo install.sh end-of-file") exit 1}' "$SELF"; then
    rm -f "$SELF"
    die 're-fetched installer is truncated'
  fi
  if sudo env ASKDO_VERSION="$VERSION" sh "$SELF" "$@"; then
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

# DSM uses native roles and ACLs, not Linux useradd/getent semantics. A fixed
# marker or native-tool footprint must never silently fall through to Linux.
DSM=0
VISUDO_TOOL=visudo
if [ -e /etc.defaults/VERSION ] || [ -L /etc.defaults/VERSION ] ||
   [ -e /usr/syno/sbin/synouser ] || [ -L /usr/syno/sbin/synouser ] ||
   [ -e /usr/syno/sbin/synogroup ] || [ -L /usr/syno/sbin/synogroup ]; then
  for P in /etc.defaults /etc.defaults/VERSION; do
    [ ! -L "$P" ] && [ "$(stat -c %u:%g "$P" 2>/dev/null)" = 0:0 ] || die 'untrusted DSM version marker'
    MODE=$(stat -c %a "$P")
    [ $((0$MODE & 0022)) -eq 0 ] || die 'untrusted DSM version marker'
  done
  [ -d /etc.defaults ] && [ -f /etc.defaults/VERSION ] || die 'untrusted DSM version marker'
  # Never source vendor metadata as shell code. Require one recognized major
  # and one numeric build field; duplicate/malformed fields are not evidence.
  awk '
    /^majorversion=/ { major++; if ($0 !~ /^majorversion="[67]"$/) bad=1 }
    /^buildnumber=/ { build++; if ($0 !~ /^buildnumber="[0-9]+"$/) bad=1 }
    END { if (bad || major != 1 || build != 1) exit 1 }
  ' /etc.defaults/VERSION || die 'unrecognized DSM version metadata'
  for P in /usr /usr/syno /usr/syno/sbin /usr/syno/sbin/synouser /usr/syno/sbin/synogroup; do
    [ ! -L "$P" ] && [ "$(stat -c %u:%g "$P" 2>/dev/null)" = 0:0 ] || die 'untrusted DSM native tool'
    MODE=$(stat -c %a "$P")
    [ $((0$MODE & 0022)) -eq 0 ] || die 'untrusted DSM native tool'
  done
  [ -f /usr/syno/sbin/synouser ] && [ -x /usr/syno/sbin/synouser ] &&
    [ -f /usr/syno/sbin/synogroup ] && [ -x /usr/syno/sbin/synogroup ] || die 'untrusted DSM native tool'
  DSM=1
  [ -x /usr/bin/python3 ] || die 'existing vendor /usr/bin/python3 required for DSM ACL metadata'
  PYTHON=$(readlink -f /usr/bin/python3) || die 'could not resolve vendor Python'
  # Only the stock vendor location is a bootstrap trust anchor. Restricting the
  # cached canonical target also makes the checked / /usr /usr/bin chain complete.
  case "$PYTHON" in
    /usr/bin/python3) ;;
    /usr/bin/python3.*)
      case "${PYTHON#/usr/bin/python3.}" in ''|*[!0-9]*) die 'unsupported vendor Python canonical target' ;; esac ;;
    *) die 'unsupported vendor Python canonical target' ;;
  esac
  [ -f "$PYTHON" ] && [ -x "$PYTHON" ] &&
    [ "$(stat -c %u:%g /usr/bin/python3)" = 0:0 ] || die 'untrusted vendor Python executable or alias'
  for P in / /usr /usr/bin "$PYTHON" /usr/syno/bin /usr/syno/bin/synoacltool; do
    [ ! -L "$P" ] && [ "$(stat -c %u:%g "$P")" = 0:0 ] || die 'untrusted DSM metadata tool'
    MODE=$(stat -c %a "$P")
    [ $((0$MODE & 0022)) -eq 0 ] || die 'writable DSM metadata tool'
  done
  [ -f /usr/syno/bin/synoacltool ] && [ -x /usr/syno/bin/synoacltool ] || die 'synoacltool required'
fi

# Only internal fixed installation/tool paths and this run's private staging are
# passed here. Stock vendor Python is the bootstrap tool, never staged code.
# Native Linux-mode evidence alone does not rule out POSIX extended ACL grants.
dsm_acl() {
  [ "$DSM" = 1 ] || return 0
  "$PYTHON" -I -S - "$1" "${2:-0}" "${3:-0}" <<'PY'
import errno, os, stat, subprocess, sys
try:
    path, uid = sys.argv[1], int(sys.argv[2])
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not (stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode)):
        raise ValueError()
    sticky_tmp = path == '/tmp' and stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o1777
    if before.st_uid != uid or (before.st_mode & 0o022 and not sticky_tmp):
        raise ValueError()
    for name in ('system.posix_acl_access', 'system.posix_acl_default'):
        try:
            os.getxattr(path, name, follow_symlinks=False)
        except OSError as error:
            if error.errno not in (errno.ENODATA, errno.ENOTSUP):
                raise
        else:
            raise ValueError()  # Even an empty returned attribute is not absence.
    if sys.argv[3] == '1':
        if before.st_mode & 0o6000:
            raise ValueError()
        try:
            os.getxattr(path, 'security.capability', follow_symlinks=False)
        except OSError as error:
            if error.errno not in (errno.ENODATA, errno.ENOTSUP):
                raise
        else:
            raise ValueError()  # Never expose capability bytes or accept empty data.
    result = subprocess.run(['/usr/syno/bin/synoacltool', '-get', path],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
    if result.returncode != 255 or result.stdout != b"(synoacltool.c, 596)It's Linux mode\n":
        raise ValueError()
    after = os.lstat(path)
    if (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_ctime_ns):
        raise ValueError()
except Exception:
    sys.exit(1)  # No ACL contents or vendor diagnostic is exposed.
PY
}
dsm_paths() {
  [ "$DSM" = 1 ] || return 0
  for P in / /usr /usr/bin "$PYTHON" /usr/syno /usr/syno/bin /usr/syno/sbin \
      /usr/syno/bin/synoacltool /usr/syno/sbin/synouser /usr/syno/sbin/synogroup \
      /usr/bin/id /etc /etc.defaults /etc.defaults/VERSION /etc/passwd /etc/group /etc/sudoers /etc/sudoers.d \
      /usr/local /usr/local/bin /usr/local/libexec /usr/local/bin/askdo /usr/local/libexec/askdo-launch \
      /var /var/lib /run /etc/systemd /etc/systemd/system \
      /etc/systemd/system/askdo.service /etc/systemd/system/askdo-gateway.service \
      /etc/sudoers.d/askdo /etc/sudoers.d/askdo-foreground /etc/askdo /etc/askdo/config.json \
      /etc/askdo/credentials /etc/askdo/examples /etc/askdo/examples/gateway-config.example.json \
      /etc/askdo/examples/host-config.example.json /var/lib/askdo /run/askdo; do
    if [ -e "$P" ] || [ -L "$P" ]; then
      EXECUTABLE=0
      case "$P" in "$PYTHON"|/usr/bin/id|/usr/syno/bin/synoacltool|/usr/syno/sbin/synouser|/usr/syno/sbin/synogroup|/usr/local/bin/askdo|/usr/local/libexec/askdo-launch) EXECUTABLE=1 ;; esac
      dsm_acl "$P" 0 "$EXECUTABLE" || return 1
    fi
  done
  if [ -n "${REVIEW_UID:-}" ] && { [ -e /var/lib/askdo-review ] || [ -L /var/lib/askdo-review ]; }; then
    dsm_acl /var/lib/askdo-review "$REVIEW_UID" || return 1
  fi
}
# Early trust/prerequisite failure never builds or changes installed state.
if [ "$DSM" = 1 ]; then
  dsm_paths || die 'DSM protected-path ACL or metadata check failed'
  if command -v visudo >/dev/null 2>&1; then
    P=$(readlink -f "$(command -v visudo)") || die 'could not resolve DSM prerequisite'
    case "$P" in /*) ;; *) die 'absolute DSM prerequisite required' ;; esac
    [ -f "$P" ] && [ -x "$P" ] || die 'DSM prerequisite is not an executable file'
    dsm_acl "$P" 0 1 || die 'DSM prerequisite privilege metadata check failed'
    VISUDO_TOOL=$P
    while [ "$P" != / ]; do
      dsm_acl "$P" || die 'DSM prerequisite ACL or metadata check failed'
      P=$(dirname "$P")
    done
  else VISUDO_TOOL=; fi
fi

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
if [ "$DSM" = 0 ] && [ -e /etc/askdo/credentials ]; then
  [ -d /etc/askdo/credentials ] &&
    [ "$(stat -c %a:%u /etc/askdo/credentials)" = 750:0 ] &&
    getent group askdo-review >/dev/null 2>&1 &&
    [ "$(stat -c %g /etc/askdo/credentials)" = "$(getent group askdo-review | cut -d: -f3)" ] ||
    die 'existing credentials directory must be root:askdo-review 0750'
fi

if [ "$DSM" = 1 ]; then umask 077; fi
if [ "$DSM" = 1 ]; then
  P=${TMPDIR:-/tmp}
  case "$P" in /*) ;; *) die 'absolute DSM staging parent required' ;; esac
  while [ "$P" != / ]; do
    dsm_acl "$P" || die 'DSM staging parent ACL check failed'
    P=$(dirname "$P")
  done
fi
TMP=$(mktemp -d "${TMPDIR:-/tmp}/askdo-install.XXXXXX") || die 'staging failed'
trap 'rm -rf "$TMP"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$DSM" = 1 ]; then dsm_acl "$TMP" || die 'DSM staging ACL check failed'; fi
# Filter native --get streams before storage: never persist other user fields
# (in particular password data). Only selected metadata/error classes are parsed.
# Return 2 means positively proved native AND local NSS absence, not any failure.
dsm_read() {
  KIND=$1 ROLE=$2
  case "$KIND:$ROLE" in group:askdo|group:askdo-review) NATIVE=/usr/syno/sbin/synogroup ;;
    user:askdo-review) NATIVE=/usr/syno/sbin/synouser ;; *) return 1 ;; esac
  rm -f "$TMP/native-status"
  ( if "$NATIVE" --get "$ROLE"; then RC=0; else RC=$?; fi; printf '%s\n' "$RC" > "$TMP/native-status" ) 2>&1 |
    awk -v statusfile="$TMP/native-status" '
      { if (++n > 128 || length($0) > 1024) { bad=1; exit 1 } }
      /^[[:space:]]*(User Name|User uid|Primary gid|Expired|Group Name|Group ID)/ || /Lastest SynoErr|SYNOGroupGet failed|SYNOUserGet failed/ { print; next }
      { unknown=1 }
      END { if (bad) exit 1; if ((getline rc < statusfile) != 1) exit 1; if (rc != 0 && unknown) print "unrecognized native diagnostic" }
    ' > "$TMP/native-metadata" || return 1
  [ -f "$TMP/native-status" ] || return 1
  "$PYTHON" -I -S - "$KIND" "$ROLE" "$TMP/native-status" "$TMP/native-metadata" <<'PY'
import re, subprocess, sys
try:
    kind, name, statusfile, metadatafile = sys.argv[1:]
    status = int(open(statusfile).read().strip())
    data = open(metadatafile).read()
    if len(data) > 4096:
        raise ValueError()
    filename, width, idfield = ('/etc/group', 4, 2) if kind == 'group' else ('/etc/passwd', 7, 2)
    rows = [line.rstrip('\n').split(':') for line in open(filename)]
    selected = [row for row in rows if row[0] == name]
    if status == 255:
        hint, code = ((r'Lastest SynoErr=\[group_db_get\.c:[0-9]+\]', r'SYNOGroupGet failed, synoerr=0x1800') if kind == 'group' else
                      (r'Lastest SynoErr=\[user_db_get\.c:[0-9]+\]', r'synouser\.c:[0-9]+ SYNOUserGet failed\. synoerr=\[0x1D00\]'))
        # Native DSM emits the two known lines in either order; require exactly one of each.
        pattern = '(?:' + hint + '\n' + code + '|' + code + '\n' + hint + ')\n'
        if selected or re.fullmatch(pattern, data) is None:
            raise ValueError()
        sys.exit(2)
    if status != 0 or len(selected) != 1 or len(selected[0]) != width:
        raise ValueError()
    fields = {}
    for line in data.splitlines():
        match = re.fullmatch(r'\s*(User Name|User uid|Primary gid|Expired|Group Name|Group ID)\s*:\s*\[([^\[\]]*)\]\s*', line)
        if match is None or match[1] in fields:
            raise ValueError()
        fields[match[1]] = match[2]
    def positive(value):
        if not re.fullmatch(r'[1-9][0-9]*', value) or int(value) >= 4294967295:
            raise ValueError()
        return int(value)
    def namespace_ids(namespace, columns, column):
        values = []
        for entry in namespace:
            if len(entry) != columns or re.fullmatch(r'[0-9]+', entry[column]) is None:
                raise ValueError()
            value = int(entry[column], 10)
            if value >= 4294967295:
                raise ValueError()
            values.append(value)
        return values
    key = 'Group ID' if kind == 'group' else 'User uid'
    ident = positive(fields[key])
    row = selected[0]
    ids = namespace_ids(rows, width, idfield)
    if row[idfield] != str(ident) or ids.count(ident) != 1:
        raise ValueError()
    if kind == 'group':
        if set(fields) not in ({'Group ID'}, {'Group Name', 'Group ID'}) or fields.get('Group Name', name) != name:
            raise ValueError()
        members = row[3].split(',') if row[3] else []
        if len(set(members)) != len(members) or any(re.fullmatch(r'[a-zA-Z0-9_.-]+', m) is None for m in members):
            raise ValueError()
        if name == 'askdo-review' and any(m != 'askdo-review' for m in members):
            raise ValueError()
        print(str(ident) + ':' + ','.join(sorted(members)))
    else:
        if set(fields) != {'User Name', 'User uid', 'Primary gid', 'Expired'} or fields['User Name'] != name or fields['Expired'] != 'true':
            raise ValueError()
        if positive(fields['Primary gid']) != 100 or row[3] != '100':
            raise ValueError()
        if subprocess.check_output(['/usr/bin/id', '-u', name], timeout=10).decode().strip() != str(ident):
            raise ValueError()
        if subprocess.check_output(['/usr/bin/id', '-g', name], timeout=10).decode().strip() != '100':
            raise ValueError()
        group_rows = [line.rstrip('\n').split(':') for line in open('/etc/group')]
        group_ids = namespace_ids(group_rows, 4, 2)
        users = [r for r, gid in zip(group_rows, group_ids) if r[0] == 'users' or gid == 100]
        if len(users) != 1 or users[0][0] != 'users' or users[0][2] != '100':
            raise ValueError()
        dedicated = [r for r in group_rows if r[0] == 'askdo-review']
        allowed = {100}
        if dedicated:
            if len(dedicated) != 1 or len(dedicated[0]) != 4:
                raise ValueError()
            allowed.add(positive(dedicated[0][2]))
            if group_ids.count(int(dedicated[0][2], 10)) != 1:
                raise ValueError()
        groups = subprocess.check_output(['/usr/bin/id', '-G', name], timeout=10).decode().split()
        if not groups or any(positive(g) not in allowed for g in groups):
            raise ValueError()
        print(str(ident) + ':100')
except Exception:
    sys.exit(1)  # Never expose native account output or account-file contents.
PY
}
DSM_UNCERTAIN=0
DSM_NEW_ROLES=
DSM_NEW_DIRS=
dsm_create() {
  dsm_paths && dsm_acl "$TMP" || die 'DSM trust changed before native role operation'
  if dsm_read "$1" "$2" > /dev/null; then die 'role appeared before creation; refusing concurrent adoption'
  else [ "$?" = 2 ] || die 'role absence changed before creation'; fi
  # A failed native operation may have side effects. Never retry or adopt it.
  DSM_UNCERTAIN=1
  printf 'attempt %s %s\n' "$1" "$2" >> "$TMP/dsm-journal"
  case "$1" in
    group) /usr/syno/sbin/synogroup --add "$2" > /dev/null 2>&1 ;;
    user)
      # Public NONSECRET placeholder, not a locked hash or authentication proof.
      # expiry=1 on the FIRST call; never set/reset an existing account password.
      /usr/syno/sbin/synouser --add askdo-review 'askdo-disabled-service-NOT-A-SECRET' 'askdo disabled reviewer' 1 '' 0 > /dev/null 2>&1 ;;
  esac || die 'native role creation failed; possible side effects retained; inspect journal'
  SNAPSHOT=$(dsm_read "$1" "$2") || die 'native role postcondition failed; possible side effects retained; inspect journal'
  if [ "$1" = group ]; then
    [ -z "${SNAPSHOT#*:}" ] || die 'new native group unexpectedly populated; state retained'
  else
    # Snapshot fixed noncredential NSS metadata and supplementary groups; changes
    # in home/shell or even otherwise-allowed membership block rollback deletion.
    awk -F: '$1 == "askdo-review" {print $3 ":" $4 ":" $6 ":" $7}' /etc/passwd > "$TMP/dsm-reviewer-nss"
    /usr/bin/id -G askdo-review >> "$TMP/dsm-reviewer-nss"
  fi
  printf '%s\n' "$SNAPSHOT" > "$TMP/dsm-$2-$1"
  printf 'created %s %s %s\n' "$1" "$2" "$SNAPSHOT" >> "$TMP/dsm-journal"
  DSM_NEW_ROLES="$1:$2 $DSM_NEW_ROLES"
  DSM_UNCERTAIN=0
}
make_dir() {
  if [ "$DSM" = 0 ]; then install -d -m "$1" -o "$2" -g "$3" "$4"; return; fi
  DIR_MODE=$1 DIR_UID=$2 DIR_GID=$3 DIR_PATH=$4
  if [ -e "$DIR_PATH" ] || [ -L "$DIR_PATH" ]; then
    [ -d "$DIR_PATH" ] && [ ! -L "$DIR_PATH" ] &&
      [ "$(stat -c %a:%u:%g "$DIR_PATH")" = "$DIR_MODE:$DIR_UID:$DIR_GID" ] || die 'existing DSM installation directory differs; refusing repair'
  else
    printf 'directory attempt %s\n' "$DIR_PATH" >> "$TMP/dsm-journal"
    # Atomic mkdir, not install -d: never claim a concurrently appeared directory.
    mkdir "$DIR_PATH" || { DSM_UNCERTAIN=1; die 'DSM directory creation failed; ownership uncertain'; }
    DSM_NEW_DIRS="$DIR_PATH $DSM_NEW_DIRS"
    stat -c %d:%i:%u:%g:%a "$DIR_PATH" > "$TMP/dir-$(printf '%s' "$DIR_PATH" | tr / _)"
    dsm_acl "$DIR_PATH" || die 'new DSM directory ACL check failed'
    chown "$DIR_UID:$DIR_GID" "$DIR_PATH" && chmod "$DIR_MODE" "$DIR_PATH" || die 'DSM directory metadata failed'
    stat -c %d:%i:%u:%g:%a "$DIR_PATH" > "$TMP/dir-$(printf '%s' "$DIR_PATH" | tr / _)"
  fi
  dsm_acl "$DIR_PATH" "$DIR_UID" || die 'DSM directory ACL check failed'
}
dsm_rollback() {
  [ "$DSM" = 1 ] || return 0
  [ "$DSM_UNCERTAIN" = 0 ] || return 1
  dsm_paths && dsm_acl "$TMP" || return 1
  # New configuration is a role dependency, removed only if byte/metadata exact.
  if [ "${DSM_CONFIG_NEW:-0}" = 1 ]; then
    [ ! -L /etc/askdo/config.json ] || return 1
    # The copy may have failed before creating anything; no dependency to remove.
    if [ -e /etc/askdo/config.json ]; then
      [ -f /etc/askdo/config.json ] &&
        [ "$(stat -c %a:%u:%g /etc/askdo/config.json)" = 600:0:0 ] &&
        cmp -s /etc/askdo/config.json "$TMP/askdo-config.example.json" && rm /etc/askdo/config.json || return 1
    fi
  fi
  for DIR_PATH in $DSM_NEW_DIRS; do
    [ ! -L "$DIR_PATH" ] && [ -d "$DIR_PATH" ] &&
      [ "$(stat -c %d:%i:%u:%g:%a "$DIR_PATH")" = "$(cat "$TMP/dir-$(printf '%s' "$DIR_PATH" | tr / _)")" ] || return 1
    # Never erase unknown contents or a native-created home recursively.
    rmdir "$DIR_PATH" || return 1
  done
  # Validate ALL identities before deleting any. Changed IDs, disabled state or
  # membership invalidate the ownership proof and retain the complete journal.
  for ENTRY in $DSM_NEW_ROLES; do
    KIND=${ENTRY%%:*} ROLE=${ENTRY#*:}
    SNAPSHOT=$(dsm_read "$KIND" "$ROLE") &&
      [ "$SNAPSHOT" = "$(cat "$TMP/dsm-$ROLE-$KIND")" ] || return 1
    if [ "$KIND" = group ] && [ -n "${SNAPSHOT#*:}" ]; then return 1; fi
    if [ "$KIND" = group ]; then
      awk -F: -v gid="${SNAPSHOT%%:*}" '$4 == gid {used=1} END {exit used ? 1 : 0}' /etc/passwd || return 1
    else
      awk -F: '$1 == "askdo-review" {print $3 ":" $4 ":" $6 ":" $7}' /etc/passwd > "$TMP/current-reviewer-nss"
      /usr/bin/id -G askdo-review >> "$TMP/current-reviewer-nss" || return 1
      cmp -s "$TMP/dsm-reviewer-nss" "$TMP/current-reviewer-nss" || return 1
      # A vendor-created home elsewhere has no installer ownership proof. Native
      # deletion may have home side effects; retain rather than risk its contents.
      [ "$(awk -F: '$1 == "askdo-review" {print $6}' /etc/passwd)" = /var/lib/askdo-review ] || return 1
    fi
  done
  # A pre-existing or native-created reviewer home is not ours to purge. Any
  # remaining install directory potentially referencing new IDs blocks deletion.
  if [ -n "$DSM_NEW_ROLES" ]; then
    for DIR_PATH in /var/lib/askdo-review /etc/askdo/credentials /run/askdo; do
      [ ! -e "$DIR_PATH" ] && [ ! -L "$DIR_PATH" ] || return 1
    done
  fi
  for ENTRY in $DSM_NEW_ROLES; do
    KIND=${ENTRY%%:*} ROLE=${ENTRY#*:}
    case "$KIND" in user) NATIVE=/usr/syno/sbin/synouser ;; group) NATIVE=/usr/syno/sbin/synogroup ;; esac
    dsm_acl "$NATIVE" || return 1
    "$NATIVE" --del "$ROLE" >/dev/null 2>&1 || return 1
    if dsm_read "$KIND" "$ROLE" > /dev/null; then return 1; else [ "$?" = 2 ] || return 1; fi
    printf 'removed %s %s\n' "$KIND" "$ROLE" >> "$TMP/dsm-journal"
    if [ "$KIND" = user ]; then
      [ ! -e /var/lib/askdo-review ] && [ ! -L /var/lib/askdo-review ] || return 1
    fi
  done
}
dsm_identity_guard() {
  [ "$DSM" = 1 ] || return 0
  SNAPSHOT=$(dsm_read user askdo-review) && [ "$SNAPSHOT" = "$REVIEW_UID:100" ] || return 1
  SNAPSHOT=$(dsm_read group askdo) && [ "${SNAPSHOT%%:*}" = "$ASKDO_GID" ] || return 1
  SNAPSHOT=$(dsm_read group askdo-review) && [ "${SNAPSHOT%%:*}" = "$REVIEW_GID" ] || return 1
}
fetch() {
  case "$1" in https://github.com/jeremyakers/askdo/releases/*) ;; *) return 1 ;; esac
  if command -v curl >/dev/null 2>&1; then curl --proto '=https' --proto-redir '=https' --max-filesize "${3:-536870912}" -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then (ulimit -f $(((${3:-536870912} + 511) / 512 + 1)); wget --https-only -qO "$2" "$1")
  else return 1; fi
}
ASSET=askdo-linux-$ARCH
HELPER=askdo-launch-linux-$ARCH
COMMON='install.sh uninstall.sh askdo-config.example.json askdo.service askdo-gateway.service askdo.sudoers gateway-config.example.json host-config.example.json LICENSE'
INVENTORY="$COMMON askdo-linux-amd64 askdo-launch-linux-amd64 askdo-linux-arm64 askdo-launch-linux-arm64 askdo-linux-amd64.sha256 askdo-launch-linux-amd64.sha256 askdo-linux-arm64.sha256 askdo-launch-linux-arm64.sha256 visudo-linux-amd64 visudo-linux-arm64 visudo-LICENSE visudo-SOURCE"
case "$VERSION" in latest) MANIFEST_URL=https://github.com/$REPO/releases/latest/download/install-manifest.v1 ;;
  *) MANIFEST_URL=https://github.com/$REPO/releases/download/$VERSION/install-manifest.v1 ;; esac
fetch "$MANIFEST_URL" "$TMP/manifest" 16384 || die 'release manifest unavailable; no source or legacy-asset fallback'
[ "$(wc -c < "$TMP/manifest")" -le 16384 ] || die 'release manifest too large'
# Data only: never source/eval a release manifest. Closed full inventory prevents
# path traversal, optional security omissions and mixed-architecture bundles.
awk -v wanted="$VERSION" -v inventory="$INVENTORY" '
  BEGIN { n=split(inventory,a," "); for(i=1;i<=n;i++) required[a[i]]=1 }
  NR==1 { if($0!="askdo-install-v1") bad=1; next }
  { if(length($0)>512 || $0 !~ /^[!-~]+( [!-~]+)*$/) bad=1 }
  $1=="repository" { if(NF!=2 || $2!="jeremyakers/askdo" || repository++) bad=1; next }
  $1=="release" { if(NF!=2 || $2 !~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/ || $2=="latest" || $2=="main" || $2=="master" || release++) bad=1; tag=$2; next }
  $1=="source" { if(NF!=2 || length($2)!=40 || $2 !~ /^[0-9a-f]+$/ || source++) bad=1; next }
  $1=="validator" { if(NF!=3 || $2!="1.9.5p2" || $3!="48" || validator++) bad=1; next }
  $1=="file" { if(NF!=4 || !($2 in required) || seen[$2]++ || length($3)!=64 || $3 !~ /^[0-9a-f]+$/ || $4 !~ /^[1-9][0-9]*$/ || length($4)>10 || $4+0>536870912) bad=1; next }
  { bad=1 }
  END { for(name in required) if(seen[name]!=1) bad=1; if(repository!=1 || release!=1 || source!=1 || validator!=1 || (wanted!="latest" && wanted!=tag)) bad=1; exit bad ? 1 : 0 }
' "$TMP/manifest" || die 'invalid release manifest schema, tag or inventory'
TAG=$(awk '$1=="release" {print $2}' "$TMP/manifest")
SOURCE_COMMIT=$(awk '$1=="source" {print $2}' "$TMP/manifest")
asset_get() {
  FILE=$1
  EXPECTED_HASH=$(awk -v f="$FILE" '$1=="file" && $2==f {print $3}' "$TMP/manifest")
  EXPECTED_SIZE=$(awk -v f="$FILE" '$1=="file" && $2==f {print $4}' "$TMP/manifest")
  [ -n "$EXPECTED_HASH" ] && [ -n "$EXPECTED_SIZE" ] || die 'asset not in release inventory'
  fetch "https://github.com/$REPO/releases/download/$TAG/$FILE" "$TMP/$FILE" "$EXPECTED_SIZE" || die "release asset unavailable: $FILE"
  [ "$(wc -c < "$TMP/$FILE")" = "$EXPECTED_SIZE" ] &&
    [ "$(sha256sum "$TMP/$FILE" | cut -d' ' -f1)" = "$EXPECTED_HASH" ] || die "release asset hash/size mismatch: $FILE"
}
asset_get install.sh
if [ ! -f "$0" ] || [ ! -r "$0" ]; then
  # A root stdin entry cannot hash buffered stdin. Continue only with the exact
  # manifest-bound, complete same-tag installer; it verifies again as a file.
  awk 'END {if (NR==0 || $0!="# askdo install.sh end-of-file") exit 1}' "$TMP/install.sh" || die 'release installer truncated'
  ASKDO_VERSION="$TAG" sh "$TMP/install.sh"
  exit "$?"
fi
cmp -s "$0" "$TMP/install.sh" || die 'installer differs from selected release; use its matching release install.sh'
for FILE in $COMMON; do [ "$FILE" = install.sh ] || asset_get "$FILE"; done
for BINARY in "$ASSET" "$HELPER"; do
  asset_get "$BINARY"
  asset_get "$BINARY.sha256"
  EXPECTED_HASH=$(awk -v f="$BINARY" '$1=="file" && $2==f {print $3}' "$TMP/manifest")
  printf '%s  %s\n' "$EXPECTED_HASH" "$BINARY" > "$TMP/checksum-expected"
  cmp -s "$TMP/checksum-expected" "$TMP/$BINARY.sha256" || die 'release checksum record disagrees with manifest'
  # No execution during verification. Require ELF64 little endian and the
  # selected CPU machine field; reject even a correctly hashed wrong-arch file.
  HEADER=$(od -An -tx1 -N7 "$TMP/$BINARY" | tr -d ' \n')
  MACHINE=$(od -An -tx1 -j18 -N2 "$TMP/$BINARY" | tr -d ' \n')
  case "$ARCH:$HEADER:$MACHINE" in amd64:7f454c46020101:3e00|arm64:7f454c46020101:b700) ;;
    *) die 'release binary ELF architecture mismatch' ;; esac
done
if [ "$DSM" = 1 ]; then
  dsm_acl "$TMP/$ASSET" 0 1 && dsm_acl "$TMP/$HELPER" 0 1 || die 'DSM staged executable privilege metadata check failed'
fi
VALIDATOR_STAGE=
VALIDATOR_STAGE_ID=
VALIDATOR_PARENT_NEW=0
VALIDATOR_PARENT_ID=
cleanup_validator() {
  if [ -n "$VALIDATOR_STAGE" ]; then
    [ ! -L "$VALIDATOR_STAGE" ] && [ -d "$VALIDATOR_STAGE" ] &&
      [ "$(stat -c %d:%i:%a:%u:%g "$VALIDATOR_STAGE")" = "$VALIDATOR_STAGE_ID" ] || return 1
    if [ -e "$VALIDATOR_STAGE/visudo" ] || [ -L "$VALIDATOR_STAGE/visudo" ]; then
      [ ! -L "$VALIDATOR_STAGE/visudo" ] && [ -f "$VALIDATOR_STAGE/visudo" ] &&
        [ "$(stat -c %a:%u:%g "$VALIDATOR_STAGE/visudo")" = 700:0:0 ] &&
        cmp -s "$VALIDATOR_STAGE/visudo" "$TMP/visudo-linux-$ARCH" && rm "$VALIDATOR_STAGE/visudo" || return 1
    fi
    rmdir "$VALIDATOR_STAGE" || return 1
    VALIDATOR_STAGE=
  fi
  if [ "$VALIDATOR_PARENT_NEW" = 1 ]; then
    [ ! -L /usr/local/libexec ] && [ -d /usr/local/libexec ] &&
      [ "$(stat -c %d:%i:%a:%u:%g /usr/local/libexec)" = "$VALIDATOR_PARENT_ID" ] || return 1
    rmdir /usr/local/libexec || return 1
    VALIDATOR_PARENT_NEW=0
  fi
}
release_finish() {
  RC=$?
  trap - EXIT
  cleanup_validator || { printf 'install.sh: validator cleanup incomplete; retained staging %s\n' "$VALIDATOR_STAGE" >&2; exit 1; }
  rm -rf "$TMP"
  exit "$RC"
}
trap 'release_finish' EXIT
# Root sudo/visudo version queries can load plugins before producing metadata.
# Validate the supported configuration AND default origins before either query;
# version equality cannot make an unchecked plugin safe. Reject, never repair.
bundled_policy_config() {
  for P in / /etc /etc/sudo.conf /etc/nsswitch.conf; do
    if [ "$P" = /etc/sudo.conf ] || [ "$P" = /etc/nsswitch.conf ]; then
      [ -e "$P" ] || { [ ! -L "$P" ] || return 1; continue; }
      [ -f "$P" ] && [ "$(wc -c < "$P")" -le 65536 ] || return 1
    fi
    [ ! -L "$P" ] && [ "$(stat -c %u:%g "$P")" = 0:0 ] || return 1
    MODE=$(stat -c %a "$P"); [ $((0$MODE & 0022)) -eq 0 ] || return 1
    dsm_acl "$P" || return 1
  done
  if [ -f /etc/sudo.conf ]; then
    CONFIG_ID=$(stat -c %d:%i:%s:%Y:%Z /etc/sudo.conf)
    awk '
      length($0)>1024 {bad=1}
      /^[[:space:]]*(#|$)/ {next}
      {
        if ($1!="Plugin" || NF<3 || $3!="sudoers.so") {bad=1; next}
        if ($2!="sudoers_policy" && $2!="sudoers_io" && $2!="sudoers_audit") {bad=1; next}
        if(seen[$2]++) bad=1
        for(i=4;i<=NF;i++) {
          if($2!="sudoers_policy" || $i !~ /^(sudoers_file=\/etc\/sudoers|sudoers_uid=0|sudoers_gid=0|sudoers_mode=0?440)$/) bad=1
          split($i,a,"="); if(option[a[1]]++) bad=1
        }
      }
      END {exit bad ? 1 : 0}
    ' /etc/sudo.conf || return 1
    [ "$(stat -c %d:%i:%s:%Y:%Z /etc/sudo.conf)" = "$CONFIG_ID" ] || return 1
  fi
  # Missing/comment-only sudo.conf still selects a default plugin. Require one
  # unambiguous supported stock origin without executing sudo to discover it.
  STOCK_PLUGIN=
  STOCK_ORIGINS='/usr/libexec/sudo/sudoers.so /usr/lib/sudo/sudoers.so'
  if [ "$DSM" = 1 ]; then STOCK_ORIGINS="$STOCK_ORIGINS /usr/lib/sudoers.so"; fi
  for P in $STOCK_ORIGINS; do
    if [ -e "$P" ] || [ -L "$P" ]; then
      [ -z "$STOCK_PLUGIN" ] && [ ! -L "$P" ] && [ -f "$P" ] || return 1
      STOCK_PLUGIN=$P
    fi
  done
  [ -n "$STOCK_PLUGIN" ] || return 1
  P=$STOCK_PLUGIN
  while [ "$P" != / ]; do
    [ ! -L "$P" ] && [ "$(stat -c %u:%g "$P")" = 0:0 ] || return 1
    MODE=$(stat -c %a "$P"); [ $((0$MODE & 0022)) -eq 0 ] || return 1
    dsm_acl "$P" || return 1
    P=$(dirname "$P")
  done
  # Absent sudo.conf means documented stock defaults. Explicit standard symbols
  # are accepted only at the compiled stock basename; Path/plugin_dir, absolute
  # aliases, unknown options and custom plugins are unsupported, even root-owned.
  if [ -f /etc/nsswitch.conf ]; then
    awk '/^[[:space:]]*sudoers[[:space:]]*:/ {n++; sub(/#.*/,""); if($0 !~ /^[[:space:]]*sudoers[[:space:]]*:[[:space:]]*files[[:space:]]*$/) bad=1} END {exit bad || n>1 ? 1 : 0}' /etc/nsswitch.conf || return 1
  fi
}
policy_check() {
  if [ -z "$VALIDATOR_STAGE" ]; then "$VISUDO_TOOL" "$@" >/dev/null 2>&1; return; fi
  bundled_policy_config || return 1
  # Do not discard nonfatal parser warnings (e.g. a missing included directory).
  # Never print policy contents or diagnostics; retained private stage is bounded.
  "$VISUDO_TOOL" "$@" > "$TMP/policy-check-output" 2> "$TMP/policy-check-errors" || return 1
  [ ! -s "$TMP/policy-check-errors" ]
}
if [ "$DSM" = 0 ] && ! command -v visudo >/dev/null 2>&1; then VISUDO_TOOL=; fi
if [ -z "$VISUDO_TOOL" ]; then
  # Never parse a newer/different runtime policy using an older bundled grammar.
  SUDO_TOOL=$(readlink -f "$(command -v sudo)") || die 'sudo runtime required for bundled validator compatibility'
  [ -f "$SUDO_TOOL" ] && [ -x "$SUDO_TOOL" ] && [ "$(stat -c %u:%g "$SUDO_TOOL")" = 0:0 ] || die 'unsafe sudo runtime'
  P=$SUDO_TOOL
  while [ "$P" != / ]; do
    [ ! -L "$P" ] && [ "$(stat -c %u:%g "$P")" = 0:0 ] || die 'unsafe sudo runtime parent'
    MODE=$(stat -c %a "$P"); [ $((0$MODE & 0022)) -eq 0 ] || die 'writable sudo runtime parent'
    dsm_acl "$P" || die 'sudo runtime ACL check failed'; P=$(dirname "$P")
  done
  bundled_policy_config || die 'bundled validator requires trusted stock local sudoers configuration; custom plugin/path/NSS settings unsupported'
  "$SUDO_TOOL" -V > "$TMP/sudo-version" 2>/dev/null || die 'could not read sudo runtime version'
  awk '/^Sudo version / {version++; if($0!="Sudo version 1.9.5p2") bad=1} /^Sudoers policy plugin version / {policy++; if($0!="Sudoers policy plugin version 1.9.5p2") bad=1} /^Sudoers file grammar version / {grammar++; if($0!="Sudoers file grammar version 48") bad=1} END {exit bad || version!=1 || policy!=1 || grammar!=1 ? 1 : 0}' "$TMP/sudo-version" || die 'bundled validator incompatible with sudo runtime version/grammar'
  asset_get "visudo-linux-$ARCH"
  HEADER=$(od -An -tx1 -N7 "$TMP/visudo-linux-$ARCH" | tr -d ' \n')
  MACHINE=$(od -An -tx1 -j18 -N2 "$TMP/visudo-linux-$ARCH" | tr -d ' \n')
  case "$ARCH:$HEADER:$MACHINE" in amd64:7f454c46020101:3e00|arm64:7f454c46020101:b700) ;; *) die 'validator ELF architecture mismatch' ;; esac
  asset_get visudo-LICENSE
  asset_get visudo-SOURCE
  for P in /usr /usr/local; do
    [ -d "$P" ] && [ ! -L "$P" ] && [ "$(stat -c %u:%g "$P")" = 0:0 ] || die 'unsafe validator parent'
    MODE=$(stat -c %a "$P"); [ $((0$MODE & 0022)) -eq 0 ] || die 'writable validator parent'
    dsm_acl "$P" || die 'validator parent ACL check failed'
  done
  if [ ! -e /usr/local/libexec ] && [ ! -L /usr/local/libexec ]; then
    mkdir -m 0755 /usr/local/libexec || die 'could not create validator parent'
    VALIDATOR_PARENT_NEW=1
    VALIDATOR_PARENT_ID=$(stat -c %d:%i:%a:%u:%g /usr/local/libexec)
  fi
  dsm_acl /usr/local/libexec || die 'validator parent ACL check failed'
  [ -d /usr/local/libexec ] && [ ! -L /usr/local/libexec ] && [ "$(stat -c %a:%u:%g /usr/local/libexec)" = 755:0:0 ] || die 'unsafe validator parent'
  VALIDATOR_STAGE=$(mktemp -d /usr/local/libexec/.askdo-validate.XXXXXX) || die 'validator staging failed'
  chmod 0700 "$VALIDATOR_STAGE"
  VALIDATOR_STAGE_ID=$(stat -c %d:%i:%a:%u:%g "$VALIDATOR_STAGE")
  dsm_acl "$VALIDATOR_STAGE" || die 'validator staging ACL check failed'
  install -m 0700 -o root -g root "$TMP/visudo-linux-$ARCH" "$VALIDATOR_STAGE/visudo" || die 'validator staging copy failed'
  dsm_acl "$VALIDATOR_STAGE/visudo" 0 1 || die 'validator executable privilege check failed'
  VISUDO_TOOL=$VALIDATOR_STAGE/visudo
  "$VISUDO_TOOL" -V > "$TMP/validator-version" 2>/dev/null || die 'bundled validator version check failed'
  printf 'visudo version 1.9.5p2\nvisudo grammar version 48\n' > "$TMP/validator-expected"
  cmp -s "$TMP/validator-version" "$TMP/validator-expected" || die 'bundled validator version/grammar mismatch'
fi
if [ "$DSM" = 1 ] && [ -z "$VALIDATOR_STAGE" ]; then
  # Native policy parser must match its installed sudo runtime, too. Never use
  # a compatible-looking alias to a different grammar/version.
  SUDO_TOOL=$(readlink -f "$(command -v sudo)") || die 'sudo runtime required'
  [ -f "$SUDO_TOOL" ] && [ -x "$SUDO_TOOL" ] || die 'invalid sudo runtime'
  P=$SUDO_TOOL
  while [ "$P" != / ]; do dsm_acl "$P" || die 'sudo runtime ACL check failed'; P=$(dirname "$P"); done
  bundled_policy_config || die 'native validator version query requires trusted stock local sudoers configuration and plugin origins'
  "$SUDO_TOOL" -V > "$TMP/sudo-version" 2>/dev/null || die 'sudo runtime version query failed'
  "$VISUDO_TOOL" -V > "$TMP/validator-version" 2>/dev/null || die 'native validator version query failed'
  awk '
    FNR==NR { if($1=="Sudo" && $2=="version") {sv++; sudo=$3} if($1=="Sudoers" && $2=="policy" && $3=="plugin" && $4=="version") {sp++; policy=$5} if($1=="Sudoers" && $2=="file" && $3=="grammar" && $4=="version") {sg++; grammar=$5} next }
    $1=="visudo" && $2=="version" {vv++; validator=$3}
    $1=="visudo" && $2=="grammar" && $3=="version" {vg++; vgrammar=$4}
    END {exit sv!=1 || sp!=1 || sg!=1 || vv!=1 || vg!=1 || sudo!=policy || sudo!=validator || grammar!=vgrammar ? 1 : 0}
  ' "$TMP/sudo-version" "$TMP/validator-version" || die 'native validator incompatible with sudo runtime'
fi
printf 'Selected release %s (source %s); verified release assets, no destination compilation.\n' "$TAG" "$SOURCE_COMMIT"
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
policy_check -cf "$TMP/staged-policy" || die 'staged sudoers validation failed'
# The pre-existing effective policy must already be valid, too.
policy_check -c || die 'existing effective sudoers validation failed'

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
      if [ "$DSM" = 1 ]; then
        dsm_acl "$SUDOERS" && [ "$(stat -c %a:%u:%g "$SUDOERS")" = 440:0:0 ] || return 1
      fi
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
    if [ "$DSM" = 1 ]; then
      case " $DSM_BINARY_WRITES " in *" $NAME "*) ;;
        *) continue ;; esac
      case "$NAME" in askdo) STAGED=$TMP/$ASSET ;; *) STAGED=$TMP/$HELPER ;; esac
      [ -f "$DEST" ] && [ "$(stat -c %a:%u:%g "$DEST")" = 755:0:0 ] && cmp -s "$DEST" "$STAGED" || return 1
    fi
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
  if [ "$DSM" = 1 ]; then
    if [ -e /etc/systemd/system/askdo.service ]; then
      [ -f /etc/systemd/system/askdo.service ] &&
        [ "$(stat -c %a:%u:%g /etc/systemd/system/askdo.service)" = 644:0:0 ] &&
        cmp -s /etc/systemd/system/askdo.service "$TMP/askdo.service" || return 1
    fi
  fi
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
    if [ "$DSM" = 1 ]; then dsm_acl "$GW" && [ "$(stat -c %a:%u:%g "$GW")" = 644:0:0 ] || return 1; fi
    [ -f "$GW" ] && cmp -s "$GW" "$TMP/askdo-gateway.service" && rm -f "$GW" || return 1
  fi
}
rollback_examples() {
  for NAME in $EXAMPLES_NEW; do
    F=/etc/askdo/examples/$NAME
    [ ! -L "$F" ] || return 1
    if [ -e "$F" ]; then
      if [ "$DSM" = 1 ]; then dsm_acl "$F" && [ "$(stat -c %a:%u:%g "$F")" = 444:0:0 ] || return 1; fi
      [ -f "$F" ] && cmp -s "$F" "$TMP/$NAME" && rm -f "$F" || return 1
    fi
  done
  if [ "$DSM" = 0 ]; then rmdir /etc/askdo/examples 2>/dev/null || :; fi
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
    DSM_OK=1
    if [ "$POLICY_OK:$BINARIES_OK:$SERVICE_OK:$GATEWAY_OK:$EXAMPLES_OK" = 1:1:1:1:1 ]; then
      dsm_rollback || DSM_OK=0
    elif [ "$DSM" = 1 ]; then DSM_OK=0; fi
    if [ "$POLICY_OK" != 1 ] || [ "$BINARIES_OK" != 1 ] || [ "$SERVICE_OK" != 1 ] || [ "$GATEWAY_OK" != 1 ] || [ "$EXAMPLES_OK" != 1 ] || [ "$DSM_OK" != 1 ]; then
      printf 'install.sh: ERROR: rollback incomplete; protected originals retained in %s; inspect policy and binaries manually\n' "$TMP" >&2
      if [ "$DSM" = 1 ]; then printf 'install.sh: DSM identities/dependencies may be retained; inspect dsm-journal and fixed-role metadata; no blind retry or home purge\n' >&2; fi
      exit 1
    fi
  fi
  cleanup_validator || { printf 'install.sh: validator cleanup incomplete; retained staging %s and journal %s\n' "$VALIDATOR_STAGE" "$TMP" >&2; exit 1; }
  rm -rf "$TMP"
  exit "$RESULT"
}
trap 'finish_install' EXIT

DSM_BINARY_WRITES=
if [ "$DSM" = 1 ]; then
  # Read every pre-existing role before ANY native mutation. A disabled account
  # must be non-admin/non-submitter and match native AND local NSS identity.
  for ROLE in askdo askdo-review; do
    if SNAPSHOT=$(dsm_read group "$ROLE"); then
      printf '%s\n' "$SNAPSHOT" > "$TMP/existing-$ROLE"
    else [ "$?" = 2 ] || die 'DSM group metadata/NSS inconsistent or unavailable'; fi
  done
  if SNAPSHOT=$(dsm_read user askdo-review); then
    REVIEW_UID=${SNAPSHOT%%:*}
  else
    [ "$?" = 2 ] || die 'DSM reviewer must be disabled, non-admin, non-submitter and native/NSS consistent'
    [ ! -e /var/lib/askdo-review ] && [ ! -L /var/lib/askdo-review ] || die 'reviewer absent but existing home is unowned; refusing adoption'
  fi
  if [ -e /etc/askdo/credentials ] || [ -L /etc/askdo/credentials ]; then
    [ -f "$TMP/existing-askdo-review" ] &&
      [ "$(stat -c %a:%u:%g /etc/askdo/credentials)" = "750:0:$(cut -d: -f1 "$TMP/existing-askdo-review")" ] || die 'existing DSM credentials directory differs'
  fi
  dsm_paths || die 'DSM protected-path ACL or metadata check failed'
  for ROLE in askdo askdo-review; do
    if [ ! -f "$TMP/existing-$ROLE" ]; then dsm_create group "$ROLE"; fi
  done
  if [ -z "${REVIEW_UID:-}" ]; then dsm_create user askdo-review; REVIEW_UID=${SNAPSHOT%%:*}; fi
  ASKDO_GID=$(dsm_read group askdo) || die 'DSM socket group changed'
  ASKDO_GID=${ASKDO_GID%%:*}
  REVIEW_GID=$(dsm_read group askdo-review) || die 'DSM review group changed'
  REVIEW_GID=${REVIEW_GID%%:*}
  dsm_identity_guard || die 'DSM identities changed after role creation'
else
getent group askdo >/dev/null || groupadd --system askdo
getent group askdo-review >/dev/null || groupadd --system askdo-review
if id askdo-review >/dev/null 2>&1; then
  [ "$(id -gn askdo-review)" = askdo-review ] || die 'existing reviewer has wrong primary group'
else
  useradd --system --gid askdo-review --shell /usr/sbin/nologin --home-dir /var/lib/askdo-review askdo-review
fi
REVIEW_UID=askdo-review REVIEW_GID=askdo-review ASKDO_GID=askdo
fi
[ ! -L /usr/local ] && [ ! -L /usr/local/libexec ] && [ ! -L /usr/local/libexec/askdo-launch ] || die 'helper path contains a symlink'
if [ "$DSM" = 1 ]; then
  dsm_paths && dsm_identity_guard || die 'DSM trust or identities changed before installation'
fi
make_dir 755 0 0 /usr/local/bin
make_dir 755 0 0 /usr/local/libexec
DSM_BINARY_WRITES="askdo $DSM_BINARY_WRITES"
install -m 0755 -o root -g root "$TMP/$ASSET" /usr/local/bin/askdo
DSM_BINARY_WRITES="askdo-launch $DSM_BINARY_WRITES"
install -m 0755 -o root -g root "$TMP/$HELPER" /usr/local/libexec/askdo-launch
make_dir 755 0 0 /etc/askdo
if [ ! -e /etc/askdo/config.json ]; then
  DSM_CONFIG_NEW=1
  install -m 0600 -o root -g root "$TMP/askdo-config.example.json" /etc/askdo/config.json
fi
make_dir 750 0 "$REVIEW_GID" /etc/askdo/credentials
make_dir 700 0 0 /var/lib/askdo
make_dir 700 "$REVIEW_UID" "$REVIEW_GID" /var/lib/askdo-review
make_dir 750 0 "$ASKDO_GID" /run/askdo
# Last privilege-enabling step: all paths and identities are now installed.
for PATH_PART in /usr/local /usr/local/libexec; do
  [ -d "$PATH_PART" ] && [ ! -L "$PATH_PART" ] && [ "$(stat -c %u:%g "$PATH_PART")" = 0:0 ] || die 'unsafe helper parent'
  MODE=$(stat -c %a "$PATH_PART")
  [ $((0$MODE & 0022)) -eq 0 ] || die 'writable helper parent'
done
[ -f /usr/local/libexec/askdo-launch ] && [ ! -L /usr/local/libexec/askdo-launch ] &&
  [ "$(stat -c %a:%u:%g /usr/local/libexec/askdo-launch)" = 755:0:0 ] || die 'unsafe helper binary'
if [ "$DSM" = 1 ]; then
  dsm_paths || die 'DSM path trust changed before grant'
  dsm_identity_guard || die 'DSM identities changed before grant'
fi
if [ ! -e "$SUDOERS" ] && [ ! -L "$SUDOERS" ]; then
  NEW_SUDOERS=1
  install -m 0440 -o root -g root "$TMP/staged-policy" "$SUDOERS" || die 'sudoers install failed'
fi
if [ "$DSM" = 1 ]; then dsm_acl "$SUDOERS" || die 'DSM installed policy ACL check failed'; fi
if ! policy_check -c; then
  die 'effective sudoers validation failed'
fi
if [ -e "$OLD_SUDOERS" ]; then
  cmp -s "$OLD_SUDOERS" "$TMP/legacy-policy" || die 'legacy policy changed during upgrade; inspect both grants'
  rm "$OLD_SUDOERS" || die 'could not remove legacy policy; inspect both grants'
  if ! policy_check -c; then
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
  if [ "$DSM" = 1 ]; then GATEWAY_UNIT_NEW=1; fi
  install -m 0644 -o root -g root "$TMP/askdo-gateway.service" "$GWUNIT" || die 'gateway unit installation failed'
  GATEWAY_UNIT_NEW=1
fi
# Read-only fleet configuration examples; a differing operator copy is kept.
make_dir 755 0 0 /etc/askdo/examples
for NAME in gateway-config.example.json host-config.example.json; do
  F=/etc/askdo/examples/$NAME
  if [ -e "$F" ] || [ -L "$F" ]; then
    if [ -f "$F" ] && [ ! -L "$F" ] && cmp -s "$F" "$TMP/$NAME"; then continue; fi
    printf 'install.sh: WARNING: preserving existing %s (differs from shipped example)\n' "$F" >&2
    continue
  fi
  if [ "$DSM" = 1 ]; then EXAMPLES_NEW="$EXAMPLES_NEW $NAME"; fi
  install -m 0444 -o root -g root "$TMP/$NAME" "$F" || die "example install failed: $NAME"
  if [ "$DSM" = 0 ]; then EXAMPLES_NEW="$EXAMPLES_NEW $NAME"; fi
done
if [ "$DSM" = 1 ]; then dsm_paths && dsm_identity_guard || die 'DSM final installed-path or identity check failed'; fi
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload >/dev/null 2>&1 || :; fi
VALIDATOR_PARENT_NEW=0 # The successfully installed helper now owns this parent.
cleanup_validator || die 'validator cleanup incomplete; staging retained'
INSTALL_DONE=1
if [ "$MIGRATING" = 1 ] && [ "$DSM" = 1 ]; then
  printf 'WARNING: retaining DSM askdo-foreground group; no full NSS enumeration or native ownership proof; legacy grant removed\n' >&2
elif [ "$MIGRATING" = 1 ]; then
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
