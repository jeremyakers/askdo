#!/bin/sh
# Copied source only, disposable rootless Docker, no host account/service calls.
set -eu
if [ "${1:-}" != --inside ]; then
  ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
  case "$(docker info --format '{{json .SecurityOptions}}')" in
    *'"name=rootless"'*) ;; *) exit 1 ;;
  esac
  C=$(docker create --tmpfs /stage:rw,noexec,mode=0700 -w /src golang:1.27 sh /src/scripts/test-dsm-install.sh --inside "${1:-}")
  trap 'docker rm -f "$C" >/dev/null 2>&1 || :' EXIT
  git -C "$ROOT" ls-files -z | tar -C "$ROOT" --null -T - -cf - | docker cp - "$C:/src"
  docker cp "$0" "$C:/src/scripts/test-dsm-install.sh"
  docker cp "$ROOT/scripts/test-install-release-fixture.sh" "$C:/src/scripts/test-install-release-fixture.sh"
  if [ "${1:-}" = --real-validator ]; then
    docker cp "$ROOT/../.opencode/nas-compat/validator-build/candidate-amd64" "$C:/real-validator"
  fi
  docker start -a "$C"
  exit "$(docker inspect --format '{{.State.ExitCode}}' "$C")"
fi
fail() { printf '%s\n' "$*" >&2; cat /tmp/result >&2; exit 1; }
apt-get update -qq >/dev/null && apt-get install -y -qq sudo python3 >/dev/null
mkdir -p /etc.defaults /usr/syno/sbin /usr/syno/bin /fixture /usr/local/libexec
# Native absence replies for synouser/synogroup adapters. The measured DSM user
# reply lists the absence code before the source hint; shape files are per kind.
cat > /fixture/absence.sh <<'EOF'
absence() {
  if [ "$1" = user ]; then
    hint='Lastest SynoErr=[user_db_get.c:36]'; code='synouser.c:406 SYNOUserGet failed. synoerr=[0x1D00]'
  else
    hint='Lastest SynoErr=[group_db_get.c:26]'; code='SYNOGroupGet failed, synoerr=0x1800'
  fi
  rc=255
  shape=$(cat "/fixture/absence-shape-$1" 2>/dev/null || echo forward)
  case "$shape" in
    forward) printf '%s\n%s\n' "$hint" "$code";;
    reverse) printf '%s\n%s\n' "$code" "$hint";;
    duplicate-hint) printf '%s\n%s\n%s\n' "$hint" "$hint" "$code";;
    duplicate-code) printf '%s\n%s\n%s\n' "$code" "$hint" "$code";;
    missing-hint) printf '%s\n' "$code";;
    missing-code) printf '%s\n' "$hint";;
    extra-unknown) printf '%s\n%s\n%s\n' "$code" "$hint" 'unrecognized fixture line';;
    permission) printf '%s\n%s\n%s\n' "$code" "$hint" 'permission denied';;
    wrong-status) printf '%s\n%s\n' "$code" "$hint"; rc=1;;
  esac
  exit "$rc"
}
EOF
if [ -d /real-validator ]; then mv /real-validator /fixture/real-validator; fi
printf 'majorversion="7"\nbuildnumber="72806"\n' > /etc.defaults/VERSION
groupadd -g 100 users 2>/dev/null || :
sh scripts/test-install-release-fixture.sh
cp /fixture/release/askdo-linux-amd64 /fixture/askdo
cat > /usr/local/bin/systemctl <<'EOF'
#!/bin/sh
echo "service $1" >> /fixture/calls
case "$1" in daemon-reload) exit 0;; is-active) exit 3;; disable) exit 0;; *) exit 1;; esac
EOF
cat > /usr/syno/bin/synoacltool <<'EOF'
#!/bin/sh
if [ -e /fixture/acl-unknown ]; then echo 'unknown ACL'; exit 255; fi
if [ -e /fixture/acl-permission ]; then echo 'permission denied'; exit 1; fi
if [ -e /fixture/validator-foreign ]; then
  case "$2" in /usr/local/libexec/.askdo-validate.*) if [ -d "$2" ]; then echo foreign > "$2/foreign"; fi;; esac
fi
printf "(synoacltool.c, 596)It's Linux mode\n"
exit 255
EOF
cat > /usr/syno/sbin/synogroup <<'EOF'
#!/bin/sh
set -eu
case "$1" in
--get)
  if [ -e /fixture/group-permission ]; then echo 'permission denied'; exit 255; fi
  if [ -e /fixture/unknown-absence ]; then
    printf 'Lastest SynoErr=[group_db_get.c:26]\nSYNOGroupGet failed, synoerr=0x1800\npermission denied\n'; exit 255
  fi
  if [ -e /fixture/wrong-absence-class ]; then
    printf 'Lastest SynoErr=[group_db_getXc:26]\nSYNOGroupGet failed, synoerr=0x1800\n'; exit 255
  fi
  if row=$(/usr/bin/getent group "$2"); then
    gid=$(printf '%s' "$row" | cut -d: -f3)
    [ ! -e /fixture/bad-gid ] || gid=0
    printf 'Group Name : [%s]\nGroup ID : [%s]\n' "$2" "$gid"
    [ ! -e /fixture/duplicate-group ] || printf 'Group ID : [%s]\n' "$gid"
    exit 0
  fi
  . /fixture/absence.sh; absence group;;
--add)
  echo "group add $2" >> /fixture/calls
  /usr/sbin/groupadd "$2"
  [ ! -e "/fixture/fail-add-$2" ] || exit 1;;
--del)
  echo "group del $2" >> /fixture/calls
  /usr/sbin/groupdel "$2";;
*) exit 1;;
esac
EOF
cat > /usr/syno/sbin/synouser <<'EOF'
#!/bin/sh
set -eu
case "$1" in
--get)
  if [ -e /fixture/user-permission ]; then echo 'permission denied'; exit 255; fi
  if [ ! -e /fixture/native-absent-user ] && row=$(/usr/bin/getent passwd "$2"); then
    uid=$(printf '%s' "$row" | cut -d: -f3)
    [ ! -e /fixture/bad-uid ] || uid=0
    expired=true; [ ! -e /fixture/enabled ] || expired=false
    name=$2; [ ! -e /fixture/wrong-name ] || name=nobody
    printf 'User Name : [%s]\nUser uid : [%s]\nPrimary gid : [100]\nExpired : [%s]\n' "$name" "$uid" "$expired"
    [ ! -e /fixture/duplicate-user ] || printf 'User uid : [%s]\n' "$uid"
    exit 0
  fi
  . /fixture/absence.sh; absence user;;
--add)
  # Never capture full argv/password in fixture evidence.
  test "$5:$6:$7" = '1::0'
  echo "user add $2 expired=1" >> /fixture/calls
  /usr/sbin/useradd -g users -d /var/lib/askdo-review -s /usr/sbin/nologin "$2"
  [ ! -e /fixture/fail-user-add ] || exit 1;;
--del)
  echo "user del $2" >> /fixture/calls
  /usr/sbin/userdel "$2";;
*) exit 1;;
esac
EOF
chmod 0755 /usr/local/bin/go /usr/local/bin/systemctl /usr/syno/bin/synoacltool
chmod 0700 /usr/syno/sbin/synouser /usr/syno/sbin/synogroup
for cmd in getent groupadd useradd userdel groupdel; do
  printf '#!/bin/sh\necho generic-%s >> /fixture/calls\nexit 1\n' "$cmd" > "/usr/local/bin/$cmd"
  chmod 0755 "/usr/local/bin/$cmd"
done
export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
: > /fixture/calls
sh /src/install.sh > /tmp/result 2>&1 || fail 'fresh DSM installation failed'
test "$(id -g askdo-review)" = 100 || fail 'native NSS primary altered'
cmp /usr/local/bin/askdo /fixture/release/askdo-linux-amd64 || fail 'downloaded client differs'
cmp /usr/local/libexec/askdo-launch /fixture/release/askdo-launch-linux-amd64 || fail 'downloaded helper differs'
if grep -q forbidden-go /fixture/calls; then fail 'destination Go invoked'; fi
cmp /etc/sudoers.d/askdo /src/contrib/askdo.sudoers || fail 'policy mismatch'
test "$(stat -c %g /etc/askdo/credentials)" = "$(/usr/bin/getent group askdo-review | cut -d: -f3)" || fail 'named credential group mismatch'
if grep -E '^service (enable|start|restart)' /fixture/calls; then fail 'service activated'; fi
printf 'DSM fresh success passed (native adapters only)\n'
uid=$(id -u askdo-review)
gid=$(/usr/bin/getent group askdo-review | cut -d: -f3)
/usr/sbin/useradd -G askdo -s /usr/sbin/nologin existing-submitter
printf 'operator configuration\n' > /etc/askdo/config.json
: > /fixture/calls
sh /src/install.sh > /tmp/result 2>&1 || fail 'repeat DSM install failed'
test "$(id -u askdo-review)" = "$uid" && test "$(/usr/bin/getent group askdo-review | cut -d: -f3)" = "$gid" || fail 'repeat identities changed'
grep -qx 'operator configuration' /etc/askdo/config.json || fail 'operator config changed'
id -nG existing-submitter | grep -qw askdo || fail 'existing submitter membership changed'
if grep -E '^(user|group) (add|del)|generic-' /fixture/calls; then fail 'repeat mutated roles or used generic backend'; fi
reset_fixture() {
  /usr/sbin/userdel askdo-review 2>/dev/null || :
  /usr/sbin/userdel existing-submitter 2>/dev/null || :
  /usr/sbin/groupdel askdo-review 2>/dev/null || :
  /usr/sbin/groupdel askdo 2>/dev/null || :
  rm -rf /etc/askdo /var/lib/askdo /var/lib/askdo-review /run/askdo
  rm -f /usr/local/bin/askdo /usr/local/libexec/askdo-launch /etc/sudoers.d/askdo \
    /etc/systemd/system/askdo.service /etc/systemd/system/askdo-gateway.service
  rm -f /fixture/enabled /fixture/*-permission /fixture/acl-unknown /fixture/bad-* \
    /fixture/duplicate-* /fixture/fail-* /fixture/change-* /fixture/unknown-absence \
    /fixture/wrong-* /fixture/absence-shape-* /fixture/native-absent-user /usr/local/bin/visudo /usr/local/bin/install
  : > /fixture/calls
}
expect_failure() {
  if sh /src/install.sh > /tmp/result 2>&1; then fail 'injected unsafe state accepted'; fi
  test ! -e /etc/sudoers.d/askdo || fail 'failed install left new grant'
}
no_mutations() {
  if grep -E '^(user|group) (add|del)|generic-' /fixture/calls; then fail 'early failure mutated identity'; fi
}
# Native absence diagnostics: both recognized lines, either order, only with 255 and no local row.
for absent in user:reverse user:forward group:reverse group:forward; do
  reset_fixture
  printf '%s\n' "${absent#*:}" > "/fixture/absence-shape-${absent%%:*}"
  sh /src/install.sh > /tmp/result 2>&1 || fail "native absence ($absent) refused"
  test "$(id -g askdo-review)" = 100 || fail "native absence ($absent) did not create reviewer"
  sh /src/install.sh > /tmp/result 2>&1 || fail "native absence ($absent) repeat failed"
  printf 'DSM native absence accepted: %s\n' "$absent"
done
for absent in user:duplicate-hint user:duplicate-code user:missing-hint user:missing-code user:extra-unknown \
  user:permission user:wrong-status group:duplicate-hint group:duplicate-code group:missing-hint \
  group:missing-code group:extra-unknown group:permission group:wrong-status user:nss-present; do
  reset_fixture
  if [ "${absent#*:}" = nss-present ]; then
    /usr/sbin/useradd -g users -s /usr/sbin/nologin askdo-review
    printf 'reverse\n' > /fixture/absence-shape-user
    : > /fixture/native-absent-user
  else
    printf '%s\n' "${absent#*:}" > "/fixture/absence-shape-${absent%%:*}"
  fi
  : > /fixture/calls
  expect_failure
  no_mutations
  printf 'DSM native absence refused: %s\n' "$absent"
done
reset_fixture
# Fixed physical DSM origin: genuine package bytes moved ONLY in this isolated
# namespace. The version oracle does not prove Debian sudo's compiled defaults
# match DSM; real bundled visudo still performs the policy checks.
reset_fixture
ORIGIN_BASELINE=
for path in /usr/libexec/sudo/sudoers.so /usr/lib/sudo/sudoers.so; do
  if [ -f "$path" ]; then test -z "$ORIGIN_BASELINE" || fail 'ambiguous fixture origin'; ORIGIN_BASELINE=$path; fi
done
test -n "$ORIGIN_BASELINE" && test ! -e /usr/lib/sudoers.so || fail 'unexpected fixture stock layout'
origin_hash=$(sha256sum "$ORIGIN_BASELINE" | cut -d' ' -f1)
lib_mode=$(stat -c %a /usr/lib)
if [ -e /etc/sudo.conf ]; then cp /etc/sudo.conf /fixture/origin-sudo-conf; fi
mv "$ORIGIN_BASELINE" /usr/lib/sudoers.so
  mv /usr/sbin/visudo /usr/sbin/visudo.saved
cat > /usr/local/bin/sudo <<'EOF'
#!/bin/sh
printf 'queried\n' >> /fixture/origin-queries
if [ "$1" = -V ]; then printf 'Sudo version 1.9.5p2\nSudoers policy plugin version 1.9.5p2\nSudoers file grammar version 48\n'; exit 0; fi
exit 1
EOF
chmod 0755 /usr/local/bin/sudo
for config in absent commented explicit; do
  reset_fixture
  case "$config" in
    absent) rm -f /etc/sudo.conf ;;
    commented) printf '# stock defaults\n' > /etc/sudo.conf ;;
    explicit) printf 'Plugin sudoers_policy sudoers.so\nPlugin sudoers_io sudoers.so\nPlugin sudoers_audit sudoers.so\n' > /etc/sudo.conf ;;
  esac
  rm -f /fixture/origin-queries
  TMPDIR=/stage sh /src/install.sh > /tmp/result 2>&1 || fail "fixed physical DSM origin rejected ($config)"
  test -s /fixture/origin-queries || fail 'accepted DSM origin did not reach validated query'
  uid=$(id -u askdo-review)
  gid=$(/usr/bin/getent group askdo-review | cut -d: -f3)
  printf 'operator-fixture-config\n' > /etc/askdo/config.json
  : > /fixture/calls
  TMPDIR=/stage sh /src/install.sh > /tmp/result 2>&1 || fail 'DSM physical-origin repeat failed'
  test "$(id -u askdo-review)" = "$uid" && test "$(/usr/bin/getent group askdo-review | cut -d: -f3)" = "$gid" || fail 'DSM physical-origin repeat changed identities'
  grep -qx 'operator-fixture-config' /etc/askdo/config.json || fail 'DSM physical-origin repeat changed config'
  no_mutations
  cmp /usr/local/bin/askdo /fixture/release/askdo-linux-amd64 || fail 'DSM physical-origin client bytes differ'
  cmp /usr/local/libexec/askdo-launch /fixture/release/askdo-launch-linux-amd64 || fail 'DSM physical-origin helper bytes differ'
  printf 'DSM physical stock origin PASS: %s config and repeat\n' "$config"
done
for unsafe in missing symlink duplicate nonroot writable parent-writable acl; do
  reset_fixture
  rm -f /etc/sudo.conf /fixture/origin-queries
  case "$unsafe" in
    missing) mv /usr/lib/sudoers.so /fixture/origin-module ;;
    symlink) mv /usr/lib/sudoers.so /fixture/origin-module; ln -s /fixture/origin-module /usr/lib/sudoers.so ;;
    duplicate) cp -p /usr/lib/sudoers.so "$ORIGIN_BASELINE" ;;
    nonroot) chown 65534:65534 /usr/lib/sudoers.so ;;
    writable) chmod 0666 /usr/lib/sudoers.so ;;
    parent-writable) chmod 0777 /usr/lib ;;
    acl)
      /usr/bin/python3 -I -S - <<'PY'
import os, struct
entries = [(1,7,0xffffffff),(2,4,65534),(4,5,0xffffffff),(16,5,0xffffffff),(32,5,0xffffffff)]
os.setxattr('/usr/lib', 'system.posix_acl_access', struct.pack('<I',2) + b''.join(struct.pack('<HHI',*e) for e in entries))
PY
      ;;
  esac
  expect_failure
  test ! -e /fixture/origin-queries || fail 'unsafe DSM physical origin queried sudo'
  test ! -s /fixture/calls || fail 'unsafe DSM physical origin invoked mutation/compiler/service'
  case "$unsafe" in
    missing) mv /fixture/origin-module /usr/lib/sudoers.so ;;
    symlink) rm /usr/lib/sudoers.so; mv /fixture/origin-module /usr/lib/sudoers.so ;;
    duplicate) rm "$ORIGIN_BASELINE" ;;
    nonroot) chown 0:0 /usr/lib/sudoers.so ;;
    writable) chmod 0644 /usr/lib/sudoers.so ;;
    parent-writable) chmod "$lib_mode" /usr/lib ;;
    acl) /usr/bin/python3 -I -S -c "import os; os.removexattr('/usr/lib', 'system.posix_acl_access')"; chmod "$lib_mode" /usr/lib ;;
  esac
  printf 'DSM physical stock origin refusal PASS: %s before query\n' "$unsafe"
done
# Marker/tool absence, not a platform-force option: ordinary Linux still refuses
# the third location even when it is safe and the fallback version would match.
reset_fixture
mv /etc.defaults/VERSION /fixture/origin-version
mv /usr/syno /usr/syno.origin-saved
rm -f /fixture/origin-queries
expect_failure
test ! -e /fixture/origin-queries && test ! -s /fixture/calls || fail 'Linux accepted DSM-only physical origin'
mv /usr/syno.origin-saved /usr/syno
mv /fixture/origin-version /etc.defaults/VERSION
test "$(sha256sum /usr/lib/sudoers.so | cut -d' ' -f1)" = "$origin_hash" || fail 'stock fixture module bytes changed'
mv /usr/lib/sudoers.so "$ORIGIN_BASELINE"
  mv /usr/sbin/visudo.saved /usr/sbin/visudo
rm /usr/local/bin/sudo
if [ -f /fixture/origin-sudo-conf ]; then cp /fixture/origin-sudo-conf /etc/sudo.conf; else rm -f /etc/sudo.conf; fi
printf 'Linux origin allowlist unchanged; physical module bytes restored\n'
reset_fixture
if [ "${2:-}" = --plugin-origin-test ]; then exit 0; fi
# Starter-config copy can fail without a target or with uncertain side effects.
# Record only synthetic bytes/hashes; never print config contents as evidence.
reset_fixture
/usr/sbin/groupadd config-unrelated
/usr/sbin/useradd -g users -G config-unrelated -s /usr/sbin/nologin config-unrelated
unrelated_uid=$(id -u config-unrelated)
unrelated_groups=$(id -G config-unrelated)
for config_state in absent partial dangling foreign directory; do
  reset_fixture
  cat > /usr/local/bin/install <<EOF
#!/bin/sh
for last do :; done
if [ "\$last" = /etc/askdo/config.json ]; then
  case $config_state in
    partial) printf '{' > "\$last"; chmod 0600 "\$last" ;;
    dangling) ln -s /etc/fixture-missing-config "\$last" ;;
    foreign) printf 'unrelated-fixture-config\n' > "\$last"; chmod 0600 "\$last" ;;
    directory) mkdir "\$last" ;;
  esac
  if [ -f "\$last" ]; then sha256sum "\$last" | cut -d' ' -f1 > /fixture/config-failure-hash; fi
  exit 1
fi
exec /usr/bin/install "\$@"
EOF
  chmod 0755 /usr/local/bin/install
  expect_failure
  test "$(id -u config-unrelated)" = "$unrelated_uid" &&
    test "$(id -G config-unrelated)" = "$unrelated_groups" || fail 'config rollback changed unrelated identity/membership'
  test ! -e /usr/local/bin/askdo && test ! -e /usr/local/libexec/askdo-launch || fail 'config failure retained new binaries'
  if [ "$config_state" = absent ]; then
    if grep -q 'rollback incomplete' /tmp/result; then fail 'absent failed config copy incorrectly retained rollback state'; fi
    for role in askdo askdo-review; do
      if /usr/bin/getent group "$role" >/dev/null; then fail 'absent config failure retained new group'; fi
    done
    if /usr/bin/getent passwd askdo-review >/dev/null; then fail 'absent config failure retained new reviewer'; fi
    for path in /etc/askdo /var/lib/askdo /var/lib/askdo-review /run/askdo; do
      test ! -e "$path" && test ! -L "$path" || fail 'absent config failure retained new directory';
    done
  else
    grep -q 'rollback incomplete' /tmp/result || fail 'uncertain config failure discarded journal'
    if grep -E '^(user|group) del' /fixture/calls; then fail 'uncertain config failure deleted roles'; fi
    /usr/bin/getent passwd askdo-review >/dev/null || fail 'uncertain config failure did not retain reviewer'
    case "$config_state" in
      partial|foreign) test "$(sha256sum /etc/askdo/config.json | cut -d' ' -f1)" = "$(cat /fixture/config-failure-hash)" || fail 'unknown config bytes changed' ;;
      dangling) test -L /etc/askdo/config.json && test "$(readlink /etc/askdo/config.json)" = /etc/fixture-missing-config || fail 'dangling config link changed' ;;
      directory) test -d /etc/askdo/config.json && test ! -L /etc/askdo/config.json || fail 'nonregular config target changed' ;;
    esac
  fi
  printf 'config-copy rollback PASS: %s\n' "$config_state"
done
reset_fixture
/usr/sbin/userdel config-unrelated
/usr/sbin/groupdel config-unrelated
if [ "${2:-}" = --config-rollback-test ]; then exit 0; fi
# Review2 records attempted execution only; no custom module/exploit payload.
# Version replies remain explicitly synthetic, not native compatibility proof.
review2_failures=0
review2_check() {
  if [ "$1" = 0 ]; then printf 'review2 regression PASS: %s\n' "$2"
  else printf 'review2 regression FAIL: %s\n' "$2"; review2_failures=$((review2_failures + 1)); fi
}
reset_fixture
if [ -e /etc/sudo.conf ]; then cp /etc/sudo.conf /fixture/review2-sudo-conf; fi
STOCK_PLUGIN=
for path in /usr/libexec/sudo/sudoers.so /usr/lib/sudo/sudoers.so; do
  if [ -f "$path" ]; then test -z "$STOCK_PLUGIN" || fail 'ambiguous fixture stock plugin'; STOCK_PLUGIN=$path; fi
done
test -n "$STOCK_PLUGIN" || fail 'fixture stock sudo plugin unavailable'
PLUGIN_PARENT=$(dirname "$STOCK_PLUGIN")
PLUGIN_MODE=$(stat -c %a "$PLUGIN_PARENT")
cp -p "$STOCK_PLUGIN" /fixture/review2-stock-plugin
for seam in native fallback; do
  if [ "$seam" = fallback ]; then mv /usr/sbin/visudo /usr/sbin/visudo.review2-saved; fi
  for origin in custom default commented missing ambiguous; do
    reset_fixture
    case "$origin" in
      custom) printf 'Plugin sudoers_policy unsupported.so\n' > /etc/sudo.conf ;;
      default) rm -f /etc/sudo.conf; chmod 0777 "$PLUGIN_PARENT" ;;
      commented) printf '# no plugin directives\n' > /etc/sudo.conf; chmod 0777 "$PLUGIN_PARENT" ;;
      missing) rm -f /etc/sudo.conf; mv "$STOCK_PLUGIN" /fixture/review2-plugin-away ;;
      ambiguous)
        rm -f /etc/sudo.conf
        case "$STOCK_PLUGIN" in /usr/libexec/*) OTHER_PLUGIN=/usr/lib/sudo/sudoers.so;; *) OTHER_PLUGIN=/usr/libexec/sudo/sudoers.so;; esac
        mkdir -p "$(dirname "$OTHER_PLUGIN")"
        cp -p "$STOCK_PLUGIN" "$OTHER_PLUGIN" ;;
    esac
    chmod 0644 /etc/sudo.conf 2>/dev/null || :
    cat > /usr/local/bin/sudo <<'EOF'
#!/bin/sh
printf 'queried\n' >> /fixture/review2-sudo-queries
if [ "$1" = -V ]; then printf 'Sudo version 1.9.5p2\nSudoers policy plugin version 1.9.5p2\nSudoers file grammar version 48\n'; exit 0; fi
exit 1
EOF
    chmod 0755 /usr/local/bin/sudo
    rm -f /fixture/review2-sudo-queries
    ok=0
    if sh /src/install.sh > /tmp/result 2>&1; then ok=1; fi
    test ! -e /fixture/review2-sudo-queries || ok=1
    test ! -e /etc/sudoers.d/askdo || ok=1
    if grep -E '^(user|group) (add|del)|forbidden-' /fixture/calls >/dev/null; then ok=1; fi
    review2_check "$ok" "$seam refuses $origin plugin origin before sudo version query"
    if [ "$origin" = missing ]; then mv /fixture/review2-plugin-away "$STOCK_PLUGIN"; fi
    if [ "$origin" = ambiguous ]; then rm "$OTHER_PLUGIN"; rmdir "$(dirname "$OTHER_PLUGIN")"; fi
    cp -p /fixture/review2-stock-plugin "$STOCK_PLUGIN"
    chmod "$PLUGIN_MODE" "$PLUGIN_PARENT"
    rm /usr/local/bin/sudo
  done
  if [ "$seam" = fallback ]; then mv /usr/sbin/visudo.review2-saved /usr/sbin/visudo; fi
done
if [ -f /fixture/review2-sudo-conf ]; then cp /fixture/review2-sudo-conf /etc/sudo.conf; else rm -f /etc/sudo.conf; fi
reset_fixture
ln -s "$(readlink -f /usr/bin/python3)" /fixture/stock-python
mkdir -p /fixture/python-writable
chown 65534:65534 /fixture/python-writable
chmod 0777 /fixture/python-writable
cat > /fixture/python-writable/python3.11 <<'EOF'
#!/bin/sh
printf 'invoked\n' >> /fixture/review2-python-executed
exec /fixture/stock-python "$@"
EOF
chmod 0755 /fixture/python-writable/python3.11
mv /usr/bin/python3 /usr/bin/python3.review2-saved
ln -s /fixture/python-writable/python3.11 /usr/bin/python3
: > /tmp/fetch-urls
rm -f /fixture/review2-python-executed
ok=0
if sh /src/install.sh > /tmp/result 2>&1; then ok=1; fi
test ! -e /fixture/review2-python-executed || ok=1
test ! -s /tmp/fetch-urls || ok=1
test ! -s /fixture/calls || ok=1
test ! -e /etc/sudoers.d/askdo || ok=1
review2_check "$ok" 'vendor Python outside trusted canonical ancestors refused before execution/fetch'
rm /usr/bin/python3
mv /usr/bin/python3.review2-saved /usr/bin/python3
reset_fixture
if [ "${2:-}" = --review2-red ]; then
  test "$review2_failures" = 0
  exit "$?"
fi
test "$review2_failures" = 0 || fail 'review2 trust regressions failed'
reset_fixture
# The stock canonical target must remain the executable for BOTH metadata
# helpers even when the original alias is replaced after bootstrap validation.
cp /usr/syno/bin/synoacltool /fixture/review2-acl-original
cat > /fixture/review2-alias-python <<'EOF'
#!/bin/sh
printf 'invoked\n' >> /fixture/review2-alias-executed
exit 1
EOF
chmod 0755 /fixture/review2-alias-python
cat > /usr/syno/bin/synoacltool <<'EOF'
#!/bin/sh
if [ "$2" = /tmp ] && [ ! -e /fixture/review2-alias-swapped ]; then
  mv /usr/bin/python3 /usr/bin/python3.review2-saved
  ln -s /fixture/review2-alias-python /usr/bin/python3
  touch /fixture/review2-alias-swapped
fi
exec /fixture/review2-acl-original "$@"
EOF
chmod 0755 /usr/syno/bin/synoacltool
sh /src/install.sh > /tmp/result 2>&1 || fail 'cached canonical Python execution failed after alias swap'
test -e /fixture/review2-alias-swapped && test ! -e /fixture/review2-alias-executed || fail 'unchecked Python alias executed'
cmp /usr/local/bin/askdo /fixture/release/askdo-linux-amd64 || fail 'canonical Python install bytes differ'
rm /usr/bin/python3
mv /usr/bin/python3.review2-saved /usr/bin/python3
cp /fixture/review2-acl-original /usr/syno/bin/synoacltool
printf 'review2 regression PASS: cached canonical vendor Python used after alias swap\n'
reset_fixture
# Review regressions run before the ordinary matrix; red mode collects each
# independent rejected-candidate failure rather than stopping at the first one.
review_failures=0
review_check() {
  if [ "$1" = 0 ]; then printf 'review regression PASS: %s\n' "$2"
  else printf 'review regression FAIL: %s\n' "$2"; review_failures=$((review_failures + 1)); fi
}
reset_fixture
mkdir -p /fixture/aliases
chmod 0777 /fixture/aliases
ln -s /usr/sbin/visudo /fixture/aliases/visudo
cp /usr/syno/bin/synoacltool /fixture/acl-original
cat > /usr/syno/bin/synoacltool <<'EOF'
#!/bin/sh
# Deterministic delayed alias swap, AFTER both canonical targets were checked.
if [ "$2" = /tmp ] && [ -L /fixture/aliases/visudo ]; then
  rm /fixture/aliases/visudo
  for tool in visudo; do
    printf '#!/bin/sh\necho rogue-%s >> /fixture/rogue\nexit 1\n' "$tool" > "/fixture/aliases/$tool"
    chmod 0755 "/fixture/aliases/$tool"
  done
fi
exec /fixture/acl-original "$@"
EOF
chmod 0755 /usr/syno/bin/synoacltool
PATH="/fixture/aliases:$PATH" sh /src/install.sh > /tmp/result 2>&1 || :
ok=0; test ! -e /fixture/rogue || ok=1
review_check "$ok" 'validated canonical tools stay pinned after alias swap'
cp /fixture/acl-original /usr/syno/bin/synoacltool
rm -rf /fixture/aliases
for alias in uid dedicated users; do
  reset_fixture
  /usr/sbin/groupadd askdo
  /usr/sbin/groupadd askdo-review
  /usr/sbin/useradd -g users -s /usr/sbin/nologin askdo-review
  /usr/bin/python3 -I -S - "$alias" <<'PY'
import sys
kind = sys.argv[1]
path = '/etc/passwd' if kind == 'uid' else '/etc/group'
rows = [line.rstrip('\n').split(':') for line in open(path)]
role = 'users' if kind == 'users' else 'askdo-review'
ident = next(row[2] for row in rows if row[0] == role)
row = ['review-alias','x','0'+ident,'100','fixture','/nonexistent','/usr/sbin/nologin'] if kind == 'uid' else ['review-alias','x','0'+ident,'']
with open(path, 'a') as out:
    out.write(':'.join(row)+'\n')
PY
  ok=0
  if sh /src/install.sh > /tmp/result 2>&1; then ok=1; fi
  if grep -E '^(user|group) (add|del)' /fixture/calls >/dev/null; then ok=1; fi
  test ! -e /etc/sudoers.d/askdo || ok=1
  review_check "$ok" "numeric leading-zero $alias alias refused before mutation/grant"
  /usr/bin/python3 -I -S - <<'PY'
for path in ('/etc/passwd','/etc/group'):
    lines = [line for line in open(path) if not line.startswith('review-alias:')]
    with open(path, 'w') as out:
        out.writelines(lines)
PY
done
reset_fixture
# Synthetic unrelated local rows only inside this disposable container. Real
# adapter useradd/groupadd now rewrite database files substantially above 16KiB.
/usr/bin/python3 -I -S - <<'PY'
for path, width in (('/etc/passwd',7),('/etc/group',4)):
    with open(path, 'a') as out:
        for i in range(800):
            row = ['bulk-fixture-'+str(i),'x',str(200000+i)]
            row += ['100','unrelated-fixture','/nonexistent','/usr/sbin/nologin'] if width == 7 else ['']
            out.write(':'.join(row)+'\n')
PY
awk -F: '$1 ~ /^bulk-fixture-/ {print}' /etc/passwd > /fixture/bulk-passwd
awk -F: '$1 ~ /^bulk-fixture-/ {print}' /etc/group > /fixture/bulk-group
ok=0
sh /src/install.sh > /tmp/result 2>&1 || ok=1
awk -F: '$1 ~ /^bulk-fixture-/ {print}' /etc/passwd > /fixture/bulk-passwd-after
awk -F: '$1 ~ /^bulk-fixture-/ {print}' /etc/group > /fixture/bulk-group-after
cmp /fixture/bulk-passwd /fixture/bulk-passwd-after || ok=1
cmp /fixture/bulk-group /fixture/bulk-group-after || ok=1
review_check "$ok" 'large account databases succeed with unrelated rows unchanged'
/usr/bin/python3 -I -S - <<'PY'
for path in ('/etc/passwd','/etc/group'):
    lines = [line for line in open(path) if not line.startswith('bulk-fixture-')]
    with open(path, 'w') as out:
        out.writelines(lines)
PY
reset_fixture
if [ "${2:-}" = --review-red ]; then
  test "$review_failures" = 0
  exit "$?"
fi
test "$review_failures" = 0 || fail 'review correction regressions failed'
reset_fixture
# Real security.capability metadata on the unchanged reviewed binary. This only
# sets an xattr inside the disposable rootless container; never executes it.
cp /fixture/askdo /usr/local/bin/askdo
chmod 0755 /usr/local/bin/askdo
sha256sum /usr/local/bin/askdo > /fixture/cap-bytes
if /usr/bin/python3 -I -S - <<'PY'
import errno, os, struct, sys
try:
    os.setxattr('/usr/local/bin/askdo', 'security.capability', struct.pack('<IIIII',0x02000001,1,0,0,0))
except OSError as error:
    if error.errno in (errno.EPERM, errno.ENOTSUP):
        sys.exit(77)
    raise
PY
then
  sha256sum -c /fixture/cap-bytes >/dev/null || fail 'capability fixture changed executable bytes'
  expect_failure
  no_mutations
  /usr/bin/python3 -I -S -c "import os; os.removexattr('/usr/local/bin/askdo', 'security.capability')"
  printf 'review regression PASS: actual executable capability denied with unchanged bytes\n'
else
  rc=$?
  test "$rc" = 77 || fail 'capability fixture creation failed'
  printf 'SKIP actual security.capability fixture: rootless filesystem lacks SETFCAP/xattr support\n'
fi
reset_fixture
mv /usr/sbin/visudo /usr/sbin/visudo.saved
# Incompatible real Linux sudo cannot use the older bundle.
expect_failure
grep -q 'incompatible with sudo runtime' /tmp/result || fail 'missing validator compatibility diagnostic'
no_mutations
# ADAPTER version oracle for the intended native 1.9.5p2/grammar48 branch.
cat > /usr/local/bin/sudo <<'EOF'
#!/bin/sh
if [ "$1" = -V ]; then printf 'Sudo version 1.9.5p2\nSudoers policy plugin version 1.9.5p2\nSudoers file grammar version 48\n'; exit 0; fi
exec /usr/bin/sudo "$@"
EOF
chmod 0755 /usr/local/bin/sudo
if [ -d /fixture/real-validator ]; then
  cp /etc/sudoers /fixture/sudoers-original
  if [ -e /etc/sudo.conf ]; then cp /etc/sudo.conf /fixture/sudo-conf-original; fi
  for problem in custom-policy same-symbol path ldap malformed-include missing-include; do
    reset_fixture
    cp /fixture/sudoers-original /etc/sudoers
    printf '# default stock sudoers configuration\n' > /etc/sudo.conf
    case "$problem" in
      custom-policy) printf 'Plugin custom_policy custom.so\n' > /etc/sudo.conf;;
      same-symbol) printf 'Plugin sudoers_policy custom.so\n' > /etc/sudo.conf;;
      path) printf 'Path plugin_dir /untrusted\n' > /etc/sudo.conf;;
      ldap) printf 'sudoers: files ldap\n' >> /etc/nsswitch.conf;;
      malformed-include) printf '@include /etc/fixture-bad-policy\n' >> /etc/sudoers; printf 'invalid sudoers syntax =\n' > /etc/fixture-bad-policy;;
      missing-include) printf '@include /etc/fixture-missing-file\n' >> /etc/sudoers;;
    esac
    expect_failure
    no_mutations
    awk '$1 != "sudoers:" {print}' /etc/nsswitch.conf > /fixture/nsswitch-clean
    cp /fixture/nsswitch-clean /etc/nsswitch.conf
    rm -f /etc/fixture-bad-policy
  done
  reset_fixture
  cp /fixture/sudoers-original /etc/sudoers
  printf '# stock default policy\n' > /etc/sudo.conf
  printf '@includedir /etc/fixture-missing-dir\n' >> /etc/sudoers
  TMPDIR=/stage sh /src/install.sh > /tmp/result 2>&1 || fail 'upstream missing unrelated includedir semantics rejected'
  test ! -e /etc/fixture-missing-dir || fail 'installer created unrelated includedir'
  cmp /usr/local/bin/askdo /fixture/release/askdo-linux-amd64 || fail 'real-checker install client differs'
  if grep -E 'forbidden-go|forbidden-compiler' /fixture/calls; then fail 'real checker destination compiled'; fi
  cp /fixture/sudoers-original /etc/sudoers
  # Positive explicit conventional stock symbols/options as well as defaults.
  printf 'Plugin sudoers_policy sudoers.so sudoers_file=/etc/sudoers sudoers_uid=0 sudoers_gid=0 sudoers_mode=0440\nPlugin sudoers_io sudoers.so\nPlugin sudoers_audit sudoers.so\n' > /etc/sudo.conf
  reset_fixture
  TMPDIR=/stage sh /src/install.sh > /tmp/result 2>&1 || fail 'real checker stock plugin configuration failed'
  # Role creation is expected here; compiler execution never is.
  if grep -E 'forbidden-go|forbidden-compiler' /fixture/calls; then fail 'real checker destination compiled'; fi
  if [ -f /fixture/sudo-conf-original ]; then cp /fixture/sudo-conf-original /etc/sudo.conf; else rm /etc/sudo.conf; fi
  reset_fixture
fi
TMPDIR=/stage sh /src/install.sh > /tmp/result 2>&1 || fail 'verified validator adapter on noexec download staging failed'
test -z "$(find /usr/local/libexec -name '.askdo-validate.*' -print)" || fail 'validator staging retained after success'
# A staged validator directory with unrelated additions cannot be recursively
# erased to force cleanup; the installation fails and retains the journal.
reset_fixture
touch /fixture/validator-foreign
expect_failure
grep -q 'validator cleanup incomplete' /tmp/result || fail 'foreign validator staging not retained/reported'
test -n "$(find /usr/local/libexec -path '*/.askdo-validate.*/foreign' -print)" || fail 'foreign validator staging content erased'
rm /fixture/validator-foreign
find /usr/local/libexec -maxdepth 1 -name '.askdo-validate.*' -exec rm -rf '{}' ';'
rm /usr/local/bin/sudo
mv /usr/sbin/visudo.saved /usr/sbin/visudo
reset_fixture
mv /usr/bin/python3 /usr/bin/python3.saved
expect_failure
grep -q 'vendor /usr/bin/python3 required' /tmp/result || fail 'missing Python diagnostic'
test ! -s /fixture/calls || fail 'missing Python built or mutated'
mv /usr/bin/python3.saved /usr/bin/python3
for flag in acl-unknown acl-permission group-permission user-permission unknown-absence wrong-absence-class; do
  reset_fixture
  touch "/fixture/$flag"
  expect_failure
  no_mutations
done
# Actual POSIX extended ACL data, not a shimmed xattr result.
reset_fixture
/usr/bin/python3 -I -S - <<'PY'
import os, struct
entries = [(1,7,0xffffffff),(2,4,65534),(4,5,0xffffffff),(16,5,0xffffffff),(32,5,0xffffffff)]
os.setxattr('/usr/local/libexec', 'system.posix_acl_access', struct.pack('<I',2) + b''.join(struct.pack('<HHI',*e) for e in entries))
PY
expect_failure
no_mutations
/usr/bin/python3 -I -S -c "import os; os.removexattr('/usr/local/libexec', 'system.posix_acl_access')"
for flag in enabled bad-uid duplicate-user wrong-name; do
  reset_fixture
  /usr/sbin/groupadd askdo
  /usr/sbin/groupadd askdo-review
  /usr/sbin/useradd -g users -d /var/lib/askdo-review -s /usr/sbin/nologin askdo-review
  uid=$(id -u askdo-review)
  touch "/fixture/$flag"
  expect_failure
  no_mutations
  test "$(id -u askdo-review)" = "$uid" || fail 'unsafe existing account modified'
done
for flag in bad-gid duplicate-group; do
  reset_fixture
  /usr/sbin/groupadd askdo
  touch "/fixture/$flag"
  expect_failure
  no_mutations
done
for group in askdo administrators; do
  reset_fixture
  /usr/sbin/groupadd askdo
  /usr/sbin/groupadd askdo-review
  /usr/sbin/groupadd administrators 2>/dev/null || :
  /usr/sbin/useradd -g users -G "$group" -s /usr/sbin/nologin askdo-review
  expect_failure
  no_mutations
done
for collision in uid gid; do
  reset_fixture
  /usr/sbin/groupadd askdo
  /usr/sbin/groupadd askdo-review
  /usr/sbin/useradd -g users -s /usr/sbin/nologin askdo-review
  if [ "$collision" = uid ]; then
    /usr/sbin/useradd -o -u "$(id -u askdo-review)" -s /usr/sbin/nologin collision-user
  else
    /usr/sbin/groupadd -o -g "$(/usr/bin/getent group askdo-review | cut -d: -f3)" collision-group
  fi
  expect_failure
  no_mutations
  /usr/sbin/userdel collision-user 2>/dev/null || :
  /usr/sbin/groupdel collision-group 2>/dev/null || :
done
# Partial failed native adds are NEVER adopted or deleted even if NSS appeared.
for flag in fail-add-askdo fail-add-askdo-review fail-user-add; do
  reset_fixture
  touch "/fixture/$flag"
  expect_failure
  grep -q 'rollback incomplete' /tmp/result || fail 'ambiguous creation discarded journal'
  if grep -E '^(user|group) del' /fixture/calls; then fail 'ambiguous creation blindly deleted'; fi
  /usr/bin/getent group askdo >/dev/null || fail 'ambiguous native state not retained'
done
reset_fixture
touch /fixture/bad-gid
expect_failure
grep -q 'rollback incomplete' /tmp/result || fail 'malformed post-create metadata adopted'
if grep -E '^(user|group) del' /fixture/calls; then fail 'unverified postcondition deleted'; fi
# Real visudo remains the parser; wrappers only inject specific failure phases.
for phase in staged existing committed; do
  reset_fixture
  cat > /usr/local/bin/visudo <<EOF
#!/bin/sh
case "\$1:$phase" in
 -cf:staged) exit 1;;
 -c:existing) if [ ! -e /etc/sudoers.d/askdo ]; then exit 1; fi;;
 -c:committed) if [ -e /etc/sudoers.d/askdo ]; then exit 1; fi;;
esac
exec /usr/sbin/visudo "\$@"
EOF
  chmod 0755 /usr/local/bin/visudo
  expect_failure
  if [ "$phase" = committed ]; then
    /usr/bin/getent passwd askdo-review >/dev/null && fail 'proven fresh reviewer not rolled back'
    /usr/bin/getent group askdo >/dev/null && fail 'proven fresh group not rolled back'
    test ! -e /var/lib/askdo-review && test ! -e /etc/askdo || fail 'new empty directories retained'
  else no_mutations; fi
done
reset_fixture
cat > /usr/local/bin/install <<'EOF'
#!/bin/sh
for last do :; done
if [ "$last" = /etc/systemd/system/askdo.service ]; then exit 1; fi
exec /usr/bin/install "$@"
EOF
chmod 0755 /usr/local/bin/install
expect_failure
# Absent failed unit and exact unchanged new assets permit proven role rollback.
if /usr/bin/getent passwd askdo-review >/dev/null; then fail 'unit failure retained proven fresh reviewer'; fi
test ! -e /var/lib/askdo-review || fail 'unit failure retained new empty home'
# Unknown added content, changed native identity, changed membership and changed
# installed binary each independently prevent deleting roles after a failure.
for change in content uid membership binary; do
  reset_fixture
  cat > /usr/local/bin/install <<EOF
#!/bin/sh
for last do :; done
if [ "\$last" = /etc/systemd/system/askdo.service ]; then
  case $change in
    content) echo foreign > /var/lib/askdo-review/foreign ;;
    uid) /usr/sbin/usermod -u 42424 askdo-review ;;
    membership) /usr/sbin/usermod -aG askdo nobody ;;
    binary) echo foreign > /usr/local/bin/askdo ;;
  esac
  exit 1
fi
exec /usr/bin/install "\$@"
EOF
  chmod 0755 /usr/local/bin/install
  expect_failure
  grep -q 'rollback incomplete' /tmp/result || fail 'changed dependency/identity lost journal'
  if grep -E '^(user|group) del' /fixture/calls; then fail 'changed ownership deleted identity'; fi
  /usr/bin/getent passwd askdo-review >/dev/null || fail 'changed identity not retained'
  /usr/sbin/gpasswd -d nobody askdo >/dev/null 2>&1 || :
done
reset_fixture
findmnt -no OPTIONS /stage | grep -qw noexec || fail 'fixture staging is not noexec'
TMPDIR=/stage sh /src/install.sh > /tmp/result 2>&1 || fail 'noexec staging install failed'
# Root stdin entry, unchanged local-source selector.
sh < /src/install.sh > /tmp/result 2>&1 || fail 'root piped entry failed'
# Actual non-root local and piped entry: sudo remains real and validates policy.
printf 'nobody ALL=(root) NOPASSWD: ALL\n' > /etc/sudoers.d/fixture-entry
chmod 0440 /etc/sudoers.d/fixture-entry
touch /tmp/fetch-urls
chmod 0666 /tmp/fetch-urls
/usr/sbin/runuser -u nobody -- env PATH="$PATH" sh /src/install.sh > /tmp/result 2>&1 || fail 'non-root local sudo entry failed'
/usr/sbin/runuser -u nobody -- env PATH="$PATH" sh < /src/install.sh > /tmp/result 2>&1 || fail 'non-root piped sudo entry failed'
grep -qx 'https://github.com/jeremyakers/askdo/releases/latest/download/install.sh' /tmp/fetch-urls || fail 'piped self release selector lost'
sh /src/install.sh --version fixture-ref > /tmp/result 2>&1 || fail 'explicit release tag entry failed'
grep -qx 'https://github.com/jeremyakers/askdo/releases/download/fixture-ref/install-manifest.v1' /tmp/fetch-urls || fail 'explicit release tag lost'
rm /etc/sudoers.d/fixture-entry
# DSM legacy cleanup retains groups without generic full NSS enumeration.
/usr/sbin/groupadd askdo-foreground
printf '%%askdo-foreground ALL=(root) NOPASSWD: /usr/local/libexec/askdo-launch ""\nDefaults!/usr/local/libexec/askdo-launch !use_pty\n' > /etc/sudoers.d/askdo-foreground
chmod 0440 /etc/sudoers.d/askdo-foreground
: > /fixture/calls
sh /src/install.sh > /tmp/result 2>&1 || fail 'DSM legacy migration failed'
test ! -e /etc/sudoers.d/askdo-foreground || fail 'legacy grant retained'
/usr/bin/getent group askdo-foreground >/dev/null || fail 'unproved native legacy group deleted'
no_mutations
/usr/sbin/groupdel askdo-foreground
reset_fixture
sh /src/install.sh > /tmp/result 2>&1 || fail 'final fresh DSM install failed'
uid=$(id -u askdo-review)
: > /fixture/calls
sh /src/uninstall.sh --purge --yes > /tmp/result 2>&1 || fail 'DSM purge failed'
grep -q 'retaining DSM identities' /tmp/result || fail 'missing native retention warning'
test "$(id -u askdo-review)" = "$uid" && test -d /var/lib/askdo-review || fail 'native identity/home purged'
no_mutations
printf 'DSM entry success/repeat/prerequisite/ACL/identity/rollback/purge matrix passed (adapters, not native proof)\n'
