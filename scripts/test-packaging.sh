#!/bin/sh
# Disposable root only; no host installation or service control.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
if [ "${1:-}" != --inside ]; then
  case "$(docker info --format '{{json .SecurityOptions}}')" in *'"name=rootless"'*) ;; *) exit 1;; esac
  C=$(docker create -w /src golang:1.27 sh /src/scripts/test-packaging.sh --inside)
  trap 'docker rm -f "$C" >/dev/null 2>&1 || :' EXIT
  git -C "$ROOT" ls-files -z | tar -C "$ROOT" --null -T - -cf - | docker cp - "$C:/src"
  docker cp "$ROOT/scripts" "$C:/src/"
  docker start -a "$C"
  exit "$(docker inspect --format '{{.State.ExitCode}}' "$C")"
fi
exec sh -ec '
  export GOTOOLCHAIN=local
  apt-get update -qq >/dev/null && apt-get install -y -qq sudo >/dev/null
  sh /src/scripts/test-install-release-fixture.sh
  export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  printf "#!/bin/sh\nprintf \"%%s\\n\" \"\$*\" >> /tmp/systemctl-calls\nif [ \"\$1\" = is-active ] && [ \"\$3\" = askdo-gateway.service ]; then [ -e /tmp/gw-active ] && exit 0 || exit 3; fi\nif [ \"\$1\" = disable ] && [ \"\$3\" = askdo-gateway.service ]; then rm -f /tmp/gw-active; fi\ncase \"\$1\" in enable|start|restart|stop) exit 1;; is-active) exit 3;; esac\nexit 0\n" > /usr/local/bin/systemctl
  chmod +x /usr/local/bin/systemctl
  old=/etc/sudoers.d/askdo-foreground
  new=/etc/sudoers.d/askdo
  printf "%%askdo-foreground ALL=(root) NOPASSWD: /usr/local/libexec/askdo-launch \"\"\nDefaults!/usr/local/libexec/askdo-launch !use_pty\n" > /tmp/old-policy
  chmod 0440 /tmp/old-policy
  fail() { printf "%s\n" "$*" >&2; exit 1; }
  sh /src/install.sh
  cmp /usr/local/bin/askdo /fixture/release/askdo-linux-amd64
  cmp /usr/local/libexec/askdo-launch /fixture/release/askdo-launch-linux-amd64
  test ! -s /fixture/calls || fail "destination compiler invoked"
  test ! -e "$old" && ! getent group askdo-foreground || fail "fresh install created legacy grant/group"
  cmp "$new" /src/contrib/askdo.sudoers
  test "$(stat -c %a:%u:%g "$new")" = 440:0:0
  cmp /etc/systemd/system/askdo-gateway.service /src/contrib/askdo-gateway.service
  test "$(stat -c %a:%u:%g /etc/systemd/system/askdo-gateway.service)" = 644:0:0
  cmp /etc/askdo/examples/gateway-config.example.json /src/examples/fleet/gateway-config.example.json
  cmp /etc/askdo/examples/host-config.example.json /src/examples/fleet/host-config.example.json
  test "$(stat -c %a:%u:%g /etc/askdo/examples/gateway-config.example.json)" = 444:0:0
  test "$(stat -c %a:%u:%g /etc/askdo/examples/host-config.example.json)" = 444:0:0
  test ! -e /etc/askdo-gateway || fail "installer created gateway server state"
  visudo -c >/dev/null
  test ! -s /tmp/systemctl-calls || ! grep -E "^(enable|start|restart|stop) " /tmp/systemctl-calls
  printf "# foreign unit\n" > /etc/systemd/system/askdo-gateway.service
  if sh /src/install.sh; then fail "differing gateway unit overwritten"; fi
  grep -qx "# foreign unit" /etc/systemd/system/askdo-gateway.service || fail "foreign gateway unit modified"
  cp /src/contrib/askdo-gateway.service /etc/systemd/system/askdo-gateway.service
  install -d -m 0700 /etc/askdo-gateway
  printf "server-state-marker\n" > /etc/askdo-gateway/config.json
  install -d -m 0700 /var/lib/askdo-gateway
  printf "db-marker\n" > /var/lib/askdo-gateway/gateway.db
  mv /var/lib/askdo-gateway /var/lib/askdo-gateway.real
  ln -s /var/lib/askdo-gateway.real /var/lib/askdo-gateway
  if sh /src/uninstall.sh --purge --yes; then fail "symlinked gateway state dir purged"; fi
  test -f /var/lib/askdo-gateway.real/gateway.db || fail "symlink target harmed"
  rm /var/lib/askdo-gateway
  chown 65534:65534 /var/lib/askdo-gateway.real
  mv /var/lib/askdo-gateway.real /var/lib/askdo-gateway
  if sh /src/uninstall.sh --purge --yes; then fail "foreign-owned gateway state dir purged"; fi
  test -f /var/lib/askdo-gateway/gateway.db || fail "foreign-owned dir harmed"
  chown 0:0 /var/lib/askdo-gateway
  sh /src/uninstall.sh --purge --yes
  test ! -e "$new"
  test ! -e /etc/systemd/system/askdo-gateway.service || fail "recognized gateway unit retained"
  test ! -e /etc/askdo-gateway || fail "purge kept gateway server state"
  test ! -e /var/lib/askdo-gateway || fail "purge kept gateway database"
  mkdir -p /tmp/mock
  printf "#!/bin/sh\nfor arg do case \"\$arg\" in https://*) printf \"%%s\\n\" \"\$arg\" >> /tmp/missing-release-urls;; esac; done\nexit 1\n" > /tmp/mock/curl
  chmod +x /tmp/mock/curl
  if (cd /tmp && PATH="/tmp/mock:$PATH" sh /src/install.sh --version v999.0.0); then fail "missing release accepted"; fi
  grep -qx "https://github.com/jeremyakers/askdo/releases/download/v999.0.0/install-manifest.v1" /tmp/missing-release-urls
  if grep -q "codeload" /tmp/missing-release-urls; then fail "source fallback requested"; fi
  rm /tmp/mock/curl
  printf "#!/bin/sh\nif [ \"\$1\" = -c ] && [ -e /etc/sudoers.d/askdo ]; then exit 1; fi\nexec /usr/sbin/visudo \"\$@\"\n" > /tmp/mock/visudo
  chmod +x /tmp/mock/visudo
  if PATH="/tmp/mock:$PATH" sh /src/install.sh; then fail "fresh visudo failure accepted"; fi
  rm /tmp/mock/visudo
  test ! -e "$new" && test ! -e /usr/local/libexec/askdo-launch && test ! -e /usr/local/bin/askdo || fail "fresh rollback left a grant or binaries"
  getent group askdo >/dev/null || groupadd --system askdo
  useradd --system -G askdo --shell /usr/sbin/nologin askdo-member-a
  useradd --system -G askdo --shell /usr/sbin/nologin askdo-member-b
  useradd --system --shell /usr/sbin/nologin outsider
  groupadd -g 989 askdo-foreground
  useradd --system --gid askdo-foreground --shell /usr/sbin/nologin legacy-primary
  useradd --system -G askdo-foreground --shell /usr/sbin/nologin legacy-supp
  cp /tmp/old-policy "$old"
  install -d -m 0755 /usr/local/libexec
  printf "#!/bin/sh\n# legacy helper marker\nexit 0\n" > /tmp/legacy-helper
  printf "#!/bin/sh\n# legacy client marker\nexit 0\n" > /tmp/legacy-client
  install -m 0755 /tmp/legacy-helper /usr/local/libexec/askdo-launch
  install -m 0755 /tmp/legacy-client /usr/local/bin/askdo
  printf "# legacy service marker\n" > /etc/systemd/system/askdo.service
  cp /etc/systemd/system/askdo.service /tmp/legacy-service
  check_old_install() {
    cmp /usr/local/libexec/askdo-launch /tmp/legacy-helper || fail "legacy helper bytes changed"
    cmp /usr/local/bin/askdo /tmp/legacy-client || fail "legacy client bytes changed"
    cmp /etc/systemd/system/askdo.service /tmp/legacy-service || fail "legacy service bytes changed"
    test "$(stat -c %a:%u:%g /usr/local/libexec/askdo-launch)" = 755:0:0 || fail "legacy helper metadata changed"
    test "$(stat -c %a:%u:%g /usr/local/bin/askdo)" = 755:0:0 || fail "legacy client metadata changed"
    test "$(stat -c %a:%u:%g /etc/systemd/system/askdo.service)" = 644:0:0 || fail "legacy service metadata changed"
    cmp "$old" /tmp/old-policy || fail "legacy policy changed"
    test ! -e "$new" || fail "new grant retained after failed install"
    visudo -c >/dev/null || fail "effective old sudoers invalid"
  }
  uid1=$(id -u askdo-member-a); uid2=$(id -u askdo-member-b)
  chmod 0777 /usr/local/libexec/askdo-launch
  if sh /src/install.sh; then fail "writable legacy helper accepted"; fi
  cmp "$old" /tmp/old-policy
  test ! -e "$new"
  chmod 0755 /usr/local/libexec/askdo-launch
  check_old_install
  printf "# edited\n" > "$old"
  if sh /src/install.sh; then fail "edited legacy policy accepted"; fi
  test ! -e "$new" && test "$(id -u askdo-member-a)" = "$uid1"
  cp /tmp/old-policy "$old"
  for failure in staged dual removed dual removed dual removed; do
    printf "#!/bin/sh\ncase \"\$1:$failure\" in -cf:staged) exit 1;; -c:dual) if [ -e /etc/sudoers.d/askdo ] && [ -e /etc/sudoers.d/askdo-foreground ]; then exit 1; fi;; -c:removed) if [ -e /etc/sudoers.d/askdo ] && [ ! -e /etc/sudoers.d/askdo-foreground ]; then exit 1; fi;; esac\nexec /usr/sbin/visudo \"\$@\"\n" > /tmp/mock/visudo
    chmod +x /tmp/mock/visudo
    if PATH="/tmp/mock:$PATH" sh /src/install.sh; then fail "injected $failure visudo failure accepted"; fi
    rm /tmp/mock/visudo
    check_old_install
  done
  sh /src/install.sh
  test ! -e "$old" && test -e "$new"
  cmp "$new" /src/contrib/askdo.sudoers
  test "$(id -u askdo-member-a)" = "$uid1" && test "$(id -u askdo-member-b)" = "$uid2"
  id -nG askdo-member-a | grep -qw askdo
  id -nG askdo-member-b | grep -qw askdo
  getent group askdo-foreground >/dev/null || fail "populated legacy group deleted"
  test "$(id -g legacy-primary)" = 989
  if sudo -l -U legacy-supp /usr/local/libexec/askdo-launch >/dev/null 2>&1; then fail "legacy group retained helper grant"; fi
  userdel legacy-primary
  userdel legacy-supp
  cp /tmp/old-policy "$old"
  cp /usr/local/bin/askdo /tmp/current-client
  cp /usr/local/libexec/askdo-launch /tmp/current-helper
  printf "#!/bin/sh\nif [ \"\$1\" = -c ] && [ -e /etc/sudoers.d/askdo ] && [ -e /etc/sudoers.d/askdo-foreground ]; then exit 1; fi\nexec /usr/sbin/visudo \"\$@\"\n" > /tmp/mock/visudo
  chmod +x /tmp/mock/visudo
  if PATH="/tmp/mock:$PATH" sh /src/install.sh; then fail "dual-policy failure accepted"; fi
  rm /tmp/mock/visudo
  cmp /usr/local/bin/askdo /tmp/current-client
  cmp /usr/local/libexec/askdo-launch /tmp/current-helper
  cmp "$old" /tmp/old-policy
  cmp "$new" /src/contrib/askdo.sudoers
  visudo -c >/dev/null
  sh /src/install.sh
  test ! -e "$old" && ! getent group askdo-foreground || fail "exact dual policy recovery failed"
  visudo -c >/dev/null
  sudo -l -U askdo-member-a /usr/local/libexec/askdo-launch >/dev/null
  if sudo -l -U outsider /usr/local/libexec/askdo-launch >/dev/null 2>&1; then fail "outsider granted helper"; fi
  sh /src/install.sh
  test ! -e "$old"
  cmp /etc/systemd/system/askdo-gateway.service /src/contrib/askdo-gateway.service || fail "reinstall changed gateway unit"
  printf "# admin edit\n" > "$new"
  printf "# admin edit\n" > /etc/systemd/system/askdo-gateway.service
  install -d -m 0700 /etc/askdo-gateway
  printf "credentials-marker\n" > /etc/askdo-gateway/signing.key
  printf "credentials-marker\n" > /tmp/gw-marker
  install -d -m 0700 /var/lib/askdo-gateway
  printf "db-marker\n" > /var/lib/askdo-gateway/gateway.db
  printf "db-marker\n" > /tmp/gw-db-marker
  # An edited (unrecognized) gateway unit shares ExecStart=/usr/local/bin/askdo
  # with the main install, so uninstall must refuse before ANY service control
  # or removal, leaving every artifact byte- and metadata-identical; plain and
  # --purge --yes are refused identically.
  cp /etc/systemd/system/askdo.service /tmp/snap-service
  cp /usr/local/bin/askdo /tmp/snap-client
  cp /usr/local/libexec/askdo-launch /tmp/snap-helper
  getent group askdo > /tmp/snap-group
  touch /tmp/gw-active
  check_refused_uninstall() {
    test ! -s /tmp/systemctl-calls || fail "service control attempted before gateway unit refusal"
    cmp /etc/systemd/system/askdo.service /tmp/snap-service || fail "askdo unit changed by refused uninstall"
    test "$(stat -c %a:%u:%g /etc/systemd/system/askdo.service)" = 644:0:0 || fail "askdo unit metadata changed"
    cmp /usr/local/bin/askdo /tmp/snap-client || fail "client binary changed by refused uninstall"
    test "$(stat -c %a:%u:%g /usr/local/bin/askdo)" = 755:0:0 || fail "client binary metadata changed"
    cmp /usr/local/libexec/askdo-launch /tmp/snap-helper || fail "helper changed by refused uninstall"
    test "$(stat -c %a:%u:%g /usr/local/libexec/askdo-launch)" = 755:0:0 || fail "helper metadata changed"
    grep -qx "# admin edit" "$new" || fail "unknown policy changed by refused uninstall"
    grep -qx "# admin edit" /etc/systemd/system/askdo-gateway.service || fail "foreign gateway unit changed"
    getent group askdo | cmp -s - /tmp/snap-group || fail "askdo group changed by refused uninstall"
    cmp /etc/askdo-gateway/signing.key /tmp/gw-marker || fail "gateway credentials changed by refused uninstall"
    cmp /var/lib/askdo-gateway/gateway.db /tmp/gw-db-marker || fail "gateway database changed by refused uninstall"
    test -e /tmp/gw-active || fail "gateway active state changed by refused uninstall"
  }
  : > /tmp/systemctl-calls
  if sh /src/uninstall.sh; then fail "uninstall proceeded with unrecognized gateway unit"; fi
  check_refused_uninstall
  : > /tmp/systemctl-calls
  if sh /src/uninstall.sh --purge --yes; then fail "purge proceeded with unrecognized gateway unit"; fi
  check_refused_uninstall
  # A recognized (shipped, byte-identical) active unit is disabled before removal.
  cp /src/contrib/askdo.sudoers "$new"
  chmod 0440 "$new"
  cp /src/contrib/askdo-gateway.service /etc/systemd/system/askdo-gateway.service
  : > /tmp/systemctl-calls
  sh /src/uninstall.sh
  grep -qx "disable --now askdo-gateway.service" /tmp/systemctl-calls || fail "recognized active gateway unit not disabled"
  test ! -e /etc/systemd/system/askdo-gateway.service || fail "recognized gateway unit retained"
  cmp /var/lib/askdo-gateway/gateway.db /tmp/gw-db-marker || fail "plain uninstall removed gateway database"
  rm -f /tmp/gw-active
  sh /src/uninstall.sh --purge --yes
  test ! -e "$new"
  test ! -e /etc/askdo-gateway || fail "purge kept gateway credentials"
  test ! -e /var/lib/askdo-gateway || fail "purge kept gateway database"
  echo "packaging lifecycle passed"
'
