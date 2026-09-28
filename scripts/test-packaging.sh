#!/bin/sh
# Disposable root only; no host installation or service control.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
exec docker run --rm -v "$ROOT:/src:ro" -w /src golang:1.27 sh -ec '
  export GOTOOLCHAIN=local ASKDO_SOURCE_DIR=/src
  apt-get update -qq >/dev/null && apt-get install -y -qq sudo >/dev/null
  printf "#!/bin/sh\nprintf \"%%s\\n\" \"\$*\" >> /tmp/systemctl-calls\ncase \"\$1\" in enable|start|restart|stop) exit 1;; is-active) exit 3;; esac\nexit 0\n" > /usr/local/bin/systemctl
  chmod +x /usr/local/bin/systemctl
  old=/etc/sudoers.d/askdo-foreground
  new=/etc/sudoers.d/askdo
  printf "%%askdo-foreground ALL=(root) NOPASSWD: /usr/local/libexec/askdo-launch \"\"\nDefaults!/usr/local/libexec/askdo-launch !use_pty\n" > /tmp/old-policy
  chmod 0440 /tmp/old-policy
  fail() { printf "%s\n" "$*" >&2; exit 1; }
  sh /src/install.sh
  test ! -e "$old" && ! getent group askdo-foreground || fail "fresh install created legacy grant/group"
  cmp "$new" /src/contrib/askdo.sudoers
  test "$(stat -c %a:%u:%g "$new")" = 440:0:0
  visudo -c >/dev/null
  test ! -s /tmp/systemctl-calls || ! grep -E "^(enable|start|restart|stop) " /tmp/systemctl-calls
  sh /src/uninstall.sh --purge --yes
  test ! -e "$new"
  mkdir -p /tmp/mock
  printf "#!/bin/sh\nprintf \"%%s\\n\" \"\$2\" >> /tmp/fetch-urls\nexit 1\n" > /tmp/mock/curl
  chmod +x /tmp/mock/curl
  if (cd /tmp && ASKDO_SOURCE_DIR= PATH="/tmp/mock:$PATH" sh /src/install.sh --version v999.0.0); then fail "missing source accepted"; fi
  grep -qx "https://codeload.github.com/jeremyakers/askdo/tar.gz/v999.0.0" /tmp/fetch-urls
  if grep -q "/releases/" /tmp/fetch-urls; then fail "release assets requested on source-only install"; fi
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
  printf "# admin edit\n" > "$new"
  sh /src/uninstall.sh
  test -e "$new" || fail "uninstall deleted unknown policy"
  cp /src/contrib/askdo.sudoers "$new"
  chmod 0440 "$new"
  sh /src/uninstall.sh --purge --yes
  test ! -e "$new"
  echo "packaging lifecycle passed"
'
