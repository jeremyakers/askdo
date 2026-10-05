#!/bin/sh
# Disposable container ONLY. /hostmeta.test is a CGO_ENABLED=0 binary.
set -eu
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo >/dev/null
# Ubuntu's base image reserves 1000; remove only its disposable image account.
if id ubuntu >/dev/null 2>&1; then userdel ubuntu; fi
useradd -u 1000 alice
useradd -u 1001 bob
useradd -u 1002 askdo
useradd -u 1003 opencode
groupadd exemptmeta
useradd -u 1004 -G exemptmeta exemptuser
useradd -u 1005 scopeduser
getent group askdo >/dev/null || groupadd -g 997 askdo
getent passwd launchuser >/dev/null || useradd -u 1007 -g askdo launchuser
mkdir -p /usr/local/libexec
printf '#!/bin/sh\nexit 0\n' >/usr/local/libexec/askdo-launch
chmod 0755 /usr/local/libexec/askdo-launch
cat >/etc/sudoers.d/hostmeta-fixture <<'RULES'
Defaults env_keep += "CANARY_DEFAULT"
alice,bob ALL=(root) NOPASSWD: /usr/bin/true "", /usr/bin/false CANARY_ARGUMENT
alice,bob ALL=(ALL:ALL) ALL
Defaults:opencode !authenticate
Defaults!/usr/bin/true !use_pty
# Deployed Ubuntu hosts list these exact scoped command Defaults lines, one
# carrying the single Unix glob wildcard used by GNU sudo 1.9 for the KDE stub.
Defaults!/usr/local/libexec/askdo-launch !use_pty
Defaults!/usr/lib/*/libexec/kf5/kdesu_stub !use_pty
opencode ALL=(root) ALL
opencode ALL=(root) PASSWD: /usr/bin/true ""
opencode ALL=(root) NOPASSWD: /usr/bin/true ""
# Canonical literal policy from the deployed hosts: empty argv only.
%askdo ALL=(root) NOPASSWD: /usr/local/libexec/askdo-launch ""
Defaults:exemptuser exempt_group=exemptmeta
exemptuser ALL=(root) PASSWD: ALL
scopeduser ALL=(root) PASSWD: ALL
RULES
chmod 0440 /etc/sudoers.d/hostmeta-fixture
visudo -c
sudo --version | head -1
LC_ALL=C /usr/bin/sudo -n -ll -U alice
LC_ALL=C /usr/bin/sudo -n -ll -U opencode
LC_ALL=C /usr/bin/sudo -n -ll -U exemptuser
LC_ALL=C /usr/bin/sudo -n -ll -U launchuser
ASKDO_HOSTMETA_ROOT_FIXTURE=1 /hostmeta.test -test.run '^TestRealSudo(Authentication)?RootFixture$' -test.v
ASKDO_HOSTMETA_ROOT_FIXTURE=1 /hostmeta.test -test.run '^TestRealSudoLegacyLaunchRootFixture$' -test.v
cat >/etc/sudoers.d/scoped-fixture <<'RULES'
Defaults>root !authenticate
Defaults!/usr/bin/false !authenticate
RULES
chmod 0440 /etc/sudoers.d/scoped-fixture
visudo -c
LC_ALL=C /usr/bin/sudo -n -ll -U scopeduser
ASKDO_HOSTMETA_ROOT_FIXTURE=1 /hostmeta.test -test.run '^TestRealSudoScopedRootFixture$' -test.v
