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
cat >/etc/sudoers.d/hostmeta-fixture <<'RULES'
Defaults env_keep += "CANARY_DEFAULT"
alice,bob ALL=(root) NOPASSWD: /usr/bin/true "", /usr/bin/false CANARY_ARGUMENT
alice,bob ALL=(ALL:ALL) ALL
Defaults:opencode !authenticate
Defaults!/usr/bin/true !use_pty
opencode ALL=(root) ALL
opencode ALL=(root) PASSWD: /usr/bin/true ""
opencode ALL=(root) NOPASSWD: /usr/bin/true ""
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
ASKDO_HOSTMETA_ROOT_FIXTURE=1 /hostmeta.test -test.run '^TestRealSudo(Authentication)?RootFixture$' -test.v
cat >/etc/sudoers.d/scoped-fixture <<'RULES'
Defaults>root !authenticate
Defaults!/usr/bin/false !authenticate
RULES
chmod 0440 /etc/sudoers.d/scoped-fixture
visudo -c
LC_ALL=C /usr/bin/sudo -n -ll -U scopeduser
ASKDO_HOSTMETA_ROOT_FIXTURE=1 /hostmeta.test -test.run '^TestRealSudoScopedRootFixture$' -test.v
