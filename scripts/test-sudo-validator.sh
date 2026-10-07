#!/bin/sh
# Never executes the validator on the host or reads the host's policy.
# Usage: sh scripts/test-sudo-validator.sh /path/to/visudo-linux-ARCH [amd64|arm64]
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
. "$ROOT/contrib/validator/source.env"
die() { printf '%s\n' "$*" >&2; exit 1; }
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then die "usage: $0 VALIDATOR [amd64|arm64]"; fi
if [ ! -f "$1" ] || [ -L "$1" ]; then die "validator must be a regular non-symlink file"; fi
ARCH=${2:-amd64}
case "$ARCH" in amd64|arm64) ;; *) die "unsupported architecture: $ARCH" ;; esac
case "$(docker info --format '{{json .SecurityOptions}}')" in
  *'"name=rootless"'*) ;; *) die "refusing non-rootless Docker" ;;
esac
PLATFORM_IMAGE=$VALIDATOR_IMAGE
EXEC_PLATFORM="linux/$ARCH"
if [ "$ARCH" = arm64 ]; then
  # Exact AMD64 child of the official pinned Debian cross-build index. This
  # runs host-architecture QEMU explicitly, never an ARM64 shell via binfmt.
  PLATFORM_IMAGE=debian@sha256:a4672c0cb26fbdde88e38fa2dfb6c681942306680e41e4378b28770b6e79ee91
  EXEC_PLATFORM=linux/amd64
fi
docker image inspect "$PLATFORM_IMAGE" >/dev/null 2>&1 || docker pull --platform "$EXEC_PLATFORM" "$PLATFORM_IMAGE"
CONTAINER=
cleanup() { if [ -n "$CONTAINER" ]; then docker rm -f "$CONTAINER" >/dev/null 2>&1 || :; fi; }
trap cleanup 0
trap 'exit 1' 1 2 3 15
# CHOWN is only for fake metadata in the rootless namespace. No DAC_OVERRIDE,
# DAC_READ_SEARCH, SYS_PTRACE or setuid capabilities are given to the checker.
CONTAINER=$(docker create --platform "$EXEC_PLATFORM" --network bridge \
  --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges \
  -e ARCH="$ARCH" \
  "$PLATFORM_IMAGE" sh -eu -c '
    export LC_ALL=C
    if [ "$ARCH" = arm64 ]; then
      test "$(uname -m)" = x86_64
      export DEBIAN_FRONTEND=noninteractive
      printf "#!/bin/sh\nexit 101\n" > /usr/sbin/policy-rc.d
      chmod 0755 /usr/sbin/policy-rc.d
      apt-get -o APT::Sandbox::User=root update
      apt-get -o APT::Sandbox::User=root install -y --no-install-recommends qemu-user-static strace file binutils
      printf "execution=explicit qemu-aarch64-static user mode; host=%s kernel=%s; not native ARM64\n" "$(uname -m)" "$(uname -r)"
    else
      test "$(uname -m)" = x86_64
      apk add --no-cache strace file binutils
    fi
    checker() {
      if [ "$ARCH" = arm64 ]; then
        qemu-aarch64-static -0 validator /validator "$@"
      else
        /validator "$@"
      fi
    }
    chown 0:0 /validator
    chmod 0755 /validator
    expect() {
      label=$1; want=$2; shift 2
      rc=0; "$@" > /tmp/stdout 2> /tmp/stderr || rc=$?
      cat /tmp/stdout /tmp/stderr
      if [ "$rc" != "$want" ]; then
        printf "FAIL %s: wanted rc=%s got rc=%s\n" "$label" "$want" "$rc" >&2; exit 1
      fi
      printf "PASS %s rc=%s\n" "$label" "$rc"
    }
    # No DAC_OVERRIDE: explicitly make root-owned synthetic files writable
    # during fixture setup, and restore sudoers metadata before every check.
    put() {
      path=$1; shift
      if [ -e "$path" ]; then chmod 0644 "$path"; fi
      printf "%s\n" "$@" > "$path"
      chmod 0440 "$path"
    }
    checker -V > /tmp/version.out 2> /tmp/version.err
    grep -Fx "validator version 1.9.5p2" /tmp/version.out
    grep -Fx "validator grammar version 48" /tmp/version.out
    test ! -s /tmp/version.err
    printf "PASS version stdout/stderr\n"
    file /validator
    readelf -h -l -d /validator > /tmp/elf
    if grep -E "INTERP|\(NEEDED\)" /tmp/elf; then exit 1; fi
    case "$ARCH" in
      amd64) grep -F "Advanced Micro Devices X86-64" /tmp/elf ;;
      arm64) grep -F "AArch64" /tmp/elf ;;
    esac
    [ "$(stat -c %a /validator)" = 755 ]
    printf "PASS static ELF and ordinary 0755 checker\n"
    mkdir -m 0755 /fixture /fixture/d
    put /fixture/staged "root ALL=(ALL) ALL"
    chmod 0440 /fixture/staged
    expect staged-valid 0 checker -c -f /fixture/staged
    put /fixture/staged "root ALL=(ALL ALL"
    expect staged-invalid 1 checker -c -f /fixture/staged
    put /fixture/staged "root ALL=(ALL) ALL"
    put /etc/sudoers "root ALL=(ALL) ALL" "#include /fixture/required" "#includedir /fixture/d"
    put /fixture/required "root ALL=(ALL) /bin/true"
    put /fixture/d/10-valid "root ALL=(ALL) /bin/false"
    put /fixture/d/ignored.conf "this is invalid syntax"
    put /fixture/d/ignored~ "this is invalid syntax"
    chmod 0440 /etc/sudoers /fixture/required /fixture/d/*
    expect effective-valid-includes-exclusions 0 checker -c
    expect repeated-effective-valid 0 checker -c
    put /fixture/d/20-invalid "root ALL=(ALL ALL"
    chmod 0440 /fixture/d/20-invalid
    expect malformed-included-file 1 checker -c
    rm /fixture/d/20-invalid
    rm /fixture/required
    expect missing-required-include 1 checker -c
    put /fixture/required "root ALL=(ALL) /bin/true"
    chmod 0000 /fixture/required
    expect unreadable-required-include 1 checker -c
    chmod 0440 /fixture/required
    chmod 0666 /etc/sudoers
    expect effective-bad-mode 1 checker -c
    # Upstream -f checks syntax only, even for unsafe metadata; do not conceal it.
    expect staged-skips-metadata 0 checker -c -f /etc/sudoers
    chmod 0440 /etc/sudoers
    chown 123:0 /etc/sudoers
    expect effective-bad-owner 1 checker -c
    chown 0:0 /etc/sudoers
    expect effective-owner-mode-restored 0 checker -c
    chmod 0666 /fixture/d/10-valid
    expect included-bad-mode 1 checker -c
    chmod 0440 /fixture/d/10-valid
    chown 123:124 /fixture/d/10-valid
    # Without DAC_OVERRIDE upstream skips unreadable includedir entries.
    expect unreadable-includedir-entry-upstream-skipped 0 checker -c
    chown 123:0 /fixture/d/10-valid
    expect included-bad-owner 1 checker -c
    chown 0:0 /fixture/d/10-valid
    # The symbol is recognized without opening/loading the plugin module.
    put /fixture/effective "root ALL=(ALL) ALL"
    chmod 0440 /fixture/effective
    put /etc/sudoers "root ALL=(ALL ALL"
    put /etc/sudo.conf "Plugin sudoers_policy /path/nonexistentplugin.so sudoers_file=/fixture/effective sudoers_uid=0 sudoers_gid=0 sudoers_mode=0440"
    expect sudo-conf-effective-path 0 checker -c
    expect explicit-staged-overrides-plugin-path 0 checker -c -f /fixture/staged
    put /fixture/effective "root ALL=(ALL ALL"
    expect sudo-conf-effective-malformed 1 checker -c
    put /fixture/effective "root ALL=(ALL) ALL"
    put /etc/sudo.conf "Plugin sudoers_policy /path/nonexistentplugin.so sudoers_file=/fixture/effective sudoers_uid=123 sudoers_gid=124 sudoers_mode=0400"
    expect plugin-owner-mode-enforced 1 checker -c
    # Container root lacks DAC_OVERRIDE, so preserve namespace root read access
    # through gid 0 here, and test uid and gid options separately below.
    put /etc/sudo.conf "Plugin sudoers_policy /path/nonexistentplugin.so sudoers_file=/fixture/effective sudoers_uid=123 sudoers_gid=0 sudoers_mode=0440"
    chmod 0440 /fixture/effective
    chown 123:0 /fixture/effective
    expect plugin-uid-honored 0 checker -c
    put /etc/sudo.conf "Plugin sudoers_policy /path/nonexistentplugin.so sudoers_file=/fixture/effective sudoers_uid=0 sudoers_gid=124 sudoers_mode=0400"
    chown 0:124 /fixture/effective
    chmod 0400 /fixture/effective
    expect plugin-gid-mode-honored 0 checker -c
    expect plugin-config-repeat 0 checker -c
    if [ "$ARCH" = arm64 ]; then
      # Host trace captures translated guest file syscalls. Target executable
      # pathname appears in execve(QEMU argv) only; QEMU itself is static too.
      strace -f -e trace=%file -o /tmp/trace qemu-aarch64-static -0 validator /validator -c
    else
      strace -f -e trace=%file -o /tmp/trace /validator -c
    fi
    grep -F "\"/etc/sudo.conf\"" /tmp/trace
    grep -F "\"/fixture/effective\"" /tmp/trace
    if grep -E "nonexistentplugin|libsudo_util|libnss_|[.]so([.\"]|$)" /tmp/trace; then
      printf "FAIL unexpected runtime shared-library/plugin access\n" >&2; exit 1
    fi
    printf "PASS runtime sudo.conf read without plugin/libsudo_util/NSS modules\n"
    rm /etc/sudo.conf
    put /etc/sudoers "root ALL=(ALL) ALL" "#includedir /fixture/absent-directory"
    # Historical upstream allows an absent include directory. Measure honestly.
    expect missing-includedir-upstream-allowed 0 checker -c
    put /etc/sudo.conf "Plugin custom_policy /path/nonexistentplugin.so"
    # Upstream falls back to /etc/sudoers, not the custom policy language.
    # Installer integration MUST reject this configuration before using visudo.
    expect unknown-policy-upstream-fallback 0 checker -c
    printf "UNSUPPORTED custom/non-sudoers plugins: installer must fail closed\n"
    printf "UNSUPPORTED external NSS modules: musl uses local passwd/group, not host glibc NSS\n"
    printf "LIMIT upstream may skip missing directories/unreadable includedir entries\n"
    printf "PASS standalone validator synthetic matrix\n"
  ')
docker cp "$1" "$CONTAINER:/validator"
START_RC=0
docker start --attach "$CONTAINER" || START_RC=$?
RC=$(docker inspect --format '{{.State.ExitCode}}' "$CONTAINER")
if [ "$RC" != 0 ] || [ "$START_RC" != 0 ]; then
  die "validator test container failed (exit $RC, Docker $START_RC)"
fi
