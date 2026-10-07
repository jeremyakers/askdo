#!/bin/sh
# Build only upstream visudo + its static parser/utility archives OFFHOST.
# Usage: sh scripts/build-sudo-validator.sh NEW_OUTPUT_DIRECTORY [amd64|arm64]
# Requires rootless Docker and curl, never host compiler/packages/root mounts.
# arm64 delegates to the OFFHOST AMD64 cross helper with explicit container
# QEMU user mode; neither route registers binfmt or changes host namespaces.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
. "$ROOT/contrib/validator/source.env"
die() { printf '%s\n' "$*" >&2; exit 1; }
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then die "usage: $0 NEW_OUTPUT_DIRECTORY [amd64|arm64]"; fi
ARCH=${2:-amd64}
case "$ARCH" in amd64|arm64) ;; *) die "unsupported architecture: $ARCH" ;; esac
if [ "$ARCH" = arm64 ]; then
  exec sh "$ROOT/scripts/build-sudo-validator-arm64.sh" "$1"
fi
PARENT=$(dirname -- "$1")
[ -d "$PARENT" ] || die "output parent does not exist: $PARENT"
PARENT=$(CDPATH='' cd -- "$PARENT" && pwd -P)
BASE=$(basename -- "$1")
case "$BASE" in .|..|/) die "invalid output directory" ;; esac
OUT="$PARENT/$BASE"
if [ -e "$OUT" ] || [ -L "$OUT" ]; then die "output already exists: $OUT"; fi
case "$(docker info --format '{{json .SecurityOptions}}')" in
  *'"name=rootless"'*) ;; *) die "refusing non-rootless Docker" ;;
esac
STAGE=$(mktemp -d "$PARENT/.visudo-build.XXXXXX")
CONTAINER=
KEEP_STAGE=0
cleanup() {
  if [ -n "$CONTAINER" ]; then docker rm -f "$CONTAINER" >/dev/null 2>&1 || :; fi
  if [ "$KEEP_STAGE" = 0 ]; then rm -rf -- "$STAGE"; fi
}
trap cleanup 0
trap 'exit 1' 1 2 3 15
mkdir "$STAGE/inputs" "$STAGE/assets"
curl --fail --location --proto '=https' --tlsv1.2 --max-time 120 \
  --output "$STAGE/inputs/sudo.tar.gz" "$SUDO_URL"
printf '%s  %s\n' "$SUDO_SHA256" "$STAGE/inputs/sudo.tar.gz" | sha256sum -c -
curl --fail --location --proto '=https' --tlsv1.2 --max-time 120 \
  --output "$STAGE/inputs/musl.tar.gz" "$MUSL_NOTICE_URL"
printf '%s  %s\n' "$MUSL_NOTICE_SHA256" "$STAGE/inputs/musl.tar.gz" | sha256sum -c -
# A cached index may resolve to another platform; inspect success alone is
# not proof that the requested build image exists (especially on ARM64 hosts).
PLATFORM=$(docker image inspect "$VALIDATOR_IMAGE" --format '{{.Os}}/{{.Architecture}}' 2>/dev/null || :)
if [ "$PLATFORM" != "linux/$ARCH" ]; then
  docker pull --platform "linux/$ARCH" "$VALIDATOR_IMAGE"
  PLATFORM=$(docker image inspect "$VALIDATOR_IMAGE" --format '{{.Os}}/{{.Architecture}}')
  [ "$PLATFORM" = "linux/$ARCH" ] || die "pulled validator image platform $PLATFORM does not match linux/$ARCH"
fi
# Only public archives and fixed build metadata are copied in, never the repo,
# Docker socket, credentials or host /etc. Container root is namespace root.
CONTAINER=$(docker create --platform "linux/$ARCH" --network bridge \
  --cap-drop ALL --security-opt no-new-privileges \
  -e ARCH="$ARCH" -e IMAGE="$VALIDATOR_IMAGE" \
  "$VALIDATOR_IMAGE" sh -eu -c '
    export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1611416856
    case "$ARCH:$(uname -m)" in amd64:x86_64|arm64:aarch64) ;; *) exit 1 ;; esac
    apk add --no-cache build-base linux-headers file binutils
    # Fail instead of silently attaching a notice for a different libc.
    mkdir /work /out
    apk info -v > /out/visudo-PACKAGES
    grep -Fx "musl-1.2.5-r3" /out/visudo-PACKAGES
    grep -Fx "musl-dev-1.2.5-r3" /out/visudo-PACKAGES
    tar -xzf /tmp/sudo.tar.gz -C /work
    tar -xzf /tmp/musl.tar.gz -C /work
    cd /work/sudo-1.9.5p2
    export CFLAGS="-O2 -fno-ident"
    if [ "$ARCH" = amd64 ]; then CFLAGS="$CFLAGS -march=x86-64 -mtune=generic"; fi
    export LDFLAGS="-static -Wl,--build-id=none"
    # 1.9.5p2 does not implement --with-sudoers. Keep the explicit requested
    # path, but sysconfdir is what actually sets _PATH_SUDOERS in its Makefile.
    # Assert the generated path below rather than trust an ignored option.
    set -- --prefix=/work/prefix --sysconfdir=/etc --with-sudoers=/etc/sudoers \
      --with-sudoers-uid=0 --with-sudoers-gid=0 --with-sudoers-mode=0440 \
      --disable-shared-libutil --disable-shared --enable-static --disable-pie \
      --disable-nls --disable-log-server --disable-log-client --disable-zlib \
      --without-pam --without-ldap --without-selinux --without-linux-audit \
      --without-sssd --disable-openssl --disable-gcrypt
    printf "%s\n" "configure $*" "CFLAGS=$CFLAGS" "LDFLAGS=$LDFLAGS" \
      "visudo link adds libtool -all-static and -Wl,-Map,/out/visudo-link.map" > /out/visudo-BUILD
    if ! ./configure "$@" > /out/configure.log 2>&1; then
      cat /out/configure.log config.log; exit 1
    fi
    grep "unrecognized options" /out/configure.log || :
    grep -Fx "sysconfdir = /etc" plugins/sudoers/Makefile
    grep -Fx "sudoersdir = \$(sysconfdir)" plugins/sudoers/Makefile
    grep -F "_PATH_SUDOERS=" plugins/sudoers/Makefile
    grep -E "^#define SUDOERS_GRAMMAR_VERSION[[:space:]]+48$" plugins/sudoers/sudoers_version.h
    # Never make all, install, sudo, sudoers.so, PAM or runtime plugins.
    if ! make -C lib/util -j2 libsudo_util.la > /out/compile.log 2>&1 || \
       ! make -C plugins/sudoers -j2 visudo \
         LDFLAGS="$LDFLAGS -all-static -Wl,-Map,/out/visudo-link.map" >> /out/compile.log 2>&1; then
      cat /out/compile.log; exit 1
    fi
    test ! -e src/sudo
    test ! -e plugins/sudoers/sudoers.so
    cp plugins/sudoers/visudo "/out/visudo-linux-$ARCH"
    chmod 0755 "/out/visudo-linux-$ARCH"
    file "/out/visudo-linux-$ARCH" > /out/visudo-ELF
    readelf -h -l -d "/out/visudo-linux-$ARCH" >> /out/visudo-ELF
    if grep -E "INTERP|\(NEEDED\)" /out/visudo-ELF; then
      cat /out/visudo-ELF /out/compile.log; exit 1
    fi
    case "$ARCH" in
      amd64) grep -F "Advanced Micro Devices X86-64" /out/visudo-ELF ;;
      arm64) grep -F "AArch64" /out/visudo-ELF ;;
    esac
    "/out/visudo-linux-$ARCH" -V > /out/visudo-V.stdout 2> /out/visudo-V.stderr
    grep -Fx "visudo-linux-$ARCH version 1.9.5p2" /out/visudo-V.stdout
    grep -Fx "visudo-linux-$ARCH grammar version 48" /out/visudo-V.stdout
    test ! -s /out/visudo-V.stderr
    # Preserve full upstream notices, not a rewritten ISC-only summary.
    cp doc/LICENSE /out/visudo-LICENSE
    printf "\n===== musl 1.2.5 COPYRIGHT =====\n" >> /out/visudo-LICENSE
    cat /work/musl-1.2.5/COPYRIGHT >> /out/visudo-LICENSE
    # qsort is used by include-directory sorting; its MIT-style header is
    # separately retained. ARM64 string routines have Arm MIT notices.
    for f in src/stdlib/qsort.c src/string/aarch64/memcpy.S src/string/aarch64/memset.S; do
      printf "\n===== musl %s notice =====\n" "$f" >> /out/visudo-LICENSE
      sed -n "1,/^ \*\//p" "/work/musl-1.2.5/$f" >> /out/visudo-LICENSE
    done
    printf "\n===== GCC startup/runtime notice =====\n" >> /out/visudo-LICENSE
    cat /tmp/gcc-runtime-NOTICE >> /out/visudo-LICENSE
    apk info -v > /out/visudo-PACKAGES
    printf "%s\n" "image=$IMAGE" "architecture=$ARCH" \
      "targets=lib/util/libsudo_util.la plugins/sudoers/visudo" \
      "installation=none; artifact mode=0755; no capabilities or setuid" >> /out/visudo-BUILD
    cp /tmp/source.env /out/visudo-SOURCE
    printf "%s\n" "authentication=official independently published SHA-256 (SUDO_PROVENANCE)" \
      "tag_commit=informational lightweight tag, not signed authentication" \
      "musl=Alpine signed musl-dev 1.2.5 package; archive used for notices only" \
      "licenses=sudo doc/LICENSE; musl COPYRIGHT and qsort/Arm notices; GCC startup runtime exception" \
      "gcc_notice=https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html" \
      "scope=upstream check tool only, not sudo runtime or plugins" \
      "integration=use fixed -c -f STAGED then -c for effective policy; -f skips ownership/mode checks" \
      "unsupported=custom/nonstandard policy plugins (even if named sudoers_policy) and external NSS modules need installer rejection" \
      "upstream_limit=missing includedir and unreadable includedir entries may be skipped; required include fails" \
      "security=historical parser only; installer must not accept caller-supplied checker options or replace native sudo" >> /out/visudo-SOURCE
    cd /out
    sha256sum "visudo-linux-$ARCH" > "visudo-linux-$ARCH.sha256"
    sha256sum visudo-LICENSE > visudo-LICENSE.sha256
    sha256sum visudo-SOURCE > visudo-SOURCE.sha256
    cat visudo-ELF "visudo-linux-$ARCH.sha256"
  ')
docker cp "$STAGE/inputs/sudo.tar.gz" "$CONTAINER:/tmp/sudo.tar.gz"
docker cp "$STAGE/inputs/musl.tar.gz" "$CONTAINER:/tmp/musl.tar.gz"
docker cp "$ROOT/contrib/validator/source.env" "$CONTAINER:/tmp/source.env"
docker cp "$ROOT/contrib/validator/gcc-runtime-NOTICE" "$CONTAINER:/tmp/gcc-runtime-NOTICE"
START_RC=0
docker start --attach "$CONTAINER" || START_RC=$?
RC=$(docker inspect --format '{{.State.ExitCode}}' "$CONTAINER")
if [ "$RC" != 0 ] || [ "$START_RC" != 0 ]; then
  die "validator build container failed (exit $RC, Docker $START_RC); see output above"
fi
docker cp "$CONTAINER:/out/." "$STAGE/assets/"
# Tests use another fresh container with only this binary and fake policy data.
sh "$ROOT/scripts/test-sudo-validator.sh" "$STAGE/assets/visudo-linux-$ARCH" "$ARCH" \
  > "$STAGE/assets/visudo-TEST.log" 2>&1 || {
    KEEP_STAGE=1
    cat "$STAGE/assets/visudo-TEST.log"
    die "validator tests failed; unpublished diagnostic assets retained at $STAGE/assets"
  }
cat "$STAGE/assets/visudo-TEST.log"
if [ -e "$OUT" ] || [ -L "$OUT" ]; then die "output appeared during build: $OUT"; fi
mv -T -n -- "$STAGE/assets" "$OUT"
if [ -d "$STAGE/assets" ]; then die "output appeared during publication: $OUT"; fi
printf '%s\n' "standalone validator candidate: $OUT"
