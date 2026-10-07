#!/bin/sh
# OFFHOST only: AMD64 signed Debian cross GCC + source-built musl, explicit
# QEMU user mode. No binfmt registration or native ARM64 kernel claim.
# Usage: sh scripts/build-sudo-validator-arm64.sh NEW_OUTPUT_DIRECTORY
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
. "$ROOT/contrib/validator/source.env"
CROSS_INDEX=debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
CROSS_IMAGE=debian@sha256:a4672c0cb26fbdde88e38fa2dfb6c681942306680e41e4378b28770b6e79ee91
die() { printf '%s\n' "$*" >&2; exit 1; }
[ "$#" = 1 ] || die "usage: $0 NEW_OUTPUT_DIRECTORY"
PARENT=$(CDPATH='' cd -- "$(dirname -- "$1")" && pwd -P)
BASE=$(basename -- "$1")
case "$BASE" in .|..|/) die "invalid output directory" ;; esac
OUT="$PARENT/$BASE"
if [ -e "$OUT" ] || [ -L "$OUT" ]; then die "output already exists: $OUT"; fi
case "$(docker info --format '{{json .SecurityOptions}}')" in
  *'"name=rootless"'*) ;; *) die "refusing non-rootless Docker" ;;
esac
STAGE=$(mktemp -d "$PARENT/.visudo-cross.XXXXXX")
CONTAINER=
cleanup() { if [ -n "$CONTAINER" ]; then docker rm -f "$CONTAINER" >/dev/null 2>&1 || :; fi; }
trap cleanup 0
trap 'exit 1' 1 2 3 15
# Retain staging on any failure for exact compiler/QEMU diagnostics.
mkdir "$STAGE/inputs" "$STAGE/assets"
docker manifest inspect "$CROSS_INDEX" > "$STAGE/inputs/image-index.json"
jq -e --arg digest "${CROSS_IMAGE#*@}" '
  [.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64")]
  | length == 1 and .[0].digest == $digest' "$STAGE/inputs/image-index.json" >/dev/null
curl --fail --location --proto '=https' --tlsv1.2 --max-time 120 \
  --output "$STAGE/inputs/sudo.tar.gz" "$SUDO_URL"
printf '%s  %s\n' "$SUDO_SHA256" "$STAGE/inputs/sudo.tar.gz" | sha256sum -c -
curl --fail --location --proto '=https' --tlsv1.2 --max-time 120 \
  --output "$STAGE/inputs/musl.tar.gz" "$MUSL_NOTICE_URL"
printf '%s  %s\n' "$MUSL_NOTICE_SHA256" "$STAGE/inputs/musl.tar.gz" | sha256sum -c -
docker image inspect "$CROSS_IMAGE" >/dev/null 2>&1 || docker pull --platform linux/amd64 "$CROSS_IMAGE"
CONTAINER=$(docker create --platform linux/amd64 --network bridge --cap-drop ALL \
  --security-opt no-new-privileges -e IMAGE="$CROSS_IMAGE" -e INDEX="$CROSS_INDEX" \
  "$CROSS_IMAGE" sh -eu -c '
    export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1611416856 DEBIAN_FRONTEND=noninteractive
    test "$(uname -m)" = x86_64
    # No recommends: qemu-user-static registers no host binfmt service. Avoid
    # service starts even inside this disposable container during apt setup.
    printf "#!/bin/sh\nexit 101\n" > /usr/sbin/policy-rc.d
    chmod 0755 /usr/sbin/policy-rc.d
    # All capabilities remain dropped; apt stays namespace root rather than
    # trying _apt setuid/setgroups (not permitted by this container contract).
    apt-get -o APT::Sandbox::User=root update
    apt-get -o APT::Sandbox::User=root install -y --no-install-recommends build-essential gcc-aarch64-linux-gnu \
      qemu-user-static file binutils
    mkdir /work /out
    dpkg-query -W > /out/visudo-PACKAGES
    cp /tmp/image-index.json /out/visudo-IMAGE-INDEX.json
    # Archive publisher uid/gid are irrelevant to compilation; GNU tar root
    # defaults would require CHOWN, deliberately absent from build container.
    tar --no-same-owner -xzf /tmp/musl.tar.gz -C /work
    tar --no-same-owner -xzf /tmp/sudo.tar.gz -C /work
    cd /work/musl-1.2.5
    # Compiler and configure probes execute on AMD64; target code never relies
    # on host binfmt. Installed prefix is private to this disposable container.
    CC=aarch64-linux-gnu-gcc AR=aarch64-linux-gnu-ar RANLIB=aarch64-linux-gnu-ranlib \
      CFLAGS="-O2" ./configure --target=aarch64-linux-musl \
      --prefix=/work/musl --disable-shared --enable-wrapper=gcc > /out/musl-configure.log 2>&1
    if ! make -j2 > /out/musl-compile.log 2>&1; then cat /out/musl-compile.log; exit 1; fi
    make install >> /out/musl-compile.log 2>&1
    test -x /work/musl/bin/musl-gcc
    cd /work/sudo-1.9.5p2
    export REALGCC=aarch64-linux-gnu-gcc CC=/work/musl/bin/musl-gcc
    export CFLAGS="-O2 -fno-ident" LDFLAGS="-static -Wl,--build-id=none"
    BUILD=$(sh ./config.guess)
    set -- --build="$BUILD" --host=aarch64-linux-musl --prefix=/work/prefix \
      --sysconfdir=/etc --with-sudoers=/etc/sudoers --with-sudoers-uid=0 \
      --with-sudoers-gid=0 --with-sudoers-mode=0440 --disable-shared-libutil \
      --disable-shared --enable-static --disable-pie --disable-nls \
      --disable-log-server --disable-log-client --disable-zlib --without-pam \
      --without-ldap --without-selinux --without-linux-audit --without-sssd \
      --disable-openssl --disable-gcrypt
    printf "%s\n" "configure $*" "CC=$CC REALGCC=$REALGCC" "CFLAGS=$CFLAGS" \
      "LDFLAGS=$LDFLAGS" "image=$IMAGE" "image_index=$INDEX" \
      "selected_manifest=${IMAGE#*@}" "architecture=arm64" \
      "method=AMD64 cross GCC; source-built musl; explicit qemu-aarch64-static user mode" \
      "kernel=$(uname -r); execution_host=$(uname -m); not native ARM64 hardware/kernel" \
      "musl_configure=--target=aarch64-linux-musl --prefix=/work/musl --disable-shared --enable-wrapper=gcc CC=aarch64-linux-gnu-gcc AR=aarch64-linux-gnu-ar RANLIB=aarch64-linux-gnu-ranlib CFLAGS=-O2" \
      "visudo_link=$LDFLAGS -all-static -Wl,-Map,/out/visudo-link.map" > /out/visudo-BUILD
    if ! ./configure "$@" > /out/configure.log 2>&1; then cat /out/configure.log config.log; exit 1; fi
    grep -Fx "sysconfdir = /etc" plugins/sudoers/Makefile
    grep -Fx "sudoersdir = \$(sysconfdir)" plugins/sudoers/Makefile
    grep -F "_PATH_SUDOERS=" plugins/sudoers/Makefile
    grep -E "^#define SUDOERS_GRAMMAR_VERSION[[:space:]]+48$" plugins/sudoers/sudoers_version.h
    # Upstream recipes compile these ABI-dependent generators with target CC
    # but execute them directly. Generate with explicit QEMU before library
    # make, retaining normal dependency timestamps and unmodified source rules.
    printf "%s\n" "make -C lib/util -j2 mksigname mksiglist CFLAGS=$CFLAGS -static" \
      "qemu-aarch64-static lib/util/mksigname > lib/util/signame.c" \
      "qemu-aarch64-static lib/util/mksiglist > lib/util/siglist.c" >> /out/visudo-BUILD
    if ! make -C lib/util -j2 mksigname mksiglist CFLAGS="$CFLAGS -static" \
      > /out/generators-compile.log 2>&1; then cat /out/generators-compile.log; exit 1; fi
    for generator in mksigname mksiglist; do
      file "lib/util/$generator" >> /out/visudo-GENERATORS-ELF
      readelf -h -l -d "lib/util/$generator" > /out/generator-elf.tmp
      grep -F AArch64 /out/generator-elf.tmp
      if grep -E "INTERP|\(NEEDED\)" /out/generator-elf.tmp; then exit 1; fi
      cat /out/generator-elf.tmp >> /out/visudo-GENERATORS-ELF
    done
    rm /out/generator-elf.tmp
    qemu-aarch64-static lib/util/mksigname > lib/util/signame.c
    qemu-aarch64-static lib/util/mksiglist > lib/util/siglist.c
    test -s lib/util/signame.c
    test -s lib/util/siglist.c
    sha256sum lib/util/mksigname lib/util/mksiglist lib/util/signame.c lib/util/siglist.c \
      > /out/visudo-GENERATORS.sha256
    cat /out/visudo-GENERATORS.sha256 >> /out/visudo-BUILD
    if ! make -C lib/util -j2 libsudo_util.la > /out/compile.log 2>&1 || \
       ! make -C plugins/sudoers -j2 visudo LDFLAGS="$LDFLAGS -all-static -Wl,-Map,/out/visudo-link.map" >> /out/compile.log 2>&1; then
      cat /out/compile.log; exit 1
    fi
    test ! -e src/sudo
    test ! -e plugins/sudoers/sudoers.so
    cp plugins/sudoers/visudo /out/visudo-linux-arm64
    chmod 0755 /out/visudo-linux-arm64
    file /out/visudo-linux-arm64 > /out/visudo-ELF
    readelf -h -l -d /out/visudo-linux-arm64 >> /out/visudo-ELF
    grep -F AArch64 /out/visudo-ELF
    if grep -E "INTERP|\(NEEDED\)" /out/visudo-ELF; then exit 1; fi
    qemu-aarch64-static -0 visudo-linux-arm64 /out/visudo-linux-arm64 -V \
      > /out/visudo-V.stdout 2> /out/visudo-V.stderr
    grep -Fx "visudo-linux-arm64 version 1.9.5p2" /out/visudo-V.stdout
    grep -Fx "visudo-linux-arm64 grammar version 48" /out/visudo-V.stdout
    test ! -s /out/visudo-V.stderr
    cp doc/LICENSE /out/visudo-LICENSE
    printf "\n===== musl 1.2.5 COPYRIGHT =====\n" >> /out/visudo-LICENSE
    cat /work/musl-1.2.5/COPYRIGHT >> /out/visudo-LICENSE
    for f in src/stdlib/qsort.c src/string/aarch64/memcpy.S src/string/aarch64/memset.S; do
      printf "\n===== musl %s notice =====\n" "$f" >> /out/visudo-LICENSE
      sed -n "1,/^ \*\//p" "/work/musl-1.2.5/$f" >> /out/visudo-LICENSE
    done
    printf "\n===== GCC startup/runtime notice =====\n" >> /out/visudo-LICENSE
    cat /tmp/gcc-runtime-NOTICE >> /out/visudo-LICENSE
    cp /tmp/source.env /out/visudo-SOURCE
    printf "%s\n" "authentication=official independently published sudo SHA-256 (SUDO_PROVENANCE)" \
      "method=arm64-cross-explicit-qemu-user; no binfmt; not native ARM64 kernel" \
      "header_VALIDATOR_IMAGE=native AMD64 build default only; not actual cross image" \
      "cross_image=$IMAGE" "cross_image_index=$INDEX" "selected_manifest=${IMAGE#*@}" \
      "musl=1.2.5 compiled from MUSL_NOTICE_URL archive matching MUSL_NOTICE_SHA256; not Alpine package" \
      "musl_authentication=content pin; not independently verified release signature" \
      "toolchain=Debian signed apt gcc-aarch64-linux-gnu; inventory in visudo-PACKAGES" \
      "qemu=build/test tool only; not redistributed or destination dependency" \
      "scope=upstream checker only; no sudo runtime, PAM or plugins" \
      "integration=fixed staged -c -f then effective -c; reject nonstandard policy/NSS" \
      "upstream_limit=-f skips metadata; missing includedir/unreadable entries may be skipped" >> /out/visudo-SOURCE
    cd /out
    sha256sum visudo-linux-arm64 > visudo-linux-arm64.sha256
    sha256sum visudo-LICENSE > visudo-LICENSE.sha256
    sha256sum visudo-SOURCE > visudo-SOURCE.sha256
    cat visudo-ELF visudo-linux-arm64.sha256
  ')
docker cp "$STAGE/inputs/sudo.tar.gz" "$CONTAINER:/tmp/sudo.tar.gz"
docker cp "$STAGE/inputs/musl.tar.gz" "$CONTAINER:/tmp/musl.tar.gz"
docker cp "$STAGE/inputs/image-index.json" "$CONTAINER:/tmp/image-index.json"
docker cp "$ROOT/contrib/validator/source.env" "$CONTAINER:/tmp/source.env"
docker cp "$ROOT/contrib/validator/gcc-runtime-NOTICE" "$CONTAINER:/tmp/gcc-runtime-NOTICE"
START_RC=0
docker start --attach "$CONTAINER" || START_RC=$?
RC=$(docker inspect --format '{{.State.ExitCode}}' "$CONTAINER")
docker cp "$CONTAINER:/out/." "$STAGE/assets/" || :
if [ "$RC" != 0 ] || [ "$START_RC" != 0 ]; then die "cross build failed ($RC, Docker $START_RC); evidence $STAGE"; fi
sh "$ROOT/scripts/test-sudo-validator.sh" "$STAGE/assets/visudo-linux-arm64" arm64 \
  > "$STAGE/assets/visudo-TEST.log" 2>&1 || { cat "$STAGE/assets/visudo-TEST.log"; die "cross tests failed; evidence $STAGE"; }
cat "$STAGE/assets/visudo-TEST.log"
if [ -e "$OUT" ] || [ -L "$OUT" ]; then die "output appeared during build"; fi
mv -T -n -- "$STAGE/assets" "$OUT"
if [ -d "$STAGE/assets" ]; then die "output appeared during publication"; fi
rm -rf -- "$STAGE"
printf '%s\n' "ARM64 cross candidate (explicit user-mode emulation): $OUT"
