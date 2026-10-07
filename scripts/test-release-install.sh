#!/bin/sh
# Release-transfer contract red/green, no host installation or mounts.
set -eu
if [ "${1:-}" != --inside ]; then
  ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
  case "$(docker info --format '{{json .SecurityOptions}}')" in *'"name=rootless"'*) ;; *) exit 1;; esac
  C=$(docker create -w /src golang:1.27 sh /src/scripts/test-release-install.sh --inside)
  trap 'docker rm -f "$C" >/dev/null 2>&1 || :' EXIT
  git -C "$ROOT" ls-files -z | tar -C "$ROOT" --null -T - -cf - | docker cp - "$C:/src"
  docker cp "$ROOT/scripts" "$C:/src/"
  docker start -a "$C"
  exit "$(docker inspect --format '{{.State.ExitCode}}' "$C")"
fi
apt-get update -qq >/dev/null && apt-get install -y -qq sudo >/dev/null
sh scripts/test-install-release-fixture.sh
export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
printf '#!/bin/sh\ncase "$1" in is-active) exit 3;; daemon-reload|disable) exit 0;; *) exit 1;; esac\n' > /usr/local/bin/systemctl
chmod 0755 /usr/local/bin/systemctl
if ! sh /src/install.sh > /tmp/result 2>&1; then
  cat /tmp/result; cat /fixture/calls; exit 1
fi
cmp /usr/local/bin/askdo /fixture/release/askdo-linux-amd64
cmp /usr/local/libexec/askdo-launch /fixture/release/askdo-launch-linux-amd64
test ! -s /fixture/calls
grep -qx 'https://github.com/jeremyakers/askdo/releases/latest/download/install-manifest.v1' /tmp/fetch-urls
test "$(grep -c '/latest/' /tmp/fetch-urls)" = 1
printf 'release-download installer transfer passed; zero destination Go calls\n'
sh /src/uninstall.sh --purge --yes >/dev/null
cp /fixture/manifest /fixture/good-manifest
cp /fixture/release/askdo-linux-amd64 /fixture/good-binary
cp /fixture/release/install.sh /fixture/good-installer
cp /fixture/release/askdo-linux-amd64.sha256 /fixture/good-checksum
negative() {
  : > /fixture/calls
  if sh /src/install.sh "$@" > /tmp/result 2>&1; then cat /tmp/result; exit 1; fi
  test ! -e /etc/sudoers.d/askdo && test ! -e /etc/askdo
  test ! -s /fixture/calls
  if getent group askdo >/dev/null || getent passwd askdo-review >/dev/null; then exit 1; fi
}
for problem in header duplicate hash tag architecture unknown missing-source source traversal; do
  cp /fixture/good-manifest /fixture/manifest
  case "$problem" in
    header) awk 'NR==1 {$0="askdo-install-v2"} {print}' /fixture/good-manifest > /fixture/manifest ;;
    duplicate) printf 'release fixture-ref\n' >> /fixture/manifest ;;
    hash) awk '$1=="file" && $2=="askdo-linux-amd64" {$3="bad"} {print}' /fixture/good-manifest > /fixture/manifest ;;
    tag) awk '$1=="release" {$2="other-tag"} {print}' /fixture/good-manifest > /fixture/manifest ;;
    architecture) awk '$2!="askdo-linux-arm64" {print}' /fixture/good-manifest > /fixture/manifest ;;
    unknown) printf 'future-field dangerous\n' >> /fixture/manifest ;;
    missing-source) awk '$1!="source" {print}' /fixture/good-manifest > /fixture/manifest ;;
    source) awk '$1=="source" {$2="not-a-commit"} {print}' /fixture/good-manifest > /fixture/manifest ;;
    traversal) printf 'file ../unsafe deadbeef 1\n' >> /fixture/manifest ;;
  esac
  negative --version fixture-ref
done
cp /fixture/good-manifest /fixture/manifest
printf 'corruption\n' >> /fixture/release/askdo-linux-amd64
negative
cp /fixture/good-binary /fixture/release/askdo-linux-amd64
mv /fixture/release/askdo-linux-amd64.sha256 /fixture/missing-checksum
negative
mv /fixture/missing-checksum /fixture/release/askdo-linux-amd64.sha256
# Rebound wrong-architecture bytes still fail without executing the payload.
cp /fixture/release/askdo-linux-arm64 /fixture/release/askdo-linux-amd64
(cd /fixture/release && sha256sum askdo-linux-amd64 > askdo-linux-amd64.sha256)
for name in askdo-linux-amd64 askdo-linux-amd64.sha256; do
  hash=$(sha256sum "/fixture/release/$name" | cut -d' ' -f1)
  size=$(wc -c < "/fixture/release/$name")
  awk -v name="$name" -v hash="$hash" -v size="$size" '$1=="file" && $2==name {$3=hash; $4=size} {print}' /fixture/manifest > /fixture/update
  cp /fixture/update /fixture/manifest
done
negative
cp /fixture/good-binary /fixture/release/askdo-linux-amd64
cp /fixture/good-checksum /fixture/release/askdo-linux-amd64.sha256
cp /fixture/good-manifest /fixture/manifest
printf '# divergent release installer\n' >> /fixture/release/install.sh
hash=$(sha256sum /fixture/release/install.sh | cut -d' ' -f1)
size=$(wc -c < /fixture/release/install.sh)
awk -v hash="$hash" -v size="$size" '$1=="file" && $2=="install.sh" {$3=hash; $4=size} {print}' /fixture/manifest > /fixture/update
cp /fixture/update /fixture/manifest
negative
cp /fixture/good-installer /fixture/release/install.sh
cp /fixture/good-manifest /fixture/manifest
ASKDO_SOURCE_DIR=/src negative
negative --version main
negative --version v999.0.0
: > /tmp/fetch-urls
sh /src/install.sh --version fixture-ref >/tmp/result 2>&1
test "$(grep -c '/latest/' /tmp/fetch-urls || :)" = 0
cmp /usr/local/bin/askdo /fixture/release/askdo-linux-amd64
test ! -s /fixture/calls
printf 'release manifest/tag/hash/size/architecture/self-binding negatives passed before mutation\n'
