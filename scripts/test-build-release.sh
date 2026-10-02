#!/bin/sh
# Build into disposable storage; assert exactly the installer-facing release set.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TMPROOT=${TMPDIR:-/var/tmp}
test -d "$TMPROOT" || { echo "temporary parent is missing: $TMPROOT" >&2; exit 1; }
test "$(df -BG --output=avail "$TMPROOT" | tr -dc '0-9')" -ge 20 || {
  echo "$TMPROOT has less than 20 GiB free" >&2; exit 1;
}
TMP=$(mktemp -d "$TMPROOT/askdo-release-test.XXXXXX")
trap 'rm -rf -- "$TMP"' 0
trap 'exit 1' 1 2 3 15
OUT="$TMP/release"

"$ROOT/scripts/build-release.sh" "$OUT"

set -- "$OUT"/*
test "$#" -eq 8 || { echo "expected 8 release files, found $#" >&2; exit 1; }
for arch in amd64 arm64; do
  case "$arch" in
    amd64) machine='Advanced Micro Devices X86-64' ;;
    arm64) machine='AArch64' ;;
  esac
  for name in askdo askdo-launch; do
    asset="$name-linux-$arch"
    test -s "$OUT/$asset" && test -s "$OUT/$asset.sha256"
    test -x "$OUT/$asset"
    test "$(wc -l < "$OUT/$asset.sha256")" -eq 1
    actual=$(cd "$OUT" && sha256sum "$asset")
    test "$(cd "$OUT" && cat "$asset.sha256")" = "$actual" || {
      echo "checksum name or contents incorrect: $asset" >&2; exit 1;
    }
    (cd "$OUT" && sha256sum -c --status "$asset.sha256")
    readelf -h "$OUT/$asset" | grep -F "Machine:                           $machine" >/dev/null
    go version -m "$OUT/$asset" | grep -F 'CGO_ENABLED=0' >/dev/null
    if go version -m "$OUT/$asset" | grep -F 'askdo_fleet_fixture' >/dev/null; then
      echo "release asset carries the test-only fleet fixture tag: $asset" >&2; exit 1;
    fi
    echo "verified $asset $asset.sha256"
  done
done

# A second build into a populated release directory must not mix old/new assets.
before=$(cd "$OUT" && sha256sum ./* | sha256sum)
if "$ROOT/scripts/build-release.sh" "$OUT"; then
  echo 'accepted populated release directory' >&2
  exit 1
fi
after=$(cd "$OUT" && sha256sum ./* | sha256sum)
test "$before" = "$after" || { echo 'existing release contents changed' >&2; exit 1; }
echo 'release artifact matrix passed'
