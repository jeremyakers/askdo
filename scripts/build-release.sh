#!/bin/sh
# Build four Linux release binaries and their per-asset sha256sum files.
# Usage: scripts/build-release.sh [new-output-directory] (default: dist)
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-"$ROOT/dist"}
PARENT=$(dirname -- "$OUT")
test -d "$PARENT" || { echo "output parent does not exist: $PARENT" >&2; exit 1; }
PARENT=$(CDPATH='' cd -- "$PARENT" && pwd)
OUT="$PARENT/$(basename -- "$OUT")"
if [ -e "$OUT" ] || [ -L "$OUT" ]; then
  echo "release output already exists: $OUT" >&2
  exit 1
fi

# Stage the complete set beside the destination, then publish it together.
STAGE=$(mktemp -d "$PARENT/.askdo-release.XXXXXX")
trap 'rm -rf -- "$STAGE"' 0
trap 'exit 1' 1 2 3 15

for arch in amd64 arm64; do
  for name in askdo askdo-launch; do
    asset="$name-linux-$arch"
    (cd "$ROOT" && GOOS=linux GOARCH="$arch" CGO_ENABLED=0 GOTOOLCHAIN=local \
      go build -trimpath -o "$STAGE/$asset" "./cmd/$name")
    (cd "$STAGE" && sha256sum "$asset" > "$asset.sha256")
  done
done

if [ -e "$OUT" ] || [ -L "$OUT" ]; then
  echo "release output appeared during build: $OUT" >&2
  exit 1
fi
mv -T -- "$STAGE" "$OUT"
