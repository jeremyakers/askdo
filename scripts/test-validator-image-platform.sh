#!/bin/sh
# Focused image-acquisition behavior test; no Docker, network or compilation.
# Archive/checksum shims bypass download authentication ONLY in this mock phase.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' 0
trap 'exit 1' 1 2 3 15
mkdir "$TMP/bin"
cat > "$TMP/bin/curl" <<'SH'
#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then shift; : > "$1"; exit 0; fi
  shift
done
exit 90
SH
cat > "$TMP/bin/sha256sum" <<'SH'
#!/bin/sh
# Download integrity is outside this phase-only test's contract.
[ "$1" = -c ] || exit 90
cat >/dev/null
SH
cat > "$TMP/bin/docker" <<'SH'
#!/bin/sh
set -eu
printf '%s\n' "$1 $2" >> "$CASE_DIR/calls"
case "$1:$2" in
  info:--format) printf '["name=rootless"]\n' ;;
  image:inspect)
    if [ ! -f "$CASE_DIR/pulled" ]; then
      case "$CASE_NAME" in missing|pullfail) exit 1 ;; esac
    fi
    case "$*" in
      *'{{.Os}}/{{.Architecture}}'*) : > "$CASE_DIR/verified" ;;
      *) exit 0 ;;
    esac
    if [ "$CASE_NAME" = mismatch ] || { [ "$CASE_NAME" = wrong ] && [ ! -f "$CASE_DIR/pulled" ]; }; then
      printf 'linux/arm64\n'
    else
      printf 'linux/amd64\n'
    fi ;;
  pull:--platform)
    [ "$3" = linux/amd64 ] && [ "$4" = "$PINNED_IMAGE" ] || exit 91
    : > "$CASE_DIR/qualified-pull"
    [ "$CASE_NAME" != pullfail ] || exit 92
    : > "$CASE_DIR/pulled" ;;
  pull:*) : > "$CASE_DIR/unqualified-pull"; exit 93 ;;
  create:--platform)
    [ "$3" = linux/amd64 ] || exit 94
    [ -f "$CASE_DIR/verified" ] || exit 96
    if [ "$CASE_NAME" = mismatch ] || { [ "$CASE_NAME" = wrong ] && [ ! -f "$CASE_DIR/pulled" ]; }; then exit 97; fi
    : > "$CASE_DIR/create"
    # Stop before container creation/compilation; never fabricate build success.
    exit 71 ;;
  *) exit 95 ;;
esac
SH
chmod 0755 "$TMP/bin/"*
. "$ROOT/contrib/validator/source.env"
export PINNED_IMAGE=$VALIDATOR_IMAGE
FAIL=0
for CASE_NAME in correct wrong missing pullfail mismatch; do
  CASE_DIR="$TMP/$CASE_NAME"
  mkdir "$CASE_DIR"
  export CASE_NAME CASE_DIR
  RC=0
  PATH="$TMP/bin:$PATH" sh "$ROOT/scripts/build-sudo-validator.sh" "$CASE_DIR/output" amd64 \
    > "$CASE_DIR/output.log" 2>&1 || RC=$?
  OK=1
  case "$CASE_NAME" in
    correct) [ "$RC" = 71 ] && [ ! -f "$CASE_DIR/unqualified-pull" ] && [ -f "$CASE_DIR/verified" ] && [ -f "$CASE_DIR/create" ] || OK=0 ;;
    wrong|missing) [ "$RC" = 71 ] && [ -f "$CASE_DIR/qualified-pull" ] && [ -f "$CASE_DIR/verified" ] && [ -f "$CASE_DIR/create" ] || OK=0 ;;
    pullfail) [ "$RC" = 92 ] && [ -f "$CASE_DIR/qualified-pull" ] && [ ! -f "$CASE_DIR/create" ] || OK=0 ;;
    mismatch) [ "$RC" = 1 ] && [ -f "$CASE_DIR/qualified-pull" ] && [ ! -f "$CASE_DIR/create" ] || OK=0 ;;
  esac
  [ "$RC" != 0 ] || OK=0
  if [ "$OK" = 1 ]; then printf 'PASS %s phase rc=%s\n' "$CASE_NAME" "$RC";
  else printf 'FAIL %s phase rc=%s\n' "$CASE_NAME" "$RC"; cat "$CASE_DIR/output.log"; FAIL=1; fi
done
exit "$FAIL"
