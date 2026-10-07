#!/bin/sh
# OFFHOST only: freeze public source, build all Linux assets, bind installer bytes.
# Usage: sh scripts/build-release.sh NEW_OUTPUT --release TAG | --snapshot LABEL
#   --validator-amd64 PREBUILT_DIR --validator-arm64 PREBUILT_DIR --evidence NEW_DIR
# --release requires a clean checkout and an existing local tag at exact HEAD.
# --snapshot is test-only: source denotes base HEAD, NOT the dirty archive's commit.
# Evidence (source.tar, provenance.json, artifacts.json) is outside the 22 assets.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
exec python3 -I -S -B "$ROOT/scripts/build-release-bundle.py" "$@"
