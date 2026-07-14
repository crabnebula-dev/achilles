#!/usr/bin/env bash
# Builds the privileged capture helper and stages it as the Tauri sidecar
# declared in src-tauri/tauri.macos.conf.json (`bundle.externalBin`).
#
# Tauri resolves sidecars per target triple, hence the `-$TRIPLE` suffix; it
# strips the suffix when copying the binary into Contents/MacOS and signs it
# with the app's Developer ID (hardened runtime + secure timestamp), which is
# what notarization requires of the helper.
#
# Run from tauri.macos.conf.json's beforeDevCommand/beforeBuildCommand. The
# sidecar has to exist before `cargo build`: tauri-build's build script copies
# external binaries into the target dir and fails the build if one is missing.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

[ "$(uname -s)" = "Darwin" ] || exit 0

# Tauri sets these for its hooks; fall back to the host triple / release profile
# so the script also works when invoked by hand.
TRIPLE="${TAURI_ENV_TARGET_TRIPLE:-$(rustc -vV | sed -n 's/^host: //p')}"

if [ "${TAURI_ENV_DEBUG:-}" = "true" ]; then
  PROFILE_DIR="debug"
  cargo build -p netmon-helper --target "$TRIPLE"
else
  PROFILE_DIR="release"
  cargo build -p netmon-helper --release --target "$TRIPLE"
fi

mkdir -p src-tauri/binaries
cp "target/$TRIPLE/$PROFILE_DIR/achilles-netmon-helper" \
   "src-tauri/binaries/achilles-netmon-helper-$TRIPLE"
