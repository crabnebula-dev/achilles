#!/usr/bin/env bash
#
# Frontend dev loop: serve ui/ with the web-modules dev server — SCSS compiled
# per request, live reload on change — with the vendored npm dependencies
# mounted as a second root (the dev server itself never vendors).
#
#   scripts/frontend-dev.sh [ADDR]      # ADDR defaults to 127.0.0.1:8080
#
# The vendor cache lives in .cache/web-modules and refreshes when
# ui/package.json changes. Scanning in the browser needs the wasm build once:
# built here with --dev when ui/pkg is absent.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
addr="${1:-127.0.0.1:8080}"
cache=".cache/web-modules" # never inside ui/ — web_modules/ in a source root is a reserved path

[ -f ui/pkg/achilles_wasm.js ] || wasm-pack build crates/achilles-wasm --dev --no-typescript --target web --out-dir "$PWD/ui/pkg"

want="$(sha256sum ui/package.json | cut -d' ' -f1)"
if [ ! -d "$cache/web_modules" ] || [ "$(cat "$cache/manifest.sha256" 2>/dev/null)" != "$want" ]; then
  rm -rf "$cache"
  mkdir -p "$cache"
  web-modules vendor --out "$cache/web_modules" --manifest ui/package.json --importmap "$cache/importmap.json"
  echo "$want" >"$cache/manifest.sha256"
fi

exec web-modules dev ui "$cache" --addr "$addr"
