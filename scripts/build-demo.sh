#!/usr/bin/env bash
#
# Build the browser WASM demo into docs/browser/ — static files served by the
# existing GitHub Pages site (main:/docs) at <pages>/achilles/browser/.
#
#   scripts/build-demo.sh
#
# The tree is produced by web-modules (SCSS compiled, npm dependencies
# vendored, imports validated); a sw-manifest.json listing every file lets the
# service worker precache the whole shell. Set SKIP_EUVD=1 to skip the EUVD
# snapshot when iterating offline (the app still loads; EUVD reports "not yet
# downloaded").
#
# Prerequisites: `rustup target add wasm32-unknown-unknown`, `wasm-pack`, and
# the web-modules CLI (cargo install web_modules --features full).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/docs/browser"

rm -rf "$out"

# Optimised wasm (release + wasm-opt → a few MB, vs ~10 MB debug) into ui/pkg,
# where the frontend build copies it through to the output tree.
wasm-pack build "$root/crates/achilles-wasm" --release --no-typescript --target web --out-dir "$root/ui/pkg"

"$root/scripts/frontend-build.sh" "$out"

# Precache manifest for sw.js: every built file except the EUVD snapshot (owned
# by the dedicated achilles-euvd-* cache), dotfiles (the build marker, the
# vendor cache's .version markers), and the manifest itself.
(
  cd "$out"
  find . -type f \
    ! -path './euvd/*' \
    ! -name '.*' \
    ! -name 'sw-manifest.json' \
    | sort | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin]))'
) >"$out/sw-manifest.json"

# Fetch the EUVD snapshot into docs/browser/euvd/ — same-origin static shards
# the browser reads instead of the CORS-blocked EUVD API. Runs server-side, so
# no browser Origin → no CORS block.
if [ "${SKIP_EUVD:-}" = "1" ]; then
  echo "skipping EUVD snapshot (SKIP_EUVD=1)"
else
  "$root/scripts/fetch-euvd.sh" "$out/euvd"
fi

echo "demo built → $out"
echo "preview: python3 -m http.server -d \"$root/docs\" 8081  →  http://localhost:8081/browser/"
