#!/usr/bin/env bash
#
# Build the browser WASM demo into docs/browser/ — committed static files served
# by the existing GitHub Pages site (main:/docs) at <pages>/achilles/browser/.
# No CI/build step on Pages: it serves the committed files directly.
#
#   scripts/build-demo.sh
#
# Prerequisites: `rustup target add wasm32-unknown-unknown` and `wasm-pack`.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/docs/browser"

rm -rf "$out"
mkdir -p "$out"

# Optimised wasm (release + wasm-opt → a few MB, vs ~10 MB debug) into pkg/.
wasm-pack build "$root/crates/achilles-wasm" --release --target web --out-dir "$out/pkg"

# wasm-pack drops a `pkg/.gitignore` of `*`; remove it so the built artifacts are
# actually committed (Pages serves committed files). Drop the non-runtime files
# while we're at it — only the JS glue + .wasm are needed at runtime.
rm -f "$out/pkg/.gitignore" "$out/pkg/package.json" "$out/pkg/README.md" "$out/pkg"/*.d.ts

# The bundler-free UI: copy the static files the demo serves. The app uses only
# relative URLs, so it runs unchanged under the /browser/ subpath.
for f in index.html main.js tauri-shim.js styles.css \
         manifest.webmanifest sw.js icon-192.png icon-512.png icon-maskable.png; do
  cp "$root/ui/$f" "$out/$f"
done

# Fetch the EUVD snapshot into docs/browser/euvd/ — same-origin static shards
# the browser reads instead of the CORS-blocked EUVD API. Runs server-side, so
# no browser Origin → no CORS block. Set SKIP_EUVD=1 to skip when iterating
# offline (the app still loads; EUVD just reports "not yet downloaded").
if [ "${SKIP_EUVD:-}" = "1" ]; then
  echo "skipping EUVD snapshot (SKIP_EUVD=1)"
else
  "$root/scripts/fetch-euvd.sh" "$out/euvd"
fi

echo "demo built → $out"
echo "preview: python3 -m http.server -d \"$root/docs\" 8081  →  http://localhost:8081/browser/"
