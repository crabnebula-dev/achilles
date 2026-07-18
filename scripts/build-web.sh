#!/usr/bin/env bash
#
# Build the Achilles web app: compile the wasm analysis core into ui/pkg/.
#
#   scripts/build-web.sh            # debug build (fast, large .wasm)
#   scripts/build-web.sh --release  # optimised build (slower, small .wasm)
#
# Then serve the ui/ directory over HTTP — ES modules and the wasm fetch need
# an http:// origin, not file://:
#
#   python3 -m http.server -d ui 8080   # → http://localhost:8080
#
# No special cross-origin-isolation headers are required: the build uses no
# threads/SharedArrayBuffer, so plain static hosting works.
#
# Prerequisites: `rustup target add wasm32-unknown-unknown` and `wasm-pack`
# (https://rustwasm.github.io/wasm-pack/installer/).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
profile="${1:---dev}"

exec wasm-pack build "$root/crates/achilles-wasm" \
  "$profile" \
  --target web \
  --out-dir "$root/ui/pkg"
