#!/usr/bin/env bash
#
# Build the Achilles web app into dist/: compile the wasm analysis core into
# ui/pkg/, then produce the servable tree with web-modules (SCSS compiled, npm
# dependencies vendored, imports validated).
#
#   scripts/build-web.sh            # debug wasm (fast, large .wasm)
#   scripts/build-web.sh --release  # optimised wasm (slower, small .wasm)
#
# Then serve dist/ over HTTP — ES modules and the wasm fetch need an http://
# origin, not file://:
#
#   python3 -m http.server -d dist 8080   # → http://localhost:8080
#
# No special cross-origin-isolation headers are required: the build uses no
# threads/SharedArrayBuffer, so plain static hosting works.
#
# Prerequisites: `rustup target add wasm32-unknown-unknown`, `wasm-pack`
# (https://rustwasm.github.io/wasm-pack/installer/), and the web-modules CLI
# (cargo install web_modules --features full).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
profile="${1:---dev}"

wasm-pack build "$root/crates/achilles-wasm" \
  "$profile" \
  --no-typescript \
  --target web \
  --out-dir "$root/ui/pkg"

exec "$root/scripts/frontend-build.sh" dist
