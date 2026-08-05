#!/usr/bin/env bash
#
# Fetch a per-runtime EUVD snapshot for the browser build.
#
# EUVD (euvdservices.enisa.europa.eu) returns 403 "Invalid CORS request" to any
# browser-origin request, so the web build can't query the API directly. This
# script runs server-side — at build time, with no browser Origin, so no CORS
# block — paginates the API for the fixed set of runtimes Achilles detects,
# trims each advisory to the fields the analysis reads, and writes same-origin
# static shards the browser loads instead.
#
#   scripts/fetch-euvd.sh [OUT_DIR]
#   scripts/fetch-euvd.sh --list-pairs
#
# OUT_DIR defaults to docs/browser/euvd. Requires curl, jq, sha256sum.
#
# This is the only thing in CI that talks to EUVD, and it runs from one
# scheduled workflow (.github/workflows/euvd-refresh.yml). Everything else —
# the Pages deploy included — reads the snapshot that workflow publishes; see
# scripts/provision-euvd.sh. `--list-pairs` exists so the workflow reads the
# runtime list from here instead of keeping its own copy in step.
#
# Data: ENISA EUVD, CC BY 4.0 — see the NOTICE written alongside the shards.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-$root/docs/browser/euvd}"
api="https://euvdservices.enisa.europa.eu/api"
page_size=100
# Runaway guard. Google/Chrome is the largest product at ~34 pages, so this
# leaves generous headroom and never truncates in practice (matches euvd.rs).
max_pages=80

# The runtimes Achilles looks up in EUVD, as vendor|product|slug. Mirrors the
# EUVD task dispatch in crates/cve/src/lib.rs. Google/Chrome also covers CEF (it
# reuses the chrome lookup); React Native / Wails / Sciter don't query EUVD. The
# slug is the shard filename and the key the client maps back to a runtime.
pairs=(
  "Electron|Electron|electron"
  "Tauri|Tauri|tauri"
  "Node.js|Node.js|node"
  "Deno|Deno|deno"
  "Google|Chrome|chrome"
  "Google|Flutter|flutter"
  "Qt|Qt|qt"
  "nwjs|NW.js|nwjs"
  "Apple|Safari|safari"
  "Oracle|JDK|jdk"
)

if [ "${1:-}" = "--list-pairs" ]; then
  printf '%s\n' "${pairs[@]}"
  exit 0
fi

# Build into a staging directory beside the target and swap it in only once
# every shard and the manifest are written: a 429 partway through must leave the
# previous snapshot intact rather than delete it and stop. Staging next to the
# target keeps the swap on one filesystem.
parent="$(dirname "$out")"
mkdir -p "$parent"
stage="$(mktemp -d "$parent/.euvd-stage.XXXXXX")"
trap 'rm -rf "$stage"' EXIT

urlenc() { jq -rn --arg s "$1" '$s|@uri'; }

# One GET against the API. EUVD throttles request bursts — a Chrome-sized
# product paginates ~34 back-to-back requests, enough for a 429 from a shared
# CI runner IP. `--retry-all-errors` is what makes the retry cover a 429 that
# arrives without a Retry-After header, and the delay floor keeps the backoff
# from restarting the burst a second later; the cap bounds a run against a
# genuinely unavailable API.
euvd_get() {
  curl -fsS --retry 5 --retry-all-errors --retry-delay 2 --retry-max-time 120 "$1"
}

shards_json="{}"

for entry in "${pairs[@]}"; do
  IFS='|' read -r vendor product slug <<<"$entry"
  ev="$(urlenc "$vendor")"
  ep="$(urlenc "$product")"

  # Fetch every page to a temp file (the first page also reports the total,
  # which drives pagination). Accumulating via files — not a shell variable —
  # keeps a multi-thousand-entry product like Chrome under the argv length limit.
  tmp="$(mktemp -d)"
  euvd_get "$api/search?vendor=$ev&product=$ep&size=$page_size&page=0" >"$tmp/p0000.json"
  total="$(jq -r '.total // 0' "$tmp/p0000.json")"
  pages=$(((total + page_size - 1) / page_size))
  ((pages > max_pages)) && pages=$max_pages
  ((pages < 1)) && pages=1
  for ((p = 1; p < pages; p++)); do
    # Pace the pagination so we stay under the rate limit in the first place;
    # the retry in euvd_get only softens the 429s this doesn't avoid.
    sleep 1
    euvd_get "$api/search?vendor=$ev&product=$ep&size=$page_size&page=$p" \
      >"$(printf '%s/p%04d.json' "$tmp" "$p")"
  done

  # Concatenate the pages' items and trim to exactly the fields the Rust `Entry`
  # reads (crates/cve/src/sources/euvd.rs): id, description, datePublished,
  # baseScore, aliases, references, and each product's affected-version string.
  jq -c -s '[ .[].items[]? ] | [ .[] | {
    id,
    description,
    datePublished,
    baseScore,
    aliases,
    references,
    enisaIdProduct: [ (.enisaIdProduct // [])[] | { product_version } ]
  } ]' "$tmp"/p*.json >"$tmp/shard.json"

  # Content-address the shard: the filename carries its hash, so the file is
  # immutable — a fetched shard is safe to cache forever and is only refetched
  # when index.json (the single mutable "HEAD") points at a new filename. This
  # keeps correctness independent of GitHub Pages' fixed Cache-Control.
  hash="$(sha256sum "$tmp/shard.json" | cut -d' ' -f1)"
  file="$slug-${hash:0:16}.json"
  mv "$tmp/shard.json" "$stage/$file"
  rm -rf "$tmp"
  count="$(jq 'length' <"$stage/$file")"
  bytes="$(wc -c <"$stage/$file" | tr -d ' ')"
  echo "euvd: $vendor/$product → $file ($count advisories, $bytes bytes)"

  shards_json="$(jq -c \
    --arg slug "$slug" --arg vendor "$vendor" --arg product "$product" \
    --arg file "$file" --arg hash "$hash" \
    --argjson count "$count" --argjson bytes "$bytes" \
    '.[$slug] = {vendor:$vendor, product:$product, file:$file, hash:$hash, count:$count, bytes:$bytes}' \
    <<<"$shards_json")"
done

# Dataset identity = sha256 of the sorted per-shard hashes. Identical data gives
# an identical version regardless of fetch order or redeploys, so clients only
# see "updated" when the data actually changed (no false signal on a plain
# redeploy). generatedAt is display-only and never compared.
version="$(jq -rn --argjson s "$shards_json" \
  '$s | to_entries | sort_by(.key) | map("\(.key):\(.value.hash)") | join("\n")' \
  | sha256sum | cut -d' ' -f1)"
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# `source` carries the EUVD attribution inline (CC BY 4.0 requires naming the
# source, linking the licence, and stating that the data was modified). It
# travels with the manifest a client already fetches; the NOTICE below repeats
# it as a standalone file alongside the shards.
jq -n \
  --argjson shards "$shards_json" \
  --arg version "$version" \
  --arg generatedAt "$generated_at" \
  '{
    schema: 1,
    version: $version,
    generatedAt: $generatedAt,
    source: {
      name: "European Union Agency for Cybersecurity (ENISA)",
      database: "European Vulnerability Database (EUVD)",
      url: "https://euvd.enisa.europa.eu/",
      license: "CC-BY-4.0",
      licenseUrl: "https://creativecommons.org/licenses/by/4.0/",
      modified: "Reduced to the runtimes Achilles detects and re-serialised to a compact per-runtime subset.",
      endorsed: false
    },
    shards: $shards
  }' \
  >"$stage/index.json"

cat >"$stage/NOTICE" <<'NOTICE'
Vulnerability data in this directory © European Union Agency for Cybersecurity
(ENISA), European Vulnerability Database (EUVD), https://euvd.enisa.europa.eu/

Licensed under the Creative Commons Attribution 4.0 International licence
(CC BY 4.0): https://creativecommons.org/licenses/by/4.0/

Modified: reduced to the runtimes Achilles detects and re-serialised to a
compact per-runtime subset. Not endorsed by ENISA.
NOTICE

# Everything fetched and written: swap the complete snapshot into place. Up to
# here a failure has left the previous one untouched.
rm -rf "$out"
mv "$stage" "$out"

echo "euvd snapshot → $out (version ${version:0:12}…)"
