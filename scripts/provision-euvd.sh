#!/usr/bin/env bash
#
# Fill a directory with the EUVD snapshot, without contacting EUVD.
#
#   scripts/provision-euvd.sh [OUT_DIR]
#
# OUT_DIR defaults to docs/browser/euvd. Requires curl and jq; the artifact path
# also needs `gh` authenticated with `actions: read`.
#
# ENISA throttles bursts, and a Pages deploy used to re-crawl the whole API on
# every push — a README typo paid ~60 requests and could take the deploy down
# with a 429. Only .github/workflows/euvd-refresh.yml fetches now; this fills the
# build from what that workflow published:
#
#   1. the euvd-snapshot artifact of the newest successful euvd-refresh run
#   2. else the previous deployment, served by GitHub Pages
#   3. else nothing, with a warning
#
# There is deliberately no fallback to EUVD. An empty directory is a correct
# outcome: with no manifest the browser reports EUVD as not-yet-downloaded,
# whereas a partial snapshot would read as a clean bill of health.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-$root/docs/browser/euvd}"
repo="${GITHUB_REPOSITORY:-}"

# Same staging discipline as the fetcher: nothing replaces a populated target
# until a whole snapshot is in hand.
parent="$(dirname "$out")"
mkdir -p "$parent"
stage="$(mktemp -d "$parent/.euvd-provision.XXXXXX")"
trap 'rm -rf "$stage"' EXIT

# A snapshot is the manifest plus every shard it names. Anything less is refused,
# so a truncated download can never be swapped in.
complete() { # <dir>
  local dir="$1" file
  [ -s "$dir/index.json" ] || return 1
  jq -e '.shards | length > 0' "$dir/index.json" >/dev/null 2>&1 || return 1
  while read -r file; do
    [ -s "$dir/$file" ] || return 1
  done < <(jq -r '.shards[].file' "$dir/index.json")
}

from_artifact() {
  [ -n "$repo" ] || return 1
  command -v gh >/dev/null 2>&1 || return 1
  local run
  run="$(gh run list --repo "$repo" --workflow euvd-refresh.yml \
    --status success --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)"
  [ -n "$run" ] || return 1
  gh run download "$run" --repo "$repo" --name euvd-snapshot --dir "$stage" >/dev/null 2>&1 || return 1
  complete "$stage"
}

from_pages() {
  [ -n "$repo" ] || return 1
  local base="https://${repo%%/*}.github.io/${repo##*/}/browser/euvd" file
  curl -fsS --retry 3 --retry-all-errors -o "$stage/index.json" "$base/index.json" 2>/dev/null || return 1
  jq -e '.shards | length > 0' "$stage/index.json" >/dev/null 2>&1 || return 1
  while read -r file; do
    curl -fsS --retry 3 --retry-all-errors -o "$stage/$file" "$base/$file" 2>/dev/null || return 1
  done < <(jq -r '.shards[].file' "$stage/index.json")
  curl -fsS -o "$stage/NOTICE" "$base/NOTICE" 2>/dev/null || true
  complete "$stage"
}

describe() { jq -r '"\(.shards | length) shard(s), version \(.version[0:12])…"' "$stage/index.json"; }

if from_artifact; then
  echo "euvd: provisioned from the euvd-refresh artifact ($(describe))"
elif rm -rf "$stage" && mkdir -p "$stage" && from_pages; then
  echo "euvd: provisioned from the deployed site ($(describe))"
else
  echo "::warning::no EUVD snapshot available (no artifact, no deployed copy) — building without one; the browser will report EUVD as not yet downloaded"
  mkdir -p "$out"
  exit 0
fi

rm -rf "$out"
mv "$stage" "$out"
