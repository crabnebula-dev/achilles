// EUVD snapshot updater.
//
// The browser build can't query EUVD directly (it returns 403 to any
// browser-origin request), so it reads a pre-fetched snapshot published as
// same-origin static files: an `index.json` HEAD that names content-addressed
// per-runtime shards (see scripts/fetch-euvd.sh). This module fetches,
// validates, and caches that snapshot.
//
// It uses only `fetch` and the Cache Storage API, and runs on the main thread
// (driven by the shim). It deliberately does NOT touch localStorage or wasm —
// the shim wires those up.
//
// Offline-first and atomic: shards are immutable (their filename carries their
// hash), so a fetched shard is safe to cache forever; `index.json` is the one
// mutable resource, always revalidated. On update we write the shards first and
// the manifest last, so a reader never sees a manifest naming a shard that
// isn't cached yet.

const BASE = new URL("./euvd/", self.location.href);
const CACHE = "achilles-euvd-v1";
const HEAD = "index.json";

const headUrl = () => new URL(HEAD, BASE).href;
const shardUrl = (file) => new URL(file, BASE).href;
const open = () => caches.open(CACHE);

/// The committed HEAD manifest, or null if no snapshot is cached yet.
export async function currentManifest() {
  const res = await (await open()).match(headUrl());
  return res ? res.json() : null;
}

/// Read the committed snapshot as shards ready to load into wasm:
/// `{ version, generatedAt, shards: [{ slug, vendor, product, bytes }] }`, or
/// null when nothing is cached. Skips any shard missing from the cache (which
/// shouldn't happen after a commit, but keeps a torn cache from throwing).
export async function readSnapshot() {
  const manifest = await currentManifest();
  if (!manifest) return null;
  const c = await open();
  const shards = [];
  for (const [slug, s] of Object.entries(manifest.shards ?? {})) {
    const res = await c.match(shardUrl(s.file));
    if (!res) continue;
    shards.push({ slug, vendor: s.vendor, product: s.product, bytes: await res.arrayBuffer() });
  }
  return { version: manifest.version, generatedAt: manifest.generatedAt, shards };
}

/// Revalidate HEAD and, if the dataset changed (or `force` and a shard differs
/// from what's cached), fetch the changed shards, validate them, and commit
/// atomically. Returns `{ changed, version, generatedAt, changedShards }`.
/// Throws on network / parse / validation failure — the caller keeps serving
/// the previous snapshot and retries on the next trigger.
export async function checkAndUpdate({ force = false } = {}) {
  // HEAD is the only mutable resource; always revalidate it (cheap 304 on Pages).
  const head = await fetchJson(headUrl(), { cache: "no-cache" });
  assertManifest(head);

  const c = await open();
  const prev = await currentManifest();

  // Fast path: same dataset and we already hold it → nothing to do.
  if (!force && prev && prev.version === head.version) {
    return { changed: false, version: head.version, generatedAt: head.generatedAt, changedShards: [] };
  }

  // Fetch every shard whose immutable file isn't already cached.
  const fetched = [];
  const changedShards = [];
  for (const [slug, s] of Object.entries(head.shards ?? {})) {
    const url = shardUrl(s.file);
    const prevFile = prev?.shards?.[slug]?.file;
    if (s.file !== prevFile) changedShards.push(slug);
    if (await c.match(url)) continue; // immutable + already cached
    const res = await timedFetch(url, { cache: "force-cache" });
    if (!res.ok) throw new Error(`euvd shard ${slug}: HTTP ${res.status}`);
    validateShard(slug, await res.clone().text(), s.count);
    fetched.push({ url, res });
  }

  // Commit: shards first, then the manifest as the single atomic publish point.
  for (const { url, res } of fetched) await c.put(url, res);
  await c.put(headUrl(), jsonResponse(head));
  await gc(c, head);

  return {
    changed: !prev || prev.version !== head.version,
    version: head.version,
    generatedAt: head.generatedAt,
    changedShards: prev ? changedShards : Object.keys(head.shards ?? {}),
  };
}

/// Drop any cached entry not referenced by the committed HEAD (e.g. a shard
/// superseded by a new content-addressed filename), bounding the footprint.
async function gc(c, head) {
  const keep = new Set([headUrl(), ...Object.values(head.shards ?? {}).map((s) => shardUrl(s.file))]);
  for (const req of await c.keys()) {
    if (!keep.has(req.url)) await c.delete(req);
  }
}

async function fetchJson(url, opts) {
  const res = await timedFetch(url, opts);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

// A stalled fetch must not hang a check indefinitely (which would leave the
// caller stuck "checking" forever), so every request is bounded by a timeout.
const FETCH_TIMEOUT_MS = 20000;
async function timedFetch(url, opts) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

function jsonResponse(obj) {
  return new Response(JSON.stringify(obj), { headers: { "content-type": "application/json" } });
}

function assertManifest(m) {
  if (!m || typeof m !== "object" || m.schema !== 1 || typeof m.version !== "string" || !m.shards) {
    throw new Error("euvd: unrecognised index.json (schema mismatch)");
  }
}

function validateShard(slug, text, count) {
  let arr;
  try {
    arr = JSON.parse(text);
  } catch (e) {
    throw new Error(`euvd shard ${slug}: invalid JSON (${e})`);
  }
  if (!Array.isArray(arr)) throw new Error(`euvd shard ${slug}: not an array`);
  if (typeof count === "number" && arr.length !== count) {
    throw new Error(`euvd shard ${slug}: ${arr.length} entries, manifest says ${count}`);
  }
}
