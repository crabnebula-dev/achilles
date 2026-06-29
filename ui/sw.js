// Service worker for the /browser/ web app: it makes the app installable (a
// fetch handler + the manifest satisfy the install criteria) and gives it an
// offline fallback.
//
// Strategy is network-first: the demo is redeployed in place (wasm-pack keeps
// stable filenames), so we always prefer a fresh copy when online and fall back
// to the cache only when offline. The app shell is pre-cached on install so the
// very first offline load still works. Bump CACHE to evict everything.
const CACHE = "achilles-browser-v2";
const SHELL = [
  "./",
  "./index.html",
  "./main.js",
  "./tauri-shim.js",
  "./euvd-updater.js",
  "./styles.css",
  "./manifest.webmanifest",
  "./icon-192.png",
  "./icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(SHELL))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      // Only evict our own old shell caches — never the dedicated
      // `achilles-euvd-*` snapshot cache, so a shell bump can't wipe a user's
      // offline EUVD data.
      .then((keys) =>
        Promise.all(
          keys
            .filter((k) => k.startsWith("achilles-browser-") && k !== CACHE)
            .map((k) => caches.delete(k)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;
  // The EUVD snapshot is owned by the dedicated `achilles-euvd-*` cache (managed
  // by the updater). Leave its requests to the network + that cache so this
  // network-first shell cache can't double-store or serve stale snapshot bytes.
  if (new URL(request.url).pathname.includes("/euvd/")) return;
  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response.ok && new URL(request.url).origin === self.location.origin) {
          const copy = response.clone();
          caches.open(CACHE).then((cache) => cache.put(request, copy));
        }
        return response;
      })
      .catch(() => caches.match(request)),
  );
});
