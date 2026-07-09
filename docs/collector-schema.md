# Fleet collector — report schema

Achilles can run as a background fleet agent: it periodically re-discovers the
installed applications on a device and POSTs a compact **inventory** to a
collector you operate. This document is the wire contract that collector must
accept. The Achilles client is the only thing shipped here — the collector is
yours to build.

Reporting is **opt-in**. Nothing is sent until a user enables it and sets a
collector URL in **Settings → Fleet reporting**.

## Transport

```
POST <collector_url>
Content-Type: application/json
Authorization: Bearer <token>      # omitted if no token is configured
```

- `collector_url` and `token` are configured per device in the app settings.
- The client uses a 30-second timeout.
- **Any `2xx`** response is treated as success. Any non-`2xx` (or a transport
  error) is surfaced to the user as a failed report and retried on the next
  scheduled run. The response body of a non-`2xx` is shown (truncated) to aid
  debugging, so returning a short error string is helpful.
- The client does **not** currently send a `User-Agent` contract or retry
  within a single run; the next scheduled reassessment is the retry.

## Request body

```jsonc
{
  "schema_version": 1,                       // integer; bump on breaking changes
  "generated_at": 1750598400,                // unix seconds (UTC)
  "generated_at_iso": "2026-06-22T12:00:00Z",// ISO-8601, always 'Z'
  "fleet_id": "acme-corp",                   // groups devices; may be "" if unset
  "device": {
    "id": "f1e2d3c4-5678-49ab-cdef-0123456789ab", // stable UUID v4 per device
    "hostname": "Janes-MacBook-Pro",
    "os": "macos",                           // std::env::consts::OS: macos|linux|windows
    "arch": "aarch64",                       // std::env::consts::ARCH: aarch64|x86_64|…
    "app_version": "0.1.0"                   // Achilles' own version
  },
  "apps": [
    {
      "name": "Discord",                     // display name; may be null
      "bundle_id": "com.hnc.Discord",        // may be null (no platform id)
      "bundle_version": "0.0.350",           // the INSTALLED app's own version; may be null
      "framework": "electron",               // see Framework values below
      "runtimes": {                          // only the runtimes that were detected
        "electron": "37.6.0",
        "chromium": "138.0.7204.251",
        "node": "22.9.0"
      }
    }
  ]
}
```

### Field notes

- **`device.id`** is generated once (UUID v4) and persisted on the device
  (`<config-dir>/achilles/device-id`), so it is stable across runs and reports.
  It is not derived from hardware and carries no PII beyond what the user sets.
- **`bundle_version`** is the *application's* installed version (e.g. the Discord
  app release), distinct from the runtime versions in `runtimes`.
- **`apps[]`** excludes anything detected as `framework: "unknown"`. Native
  (non-embedded-webview) apps that are positively identified are included with
  `framework: "native"` and usually an empty `runtimes`.
- **`runtimes`** keys present only when detected:
  `electron`, `chromium`, `node`, `tauri`, `cef`, `nwjs`, `flutter`, `qt`,
  `react_native`, `wails`, `sciter`, `java`, `webkit`. A Tauri app that also
  bundles CEF reports both `tauri` and `cef`.

### `framework` values

Lowercase strings: `electron`, `tauri`, `nwjs`, `flutter`, `qt`,
`reactnative`, `wails`, `sciter`, `java`, `safari`, `cef`, `chromiumbrowser`,
`native`. (`unknown` is filtered out and never sent.)

## Idempotency / dedup guidance

Each report is a full snapshot for one device at one time. A collector that
wants current-state-per-device should key on `device.id` and keep the latest
`generated_at`; one that wants history should append keyed by
`(device.id, generated_at)`. The client does not assume either model.

## Minimal reference collector (for testing)

Any endpoint that returns `2xx` works. A throwaway request bin (e.g.
webhook.site) is the fastest way to eyeball payloads. A tiny local example:

```python
# python3 collector.py  — prints each report, returns 200
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n)
        print(self.headers.get("authorization"))
        print(json.dumps(json.loads(body), indent=2))
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

HTTPServer(("127.0.0.1", 8787), H).serve_forever()
```

Point the collector URL at `http://127.0.0.1:8787/` (note: a plain-HTTP
localhost endpoint is fine for testing; production collectors should be HTTPS).
