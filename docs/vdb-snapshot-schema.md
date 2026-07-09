# Trusted-host VDB snapshot schema

Achilles can source vulnerability data from a **downloadable snapshot** served by
a trusted host (the "fleet" host) instead of querying NVD/OSV/EUVD live. Devices
fetch the snapshot over HTTPS + bearer token, cache it, and **match versions
locally/offline**. For any product the snapshot doesn't cover — or when no fresh
snapshot is present — the device **falls back to the public sources**.

This document is the contract the host's snapshot endpoint must satisfy. Building
the host/snapshot is out of scope here (client-only).

## Transport

```
GET <vdb_url>
Authorization: Bearer <token>     # vdb_token, or the reporting token if unset; omitted if neither
```

- Return the snapshot JSON with any `2xx`. The device validates it parses and
  contains at least one product before replacing its cache.
- The device refreshes on its configured interval and on demand ("Refresh VDB
  now"). On a failed refresh, a cached snapshot older than the device's
  `vdb_max_age_secs` (default 14 days) is **deleted**, so lookups fall back to
  the public sources rather than matching stale data.
- Cached at `<cache-dir>/achilles/vdb-snapshot.json` (e.g. on macOS
  `~/Library/Caches/achilles/vdb-snapshot.json`).

## Snapshot body

Advisories grouped by **product key**. Each advisory is Achilles' normalized
record — **`fixed_in` is important**: the device keeps an advisory for a scanned
version `V` only when `V < fixed_in` (an advisory with no `fixed_in` is kept and
trimmed later by the central relevance filter). This is the same matching used
for live results, so a well-built snapshot yields identical findings offline.

```jsonc
{
  "schema_version": 1,
  "generated_at": 1750598400,             // unix seconds (UTC)
  "generated_at_iso": "2026-06-22T12:00:00Z",
  "products": {
    "chromium": [
      {
        "id": "CVE-2026-1234",            // primary id (CVE-… preferred)
        "source": "nvd",                  // nvd | osv | euvd | ghsa (provenance)
        "summary": "Use-after-free in …",
        "severity": "high",               // low|medium|high|critical, or null
        "fixed_in": "139.0.7258.0",       // first patched version (the match ceiling); null if unknown
        "aliases": ["GHSA-xxxx-yyyy-zzzz"],
        "published": "2026-05-01T00:00:00Z", // ISO-8601, or null
        "references": ["https://…"]
      }
    ],
    "electron": [ /* … */ ],
    "node": [ /* … */ ],
    "deno": [ /* … */ ]
  }
}
```

### Product keys

Advisories must be grouped under these exact keys (matching Achilles' runtime
buckets). Include only the products you cover; anything omitted falls back to the
public sources per device.

```
electron  tauri  node  deno  chromium  flutter  qt
nwjs  react_native  wails  sciter  webkit  java
```

Notes:
- **CEF** apps are matched against the **`chromium`** product (CEF embeds
  Chromium) — no separate `cef` key.
- **`webkit`** corresponds to Safari / system-WebKit advisories
  (`cpe:2.3:a:apple:safari:*`) for WKWebView-backed apps.
- The advisory shape is exactly `cve::Advisory`; unknown fields are ignored, so
  the host may include extras.

## How the host should build `fixed_in`

The device's local match is `scanned_version < fixed_in`. So the host should set
`fixed_in` to the first **unaffected** (patched) version for the scanned
product — the same "fix ceiling" semantics NVD version ranges and EUVD's
`product_version` (`… <X`) express. If a CVE has multiple affected ranges, emit
one advisory per range (or the tightest applicable ceiling). Advisories whose
fix version is unknown may set `fixed_in: null`; they'll surface for all versions
of that product and can be trimmed by the summary-prose ceiling.
