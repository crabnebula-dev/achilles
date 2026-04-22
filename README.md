# Achilles

A desktop app that scans your `/Applications` folder and tells you which
installed apps ship outdated runtimes, weakened hardened-runtime entitlements,
or known-CVE versions of Electron, Tauri, Chromium, Node.js, Flutter, Qt,
WKWebView, and eight other runtimes it detects.

**Achilles leads with [ENISA's EUVD][EUVD]** — the European Vulnerability
Database — as its primary feed, because EU-CNA advisories don't always make
it into the US-centric NVD or GitHub sources in time (or at all). OSV and
NVD are still queried alongside for runtime-specific coverage those feeds do
best.

Built as a Tauri 2 app, so you can see what a ~5 MB alternative to the 100 MB
Electron apps it audits actually looks like.

> **Status: alpha, macOS-only.** Detection is reliable against the handful of
> apps tested (Discord, Signal, 1Password, VS Code, Claude, HyperMeet, Zephyr
> Agency). Severity scoring is deliberately simple — this is a
> "risk indicator" tool, not a verdict.

## Quickstart

Requirements: Rust 1.80+, macOS 12+. The GUI needs nothing else to run.

```sh
cargo run -p achilles
```

The window opens, a scan kicks off automatically, and rows stream in as
bundles are detected. Click any row for a full audit + CVE lookup.

If you just want the CLI outputs:

```sh
cargo run -p detect --example detect -- "/Applications/Signal.app"
cargo run -p scan --example scan
cargo run -p macho-audit --example audit -- "/Applications/Signal.app"
cargo run -p cve --example lookup -- electron 40.4.1 npm
cargo run -p static-scan --example static-scan -- \
  "/Applications/Signal.app/Contents/Resources/app.asar"
```

## What it detects

For every bundle in standard install locations (`/Applications`,
`/System/Applications`, `~/Applications`) it extracts:

- **Framework**: one of Electron, Tauri, NW.js, Flutter, Qt, React Native,
  Wails, Sciter, Java, CEF, ChromiumBrowser, or native Cocoa — with a
  confidence rating (high/medium/low). Secondary signals (CEF, QtWebEngine
  Chromium, Hermes, …) are reported alongside the primary verdict, so a
  Tauri app that *also* bundles CEF shows both.
- **Runtime versions** surfaced: `electron`, `chromium`, `node`, `tauri`,
  `cef`, `nwjs`, `flutter`, `qt`, `react_native`, `wails`, `sciter`, `java`
  — pulled from framework Info.plists, the main Mach-O's string table, or
  bundled `release` files as appropriate.
- **Hardened-runtime entitlements**: the load-bearing ones
  (`allow-jit`, `allow-unsigned-executable-memory`,
  `disable-executable-page-protection`, `allow-dyld-environment-variables`,
  `disable-library-validation`, `get-task-allow`).
- **Code signature**: signing authority chain, Team ID, hardened-runtime
  flag, notarization staple.
- **Info.plist hardening**: `NSAllowsArbitraryLoads`, registered URL
  schemes, per-domain TLS exceptions.
- **ASAR integrity**: declared hash from `ElectronAsarIntegrity`, the actual
  hash of `Contents/Resources/app.asar` (Electron hashes the JSON header, not
  the whole file — we match that), and a boolean telling you whether the
  archive was modified after signing.
- **Runtime CVEs** for every detected runtime, via four user-toggleable
  sources:

  | Source | Default | Runtime / scope | Auth |
  |---|---|---|---|
  | [EUVD] | **on (primary)** | ENISA's EU-CNA advisory feed — vendor/product search across every runtime | none |
  | [OSV] | **on** | Electron (npm), Tauri (crates.io), React Native (npm), bundled npm deps | none |
  | [NVD] | **on** | Chromium, Node.js, Flutter, Qt, NW.js, Wails, Sciter, Java/JDK, WebKit — keyed by CPE | optional API key (5→50 req/30s) |
  | [GHSA] | off | GitHub Global Security Advisories via REST API — npm/rust/go ecosystems | **PAT required** (60→5000 req/h) |

  Sources are configured via a Settings dialog (gear button in the header).
  The dialog also exposes a **max-age-years filter** (default: 5) that
  drops advisories older than N years from the final report — essential
  for wide-net CPEs (Safari, Java, Qt, Chromium) that would otherwise
  return decades of history. Set to `0` to disable. Advisories without a
  publication date are never filtered.

  Settings live at `~/Library/Application Support/achilles/settings.json`
  with mode 0600 on Unix.

  Everything is cached on disk for 24 hours in
  `~/Library/Caches/achilles/cve/`. Historical CVE data is immutable
  once published, so repeat scans only pay for newly-seen versions.

- **Results journal**: every time a detail view finishes fetching, the
  merged payload (detection + audit + CVEs + static-scan + dep advisories)
  is written as a timestamped JSON file under
  `~/Library/Application Support/achilles/journal/<slug>/<iso-timestamp>.json`.
  Re-opening a row in the same session shows the prior payload instantly
  from the in-process cache; a small "fetched Nm ago" badge at the top of
  the detail panel surfaces the save time. No pruning — users can delete
  individual directories if they want to clean up.

- **Export to JSON**: two buttons.
  - **Export JSON** in the header dumps every row in the list, including
    whatever detail (audit / CVE report / static-scan / dep advisories)
    you've already opened for each — unopened rows export as just their
    `Detection`.
  - **Export** in the open detail panel dumps one app's full dossier into
    a single file named after the bundle.

  Both produce a self-describing `{ schema: 1, tool, generatedAt, entries: [...] }`
  JSON document. No Tauri plugin required — it's a plain Blob download.

- **System side effects** (`crates/sideeffects`): for each app, enumerates
  things it installs *outside* its own bundle:
  - Helpers / plugins / XPC services inside `Contents/Helpers`,
    `Contents/PlugIns`, `Contents/XPCServices`
  - **Native-messaging-host manifests** dropped into every Chromium-based
    browser profile (`NativeMessagingHosts/*.json`) whose `path` points
    back into the bundle — including allowed extension IDs and install
    timestamps
  - **`launchd` agents / daemons** (user + global + system scope) whose
    `Program`/`ProgramArguments` reference the bundle
  - `~/Library/Logs/<app>/` directory size and last-modified

  Surfaces categories of silent system modification that bundle-only audits
  miss. Inspired by [thatprivacyguy.com][tpg-article]'s investigation of
  Claude Desktop's browser-bridge installer, which this tool reproduces the
  findings of automatically.

- **Bundled-dependency CVEs**: reads `package-lock.json` (preferred) or
  `package.json` from inside the app's `app.asar`, extracts every
  `(name, version)` pair, and runs one OSV `/v1/querybatch` request for up
  to 1000 packages. Results cached per `(name, version)`. Note: modern
  Electron apps that bundle via Vite/webpack/rollup only surface their
  top-level deps this way — transitive deps are compiled into the main
  chunk and aren't separately queryable.

[OSV]: https://osv.dev
[NVD]: https://nvd.nist.gov/developers/vulnerabilities
[EUVD]: https://euvd.enisa.europa.eu/
[GHSA]: https://docs.github.com/en/rest/security-advisories/global-advisories
[tpg-article]: https://www.thatprivacyguy.com/blog/anthropic-spyware/

## Architecture

```
┌─ ui/ ────────────────────────────────┐   vanilla JS, no bundler
│  index.html + main.js + styles.css   │   listens on scan_event,
└────────────────┬─────────────────────┘   calls invoke() per row click
                 │
┌─ src-tauri/ ───▼─────────────────────┐
│  Tauri 2 app                         │
│    commands::discover                │
│    commands::scan        ──emits──▶  │
│    commands::detect_one              │
│    commands::audit                   │
│    commands::cve_lookup              │
│    commands::static_scan             │
│    commands::dependency_scan         │
└─┬────────────────────────────────────┘
  │
  ├─ crates/detect        framework + version extraction (Mach-O string scan)
  ├─ crates/scan          mdfind + concurrent detect(), streams ScanEvent
  ├─ crates/cve           EUVD + OSV + NVD + GHSA client with disk cache
  ├─ crates/macho-audit   entitlements / codesign / Info.plist / ASAR integrity
  ├─ crates/static-scan   ASAR reader + oxc AST rule engine (RAST)
  └─ crates/sideeffects   enumerate out-of-bundle installs: browser bridges,
                          launch agents, helpers, log directories
```

Each crate has an `examples/` binary so you can exercise it in isolation.

## Static analysis (the `static-scan` crate)

Reads `Contents/Resources/app.asar` directly — no extraction, no external
runtime — and runs a catalogue of rules against every JS/TS/HTML file. Rule
IDs mirror [Electronegativity]'s naming so findings stay portable.

The JS/TS rules are AST-driven via [oxc], not regex. Boolean property checks
like `sandbox: false` / `nodeIntegration: true` are implemented as
`ObjectExpression` visitors and handle minified forms (`sandbox: !1`,
`nodeIntegration: !0`) out of the box. The HTML CSP-presence rule stays
regex-based because oxc is JS/TS-only — for a single-property meta-tag
check, that's fine.

v1 rule set (mapped to Electronegativity wiki IDs):

| Rule | Severity | Confidence |
|---|---|---|
| `CSP_GLOBAL_CHECK` | High | Firm |
| `SANDBOX_JS_CHECK` | High | Firm |
| `NODE_INTEGRATION_JS_CHECK` | High | Firm |
| `CONTEXT_ISOLATION_JS_CHECK` | Critical | Firm |
| `WEB_SECURITY_JS_CHECK` | High | Firm |
| `ALLOW_RUNNING_INSECURE_CONTENT_JS_CHECK` | High | Firm |
| `EXPERIMENTAL_FEATURES_JS_CHECK` | Medium | Firm |
| `OPEN_EXTERNAL_JS_CHECK` | Medium | Tentative |

`OPEN_EXTERNAL_JS_CHECK` attaches a `note` to each finding: "literal URL —
likely safe" if the first argument is a string/template literal, "non-literal
argument — needs manual review" otherwise. That's enough to cut through the
noise in apps that use `shell.openExternal` for menu items and feedback
links.

Run it on its own:

```sh
cargo run -p static-scan --example static-scan -- \
  "/Applications/Signal.app/Contents/Resources/app.asar"
```

[Electronegativity]: https://github.com/doyensec/electronegativity
[oxc]: https://oxc.rs

## Known limitations

- **macOS only.** `scan::discover_applications` shells to `mdfind`;
  `macho-audit` shells to `codesign` and parses Info.plist. The same audits
  on Windows/Linux need different plumbing — tracked as a v2 concern.
- **NVD rate limits.** Without an API key, NVD allows ~5 requests per 30
  seconds. The on-disk cache (24h TTL) turns most queries into cache hits,
  but the *first* scan of a diverse `/Applications` folder will pause
  briefly between unique Chromium / Node.js versions. Add
  `NVD_API_KEY=<key>` handling in `sources/nvd.rs` if you need faster
  fresh scans.
- **Transitive-dep extraction needs a package-lock.** Apps bundled with
  Vite / webpack / rollup don't ship a resolvable node_modules tree — the
  dep list comes from `package.json` only (top-level). Apps that preserve
  node_modules (Discord, Signal, 1Password, …) get full transitive coverage.
- **Severity scoring is a stub.** The UI's `isStale()` function is a
  major-version heuristic. There's no weighted combination of CVE count,
  severity, entitlement flags, and EOL status yet.
- **Static-analysis rule coverage is narrow.** Eight rules, not the ~30 that
  Electronegativity ships. Adding more is mechanical — each new rule is
  a visitor function plus an entry in the catalogue — but the current set
  deliberately targets the highest-signal checks.
- **Obfuscated / stripped binaries degrade detection.** Tauri apps with
  `strip = true` in `Cargo.toml [profile.release]` lose the cargo-registry
  path that carries the Tauri version. The detector still identifies them
  via `tauri.localhost` / `__TAURI_INTERNALS__` strings, but drops the
  version to `None`.

## Tests

```sh
cargo test --workspace
```

Integration tests in `crates/detect/tests/` and `crates/static-scan/tests/`
are opportunistic — they look for a real fixture bundle pointed at by the
`ACHILLES_TESTAPP_BUNDLE` environment variable and skip cleanly when it's
unset. The detect-side test asserts the bundle is Electron and that runtime
versions extract; the static-scan-side test only needs the bundle to have
an `app.asar`. Any installed Electron app (Signal, Discord, VS Code, …)
works.

```sh
export ACHILLES_TESTAPP_BUNDLE=/Applications/Signal.app
cargo test --workspace
```

## Non-goals

- **Not a verdict tool.** The output is risk signals, not "this app is
  compromised." A phrase like "unsafe" never appears in the UI on purpose.
- **No telemetry.** Scanning happens entirely locally. CVE lookups hit OSV
  directly by version string — nothing about your installed apps is
  transmitted. This is a design commitment, not just a current gap.
- **Not a replacement for vendor triage.** If an advisory fires on an app
  you care about, read the upstream changelog before concluding anything.

## Contributing

The codebase is small enough that reading `crates/detect/src/lib.rs` and
`src-tauri/src/commands.rs` is the fastest way to get oriented. Bugs and
false positives against real-world bundles are the most useful thing to
file — the detection rules were tuned against ~20 apps, and anything that
ships a weirder Mach-O layout will trip them.

## Acknowledgments

Thanks to **Gregor** for sharing
[*thatprivacyguy.com — Anthropic Spyware*][tpg-article], which directly
inspired the side-effects crate (browser native-messaging-host audit,
launch-agent enumeration, out-of-bundle writes). Achilles now reproduces
that investigation's findings automatically for any scanned bundle.

## License

[PolyForm Noncommercial 1.0.0](./LICENSE).

Free to use, modify, and redistribute for any **noncommercial** purpose
— personal research, hobby projects, academic and charitable use, and
work by public-benefit organisations are all explicitly permitted. Using
the software as part of a commercial product or service requires a
separate licence from the authors.

SPDX identifier: `PolyForm-Noncommercial-1.0.0`.
