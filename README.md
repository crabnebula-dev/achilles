# Achilles

A desktop app that scans the GUI applications installed on your machine —
across **macOS, Windows, and Linux** — and tells you which ones ship outdated
runtimes, weakened process-hardening flags, or known-CVE versions of Electron,
Tauri, Chromium, Node.js, Deno, Flutter, Qt, WebView, and a dozen other
runtimes it detects.

Beyond version/CVE triage it can also:

- **Inventory an app's cryptography as a CBOM** — record its live TLS traffic
  and/or statically scan its binaries, then export a standards-based
  **CycloneDX 1.6 Cryptography Bill of Materials** graded for **post-quantum
  readiness** (see [Cryptography Bill of Materials](#cryptography-bill-of-materials-cbom)).
- **Audit bundled Rust crates** against the **RustSec** advisory database, for
  any binary built with `cargo-auditable`
  (see [Rust dependency audit](#rust-dependency-audit-cargo-auditable--rustsec)).
- **Run as a background fleet agent** — periodically re-inventory installed
  apps and report to a central collector, optionally sourcing vulnerability data
  from a **trusted-host VDB snapshot** (see [Fleet mode](#fleet-mode-background-reassessment--trusted-host-vdb)).

## Download the Beta - for Free!!!

> https://web.crabnebula.cloud/crabnebula/achilles/releases

**Achilles leads with [ENISA's EUVD][EUVD]** — the European Vulnerability
Database — as its primary feed, because EU-CNA advisories don't always make
it into the US-centric NVD or GitHub sources in time (or at all). OSV and
NVD are still queried alongside for runtime-specific coverage those feeds do
best.

Built as a Tauri 2 app, so you can see what a ~5 MB alternative to the 100 MB
Electron apps it audits actually looks like.

> **Status: beta, cross-platform.** macOS is the most battle-tested path;
> Windows and Linux discovery + detection are newer. Detection is reliable
> against the apps tested (Discord, Signal, 1Password, VS Code, Code-OSS,
> Cursor, GitKraken, Chrome, and assorted Qt/GTK apps). Severity scoring is
> deliberately simple — this is a "risk indicator" tool, not a verdict.

## Quickstart

Requirements: Rust 1.80+. macOS 12+, Windows 10+, or a Linux desktop. The GUI
needs nothing else to run.

```sh
cargo run -p achilles
```

The window opens, a scan kicks off automatically, and rows stream in as apps
are detected. Click any row for a full audit + CVE lookup.

If you just want the CLI outputs (pass a `.app` on macOS, or an executable on
Windows / Linux):

```sh
# macOS
cargo run -p detect --example detect -- "/Applications/Signal.app"
# Linux
cargo run -p detect --example detect -- "/usr/lib/electron39/electron"
# Windows
cargo run -p detect --example detect -- "C:\Users\me\AppData\Local\Programs\app\app.exe"

cargo run -p scan --example scan
cargo run -p app-audit --example audit -- <path-to-app-or-exe>
cargo run -p cve --example lookup -- electron 40.4.1 npm
cargo run -p sideeffects --example sideeffects -- <path-to-app-or-exe>
```

## How discovery works

Discovery is platform-specific but converges on a list of GUI apps — it
deliberately avoids listing the pile of CLI tools a system ships with:

- **macOS**: Spotlight (`mdfind`) enumerates `.app` bundles in standard install
  roots (`/Applications`, `/System/Applications`, `~/Applications`), with a
  filesystem-walk fallback.
- **Linux**: freedesktop `.desktop` entries (the application menu) — already
  GUI-only — resolved to their executables. Launcher shell-scripts in
  `/usr/bin` are followed to the real binary (so Chrome, VS Code, and the
  shared `electronNN` runtimes resolve correctly).
- **Windows**: Start Menu `.lnk` shortcuts (a natural GUI filter) plus per-user
  `%LOCALAPPDATA%\Programs` installs, resolved to their target `.exe`.

## What it detects

For every discovered app it extracts:

- **Framework**: one of Electron, Tauri, Deno, NW.js, Flutter, Qt, React
  Native, Wails, Sciter, Java, CEF, ChromiumBrowser, or native — with a
  confidence rating (high/medium/low). Secondary signals (CEF, QtWebEngine
  Chromium, Hermes, …) are reported alongside the primary verdict, so a Tauri
  app that *also* bundles CEF shows both — and both get their own CVE lookup
  (CEF is matched against the embedded Chromium build).
- **Runtime versions** surfaced: `electron`, `chromium`, `node`, `tauri`,
  `deno`, `cef`, `nwjs`, `flutter`, `qt`, `react_native`, `wails`, `sciter`,
  `java`, `webkit` — pulled from framework Info.plists (macOS), the executable's
  string table (cross-platform: the `Electron/`, `Chrome/`, `node-v`,
  `tauri-X.Y.Z` literals appear verbatim in Mach-O, PE, and ELF alike), the
  binary's import table (which `.dll` / `.so` framework libraries it links),
  or bundled `release` files.
- **Process hardening** — platform-appropriate:
  - **macOS**: hardened-runtime entitlements (`allow-jit`,
    `allow-unsigned-executable-memory`, `disable-library-validation`, …),
    the `codesign` authority chain / Team ID / notarization staple, and
    Info.plist flags (`NSAllowsArbitraryLoads`, URL schemes, TLS exceptions).
  - **Windows**: the Authenticode signature — presence, the signer certificate
    (subject + issuer, parsed from the embedded PKCS#7), and OS-trust-store
    verification (`WinVerifyTrust`) — plus PE mitigation flags (ASLR / DEP /
    Control Flow Guard / high-entropy ASLR) and the manifest's requested
    execution level.
  - **Linux**: ELF hardening (PIE / RELRO / NX / stack-canary / FORTIFY) and,
    for flatpak/snap apps, the declared sandbox permissions.
- **ASAR integrity** (Electron): on macOS, the declared `ElectronAsarIntegrity`
  hash vs. the actual hash of `Contents/Resources/app.asar` (Electron hashes
  the JSON header, not the whole file — we match that), and whether the archive
  was modified after signing. On Windows/Linux there's no signed baseline, so
  we surface the archive's header hash informationally.
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

  Settings live in the platform config dir (`dirs::config_dir()` — e.g.
  `~/Library/Application Support` on macOS, `%APPDATA%` on Windows, `~/.config`
  on Linux) at `achilles/settings.json`, with mode 0600 on Unix.

  Everything is cached on disk for 24 hours in
  `<cache-dir>/achilles/cve/`. Historical CVE data is immutable
  once published, so repeat scans only pay for newly-seen versions.

- **Results journal**: every time a detail view finishes fetching, the
  merged payload (detection + audit + CVEs + static-scan + dep advisories)
  is written as a timestamped JSON file under
  `<data-dir>/achilles/journal/<slug>/<iso-timestamp>.json`.
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
  things it installs *outside* its own install location, with a per-OS backend:
  - **Bundled helpers / sibling executables** — macOS `Contents/Helpers` /
    `PlugIns` / `XPCServices`, or the helper `.exe`s / binaries beside the
    main executable on Windows / Linux
  - **Native-messaging-host manifests** registered for every Chromium-based
    browser (and Firefox) whose `path` points back into the app — macOS
    `~/Library/Application Support`, Windows registry, Linux `~/.config` /
    `~/.mozilla` — including allowed extension IDs
  - **Auto-start / background entries** referencing the app — `launchd` agents
    & daemons (macOS), `Run` keys + Startup-folder shortcuts + Task Scheduler
    tasks (Windows), autostart `.desktop` entries + systemd user units (Linux)
  - the app's out-of-place **log / data directory** (macOS `~/Library/Logs`,
    Windows `%LOCALAPPDATA%`/`%APPDATA%`, Linux `~/.config` / `~/.local/share`)

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
│    discover / scan / detect_one      │  detection + audit
│    audit / static_scan / sideeffects │
│    cve_lookup / dependency_scan      │  CVEs (streams via Channel)
│    netmon_start/stop / crypto_*      │  cryptography → CBOM
│    export_cbom / rust_audit          │
│    reassess_now / *_reporting_config │  fleet reporting
│    refresh_vdb_now                   │  trusted-host VDB
│    os_info / helper_* / journal_*    │  OS badge, capture helper, journal
└─┬────────────────────────────────────┘
  │
  ├─ crates/detect        framework + version extraction (PE/ELF/Mach-O scan)
  ├─ crates/scan          per-OS discovery + concurrent detect(), streams ScanEvent
  ├─ crates/cve           EUVD + OSV + NVD + GHSA client + VDB snapshot, disk cache
  ├─ crates/app-audit     per-OS signing / hardening / ASAR integrity
  ├─ crates/static-scan   ASAR reader + oxc AST rule engine (RAST)
  ├─ crates/sideeffects   enumerate out-of-place installs: browser bridges,
  │                       launch agents, helpers, log directories
  ├─ crates/netmon        passive TLS-handshake capture → crypto evidence
  ├─ crates/netmon-helper privileged (root) capture daemon, macOS (SMAppService)
  ├─ crates/cbom          crypto evidence → CycloneDX CBOM + PQC grading
  └─ crates/rust-audit    cargo-auditable extraction + RustSec advisory match
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

## Cryptography Bill of Materials (CBOM)

Each app's detail panel has a **Cryptography** section that inventories the
cryptography an application actually uses and exports it as a
[**CycloneDX 1.6 CBOM**][cbom] graded for post-quantum readiness (RSA / ECDH /
ECDSA are NIST quantum-security level 0 — the assets to migrate before a
quantum adversary arrives). It draws on two evidence sources that fold into one
inventory (`crates/cbom`):

1. **Observed (runtime)** — a passive **network monitor** (`crates/netmon`)
   attaches to a running process by PID and records its TLS handshakes:
   versions, cipher suites (offered + selected), supported groups, signature
   schemes, SNI, and **JA3/JA4** fingerprints — plus destination routes. No
   decryption, no MITM: only what's visible in the clear handshake. (TLS 1.3
   encrypts the certificate, so cert details are surfaced for TLS ≤1.2 only.)
2. **Static (binary)** — scans the app's binaries for **linked crypto
   libraries** (BoringSSL / OpenSSL / LibreSSL / libsodium / mbedTLS / … via the
   import table) and algorithm symbols, catching cryptography a recording never
   exercised. This needs no privileges and finds e.g. the BoringSSL statically
   linked inside an Electron/CEF framework binary.

The aggregator normalizes evidence into canonical assets, **decomposes composite
cipher suites** (TLS → key-exchange + authentication + bulk cipher + hash),
classifies each asset's NIST quantum level + deprecation, builds the CBOM
provides/uses dependency graph, and produces a quantum-readiness summary. The
inventory is retained per app (survives navigation and restarts), and **Export
CBOM** writes the CycloneDX JSON.

**Capture privileges (macOS).** Per-app packet capture uses the `pktap`
interface, which requires root. Rather than elevate the app, Achilles installs a
small **privileged helper** via `SMAppService` — one approval in System
Settings, no special Apple entitlement, and it ships/updates inside the signed
`.app`. Without it, capture falls back to the default interface (BPF access) or
`sudo`. See [`docs/netmon-helper.md`](docs/netmon-helper.md).

## Rust dependency audit (cargo-auditable + RustSec)

The detail panel's **Rust dependencies (RustSec)** section finds Rust binaries
built with [`cargo-auditable`][cargo-auditable] — which embed their full
dependency tree in a `.dep-v0` section — anywhere in an app bundle, extracts the
crate list, and checks every crate against the [**RustSec advisory
database**][rustsec] (cloned/cached locally). It reports vulnerable and
unmaintained crates with their advisory id, aliases, CVSS, and patched versions
(`crates/rust-audit`).

## Fleet mode: background reassessment + trusted-host VDB

Achilles can run unattended as a lightweight fleet agent (**Settings → Fleet
reporting**, opt-in):

- **Background reassessment** — lives in the system tray (optionally launching
  at login), and on a schedule re-discovers installed apps and their runtime
  versions, POSTing an **inventory** (apps + versions + device id + timestamp +
  fleet id) to a configurable HTTPS **collector** with a bearer token. Client
  only — the collector is yours; the payload contract is
  [`docs/collector-schema.md`](docs/collector-schema.md).
- **Trusted-host VDB snapshots** — instead of each device querying NVD/OSV/EUVD
  live, it can download a signed-by-trust vulnerability-database **snapshot**
  from a trusted host and match versions **locally/offline** (falling back to
  the public sources when a snapshot is missing or a runtime isn't covered).
  This sidesteps per-device NVD rate limits and keeps queries private. Snapshot
  format: [`docs/vdb-snapshot-schema.md`](docs/vdb-snapshot-schema.md).

The header also shows an **OS version badge** that flags an out-of-date
operating system — an outdated OS usually means an outdated system WebView / TLS
stack — with one click through to the OS update settings.

[cbom]: https://cyclonedx.org/capabilities/cbom/
[cargo-auditable]: https://github.com/rust-secure-code/cargo-auditable
[rustsec]: https://github.com/RustSec/advisory-db

## Known limitations

- **Platform maturity varies.** macOS is the most-tested path.
  On Linux, apps that share a system Electron runtime
  (`/usr/lib/electronNN/electron`) are detected via that runtime, so per-app
  ASAR/resource signals can be missed; flatpak apps invoked via `flatpak run`
  don't yet resolve to a unique per-app binary.
- **NVD rate limits.** Without an API key, NVD allows ~5 requests per 30
  seconds. The on-disk cache (24h TTL) turns most queries into cache hits,
  but the *first* scan of a diverse app set will pause
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
- **No telemetry by default.** Scanning happens entirely locally and CVE
  lookups hit the public feeds by version string — nothing about your installed
  apps leaves the machine. The one exception is **opt-in fleet reporting**
  (off by default): if *you* enable it and point it at *your own* collector, the
  app inventory is sent there. There is no vendor telemetry.
- **Not a replacement for vendor triage.** If an advisory fires on an app
  you care about, read the upstream changelog before concluding anything.

## Contributing

The codebase is small enough that reading `crates/detect/src/lib.rs` and
`src-tauri/src/commands.rs` is the fastest way to get oriented. Bugs and
false positives against real-world bundles are the most useful thing to
file — the detection rules were tuned against ~20 apps, and anything that
ships a weirder binary layout will trip them.

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

## Project Credit
This was built by Daniel Thompson-Yvetot at https://crabnebula.dev 

## Catalogued and Archived at Software Heritage
[![SWH](https://archive.softwareheritage.org/badge/origin/https://github.com/crabnebula-dev/achilles/)](https://archive.softwareheritage.org/browse/origin/?origin_url=https://github.com/crabnebula-dev/achilles) [![SWH](https://archive.softwareheritage.org/badge/swh:1:dir:d0617676804f16abd073b7ff6f5cd816a11a18e7/)](https://archive.softwareheritage.org/swh:1:dir:d0617676804f16abd073b7ff6f5cd816a11a18e7;origin=https://github.com/crabnebula-dev/achilles;visit=swh:1:snp:d31787df5d6ccd095e362bfa60a13b538b47d57b;anchor=swh:1:rev:e18f3d3452fccee867bd86babb70e40cc61c6fd6)
