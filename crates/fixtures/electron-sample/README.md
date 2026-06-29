# `electron-sample` — a deliberately vulnerable Achilles fixture

A small, **synthetic** Electron app that exists only to exercise Achilles' analyzers against a known, stable target.
It is built from source rather than lifted from a real app, so it is license-clean, tiny, and doesn't drift between upstream releases.
**Do not use any of it as a template** — every setting here is intentionally wrong.

## What's in it

| File | Deliberate defect |
|---|---|
| `main.js` | `sandbox: false`, `nodeIntegration: true`, `contextIsolation: false`, `webSecurity: false` in a `BrowserWindow` |
| `index.html` | no `Content-Security-Policy` |
| `package.json` | depends on `lodash@4.17.20` (known prototype-pollution / ReDoS advisories) |

The builder (`cargo run -p fixtures --bin build-fixtures -- <out>`) packs these into two targets:

- `electron-sample.asar` — the renderer/main source as an Electron archive.
- `ElectronSample.app` — a minimal macOS bundle.
  A fake `Electron Framework` carries the Electron / Chromium / Node versions in its Info.plist and binary.
  The top-level `Info.plist` sets weak App Transport Security flags and registers a URL scheme.
  `Contents/Resources/app.asar` has a correct `ElectronAsarIntegrity` hash, so the integrity check is expected to pass.

## Expected findings (`expected.json`)

The manifest was generated once from a real analyzer run and then verified by hand.
It is the contract the CI assessment checks against — a lower bound, so a run must still surface at least everything listed.
Each entry traces back to a defect above:

- **detection** — `electron`, high confidence, `electron 28.1.0`, `chromium 120.0.6099.109`, `node 18.18.2`.
- **static findings** — `SANDBOX_JS_CHECK`, `NODE_INTEGRATION_JS_CHECK`, `CONTEXT_ISOLATION_JS_CHECK`, `WEB_SECURITY_JS_CHECK`, `CSP_GLOBAL_CHECK`.
- **dependencies** — `lodash@4.17.20`; its CVEs resolve live via OSV/GHSA, so the manifest pins only the package, not a volatile advisory list.
- **audit** — Info.plist `allowsArbitraryLoads`, the `insecure.example.com` TLS exception, the `achilles-sample` URL scheme, and ASAR integrity `matches: true`.

Code signing is not asserted.
The fixture is unsigned, so `codesign` reports it as unsigned and the manifest leaves those fields unchecked.

## How it runs in CI

`.github/workflows/fixtures.yml` is a two-job pipeline, and runs with read-only permissions because the fixture is treated as untrusted:

1. **build-fixtures** (Linux) — builds the target and uploads it as an artifact.
2. **assess** (macOS) — downloads the artifact and runs the real `detect`, `static-scan` and `audit` example CLIs against it.
   It runs on macOS so the bundle-layout detect/audit path is the default, so no `macos-bundle` feature is needed and the fixture stays independent of the wasm port.
   `cargo run -p fixtures --bin assess` then compares the output to `expected.json` and fails if anything is missing.

## Running / regenerating locally

```sh
# build the target
cargo run -q -p fixtures --bin build-fixtures -- /tmp/fix

# run the analyzers (on macOS — the .app detect/audit use the default bundle path)
cargo run -q -p detect       --example detect      -- /tmp/fix/ElectronSample.app  > /tmp/detect.json
cargo run -q -p static-scan  --example static-scan -- /tmp/fix/electron-sample.asar > /tmp/static.json
cargo run -q -p app-audit    --example audit       -- /tmp/fix/ElectronSample.app  > /tmp/audit.json

# assess against the manifest
cargo run -q -p fixtures --bin assess -- /tmp/detect.json /tmp/static.json /tmp/audit.json \
  crates/fixtures/electron-sample/expected.json
```

The `.app` detect/audit need the macOS bundle layout, so run them on **macOS**, where it is the default.
On Linux they require a build with the `macos-bundle` feature, which lives on the browser/wasm branch; the asar static-scan runs anywhere.

To **regenerate** the manifest after an intentional change to the fixture or the analyzers, update `expected.json` from the fresh output.
Re-verify the new findings by hand before committing.
