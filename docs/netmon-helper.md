# Privileged capture helper (macOS)

Passive per-app packet capture on macOS uses the `pktap` interface, and creating
it (`SIOCIFCREATE`) is **root-only**. Rather than run Achilles itself as root, a
tiny **root helper daemon** does the capture and streams events back to the app
over a local socket. The helper is installed and launched via **`SMAppService`**,
which — unlike a Network Extension — needs **no special Apple entitlement**: it
works within the existing Developer-ID signing + notarization that
`.github/workflows/publish.yml` already performs, and ships inside the `.app` so
the Tauri updater delivers helper updates automatically.

## Architecture

```
Achilles.app (user)                     achilles-netmon-helper (root LaunchDaemon)
  netmon::HelperSource  ──connect──▶  /var/run/dev.crabnebula.achilles.netmon.sock
     └ send PidFilter ──────────────▶  reads filter, captures target via pktap
     ◀───────────────── CapturedEvent  streams length-prefixed JSON frames
```

- Wire protocol: `crates/netmon/src/wire.rs` (length-prefixed JSON frames).
- App side: `netmon::backends::helper::HelperSource` (connects, sends
  `PidFilter`, yields `CapturedEvent`s). `default_source()` prefers it whenever
  the socket exists, else falls back to direct pcap (needs sudo) / host-wide.
- Helper: `crates/netmon-helper` (`achilles-netmon-helper` binary) — reuses
  `netmon::direct_capture_source()` (pktap) and serves the socket.

## Shipping (already wired)

- **Build + stage the helper per target** — `scripts/stage-netmon-helper.sh`,
  run automatically as the `beforeDevCommand` / `beforeBuildCommand` in
  `src-tauri/tauri.macos.conf.json`. It builds `netmon-helper` for
  `$TAURI_ENV_TARGET_TRIPLE` (falling back to the host triple) and stages it at
  `src-tauri/binaries/achilles-netmon-helper-<target-triple>`. The triple suffix
  is mandatory: Tauri resolves sidecars per target and strips it when copying
  into the bundle. Nothing to do by hand, locally or in CI.
- **Embed + sign** via `src-tauri/tauri.macos.conf.json` → `bundle.externalBin`
  (`binaries/achilles-netmon-helper`). Tauri copies sidecars to
  `Contents/MacOS/achilles-netmon-helper` — the path the LaunchDaemon plist's
  `BundleProgram` points at — and **signs each one as an executable**: Developer
  ID + hardened runtime + secure timestamp. `externalBin` is a cross-platform
  key, so it lives in the macOS-only config file; otherwise the Linux/Windows
  jobs would demand a helper binary for their own triples.
  - The daemon plist still rides along via `bundle.macOS.files` →
    `Library/LaunchDaemons/dev.crabnebula.achilles.netmon.plist`. That's fine:
    it's not a Mach-O, so it needs no signature of its own, and it's copied
    before the app is sealed.
  - ⚠️ Do **not** ship the helper via `bundle.macOS.files`. Those files are
    copied but never added to the bundler's sign list, so the helper reaches
    notarization unsigned and Apple rejects the archive with "not signed with a
    valid Developer ID certificate" / "does not include a secure timestamp" /
    "does not have the hardened runtime enabled".
- **Notarization** already runs in `publish.yml`; the embedded helper +
  LaunchDaemon are covered because they're inside the bundle at sign time.

## Auto-install (the remaining step — needs a signed build to validate)

Add a small macOS module that registers the daemon via `SMAppService` and drives
the one-time user approval. Recommended crates (macOS target only):
`objc2`, `objc2-foundation`, `objc2-service-management`.

```rust
// src-tauri/src/helper_mac.rs   (#[cfg(target_os = "macos")])
use objc2_foundation::NSString;
use objc2_service_management::{SMAppService, SMAppServiceStatus};

const PLIST: &str = "dev.crabnebula.achilles.netmon.plist";

pub fn service() -> objc2::rc::Retained<SMAppService> {
    let name = NSString::from_str(PLIST);
    unsafe { SMAppService::daemonServiceWithPlistName(&name) }
}

/// Register the daemon. First call → status becomes `RequiresApproval`; the user
/// enables it in System Settings → General → Login Items & Extensions.
pub fn install() -> Result<(), String> {
    unsafe { service().registerAndReturnError() }.map_err(|e| e.localizedDescription().to_string())
}

pub fn status() -> SMAppServiceStatus { unsafe { service().status() } }

pub fn open_login_items() {
    unsafe { SMAppService::openSystemSettingsLoginItems() };
}
```

Wire as Tauri commands (`helper_status`, `helper_install`, `helper_open_settings`)
and call `install()` on first launch / when the user clicks **Record** and the
socket is absent. UX: if `status()` is `RequiresApproval`, show a banner —
"Achilles needs a one-time approval to capture traffic" — with a button that
calls `open_login_items()`. Once enabled, launchd starts the daemon as root, the
socket appears, and `default_source()` transparently switches to `HelperSource`.

On update, call `install()` again on launch to re-validate (same-Team signature
→ no re-approval in the normal case). No workflow-secret changes are required.

## Security notes

- The helper socket is currently `0666`; a hardening pass should restrict it to
  the console user's uid via `LOCAL_PEERCRED`, and the helper should validate the
  connecting client.
- The daemon runs continuously (`KeepAlive`) but only captures while the app is
  connected and has sent a target PID.

## Fallback (already implemented)

Without the helper (or during development), `PcapSource` tries `pktap` and, if
that's denied, falls back to the default interface (needs only BPF/ChmodBPF
access) capturing **host-wide** with an in-UI notice. For full per-app capture in
dev without the helper, run the built binary with `sudo`.
