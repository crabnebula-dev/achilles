//! Framework and runtime-version detection for installed applications, across
//! macOS, Windows, and Linux.
//!
//! Given a [`DiscoveredApp`] (or a path, via [`detect`]), [`detect_app`]
//! returns a [`Detection`] describing whether the app is an Electron app, a
//! Tauri app, a plain native app, or something unrecognised, along with any
//! runtime version strings that could be extracted.
//!
//! The shape on disk differs per OS — a macOS `.app` bundle vs. a Windows /
//! Linux executable with sibling files — but the version fingerprints live as
//! literal strings in the binary (and its import table), so most of the work is
//! shared. The per-OS specifics are hidden behind an internal `Layout`.
//!
//! The detector never panics and prefers partial results over errors: if a
//! path is malformed or a binary can't be read, the affected fields are left
//! `None` and the [`Confidence`] downgraded.

use std::path::{Path, PathBuf};

mod app;
mod bundle;
mod cef;
mod chromium_browser;
mod deno;
mod electron;
mod flutter;
mod java;
mod metadata;
mod nwjs;
mod qt;
mod react_native;
#[cfg(target_os = "macos")]
mod safari;
mod sciter;
mod strings;
mod system_webview;
mod tauri;
mod wails;

pub use app::DiscoveredApp;
use app::Layout;
pub use bundle::BundleInfo;

/// Framework class of an application — be it a macOS `.app` bundle, a Windows
/// install directory, or a Linux binary plus its sibling files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Framework {
    /// Electron — `Electron Framework.framework` (macOS) or a
    /// `resources/{app,electron}.asar` + the `Electron/` UA string in the
    /// binary (Windows / Linux).
    Electron,
    /// Uses the Tauri Rust runtime (system webview: WKWebView / WebView2 /
    /// WebKitGTK).
    Tauri,
    /// NW.js (`nwjs Framework.framework` / `nw.dll` / `libnw.so`).
    NwJs,
    /// Flutter (`FlutterMacOS.framework` / `flutter_windows.dll` /
    /// `libflutter_linux_gtk.so`).
    Flutter,
    /// Qt (`QtCore.framework` / `Qt{5,6}Core.dll` / `libQt{5,6}Core.so`).
    Qt,
    /// React Native (Hermes framework / `hermes.dll` / `libhermes.so`, or
    /// RN symbols in the binary).
    ReactNative,
    /// Uses Wails (Go + system webview).
    Wails,
    /// Deno-desktop app: a bundled Deno runtime driving a system webview (or a
    /// bundled CEF/Chromium, captured separately in [`Versions::cef`]).
    Deno,
    /// Uses Sciter (HTML/CSS UI engine).
    Sciter,
    /// JVM-based app (bundled JRE with a `release` file).
    Java,
    /// Apple Safari itself (macOS). Distinct from ChromiumBrowser because Safari
    /// relies on system WebKit (`versions.webkit`) rather than a bundled
    /// Chromium.
    Safari,
    /// Bundles the Chromium Embedded Framework (`libcef`) as the *only* runtime
    /// signal. CEF alongside another runtime doesn't demote the primary verdict
    /// — see [`Versions::cef`].
    Cef,
    /// Chromium-based browser (Chrome, Arc, Brave, …). Distinct from
    /// Electron because these ship the browser shell, not an embedded app.
    ChromiumBrowser,
    /// Native (non-embedded-webview) application.
    Native,
    /// Could not determine.
    Unknown,
}

/// How sure the detector is about its [`Framework`] verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Runtime version strings extracted from a bundle's binaries.
///
/// Every field is optional: detectors populate what they can find and leave
/// the rest `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Versions {
    /// Electron framework version (e.g. `"40.4.1"`).
    pub electron: Option<String>,
    /// Bundled Chromium version (e.g. `"144.0.7559.173"`).
    pub chromium: Option<String>,
    /// Bundled Node.js version without the leading `v` (e.g. `"24.13.0"`).
    pub node: Option<String>,
    /// Tauri crate version (e.g. `"2.1.0"`).
    pub tauri: Option<String>,
    /// Deno runtime version (e.g. `"2.7.5"`), for Deno-desktop apps that
    /// bundle the Deno runtime.
    pub deno: Option<String>,
    /// Chromium Embedded Framework version, if the bundle contains the CEF
    /// framework. Populated independently of [`Framework`]: a Tauri app
    /// that also bundles CEF will show both.
    pub cef: Option<String>,
    /// NW.js framework version.
    pub nwjs: Option<String>,
    /// Flutter engine version (from `FlutterMacOS.framework`).
    pub flutter: Option<String>,
    /// Qt runtime version (from `QtCore.framework`).
    pub qt: Option<String>,
    /// React Native macOS version (from Hermes framework Info.plist or JS
    /// bundle string markers).
    pub react_native: Option<String>,
    /// Wails version (extracted from the main binary's Go build info).
    pub wails: Option<String>,
    /// Sciter library version.
    pub sciter: Option<String>,
    /// Java runtime version (from a bundled JRE's `release` file).
    pub java: Option<String>,
    /// System Safari / WKWebView version on the scanning machine.
    ///
    /// Populated for apps that use system WKWebView as their renderer
    /// (Tauri, Wails, and Safari itself). This isn't a per-app bundled
    /// runtime — it tracks with the macOS / Safari install — but it's the
    /// effective engine version those apps render with, so we surface it
    /// on each affected row so users can cross-reference with the
    /// `apple:safari` CVE stream.
    pub webkit: Option<String>,
}

/// Result of running [`detect`] on one app.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Detection {
    /// Stable identity: the `.app` dir (macOS) or primary executable
    /// (Windows / Linux). The UI keys rows on this.
    pub path: PathBuf,
    /// Directory holding the app's sibling runtime files. Downstream audits
    /// (`app-audit`, `sideeffects`, `static-scan`) use it instead of
    /// re-deriving platform paths.
    pub root: PathBuf,
    /// Primary executable, resolved per-OS (macOS `CFBundleExecutable`, the
    /// real ELF behind a Linux launcher, the Windows `.exe`). `None` when no
    /// readable executable was found.
    pub executable: Option<PathBuf>,
    pub bundle_id: Option<String>,
    pub display_name: Option<String>,
    pub bundle_version: Option<String>,
    pub framework: Framework,
    pub confidence: Confidence,
    pub versions: Versions,
}

#[derive(Debug, thiserror::Error)]
pub enum DetectError {
    #[error("path not found: {0}")]
    NotFound(PathBuf),
    #[error("not a directory: {0}")]
    NotADirectory(PathBuf),
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Inspect the application at `app_path` and return a best-effort [`Detection`].
///
/// The path should point at a `.app` directory (macOS) or the primary
/// executable (Windows / Linux). For richer cases — where discovery already
/// knows the executable and display name — prefer [`detect_app`]. A path with
/// no recognisable framework yields `Unknown` with no versions populated; we
/// still return `Ok(..)` rather than erroring so the scanner can list every
/// entry it walked.
pub fn detect(app_path: &Path) -> Result<Detection, DetectError> {
    detect_app(&DiscoveredApp::from_path(app_path))
}

/// Inspect a [`DiscoveredApp`] and return a best-effort [`Detection`]. This is
/// the entry point the scanner uses: discovery has already resolved the root,
/// executable, and display name per-OS.
pub fn detect_app(app: &DiscoveredApp) -> Result<Detection, DetectError> {
    if !app.path.exists() {
        return Err(DetectError::NotFound(app.path.clone()));
    }

    // A Windows Squirrel launcher stub points discovery at the install root,
    // which has no runtime markers; redirect to the real versioned app dir so
    // probes (and downstream audits, via `Detection.root`/`executable`) see it.
    // `app.path` is preserved as the stable identity.
    #[cfg(target_os = "windows")]
    let redirected = app::redirect_squirrel_stub(app);
    #[cfg(target_os = "windows")]
    let app = redirected.as_ref().unwrap_or(app);

    let bundle = metadata::read(app);
    // Effective executable: discovery's, falling back to the one declared in
    // platform metadata (macOS `CFBundleExecutable`). Must be a regular file —
    // a directory (or a path that vanished) would crash the mmap probes — so we
    // drop anything that isn't, leaving framework probes to skip cleanly.
    let executable = app
        .executable
        .clone()
        .or_else(|| bundle.executable.clone())
        .filter(|p| p.is_file());
    let layout = Layout::new(app.root.clone(), executable);
    let identity = &app.path;

    // Run every secondary-signal probe upfront so we can attach their
    // version strings to whichever primary verdict wins. Each probe is
    // cheap: a filesystem / import-table check, or a single mmap + string
    // scan for the binary-sniff ones.
    let cef_version = cef::detect(&layout);
    let flutter_version = flutter::detect(&layout);
    let qt_probe = qt::detect(&layout)?;
    let nwjs_probe = nwjs::detect(&layout)?;
    let rn_probe = react_native::detect(&layout)?;
    let wails_version = match layout.executable.as_deref() {
        Some(exe) => wails::detect(exe)?,
        None => None,
    };
    let deno_version = match layout.executable.as_deref() {
        Some(exe) => deno::detect(exe)?,
        None => None,
    };
    let sciter_version = sciter::detect(&layout)?;
    let java_probe = java::detect(&layout);
    // Effective system webview engine version (macOS WKWebView / Windows
    // WebView2 / Linux WebKitGTK), memoised across all apps in a scan.
    let system_webview = system_webview::detect();

    let mut extra_versions = Versions {
        cef: cef_version.clone(),
        flutter: flutter_version.clone(),
        qt: qt_probe.as_ref().and_then(|q| q.qt_version.clone()),
        nwjs: nwjs_probe.as_ref().and_then(|n| n.nwjs_version.clone()),
        react_native: rn_probe.as_ref().and_then(|r| r.version.clone()),
        wails: wails_version.clone(),
        deno: deno_version.clone(),
        sciter: sciter_version.clone(),
        java: java_probe.as_ref().and_then(|j| j.version.clone()),
        // Chromium from QtWebEngine takes precedence over nwjs chromium
        // when both exist (extremely unlikely, but defined).
        chromium: qt_probe
            .as_ref()
            .and_then(|q| q.chromium_version.clone())
            .or_else(|| nwjs_probe.as_ref().and_then(|n| n.chromium_version.clone())),
        ..Versions::default()
    };

    // Electron is the highest-signal primary verdict.
    if let Some(result) = electron::detect(&layout)? {
        let versions = merge_versions(result.versions, &extra_versions);
        return Ok(build(
            identity,
            &layout,
            &bundle,
            Framework::Electron,
            result.confidence,
            versions,
        ));
    }

    if let Some(result) = tauri::detect(&layout)? {
        let mut versions = merge_versions(result.versions, &extra_versions);
        system_webview::apply(system_webview.as_ref(), &mut versions);
        return Ok(build(
            identity,
            &layout,
            &bundle,
            Framework::Tauri,
            result.confidence,
            versions,
        ));
    }

    if nwjs_probe.is_some() {
        return Ok(build(
            identity,
            &layout,
            &bundle,
            Framework::NwJs,
            Confidence::High,
            extra_versions,
        ));
    }

    if flutter_version.is_some() {
        return Ok(build(
            identity,
            &layout,
            &bundle,
            Framework::Flutter,
            Confidence::High,
            extra_versions,
        ));
    }

    if qt_probe.is_some() {
        return Ok(build(
            identity,
            &layout,
            &bundle,
            Framework::Qt,
            Confidence::High,
            extra_versions,
        ));
    }

    if let Some(rn) = &rn_probe {
        // A bundled engine (Hermes framework / library) is High; the
        // binary-string fallback is Medium.
        let confidence = if rn.bundled_engine {
            Confidence::High
        } else {
            Confidence::Medium
        };
        return Ok(build(
            identity,
            &layout,
            &bundle,
            Framework::ReactNative,
            confidence,
            extra_versions,
        ));
    }

    if wails_version.is_some() {
        let mut versions = extra_versions.clone();
        system_webview::apply(system_webview.as_ref(), &mut versions);
        return Ok(build(
            identity,
            &layout,
            &bundle,
            Framework::Wails,
            Confidence::High,
            versions,
        ));
    }

    if deno_version.is_some() {
        let mut versions = extra_versions.clone();
        // Deno desktop renders via the system webview unless it bundles CEF
        // (already captured in `versions.cef`).
        system_webview::apply(system_webview.as_ref(), &mut versions);
        return Ok(build(
            identity,
            &layout,
            &bundle,
            Framework::Deno,
            Confidence::High,
            versions,
        ));
    }

    if sciter_version.is_some() {
        return Ok(build(
            identity,
            &layout,
            &bundle,
            Framework::Sciter,
            Confidence::High,
            extra_versions,
        ));
    }

    if java_probe.is_some() {
        // Release-file hit = High; launcher-name-only = Medium.
        let had_release = java_probe
            .as_ref()
            .and_then(|j| j.version.as_deref())
            .map(|v| v != "unknown")
            .unwrap_or(false);
        let confidence = if had_release {
            Confidence::High
        } else {
            Confidence::Medium
        };
        return Ok(build(
            identity,
            &layout,
            &bundle,
            Framework::Java,
            confidence,
            extra_versions,
        ));
    }

    // Safari itself — a deterministic bundle-id check. macOS only; no Safari
    // ships on Windows / Linux.
    #[cfg(target_os = "macos")]
    if let Some(safari_version) = safari::detect_app(bundle.bundle_id.as_deref(), &layout.root) {
        let mut versions = extra_versions.clone();
        versions.webkit = Some(safari_version);
        return Ok(build(
            identity,
            &layout,
            &bundle,
            Framework::Safari,
            Confidence::High,
            versions,
        ));
    }

    // Chromium-based browsers (Chrome, Arc, Brave, …). Check after Electron
    // because Electron apps also ship a Chromium; those are caught above.
    if let Some(browser) = chromium_browser::detect(&layout) {
        extra_versions.chromium = extra_versions.chromium.or(browser.chromium_version);
        return Ok(build(
            identity,
            &layout,
            &bundle,
            Framework::ChromiumBrowser,
            Confidence::High,
            extra_versions,
        ));
    }

    if cef_version.is_some() {
        return Ok(build(
            identity,
            &layout,
            &bundle,
            Framework::Cef,
            Confidence::High,
            extra_versions,
        ));
    }

    // Fall through: treat an app with an executable as Native, anything
    // else as Unknown. Still carry any secondary-signal versions we found.
    let framework = if layout.executable.is_some() {
        Framework::Native
    } else {
        Framework::Unknown
    };
    Ok(build(
        identity,
        &layout,
        &bundle,
        framework,
        Confidence::High,
        extra_versions,
    ))
}

fn build(
    app_path: &Path,
    layout: &Layout,
    bundle: &BundleInfo,
    framework: Framework,
    confidence: Confidence,
    versions: Versions,
) -> Detection {
    Detection {
        path: app_path.to_path_buf(),
        root: layout.root.clone(),
        executable: layout.executable.clone(),
        bundle_id: bundle.bundle_id.clone(),
        display_name: bundle.display_name.clone(),
        bundle_version: bundle.bundle_version.clone(),
        framework,
        confidence,
        versions,
    }
}

/// Overlay any `Some(..)` fields from `extra` onto `base`. Fields already
/// set on `base` (e.g. Electron's own Electron/Chromium/Node versions) win.
fn merge_versions(mut base: Versions, extra: &Versions) -> Versions {
    if base.electron.is_none() {
        base.electron = extra.electron.clone();
    }
    if base.chromium.is_none() {
        base.chromium = extra.chromium.clone();
    }
    if base.node.is_none() {
        base.node = extra.node.clone();
    }
    if base.tauri.is_none() {
        base.tauri = extra.tauri.clone();
    }
    if base.deno.is_none() {
        base.deno = extra.deno.clone();
    }
    if base.cef.is_none() {
        base.cef = extra.cef.clone();
    }
    if base.nwjs.is_none() {
        base.nwjs = extra.nwjs.clone();
    }
    if base.flutter.is_none() {
        base.flutter = extra.flutter.clone();
    }
    if base.qt.is_none() {
        base.qt = extra.qt.clone();
    }
    if base.react_native.is_none() {
        base.react_native = extra.react_native.clone();
    }
    if base.wails.is_none() {
        base.wails = extra.wails.clone();
    }
    if base.sciter.is_none() {
        base.sciter = extra.sciter.clone();
    }
    if base.java.is_none() {
        base.java = extra.java.clone();
    }
    if base.webkit.is_none() {
        base.webkit = extra.webkit.clone();
    }
    base
}
