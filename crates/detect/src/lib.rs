//! Framework and runtime-version detection for macOS `.app` bundles.
//!
//! Given a path to a `.app` bundle (or any directory that looks like one),
//! [`detect`] returns a [`Detection`] describing whether the bundle is an
//! Electron app, a Tauri app, a plain native app, or something unrecognised,
//! along with any runtime version strings that could be extracted.
//!
//! The detector never panics and prefers partial results over errors: if a
//! path is malformed or a binary can't be read, the affected fields are left
//! `None` and the [`Confidence`] downgraded.

use std::path::{Path, PathBuf};

mod bundle;
mod cef;
mod chromium_browser;
mod electron;
mod flutter;
mod java;
mod nwjs;
mod qt;
mod react_native;
mod safari;
mod sciter;
mod strings;
mod tauri;
mod wails;

pub use bundle::BundleInfo;

/// Framework class of a macOS application bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Framework {
    /// Uses `Contents/Frameworks/Electron Framework.framework`.
    Electron,
    /// Uses the Tauri Rust runtime (WKWebView on macOS by default).
    Tauri,
    /// Uses `Contents/Frameworks/nwjs Framework.framework`.
    NwJs,
    /// Uses `Contents/Frameworks/FlutterMacOS.framework`.
    Flutter,
    /// Uses Qt (`Contents/Frameworks/QtCore.framework` present).
    Qt,
    /// Uses React Native for macOS (Hermes framework or JS-bundle markers).
    ReactNative,
    /// Uses Wails (Go + system WKWebView).
    Wails,
    /// Uses Sciter (HTML/CSS UI engine).
    Sciter,
    /// JVM-based app (bundled JRE under `Contents/PlugIns/*.jdk/` or
    /// similar).
    Java,
    /// Apple Safari itself. Distinct from ChromiumBrowser because Safari
    /// relies on system WebKit (`versions.webkit`) rather than a bundled
    /// Chromium.
    Safari,
    /// Uses `Contents/Frameworks/Chromium Embedded Framework.framework` as
    /// the *only* runtime signal. A CEF framework bundled alongside another
    /// runtime doesn't demote the primary verdict — see [`Versions::cef`].
    Cef,
    /// Chromium-based browser (Chrome, Arc, Brave, …). Distinct from
    /// Electron because these ship the browser shell, not an embedded app.
    ChromiumBrowser,
    /// Native Cocoa (or other non-embedded-webview) application.
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

/// Result of running [`detect`] on one bundle.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Detection {
    pub path: PathBuf,
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

/// Inspect the bundle at `app_path` and return a best-effort [`Detection`].
///
/// The path should point at a `.app` directory (or its equivalent). Pass a
/// path without a `Contents/` child and the result will be `Unknown` with no
/// versions populated — we still return `Ok(..)` rather than erroring, because
/// the scanner wants to list every entry it walked.
pub fn detect(app_path: &Path) -> Result<Detection, DetectError> {
    let app_path = app_path.to_path_buf();
    if !app_path.exists() {
        return Err(DetectError::NotFound(app_path));
    }
    if !app_path.is_dir() {
        return Err(DetectError::NotADirectory(app_path));
    }

    let bundle = bundle::read(&app_path);

    // Run every secondary-signal probe upfront so we can attach their
    // version strings to whichever primary verdict wins. Each probe is
    // cheap: a filesystem check + an Info.plist read, or a single mmap
    // + string scan for the binary-sniff ones.
    let cef_version = cef::detect(&app_path);
    let flutter_version = flutter::detect(&app_path);
    let qt_probe = qt::detect(&app_path)?;
    let nwjs_probe = nwjs::detect(&app_path)?;
    let rn_probe = react_native::detect(&app_path, bundle.executable.as_deref())?;
    let wails_version = match bundle.executable.as_deref() {
        Some(exe) => wails::detect(exe)?,
        None => None,
    };
    let sciter_version = sciter::detect(&app_path)?;
    let java_probe = java::detect(&app_path, bundle.executable.as_deref());
    // System WKWebView version, memoised across all apps in a scan.
    let system_webkit = safari::system_webkit_version();

    let mut extra_versions = Versions {
        cef: cef_version.clone(),
        flutter: flutter_version.clone(),
        qt: qt_probe.as_ref().and_then(|q| q.qt_version.clone()),
        nwjs: nwjs_probe.as_ref().and_then(|n| n.nwjs_version.clone()),
        react_native: rn_probe.as_ref().and_then(|r| r.version.clone()),
        wails: wails_version.clone(),
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
    if let Some(result) = electron::detect(&app_path)? {
        let versions = merge_versions(result.versions, &extra_versions);
        return Ok(build(
            &app_path,
            &bundle,
            Framework::Electron,
            result.confidence,
            versions,
        ));
    }

    if let Some(result) = tauri::detect(&bundle)? {
        let mut versions = merge_versions(result.versions, &extra_versions);
        versions.webkit = system_webkit.clone();
        return Ok(build(
            &app_path,
            &bundle,
            Framework::Tauri,
            result.confidence,
            versions,
        ));
    }

    if nwjs_probe.is_some() {
        return Ok(build(
            &app_path,
            &bundle,
            Framework::NwJs,
            Confidence::High,
            extra_versions,
        ));
    }

    if flutter_version.is_some() {
        return Ok(build(
            &app_path,
            &bundle,
            Framework::Flutter,
            Confidence::High,
            extra_versions,
        ));
    }

    if qt_probe.is_some() {
        return Ok(build(
            &app_path,
            &bundle,
            Framework::Qt,
            Confidence::High,
            extra_versions,
        ));
    }

    if rn_probe.is_some() {
        // Hermes framework = High; binary-string fallback = Medium.
        let confidence = if app_path
            .join("Contents/Frameworks/hermes.framework")
            .is_dir()
        {
            Confidence::High
        } else {
            Confidence::Medium
        };
        return Ok(build(
            &app_path,
            &bundle,
            Framework::ReactNative,
            confidence,
            extra_versions,
        ));
    }

    if wails_version.is_some() {
        let mut versions = extra_versions.clone();
        versions.webkit = system_webkit.clone();
        return Ok(build(
            &app_path,
            &bundle,
            Framework::Wails,
            Confidence::High,
            versions,
        ));
    }

    if sciter_version.is_some() {
        return Ok(build(
            &app_path,
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
            &app_path,
            &bundle,
            Framework::Java,
            confidence,
            extra_versions,
        ));
    }

    // Safari itself — a deterministic bundle-id check.
    if let Some(safari_version) = safari::detect_app(bundle.bundle_id.as_deref(), &app_path) {
        let mut versions = extra_versions.clone();
        versions.webkit = Some(safari_version);
        return Ok(build(
            &app_path,
            &bundle,
            Framework::Safari,
            Confidence::High,
            versions,
        ));
    }

    // Chromium-based browsers (Chrome, Arc, Brave, …). Check after Electron
    // because Electron apps also ship a Chromium; those are caught above.
    if let Some(browser) = chromium_browser::detect(&app_path) {
        extra_versions.chromium = extra_versions
            .chromium
            .or(browser.chromium_version);
        return Ok(build(
            &app_path,
            &bundle,
            Framework::ChromiumBrowser,
            Confidence::High,
            extra_versions,
        ));
    }

    if cef_version.is_some() {
        return Ok(build(
            &app_path,
            &bundle,
            Framework::Cef,
            Confidence::High,
            extra_versions,
        ));
    }

    // Fall through: treat a bundle with an executable as Native, anything
    // else as Unknown. Still carry any secondary-signal versions we found.
    let framework = if bundle.executable.is_some() {
        Framework::Native
    } else {
        Framework::Unknown
    };
    Ok(build(
        &app_path,
        &bundle,
        framework,
        Confidence::High,
        extra_versions,
    ))
}

fn build(
    app_path: &Path,
    bundle: &BundleInfo,
    framework: Framework,
    confidence: Confidence,
    versions: Versions,
) -> Detection {
    Detection {
        path: app_path.to_path_buf(),
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
