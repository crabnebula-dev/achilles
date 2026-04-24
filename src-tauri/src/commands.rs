//! Tauri commands exposed to the frontend.
//!
//! Keep this file thin — everything heavy lives in the `detect` / `scan` /
//! `cve` / `macho_audit` crates so it remains testable without Tauri.

use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Emitter};

/// Enumerate `.app` bundles on the system, without running detection.
#[tauri::command]
pub async fn discover() -> Result<Vec<PathBuf>, String> {
    scan::discover_applications()
        .await
        .map_err(|e| e.to_string())
}

/// Run detection across every bundle Spotlight knows about, emitting
/// `scan_event` for each result. Resolves once the scan finishes.
#[tauri::command]
pub async fn scan(app: AppHandle, concurrency: Option<usize>) -> Result<usize, String> {
    let paths = scan::discover_applications()
        .await
        .map_err(|e| e.to_string())?;
    let total = paths.len();

    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let concurrency = concurrency.unwrap_or(8);
    tokio::spawn(scan::scan(paths, concurrency, tx));

    while let Some(event) = rx.recv().await {
        // Frontend-facing event name is kept stable — if you rename, bump a
        // version number in the payload too so the UI can cope.
        let _ = app.emit("scan_event", event);
    }
    Ok(total)
}

/// Run detection against a single path (used when the frontend lets the
/// user pick a custom bundle).
#[tauri::command]
pub async fn detect_one(path: PathBuf) -> Result<detect::Detection, String> {
    tokio::task::spawn_blocking(move || detect::detect(&path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// Entitlements + code-signature + Info.plist + ASAR integrity for one app.
#[tauri::command]
pub async fn audit(path: PathBuf) -> Result<macho_audit::MachoAudit, String> {
    macho_audit::audit(&path).await.map_err(|e| e.to_string())
}

/// System-level side effects: helpers/plugins/XPC inside the bundle,
/// native-messaging-host manifests dropped into browser profiles, launch
/// agents registered via `launchd`, log directory under `~/Library/Logs/`.
///
/// Arguments mirror the detect payload so the UI can pass what it already
/// has (bundle id, executable path) without re-parsing the Info.plist.
#[tauri::command]
pub async fn sideeffects(
    path: PathBuf,
    bundle_id: Option<String>,
    executable: Option<PathBuf>,
) -> Result<sideeffects::SideEffects, String> {
    tokio::task::spawn_blocking(move || {
        sideeffects::analyse(&path, bundle_id.as_deref(), executable.as_deref())
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

/// Run the OSV batch-query over every npm dependency the bundle's
/// `package-lock.json` / `package.json` declares.
///
/// Takes a pre-parsed `Vec<Dependency>` (usually from a prior `static_scan`
/// call) rather than re-reading the ASAR, so the UI can do both in parallel.
#[tauri::command]
pub async fn dependency_scan(
    deps: Vec<static_scan::Dependency>,
) -> Result<Vec<cve::NpmPackageAdvisories>, String> {
    if deps.is_empty() {
        return Ok(Vec::new());
    }
    let npm: Vec<cve::NpmPackage> = deps
        .into_iter()
        .map(|d| cve::NpmPackage {
            name: d.name,
            version: d.version,
        })
        .collect();
    let settings = cve::load_settings();
    let client = cve::OsvClient::new();
    let mut results = client.batch_npm(&npm).await.map_err(|e| e.to_string())?;
    cve::filter_npm_by_age(&mut results, settings.filters.max_age_years);
    Ok(results)
}

/// Run the AST-based static-analysis rules against the bundle's `app.asar`.
/// Works on any Electron `.app` path; for non-Electron bundles returns an
/// empty report. Heavy work — runs on a blocking thread.
#[tauri::command]
pub async fn static_scan(path: PathBuf) -> Result<static_scan::Report, String> {
    tokio::task::spawn_blocking(move || {
        let asar_path = path.join("Contents/Resources/app.asar");
        let unpacked = path.join("Contents/Resources/app");
        if asar_path.is_file() {
            static_scan::scan_asar(&asar_path).map_err(|e| e.to_string())
        } else if unpacked.is_dir() {
            static_scan::scan_directory(&unpacked).map_err(|e| e.to_string())
        } else {
            Err(format!(
                "no app.asar or Resources/app directory under {}",
                path.display()
            ))
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Query the configured CVE sources for a set of detected versions.
///
/// Uses whichever sources are enabled in [`cve::Settings`]; disabled sources
/// are skipped silently. A client is constructed per call so the newest
/// saved settings take effect immediately.
#[tauri::command]
pub async fn cve_lookup(versions: CveLookupArgs) -> Result<cve::CveReport, String> {
    let client = cve::OsvClient::new();
    Ok(client.report_for(&versions.into()).await)
}

/// Return the currently persisted settings (or [`cve::Settings::default`]
/// if no settings file exists yet).
#[tauri::command]
pub async fn get_settings() -> Result<cve::Settings, String> {
    Ok(cve::load_settings())
}

/// Persist the given settings to disk. On Unix the file is written with
/// mode 0600 since it may contain API tokens.
#[tauri::command]
pub async fn set_settings(settings: cve::Settings) -> Result<(), String> {
    cve::save_settings(&settings).map_err(|e| e.to_string())
}

/// Return the filesystem path where settings are persisted — useful for
/// showing in the UI so users know where their tokens live.
#[tauri::command]
pub async fn settings_path() -> Option<String> {
    cve::settings_path().map(|p| p.to_string_lossy().into_owned())
}

// ---------- journal --------------------------------------------------

/// Arguments for `journal_save`. The payload is frontend-assembled and kept
/// opaque on the Rust side — we only care about the key fields used for
/// grouping and display.
#[derive(Debug, serde::Deserialize)]
pub struct JournalSaveArgs {
    pub app_path: String,
    pub display_name: Option<String>,
    pub bundle_id: Option<String>,
    pub payload: serde_json::Value,
}

#[tauri::command]
pub async fn journal_save(args: JournalSaveArgs) -> Result<crate::journal::Entry, String> {
    tokio::task::spawn_blocking(move || {
        crate::journal::save(crate::journal::SaveInput {
            app_path: args.app_path,
            display_name: args.display_name,
            bundle_id: args.bundle_id,
            payload: args.payload,
        })
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

/// Return the most recent journal entry for `app_path`, or `null` if none.
#[tauri::command]
pub async fn journal_latest(app_path: String) -> Result<Option<crate::journal::Entry>, String> {
    tokio::task::spawn_blocking(move || crate::journal::latest(&app_path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// List every journal entry, newest first.
#[tauri::command]
pub async fn journal_list() -> Result<Vec<crate::journal::EntrySummary>, String> {
    tokio::task::spawn_blocking(crate::journal::list_all)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// Directory where journal entries live — exposed so the UI can show it.
#[tauri::command]
pub async fn journal_path() -> Option<String> {
    crate::journal::root_display()
}

// ---------- zoom ----------------------------------------------------

/// Set the webview's zoom factor. Used by the frontend's Cmd+=/Cmd+-/Cmd+0
/// handler to scale the entire UI — not just text. Clamping is enforced on
/// the frontend so this stays a dumb pass-through.
#[tauri::command]
pub async fn set_zoom(window: tauri::WebviewWindow, factor: f64) -> Result<(), String> {
    window.set_zoom(factor).map_err(|e| e.to_string())
}

/// Tauri has trouble deserialising types that live in other crates when
/// those crates aren't also serde users with the right feature set. Using a
/// thin local DTO sidesteps that; it's a structural copy of
/// [`detect::Versions`] and converts cleanly.
/// Frontend-friendly mirror of [`detect::Versions`]. Every field is
/// optional and extra/unknown fields are accepted so schema evolution in
/// `detect` doesn't break existing UIs sending partial payloads.
#[derive(Debug, Default, serde::Deserialize, Serialize)]
#[serde(default)]
pub struct CveLookupArgs {
    pub electron: Option<String>,
    pub chromium: Option<String>,
    pub node: Option<String>,
    pub tauri: Option<String>,
    pub cef: Option<String>,
    pub nwjs: Option<String>,
    pub flutter: Option<String>,
    pub qt: Option<String>,
    pub react_native: Option<String>,
    pub wails: Option<String>,
    pub sciter: Option<String>,
    pub java: Option<String>,
    pub webkit: Option<String>,
}

impl From<CveLookupArgs> for detect::Versions {
    fn from(v: CveLookupArgs) -> Self {
        Self {
            electron: v.electron,
            chromium: v.chromium,
            node: v.node,
            tauri: v.tauri,
            cef: v.cef,
            nwjs: v.nwjs,
            flutter: v.flutter,
            qt: v.qt,
            react_native: v.react_native,
            wails: v.wails,
            sciter: v.sciter,
            java: v.java,
            webkit: v.webkit,
        }
    }
}
