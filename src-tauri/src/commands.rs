//! Tauri commands exposed to the frontend.
//!
//! Keep this file thin — everything heavy lives in the `detect` / `scan` /
//! `cve` / `app_audit` crates so it remains testable without Tauri.

use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Emitter};

/// Enumerate installed GUI applications on the system, without running
/// detection.
#[tauri::command]
pub async fn discover() -> Result<Vec<scan::DiscoveredApp>, String> {
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

/// Platform-specific signing / hardening / integrity audit for one app.
/// `root` and `executable` come from the `Detection` so we don't re-resolve
/// per-OS paths here.
#[tauri::command]
pub async fn audit(
    path: PathBuf,
    root: PathBuf,
    executable: Option<PathBuf>,
) -> Result<app_audit::AppAudit, String> {
    app_audit::audit(&path, &root, executable.as_deref())
        .await
        .map_err(|e| e.to_string())
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

/// Run the AST-based static-analysis rules against the app's `app.asar`.
/// Works on any Electron app; for non-Electron apps returns an empty report.
/// `root` is the app's sibling-files dir (from `Detection`); the resources
/// layout differs per-OS (`Contents/Resources` on macOS, `resources` else).
/// Heavy work — runs on a blocking thread.
#[tauri::command]
pub async fn static_scan(root: PathBuf) -> Result<static_scan::Report, String> {
    tokio::task::spawn_blocking(move || {
        let resources = if cfg!(target_os = "macos") {
            root.join("Contents/Resources")
        } else {
            root.join("resources")
        };
        let asar_path = resources.join("app.asar");
        let unpacked = resources.join("app");
        if asar_path.is_file() {
            static_scan::scan_asar(&asar_path).map_err(|e| e.to_string())
        } else if unpacked.is_dir() {
            static_scan::scan_directory(&unpacked).map_err(|e| e.to_string())
        } else {
            Err(format!(
                "no app.asar or resources/app directory under {}",
                resources.display()
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
///
/// `on_update` receives a progressively-complete report each time a source
/// finishes, so the UI can paint fast sources (EUVD / OSV) without waiting on a
/// slow one (e.g. NVD retrying 503s). The resolved value is the final report.
#[tauri::command]
pub async fn cve_lookup(
    versions: CveLookupArgs,
    on_update: tauri::ipc::Channel<cve::CveReport>,
) -> Result<cve::CveReport, String> {
    let client = cve::OsvClient::new();
    let report = client
        .report_for_streaming(&versions.into(), |snapshot| {
            // A failed send just means the frontend dropped the channel (e.g.
            // the user clicked another app); the final return value still
            // carries the complete report.
            let _ = on_update.send(snapshot);
        })
        .await;
    Ok(report)
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

// ---------- fleet reporting ------------------------------------------

/// Trigger a reassessment + report now. Routed through the shared guarded
/// runner so it can't overlap a scheduled or tray-triggered run.
#[tauri::command]
pub async fn reassess_now(app: AppHandle) -> Result<(), String> {
    crate::run_reassessment(app).await;
    Ok(())
}

/// Return the persisted fleet-reporting config (defaults if none saved yet).
#[tauri::command]
pub async fn get_reporting_config() -> Result<crate::reporting::ReportingConfig, String> {
    Ok(crate::reporting::load())
}

/// Persist the fleet-reporting config and bring the OS login-item state in
/// line with its `autostart` flag.
#[tauri::command]
pub async fn set_reporting_config(
    app: AppHandle,
    config: crate::reporting::ReportingConfig,
) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;

    crate::reporting::save(&config).map_err(|e| e.to_string())?;

    let manager = app.autolaunch();
    let is_on = manager.is_enabled().unwrap_or(false);
    if config.autostart && !is_on {
        manager.enable().map_err(|e| e.to_string())?;
    } else if !config.autostart && is_on {
        manager.disable().map_err(|e| e.to_string())?;
    }

    // Reflect the new reporting on/off state in the tray status line at once.
    crate::refresh_tray_status(&app);
    Ok(())
}

/// Where the reporting config file lives, for display in the UI.
#[tauri::command]
pub async fn reporting_config_path() -> Option<String> {
    crate::reporting::path()
}

/// Download the trusted-host VDB snapshot now. No-op when VDB sourcing is
/// disabled/unconfigured. Progress is reported via the `vdb_status` event.
#[tauri::command]
pub async fn refresh_vdb_now(app: AppHandle) -> Result<(), String> {
    crate::reporting::refresh_vdb_snapshot(app).await
}

// ---------- network monitor / CBOM -----------------------------------

/// A finished capture: the traffic report plus the aggregated crypto inventory.
#[derive(Debug, Clone, Serialize)]
pub struct CbomResult {
    pub report: netmon::SessionReport,
    pub inventory: cbom::CryptoInventory,
}

/// List running processes so the user can pick a capture target.
#[tauri::command]
pub async fn netmon_processes() -> Result<Vec<netmon::RunningProcess>, String> {
    Ok(netmon::list_processes())
}

/// Whether this build/platform can capture packets (the UI disables Record if not).
#[tauri::command]
pub async fn netmon_capture_available() -> bool {
    netmon::capture_available()
}

/// Start a passive capture of `pid`'s traffic. Live observations stream over
/// `on_event`; the session runs until [`netmon_stop`]. Only one at a time.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // flat args mirror the frontend invoke
pub async fn netmon_start(
    state: tauri::State<'_, crate::NetmonState>,
    pid: u32,
    include_children: Option<bool>,
    display_name: Option<String>,
    bundle_id: Option<String>,
    exe_path: Option<String>,
    app_path: Option<String>,
    on_event: tauri::ipc::Channel<netmon::SessionDelta>,
) -> Result<netmon::SessionMeta, String> {
    let mut guard = state.0.lock().await;
    if guard.is_some() {
        return Err("a capture is already running".into());
    }

    let source = netmon::default_source().map_err(|e| e.to_string())?;
    let backend_id = source.backend_id().to_string();
    let filter = netmon::PidFilter {
        root_pid: pid,
        include_children: include_children.unwrap_or(true),
    };
    let (mut rx, handle) = source.start(filter).await.map_err(|e| e.to_string())?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let session_id = uuid::Uuid::new_v4().to_string();
    let target = netmon::TargetProcess {
        pid,
        exe_path,
        display_name,
        bundle_id,
    };
    let meta = netmon::SessionMeta {
        session_id: session_id.clone(),
        target: target.clone(),
        backend_id: backend_id.clone(),
        started_at: now,
    };

    let mut session = netmon::Session::new(session_id, target, backend_id, now);
    let join = tauri::async_runtime::spawn(async move {
        // A steady heartbeat pushes counters (bytes / flows / handshakes) to the
        // UI even when packets produce no new deltas — so the user always sees
        // that capture is live and traffic is flowing, not a frozen "0".
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_millis(500));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The loop ends when the capture stops (its sender is dropped).
        loop {
            tokio::select! {
                maybe = rx.recv() => match maybe {
                    Some(ev) => {
                        let deltas = session.ingest(ev);
                        if !deltas.is_empty() {
                            for delta in deltas {
                                let _ = on_event.send(delta);
                            }
                            let _ = on_event.send(session.counters());
                        }
                    }
                    None => break, // capture backend stopped (or died)
                },
                _ = heartbeat.tick() => {
                    let _ = on_event.send(session.counters());
                }
            }
        }
        let evidence = session.crypto_evidence();
        (session.finish(), evidence)
    });

    *guard = Some(crate::ActiveCapture {
        meta: meta.clone(),
        app_path,
        handle,
        join,
    });
    Ok(meta)
}

/// Stop the active capture, aggregate the CBOM, persist to the journal, and
/// return the report + inventory.
#[tauri::command]
pub async fn netmon_stop(
    state: tauri::State<'_, crate::NetmonState>,
) -> Result<CbomResult, String> {
    let active = state.0.lock().await.take().ok_or("no capture is running")?;
    active.handle.stop();
    let (report, mut evidence) = active.join.await.map_err(|e| e.to_string())?;

    let target = &active.meta.target;
    // Merge static binary crypto evidence with the observed (runtime) evidence
    // so the CBOM covers cryptography the recording didn't exercise.
    if let Some(exe) = target.exe_path.clone() {
        let root = active.app_path.clone();
        let static_ev = tokio::task::spawn_blocking(move || {
            cbom::static_evidence(std::path::Path::new(&exe), root.as_deref().map(std::path::Path::new))
        })
        .await
        .unwrap_or_default();
        evidence.extend(static_ev);
    }

    let app_ref = cbom::AppRef {
        name: target.display_name.clone().unwrap_or_else(|| "application".into()),
        version: None,
        bundle_id: target.bundle_id.clone(),
        path: active.app_path.clone().or_else(|| target.exe_path.clone()),
    };
    let inventory = cbom::build_inventory(app_ref, &evidence);

    // Retain the inventory for this app (survives navigation + restarts).
    let store_path = active
        .app_path
        .clone()
        .or_else(|| target.exe_path.clone())
        .unwrap_or_default();
    crate::crypto_store::save(&store_path, target.bundle_id.as_deref(), &inventory);

    // Persist alongside the app's other results in the journal.
    let payload = serde_json::json!({ "netmon": &report, "cbom": &inventory });
    let _ = crate::journal::save(crate::journal::SaveInput {
        app_path: target
            .exe_path
            .clone()
            .or_else(|| target.bundle_id.clone())
            .unwrap_or_else(|| "netmon".into()),
        display_name: target.display_name.clone(),
        bundle_id: target.bundle_id.clone(),
        payload,
    });

    Ok(CbomResult { report, inventory })
}

/// Metadata of the running capture, if any.
#[tauri::command]
pub async fn netmon_status(
    state: tauri::State<'_, crate::NetmonState>,
) -> Result<Option<netmon::SessionMeta>, String> {
    Ok(state.0.lock().await.as_ref().map(|a| a.meta.clone()))
}

/// Serialize a crypto inventory to a CycloneDX 1.6 CBOM JSON string (the UI
/// writes it to disk via the file dialog).
#[tauri::command]
pub async fn export_cbom(inventory: cbom::CryptoInventory) -> Result<String, String> {
    serde_json::to_string_pretty(&cbom::to_cyclonedx(&inventory)).map_err(|e| e.to_string())
}

/// Static-only CBOM: inventory an app's cryptography from its binaries without
/// recording traffic (linked crypto libraries + algorithm symbols).
#[tauri::command]
pub async fn crypto_inventory(
    path: PathBuf,
    executable: Option<PathBuf>,
    display_name: Option<String>,
    bundle_id: Option<String>,
) -> Result<cbom::CryptoInventory, String> {
    tokio::task::spawn_blocking(move || {
        let exe = executable.unwrap_or_else(|| path.clone());
        let evidence = cbom::static_evidence(&exe, Some(&path));
        let path_str = path.to_string_lossy().into_owned();
        let app = cbom::AppRef {
            name: display_name.unwrap_or_else(|| "application".into()),
            version: None,
            bundle_id: bundle_id.clone(),
            path: Some(path_str.clone()),
        };
        let inventory = cbom::build_inventory(app, &evidence);
        crate::crypto_store::save(&path_str, bundle_id.as_deref(), &inventory);
        inventory
    })
    .await
    .map_err(|e| e.to_string())
}

/// Load the last persisted crypto inventory for an app (retained across runs).
#[tauri::command]
pub async fn crypto_load(
    path: String,
    bundle_id: Option<String>,
) -> Option<cbom::CryptoInventory> {
    crate::crypto_store::load(&path, bundle_id.as_deref())
}

// ---------- binary header inspection ---------------------------------

/// Inspect the object-file headers (Mach-O / ELF / PE) of an app's primary
/// executable — format, architectures, file kind, header flags (PIE/NX/ASLR/…),
/// linked libraries, and segments/sections.
#[tauri::command]
pub async fn binary_headers(
    path: PathBuf,
    executable: Option<PathBuf>,
) -> Result<binmeta::BinaryMeta, String> {
    tokio::task::spawn_blocking(move || {
        let exe = executable.unwrap_or(path);
        binmeta::inspect(&exe).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

// ---------- linked-library vulnerabilities ---------------------------

/// Map a detected native-crypto library name → its NVD CPE `(vendor, product)`.
///
/// Deliberately limited to libraries where the name→CPE mapping is unambiguous
/// and the static scanner recovers an accurate upstream version banner. Apple
/// system dylibs (`libSystem`, `CommonCrypto`) carry OS build numbers that do
/// not map to CPEs, so they are intentionally absent — matching them would
/// produce noise, not findings.
fn library_cpe(name: &str) -> Option<(&'static str, &'static str)> {
    match name {
        "OpenSSL" => Some(("openssl", "openssl")),
        "LibreSSL" => Some(("openbsd", "libressl")),
        "GnuTLS" => Some(("gnu", "gnutls")),
        "wolfSSL" => Some(("wolfssl", "wolfssl")),
        "libsodium" => Some(("libsodium_project", "libsodium")),
        "mbedTLS" => Some(("arm", "mbed_tls")),
        "libgcrypt" => Some(("gnupg", "libgcrypt")),
        "nss" | "NSS" => Some(("mozilla", "nss")),
        _ => None,
    }
}

/// One linked library and the advisories affecting its detected version.
#[derive(Debug, Clone, Serialize)]
pub struct LibraryCves {
    pub library: String,
    pub version: String,
    pub advisories: Vec<cve::Advisory>,
}

/// Detect known native crypto libraries linked into an app (with their versions)
/// and look each up against NVD by CPE. Reuses the static crypto scanner, whose
/// banner-based version detection (e.g. `"OpenSSL 3.3.1"`) is more reliable for
/// CVE matching than a Mach-O `current_version`. Only libraries with a confident
/// CPE mapping *and* a detected version are queried; results with no advisories
/// are omitted so the UI shows only actionable findings.
#[tauri::command]
pub async fn library_cves(
    path: PathBuf,
    executable: Option<PathBuf>,
) -> Result<Vec<LibraryCves>, String> {
    let root = path.clone();
    let exe = executable.unwrap_or(path);
    let evidence = tokio::task::spawn_blocking(move || cbom::static_evidence(&exe, Some(&root)))
        .await
        .map_err(|e| e.to_string())?;

    // Collect unique (name, version, vendor, product) targets from the evidence.
    let mut targets: Vec<(String, String, &'static str, &'static str)> = Vec::new();
    for ev in &evidence {
        if let cbom::CryptoEvidence::Library {
            name,
            version: Some(version),
            ..
        } = ev
        {
            if let Some((vendor, product)) = library_cpe(name) {
                if !targets.iter().any(|(n, v, ..)| n == name && v == version) {
                    targets.push((name.clone(), version.clone(), vendor, product));
                }
            }
        }
    }

    let client = cve::OsvClient::new();
    let mut out = Vec::new();
    for (library, version, vendor, product) in targets {
        let advisories = client.lookup_cpe(vendor, product, &version).await;
        if !advisories.is_empty() {
            out.push(LibraryCves {
                library,
                version,
                advisories,
            });
        }
    }
    Ok(out)
}

// ---------- operating system version + update ------------------------

/// Operating-system name/version for the header badge, with a best-effort
/// "outdated" flag so the UI can nudge the user to update (an out-of-date OS
/// usually means an out-of-date system WebView / TLS stack).
#[derive(Debug, Clone, Serialize)]
pub struct OsInfo {
    pub os: String,
    pub display: String,
    pub version: Option<String>,
    pub outdated: bool,
    pub note: Option<String>,
}

#[tauri::command]
pub async fn os_info() -> OsInfo {
    compute_os_info()
}

/// Synchronous OS-version assessment, shared by the [`os_info`] command and the
/// tray status line.
pub(crate) fn compute_os_info() -> OsInfo {
    let os = std::env::consts::OS.to_string();
    let version = sysinfo::System::os_version();
    let display = sysinfo::System::long_os_version()
        .unwrap_or_else(|| format!("{os} {}", version.clone().unwrap_or_default()));

    // Conservative, easily-updated minimums. Below → nudge to update.
    let major = version
        .as_deref()
        .and_then(|v| v.split(['.', '-']).next())
        .and_then(|m| m.parse::<u32>().ok());
    let (outdated, note) = match os.as_str() {
        "macos" => match major {
            Some(m) if m < 14 => (
                true,
                Some("macOS is out of date — update for the latest Safari/WebKit security fixes.".into()),
            ),
            _ => (false, None),
        },
        "windows" => match major {
            Some(m) if m < 10 => (true, Some("Windows is out of date — update for current security fixes.".into())),
            _ => (false, None),
        },
        _ => (false, None),
    };

    OsInfo {
        os,
        display,
        version,
        outdated,
        note,
    }
}

/// Open the OS software-update settings.
#[tauri::command]
pub async fn open_os_update() -> Result<(), String> {
    open_os_update_settings().map_err(|e| e.to_string())
}

/// Launch the platform's software-update settings. Shared by the [`open_os_update`]
/// command and the tray's "System update available" item.
pub(crate) fn open_os_update_settings() -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let spawn = std::process::Command::new("open")
        .arg("x-apple.systempreferences:com.apple.Software-Update-Settings.extension")
        .spawn();
    #[cfg(target_os = "windows")]
    let spawn = std::process::Command::new("cmd")
        .args(["/c", "start", "ms-settings:windowsupdate"])
        .spawn();
    #[cfg(target_os = "linux")]
    let spawn = std::process::Command::new("xdg-open")
        .arg("gnome-control-center")
        .spawn();

    spawn.map(|_| ())
}

// ---------- rust-audit (cargo-auditable + RustSec) -------------------

/// Find cargo-auditable Rust binaries in an app and audit their embedded crate
/// dependencies against the RustSec advisory database. Heavy (mmap scan + first
/// run clones the advisory-db), so it runs on a blocking thread.
#[tauri::command]
pub async fn rust_audit(
    path: PathBuf,
    executable: Option<PathBuf>,
) -> Result<rust_audit::RustAuditReport, String> {
    tokio::task::spawn_blocking(move || {
        let exe = executable.unwrap_or_else(|| path.clone());
        rust_audit::audit(&exe, Some(&path))
    })
    .await
    .map_err(|e| e.to_string())
}

// ---------- privileged capture helper (macOS) ------------------------

/// SMAppService registration status: `enabled` | `requiresApproval` |
/// `notRegistered` | `notFound` | `unknown` | `unsupported`.
#[tauri::command]
pub async fn helper_status() -> String {
    #[cfg(target_os = "macos")]
    {
        crate::helper_mac::status_str().to_string()
    }
    #[cfg(not(target_os = "macos"))]
    {
        "unsupported".to_string()
    }
}

/// Register the privileged capture helper (prompts for approval on first use).
#[tauri::command]
pub async fn helper_install() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        crate::helper_mac::install()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("the capture helper is only available on macOS".into())
    }
}

/// Open System Settings → Login Items & Extensions so the user can approve it.
#[tauri::command]
pub async fn helper_open_settings() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        crate::helper_mac::open_login_items();
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("unsupported".into())
    }
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
    pub deno: Option<String>,
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
            deno: v.deno,
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
