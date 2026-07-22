//! `achilles` — Tauri app entry point.
//!
//! Wires the `detect` / `scan` / `cve` / `app_audit` crates into the
//! `#[tauri::command]` functions. The frontend drives them; progress is
//! streamed back via `app.emit("scan_event", …)`.
//!
//! The app also runs as a background fleet agent: it lives in the system tray,
//! can launch at login, and a scheduler periodically reassesses installed apps
//! and reports an inventory to a collector (see [`reporting`]).

mod commands;
mod crypto_store;
#[cfg(target_os = "macos")]
mod helper_mac;
mod journal;
mod reporting;

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, WindowEvent, Wry};
use tauri_plugin_autostart::{ManagerExt, MacosLauncher};

/// Serialises reassessment runs so the scheduler, tray, and manual command can
/// never overlap. Held as Tauri-managed state.
#[derive(Default)]
pub struct ReassessGuard(pub tokio::sync::Mutex<()>);

/// An in-progress network-capture session (there is at most one at a time).
pub struct ActiveCapture {
    pub meta: netmon::SessionMeta,
    /// App bundle path, for merging static binary evidence on stop.
    pub app_path: Option<String>,
    /// Stopping (or dropping) this ends the OS capture.
    pub handle: netmon::CaptureHandle,
    /// The driver task; yields the final report + crypto evidence on stop.
    pub join: tauri::async_runtime::JoinHandle<(netmon::SessionReport, Vec<cbom::CryptoEvidence>)>,
}

/// The single active capture session, if any. Held as Tauri-managed state.
#[derive(Default)]
pub struct NetmonState(pub tokio::sync::Mutex<Option<ActiveCapture>>);

/// The outcome of the most recent reassessment, summarised for the tray status
/// lines.
#[derive(Clone, Copy)]
struct LastRun {
    /// Unix seconds the run finished.
    at: u64,
    /// Apps in the inventory it built.
    count: usize,
    /// Whether the inventory was actually POSTed (vs. built-but-not-sent because
    /// reporting is off/unconfigured).
    sent: bool,
    /// Whether the run succeeded.
    ok: bool,
    /// Version-based risk tally over every detected app.
    risk: reporting::RiskSummary,
}

/// Backs the tray-menu status lines. Holds the three menu items so the scheduler
/// can relabel them, plus the last reassessment outcome they summarise. Held as
/// Tauri-managed state.
#[derive(Default)]
pub struct TrayStatus {
    /// "N apps need attention" (click → show window).
    risk_item: Mutex<Option<MenuItem<Wry>>>,
    /// "System update available" (click → open OS update settings).
    os_item: Mutex<Option<MenuItem<Wry>>>,
    /// Reporting on/off + last-check summary (disabled label).
    reporting_item: Mutex<Option<MenuItem<Wry>>>,
    last: Mutex<Option<LastRun>>,
}

/// Current unix seconds (0 if the clock is before the epoch).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The risk-summary line: how many apps need attention, from the last run.
fn tray_risk_text(last: &Option<LastRun>) -> String {
    match last {
        None => "Apps: no scan yet".to_string(),
        Some(r) if !r.ok => "Apps: last scan failed".to_string(),
        Some(r) => {
            let flagged = r.risk.warn + r.risk.bad;
            if flagged == 0 {
                format!("✓ {} apps — none at risk", r.risk.total)
            } else if r.risk.bad > 0 {
                format!("⚠ {flagged} of {} apps at risk ({} high)", r.risk.total, r.risk.bad)
            } else {
                format!("⚠ {flagged} of {} apps at risk", r.risk.total)
            }
        }
    }
}

/// The OS line: whether a system update is warranted. `None` when up to date, so
/// the caller can grey the item out.
fn tray_os_text() -> (String, bool) {
    let info = commands::compute_os_info();
    if info.outdated {
        (format!("⚠ System update available — {}", info.display), true)
    } else {
        (format!("✓ System up to date — {}", info.display), false)
    }
}

/// The reporting line: on/off plus a summary of the last reassessment.
fn tray_reporting_text(last: &Option<LastRun>) -> String {
    let cfg = reporting::load();
    let head = if cfg.enabled && !cfg.collector_url.trim().is_empty() {
        "Reporting on"
    } else {
        "Reporting off"
    };
    match last {
        None => format!("{head} · no check yet"),
        Some(r) if !r.ok => format!("{head} · last check failed"),
        Some(r) => {
            let when = short_time(r.at);
            let tail = if r.sent {
                format!("{} sent", r.count)
            } else {
                "not sent".to_string()
            };
            format!("{head} · {when} · {tail}")
        }
    }
}

/// `HH:MMZ` (UTC) extracted from the shared ISO formatter, for the compact tray
/// line. `2026-07-15T14:32:07Z` → `14:32Z`.
fn short_time(unix_secs: u64) -> String {
    let iso = journal::format_iso(unix_secs);
    match (iso.find('T'), iso.len()) {
        (Some(t), _) if iso.len() >= t + 6 => format!("{}Z", &iso[t + 1..t + 6]),
        _ => iso,
    }
}

/// Relabel the tray status item from the current config + last-run state.
/// Cheap and idempotent; safe to call from any thread that has the `AppHandle`.
fn refresh_tray_status(app: &AppHandle) {
    let state = app.state::<TrayStatus>();
    // Compute all labels up front, then release the locks before touching the
    // menu (cloning the items out keeps `state`'s borrow from outliving here).
    let (risk_text, reporting_text) = {
        let last = state.last.lock().expect("tray status lock");
        (tray_risk_text(&last), tray_reporting_text(&last))
    };
    let (os_text, os_actionable) = tray_os_text();

    let risk_item = state.risk_item.lock().expect("tray item lock").clone();
    let os_item = state.os_item.lock().expect("tray item lock").clone();
    let reporting_item = state.reporting_item.lock().expect("tray item lock").clone();

    if let Some(item) = risk_item {
        let _ = item.set_text(risk_text);
    }
    if let Some(item) = os_item {
        let _ = item.set_text(os_text);
        // Only clickable (to open update settings) when an update is warranted.
        let _ = item.set_enabled(os_actionable);
    }
    if let Some(item) = reporting_item {
        let _ = item.set_text(reporting_text);
    }
}

/// Run one reassessment, skipping if another is already in flight. This is the
/// single funnel shared by the scheduler, the tray "Reassess now" item, and the
/// `reassess_now` command — guaranteeing no overlapping runs.
pub async fn run_reassessment(app: AppHandle) {
    let guard = app.state::<ReassessGuard>();
    let _permit = match guard.0.try_lock() {
        Ok(permit) => permit,
        Err(_) => return, // a run is already in progress; skip this trigger
    };
    let last = match reporting::reassess_and_report(app.clone()).await {
        Ok(summary) => LastRun {
            at: now_secs(),
            count: summary.count,
            sent: summary.sent,
            ok: true,
            risk: summary.risk,
        },
        Err(err) => {
            eprintln!("reassessment failed: {err}");
            LastRun {
                at: now_secs(),
                count: 0,
                sent: false,
                ok: false,
                risk: reporting::RiskSummary::default(),
            }
        }
    };
    *app.state::<TrayStatus>().last.lock().expect("tray status lock") = Some(last);
    refresh_tray_status(&app);
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .manage(ReassessGuard::default())
        .manage(NetmonState::default())
        .manage(TrayStatus::default())
        .setup(|app| {
            setup_tray(app.handle())?;
            reconcile_autostart(app.handle());

            // Hide the window when launched at login (`--minimized`) so the app
            // boots straight into the background/tray.
            if std::env::args().any(|a| a == "--minimized") {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }

            // Background scheduler: once reporting is enabled, reassess shortly
            // after boot and then every configured interval. Config is re-read
            // each iteration so changes apply without a restart; awaiting the
            // run before sleeping means scheduled runs never overlap. While
            // reporting is disabled the loop just idles (no scan), polling
            // occasionally so enabling it takes effect without a restart.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_secs(15)).await;
                loop {
                    // Always run the local assessment so the tray's risky-app
                    // summary stays current; the POST inside is gated on
                    // reporting being enabled. When reporting is on we honour the
                    // configured interval; otherwise we assess on a gentle idle
                    // cadence purely to refresh the tray.
                    run_reassessment(handle.clone()).await;
                    let config = reporting::load();
                    let active = config.enabled && !config.collector_url.trim().is_empty();
                    let sleep_secs = if active {
                        config.interval_secs.max(60)
                    } else {
                        1800 // idle tray refresh (30 min)
                    };
                    tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
                }
            });

            // Independent VDB-snapshot refresh loop: keep the local trusted-host
            // snapshot fresh so CVE lookups can match offline. Idles cheaply when
            // VDB sourcing is disabled.
            let vdb_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                loop {
                    let config = reporting::load();
                    let active = config.vdb_enabled && !config.vdb_url.trim().is_empty();
                    if active {
                        let _ = reporting::refresh_vdb_snapshot(vdb_handle.clone()).await;
                    }
                    let sleep_secs = if active {
                        config.vdb_refresh_secs.max(300)
                    } else {
                        300
                    };
                    tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            // Close-to-tray: hide the main window instead of quitting. The tray
            // "Quit" item is the real exit path.
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::discover,
            commands::scan,
            commands::detect_one,
            commands::audit,
            commands::cve_lookup,
            commands::static_scan,
            commands::dependency_scan,
            commands::get_settings,
            commands::set_settings,
            commands::settings_path,
            commands::journal_save,
            commands::journal_latest,
            commands::journal_list,
            commands::journal_path,
            commands::sideeffects,
            commands::set_zoom,
            commands::reassess_now,
            commands::get_reporting_config,
            commands::set_reporting_config,
            commands::reporting_config_path,
            commands::refresh_vdb_now,
            commands::netmon_processes,
            commands::netmon_capture_available,
            commands::netmon_start,
            commands::netmon_stop,
            commands::netmon_status,
            commands::export_cbom,
            commands::crypto_inventory,
            commands::crypto_load,
            commands::binary_headers,
            commands::library_cves,
            commands::rust_audit,
            commands::os_info,
            commands::open_os_update,
            commands::helper_status,
            commands::helper_install,
            commands::helper_open_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Build the system tray icon and its Show / Reassess now / Quit menu.
fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    // Three live status lines at the top, relabelled after each assessment via
    // `refresh_tray_status`. The risk line opens the window; the OS line opens
    // update settings (enabled only when an update is warranted); the reporting
    // line is a passive label.
    let (os_text, os_actionable) = tray_os_text();
    let risk = MenuItem::with_id(app, "risk_show", tray_risk_text(&None), true, None::<&str>)?;
    let os = MenuItem::with_id(app, "os_update", os_text, os_actionable, None::<&str>)?;
    let reporting =
        MenuItem::with_id(app, "reporting_status", tray_reporting_text(&None), false, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let show = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
    let reassess = MenuItem::with_id(app, "reassess", "Reassess now", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[&risk, &os, &reporting, &sep, &show, &reassess, &quit],
    )?;

    // Keep the status items so the scheduler can relabel them later.
    {
        let state = app.state::<TrayStatus>();
        state.risk_item.lock().expect("tray item lock").replace(risk);
        state.os_item.lock().expect("tray item lock").replace(os);
        state
            .reporting_item
            .lock()
            .expect("tray item lock")
            .replace(reporting);
    }

    let mut builder = TrayIconBuilder::with_id("main-tray")
        .menu(&menu)
        // Open the menu on a normal (left) click so the status lines are visible
        // right away. "Show" / the risk line bring the window up from there.
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id.as_ref() {
            // The risk line brings the window up so the user can inspect apps.
            "show" | "risk_show" => show_main_window(app),
            "os_update" => {
                if let Err(err) = commands::open_os_update_settings() {
                    eprintln!("failed to open OS update settings: {err}");
                }
            }
            "reassess" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move { run_reassessment(app).await });
            }
            "quit" => app.exit(0),
            _ => {}
        });

    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }
    builder.build(app)?;
    Ok(())
}

/// Show and focus the main window (used by the tray Show item / icon click).
fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Bring the OS login-item state in line with the saved config.
fn reconcile_autostart(app: &AppHandle) {
    let want = reporting::load().autostart;
    let manager = app.autolaunch();
    let is_on = manager.is_enabled().unwrap_or(false);
    if want && !is_on {
        let _ = manager.enable();
    } else if !want && is_on {
        let _ = manager.disable();
    }
}
