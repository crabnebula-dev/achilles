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

use std::time::Duration;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};
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

/// Run one reassessment, skipping if another is already in flight. This is the
/// single funnel shared by the scheduler, the tray "Reassess now" item, and the
/// `reassess_now` command — guaranteeing no overlapping runs.
pub async fn run_reassessment(app: AppHandle) {
    let guard = app.state::<ReassessGuard>();
    let _permit = match guard.0.try_lock() {
        Ok(permit) => permit,
        Err(_) => return, // a run is already in progress; skip this trigger
    };
    if let Err(err) = reporting::reassess_and_report(app.clone()).await {
        eprintln!("reassessment failed: {err}");
    }
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
                    let config = reporting::load();
                    let active = config.enabled && !config.collector_url.trim().is_empty();
                    if active {
                        run_reassessment(handle.clone()).await;
                    }
                    let sleep_secs = if active {
                        config.interval_secs.max(60)
                    } else {
                        300 // idle poll for the enabled flag
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
    let show = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
    let reassess = MenuItem::with_id(app, "reassess", "Reassess now", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &reassess, &quit])?;

    let mut builder = TrayIconBuilder::with_id("main-tray")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main_window(app),
            "reassess" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move { run_reassessment(app).await });
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // Left-click the tray icon to bring the window back.
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
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
