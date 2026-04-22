//! `achilles` — Tauri app entry point.
//!
//! Wires the `detect` / `scan` / `cve` / `macho_audit` crates into five
//! `#[tauri::command]` functions. The frontend drives them; progress is
//! streamed back via `app.emit("scan_event", …)`.

mod commands;
mod journal;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
